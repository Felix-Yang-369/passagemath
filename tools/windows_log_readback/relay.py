"""Read-only same-repository GITHUB_TOKEN download; no secret/URL tracebacks."""
from pathlib import Path
import argparse,datetime,os,re,sys,time,urllib.error,urllib.parse,urllib.request
from protocol import REPOSITORY,MAX_API_BYTES,MAX_RAW_BYTES,RelayError,canonical,digest,encode,identity,require,validate_run,validate_job

API='https://api.github.com/repos/'+REPOSITORY
WAIT_SECONDS=120*60
POLL_SECONDS=30
DOWNLOAD_SECONDS=300

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def validate_blob_url(url):
    try:
        value=urllib.parse.urlsplit(url);host=value.hostname or ''
        valid=value.scheme=='https' and host.endswith('.blob.core.windows.net') and host!='blob.core.windows.net' and value.port is None and not value.username and not value.password and not value.fragment
    except Exception:valid=False
    require(valid,'UNSAFE_BLOB_REDIRECT');return host

class Client:
    def __init__(self,token,opener=None,clock=time.monotonic):
        require(isinstance(token,str) and bool(token),'MISSING_JOB_TOKEN');self.token=token;self.opener=opener or urllib.request.build_opener(NoRedirect());self.clock=clock

    def open(self,url,authorized):
        require(not authorized or url.startswith(API+'/actions/'),'UNEXPECTED_AUTHORIZED_URL')
        headers={'User-Agent':'PassageMath-immutable-job-log-relay'}
        if authorized:headers.update({'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2026-03-10','Authorization':'Bearer '+self.token})
        request=urllib.request.Request(url,headers=headers)
        try:return self.opener.open(request,timeout=60)
        except urllib.error.HTTPError as error:return error
        except Exception:raise RelayError('HTTP_TRANSPORT_ERROR') from None

    def api_json(self,route):
        require(re.fullmatch(r'/(?:runs|jobs)/[0-9]+',route) is not None,'UNEXPECTED_API_ROUTE')
        with self.open(API+'/actions'+route,True) as response:
            if response.code!=200:raise RelayError('API_HTTP_ERROR',response.code)
            try:data=response.read(MAX_API_BYTES+1)
            except Exception:raise RelayError('API_READ_ERROR') from None
            require(len(data)<=MAX_API_BYTES,'API_RESPONSE_SIZE_LIMIT');return data

    def job_log(self,job_id):
        with self.open(API+'/actions/jobs/'+str(job_id)+'/logs',True) as response:
            if response.code!=302:raise RelayError('LOG_API_EXPECTED_302',response.code)
            location=response.headers.get('Location');require(isinstance(location,str),'MISSING_LOG_LOCATION');host=validate_blob_url(location)
        # A fresh request has no Authorization or Accept header. NoRedirect
        # also applies to this second hop, so it cannot carry us to another host.
        started=self.clock();chunks=[];size=0
        with self.open(location,False) as response:
            if response.code!=200:raise RelayError('BLOB_HTTP_ERROR',response.code)
            length=response.headers.get('Content-Length')
            if length is not None:
                require(re.fullmatch('[0-9]+',length) is not None,'INVALID_CONTENT_LENGTH');require(int(length)<=MAX_RAW_BYTES,'RAW_LOG_SIZE_LIMIT')
            while True:
                require(self.clock()-started<=DOWNLOAD_SECONDS,'DOWNLOAD_TIME_LIMIT')
                try:chunk=response.read(1024*1024)
                except Exception:raise RelayError('BLOB_READ_ERROR') from None
                if not chunk:break
                size+=len(chunk);require(size<=MAX_RAW_BYTES,'RAW_LOG_SIZE_LIMIT');chunks.append(chunk)
            require(length is None or size==int(length),'TRUNCATED_CONTENT_LENGTH')
        raw=b''.join(chunks);require(bool(raw),'EMPTY_JOB_LOG')
        return raw,{'api_status':302,'blob_status':200,'blob_hostname':host,'blob_authorization_sent':False,'further_redirect_followed':False,'raw_bytes':len(raw),'raw_sha256':digest(raw)}

def wait_terminal(client,wanted,clock=time.monotonic,sleep=time.sleep):
    deadline=clock()+WAIT_SECONDS;polls=0;run_raw=client.api_json('/runs/'+str(wanted['run_id']));validate_run(run_raw,wanted)
    while True:
        require(clock()<deadline,'ORIGINAL_JOB_WAIT_TIMEOUT');job_raw=client.api_json('/jobs/'+str(wanted['job_id']));polls+=1;job=validate_job(job_raw,wanted)
        if job['status']=='completed':break
        sleep(min(POLL_SECONDS,max(0,deadline-clock())))
    while True:
        require(clock()<deadline,'ORIGINAL_RUN_WAIT_TIMEOUT');run_raw=client.api_json('/runs/'+str(wanted['run_id']));polls+=1;run=validate_run(run_raw,wanted)
        if run['status']=='completed':break
        sleep(min(POLL_SECONDS,max(0,deadline-clock())))
    validate_job(job_raw,wanted,True);validate_run(run_raw,wanted,True);return run_raw,job_raw,polls

def sensitive_values(environ):
    return [value for name,value in environ.items() if value and re.search(r'TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY',name,re.I)]

def perform(job_id,environ,client=None,clock=time.monotonic,sleep=time.sleep):
    wanted=identity(job_id);require(environ.get('GITHUB_REPOSITORY')==REPOSITORY,'RELAY_REPOSITORY_MISMATCH')
    require(environ.get('GITHUB_RUN_ID','').isdigit() and int(environ['GITHUB_RUN_ID']) not in (41248405188,41250940827),'RELAY_RUN_CONTEXT')
    client=client or Client(environ.get('GITHUB_TOKEN',''))
    run,job,polls=wait_terminal(client,wanted,clock,sleep);raw,download=client.job_log(job_id)
    receipt={'source_identity':wanted,'downloaded_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'job_log_download':download,'terminal_poll_requests':polls,
        'relay_context':{'run_id':int(environ['GITHUB_RUN_ID']),'commit_sha':environ.get('GITHUB_SHA'),'repository':REPOSITORY},
        'secret_scan':{'passed':True,'nonempty_sensitive_current_job_values_checked':len(sensitive_values(environ))},'permissions':{'actions':'read','contents':'read'},'artifact_uploads':0,'cache_writes':0,'original_workflow_reruns':0}
    files={'job.log':raw,'run-api.json':run,'job-api.json':job,'relay-receipt.json':canonical(receipt)}
    return encode(files,wanted,sensitive_values(environ))

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source-job-id',type=int,required=True);args=parser.parse_args()
    try:
        wire,header=perform(args.source_job_id,dict(os.environ));sys.stdout.buffer.write(wire);sys.stdout.buffer.flush();return 0
    except RelayError as error:
        print(canonical({'relay_complete':False,'error_type':error.code,'http_status':error.http_status}).decode('ascii'));return 1
    except Exception as error:
        # Do not print exception text, traceback, request headers or URLs.
        print(canonical({'relay_complete':False,'error_type':type(error).__name__,'http_status':None}).decode('ascii'));return 1

if __name__=='__main__':raise SystemExit(main())
