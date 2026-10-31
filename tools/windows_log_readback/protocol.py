"""Lossless opaque-byte transport for eight immutable public Actions job logs."""
from pathlib import Path
import base64,gzip,hashlib,io,json,math,re,tarfile,zlib

REPOSITORY='Felix-Yang-369/passagemath'
BRANCH='codex/native-full-profile-20261031'
WORKFLOW='.github/workflows/windows-full-profile.yml'
WORKFLOW_ID=403034508
MAX_RAW_BYTES=256*1024*1024
MAX_API_BYTES=512*1024
MAX_GZIP_BYTES=8*1024*1024
MAX_TAR_BYTES=MAX_RAW_BYTES+2*MAX_API_BYTES+1024*1024
MAX_STDOUT_BYTES=12*1024*1024
MAX_INPUT_LOG_BYTES=16*1024*1024
FRAME_BYTES=3072
FRAME_BASE64_BYTES=4096
MARKER='PM_IMMUTABLE_LOG_V1'
MEMBERS=('job.log','run-api.json','job-api.json','relay-receipt.json')
TERMINAL={'success','failure','neutral','cancelled','skipped','timed_out','action_required','startup_failure','stale'}
SOURCES={
    41248405188:{'revision':5,'commit':'1d5952d982ac9c3528c0c058c964a9ad6f907e06','jobs':{124676602021:(2973,'x64'),124676602046:(2973,'arm64'),124676601848:(2974,'x64'),124676602096:(2974,'arm64')}},
    41250940827:{'revision':6,'commit':'170b15e103c4f4b588b46809a4f854bbc5e99f64','jobs':{124684126367:(2973,'x64'),124684126630:(2973,'arm64'),124684126632:(2974,'x64'),124684126560:(2974,'arm64')}}}

class RelayError(Exception):
    def __init__(self,code,http_status=None):self.code=code;self.http_status=http_status;super().__init__(code)

def require(value,code):
    if not value:raise RelayError(code)

def digest(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def pairs(rows):
    result={}
    for key,value in rows:
        require(key not in result,'DUPLICATE_JSON_KEY');result[key]=value
    return result
def parse(raw):
    try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(RelayError('NONFINITE_JSON')))
    except RelayError:raise
    except Exception:raise RelayError('INVALID_JSON') from None
def integer(value,minimum=0):return type(value) is int and value>=minimum
def same_identity(value,wanted):return isinstance(value,dict) and canonical(value)==canonical(wanted)

def identity(job_id):
    require(type(job_id) is int,'JOB_ID_TYPE')
    for run,source in SOURCES.items():
        if job_id in source['jobs']:
            pr,arch=source['jobs'][job_id]
            return {'repository':REPOSITORY,'run_id':run,'run_attempt':1,'commit_sha':source['commit'],'workflow_id':WORKFLOW_ID,'job_id':job_id,'pr':pr,'arch':arch}
    raise RelayError('UNLOCKED_SOURCE_JOB')

def validate_run(raw,wanted,terminal=False):
    require(type(raw) is bytes and len(raw)<=MAX_API_BYTES,'RUN_API_SIZE');row=parse(raw)
    require(isinstance(row,dict),'RUN_API_TYPE')
    for key,expected in (('id',wanted['run_id']),('workflow_id',WORKFLOW_ID),('run_attempt',1)):
        require(type(row.get(key)) is int and row[key]==expected,'RUN_API_IDENTITY')
    require(row.get('head_sha')==wanted['commit_sha'] and row.get('head_branch')==BRANCH and row.get('event')=='push' and row.get('path')==WORKFLOW,'RUN_SOURCE_IDENTITY')
    require(row.get('repository',{}).get('full_name')==REPOSITORY and row.get('repository',{}).get('private') is False,'RUN_PUBLIC_REPOSITORY')
    require(row.get('status') in ('queued','in_progress','completed','waiting','pending','requested'),'RUN_STATUS')
    if terminal:require(row.get('status')=='completed' and row.get('conclusion') in TERMINAL,'RUN_NOT_TERMINAL')
    if wanted['run_id']==41248405188 and row.get('status')=='completed':require(row.get('conclusion')=='failure','R5_RUN_CONCLUSION_CHANGED')
    return row

def validate_job(raw,wanted,terminal=False):
    require(type(raw) is bytes and len(raw)<=MAX_API_BYTES,'JOB_API_SIZE');row=parse(raw)
    require(isinstance(row,dict),'JOB_API_TYPE')
    for key,expected in (('id',wanted['job_id']),('run_id',wanted['run_id']),('run_attempt',1)):
        require(type(row.get(key)) is int and row[key]==expected,'JOB_API_IDENTITY')
    require(row.get('head_sha')==wanted['commit_sha'] and row.get('labels')==[{'x64':'windows-2022','arm64':'windows-11-arm'}[wanted['arch']]],'JOB_SOURCE_OR_RUNNER')
    require(row.get('run_url')=='https://api.github.com/repos/'+REPOSITORY+'/actions/runs/'+str(wanted['run_id']),'JOB_RUN_URL')
    require(row.get('status') in ('queued','in_progress','completed','waiting'),'JOB_STATUS')
    if terminal:require(row.get('status')=='completed' and row.get('conclusion') in TERMINAL,'JOB_NOT_TERMINAL')
    if wanted['run_id']==41248405188 and row.get('status')=='completed':require(row.get('conclusion')=='failure','R5_JOB_CONCLUSION_CHANGED')
    return row

def scan_sensitive(files,sensitive_values):
    values=[value.encode('utf-8') if isinstance(value,str) else value for value in sensitive_values if value]
    require(all(type(value) is bytes for value in values),'SECRET_SCAN_TYPE')
    for data in files.values():
        require(type(data) is bytes,'FILE_BYTES_TYPE')
        require(not any(value in data for value in values),'SENSITIVE_ENV_VALUE_FOUND')

def canonical_tar(files):
    require(set(files)==set(MEMBERS),'ARCHIVE_MEMBER_SET');output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name in MEMBERS:
            data=files[name];require(type(data) is bytes,'FILE_BYTES_TYPE');info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o600;info.mtime=0;info.uid=info.gid=0;info.uname=info.gname='';archive.addfile(info,io.BytesIO(data))
    value=output.getvalue();require(len(value)<=MAX_TAR_BYTES,'TAR_SIZE_LIMIT');return value

def receipt_valid(files,wanted):
    row=parse(files['relay-receipt.json']);require(same_identity(row.get('source_identity'),wanted) and row.get('secret_scan',{}).get('passed') is True,'RECEIPT_IDENTITY_OR_SECRET_SCAN')
    download=row.get('job_log_download',{});host=download.get('blob_hostname','')
    require(download.get('api_status')==302 and type(download.get('api_status')) is int and download.get('blob_status')==200 and type(download.get('blob_status')) is int,'DOWNLOAD_HTTP_STATUS')
    require(isinstance(host,str) and host.endswith('.blob.core.windows.net') and host!='blob.core.windows.net' and download.get('blob_authorization_sent') is False and download.get('further_redirect_followed') is False,'DOWNLOAD_BLOB_AUTH_BOUNDARY')
    require(type(download.get('raw_bytes')) is int and download['raw_bytes']==len(files['job.log']) and download.get('raw_sha256')==digest(files['job.log']),'DOWNLOAD_RAW_IDENTITY')
    return row

def encode(files,wanted,sensitive_values=()):
    require(same_identity(wanted,identity(wanted.get('job_id'))),'ENCODE_SOURCE_IDENTITY')
    require(type(files.get('job.log')) is bytes and 0<len(files['job.log'])<=MAX_RAW_BYTES,'RAW_LOG_SIZE_LIMIT')
    require(set(files)==set(MEMBERS) and all(type(files[name]) is bytes and len(files[name])<=MAX_API_BYTES for name in MEMBERS if name!='job.log'),'API_OR_RECEIPT_SIZE')
    validate_run(files['run-api.json'],wanted,True);validate_job(files['job-api.json'],wanted,True);receipt_valid(files,wanted);scan_sensitive(files,sensitive_values)
    tar=canonical_tar(files);compressed=gzip.compress(tar,compresslevel=9,mtime=0);require(len(compressed)<=MAX_GZIP_BYTES,'GZIP_SIZE_LIMIT')
    chunks=[compressed[start:start+FRAME_BYTES] for start in range(0,len(compressed),FRAME_BYTES)]
    header={'schema':1,'source_identity':wanted,'format':'canonical-ustar+single-gzip','files':[{'path':name,'bytes':len(files[name]),'sha256':digest(files[name])} for name in MEMBERS],
        'tar_bytes':len(tar),'gzip_bytes':len(compressed),'gzip_sha256':digest(compressed),'frame_count':len(chunks),'frame_base64_bytes':FRAME_BASE64_BYTES}
    head=canonical(header);lines=[MARKER+' BEGIN '+base64.b64encode(head).decode('ascii')]
    for index,chunk in enumerate(chunks):lines.append(f'{MARKER} FRAME {wanted["job_id"]} {index} {len(chunks)} {digest(chunk)} '+base64.b64encode(chunk).decode('ascii'))
    end={'source_job_id':wanted['job_id'],'header_sha256':digest(head),'gzip_sha256':digest(compressed),'raw_log_sha256':digest(files['job.log']),'frame_count':len(chunks)}
    lines.append(MARKER+' END '+base64.b64encode(canonical(end)).decode('ascii'));wire=('\n'.join(lines)+'\n').encode('ascii');require(len(wire)<=MAX_STDOUT_BYTES,'RELAY_STDOUT_SIZE_LIMIT')
    return wire,header

def b64(value,limit):
    require(isinstance(value,str) and 0<len(value)<=limit,'BASE64_SIZE')
    try:result=base64.b64decode(value,validate=True)
    except Exception:raise RelayError('INVALID_BASE64') from None
    require(base64.b64encode(result).decode('ascii')==value,'NONCANONICAL_BASE64');return result

def single_gzip(value,expected):
    require(integer(expected,1) and expected<=MAX_TAR_BYTES,'TAR_SIZE_LIMIT')
    try:
        decoder=zlib.decompressobj(16+zlib.MAX_WBITS);data=decoder.decompress(value,expected+1)
        require(len(data)==expected and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,'GZIP_TRAILING_TRUNCATED_OR_SIZE')
        require(decoder.flush()==b'','GZIP_TRAILING_OUTPUT');return data
    except RelayError:raise
    except Exception:raise RelayError('INVALID_GZIP') from None

def decode(log,wanted):
    require(same_identity(wanted,identity(wanted.get('job_id'))),'DECODE_SOURCE_IDENTITY');require(type(log) is bytes and len(log)<=MAX_INPUT_LOG_BYTES,'RELAY_INPUT_SIZE_LIMIT')
    try:text=log.decode('utf-8')
    except Exception:raise RelayError('RELAY_LOG_UTF8') from None
    lines=[]
    for original in text.splitlines():
        line=re.sub(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z ', '',original,count=1)
        if line.startswith(MARKER):lines.append(line)
    require(len(lines)>=3 and lines[0].startswith(MARKER+' BEGIN ') and lines[-1].startswith(MARKER+' END '),'MISSING_BEGIN_OR_END')
    head=b64(lines[0][len(MARKER+' BEGIN '):],65536);header=parse(head)
    require(canonical(header)==head and set(header)=={'schema','source_identity','format','files','tar_bytes','gzip_bytes','gzip_sha256','frame_count','frame_base64_bytes'},'HEADER_CANONICAL_OR_KEYS')
    require(type(header['schema']) is int and header['schema']==1 and same_identity(header['source_identity'],wanted) and header['format']=='canonical-ustar+single-gzip','HEADER_SOURCE_IDENTITY')
    require(isinstance(header['files'],list) and len(header['files'])==4 and all(isinstance(row,dict) for row in header['files']),'FILE_MANIFEST')
    count=header['frame_count'];require(integer(count,1) and count<4096 and type(header['frame_base64_bytes']) is int and header['frame_base64_bytes']==FRAME_BASE64_BYTES and len(lines)==count+2,'FRAME_COUNT')
    require(integer(header['gzip_bytes'],1) and header['gzip_bytes']<=MAX_GZIP_BYTES and count==math.ceil(header['gzip_bytes']/FRAME_BYTES),'GZIP_OR_FRAME_SIZE')
    chunks=[]
    for index,line in enumerate(lines[1:-1]):
        parts=line.split(' ');require(len(parts)==7 and parts[:2]==[MARKER,'FRAME'],'FRAME_SHAPE')
        require(parts[2:5]==[str(wanted['job_id']),str(index),str(count)],'FRAME_ORDER_IDENTITY_OR_DUPLICATE')
        chunk=b64(parts[6],FRAME_BASE64_BYTES);require(digest(chunk)==parts[5],'FRAME_SHA256')
        expected=FRAME_BYTES if index<count-1 else header['gzip_bytes']-FRAME_BYTES*(count-1)
        require(len(chunk)==expected and (len(parts[6])==FRAME_BASE64_BYTES if index<count-1 else True),'FRAME_EXACT_SIZE');chunks.append(chunk)
    compressed=b''.join(chunks);require(len(compressed)==header['gzip_bytes'] and digest(compressed)==header['gzip_sha256'],'GZIP_LENGTH_OR_SHA256')
    end=parse(b64(lines[-1][len(MARKER+' END '):],4096));require(canonical(end)==canonical({'source_job_id':wanted['job_id'],'header_sha256':digest(head),'gzip_sha256':digest(compressed),'raw_log_sha256':header['files'][0].get('sha256'),'frame_count':count}),'END_MARKER_IDENTITY')
    plain=single_gzip(compressed,header['tar_bytes']);files={}
    try:
        with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as archive:
            members=archive.getmembers();require([row.name for row in members]==list(MEMBERS) and all(row.isfile() and not row.pax_headers for row in members),'ARCHIVE_MEMBER_TYPE_OR_ORDER')
            for row in members:
                cap=MAX_RAW_BYTES if row.name=='job.log' else MAX_API_BYTES;require(integer(row.size) and row.size<=cap,'ARCHIVE_MEMBER_SIZE');files[row.name]=archive.extractfile(row).read()
    except RelayError:raise
    except Exception:raise RelayError('INVALID_TAR') from None
    require(canonical_tar(files)==plain,'NONCANONICAL_OR_TRAILING_TAR')
    require(isinstance(header['files'],list) and len(header['files'])==4,'FILE_MANIFEST')
    for name,pin in zip(MEMBERS,header['files']):
        require(set(pin)=={'path','bytes','sha256'} and pin['path']==name and type(pin['bytes']) is int and pin['bytes']==len(files[name]) and pin['sha256']==digest(files[name]),'FILE_LENGTH_OR_SHA256')
    require(0<len(files['job.log'])<=MAX_RAW_BYTES,'RAW_LOG_SIZE_LIMIT');validate_run(files['run-api.json'],wanted,True);validate_job(files['job-api.json'],wanted,True);receipt_valid(files,wanted)
    return files,header

def recover_to(log,wanted,output):
    output=Path(output);require(not output.exists(),'REFUSE_EXISTING_OUTPUT');files,header=decode(log,wanted);output.mkdir(parents=True,exist_ok=False)
    for name,data in files.items():
        target=output/(str(wanted['job_id'])+'.complete.log' if name=='job.log' else name)
        with target.open('xb') as stream:stream.write(data)
    receipt={'source_identity':wanted,'restored_original_files':header['files'],'transport_only':True,'mathematical_or_profile_acceptance_claimed':False,'relay_input_sha256':digest(log)}
    with (output/'RECOVERY_RECEIPT.json').open('xb') as stream:stream.write(canonical(receipt)+b'\n')
    return receipt
