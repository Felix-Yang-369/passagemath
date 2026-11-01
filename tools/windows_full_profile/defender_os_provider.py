"""Narrow, read-only Windows Defender MpOAV OS-component attestation prototype.

Import is pure. Only explicit Windows probe/attest calls use native APIs or
PowerShell. No Sage import, configuration change, trust-store change or DLL load.
"""
from pathlib import Path,PureWindowsPath
import base64,contextlib,ctypes,hashlib,importlib.util,json,os,re,struct,uuid
from ctypes import wintypes as W

PROGRAM_DATA_ID='62AB5D82-FDC1-4DC3-A9DD-070D1D495D97'
ROOT_CERTIFICATES={
 '3B1EFD3A66EA28B16697394703A72CA340A05BD5':'df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e',
 '8F43288AD272F3103B6FB1428485EA3014C0BCFE':'847df6a78497943f27fc72eb93f9a637320a02b561d0a91b09e87a7807ed7c61',
}
VERSION=re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\Z')
OWNED_HELPER_SHA='d4c0be4d4184b397d3abee350e4d509b94d48fb381b4e9b429012865a1ae78b1'

class AttestationError(Exception):
    def __init__(self,code):self.code=code;super().__init__(code)
def require(condition,code):
    if not condition:raise AttestationError(code)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def unique(pairs):
    result={}
    for key,value in pairs:require(key not in result,'DUPLICATE_JSON_KEY');result[key]=value
    return result
def validate_target_machine(machine):
    require(type(machine) is int and machine in (0x8664,0xaa64),'NATIVE_TARGET_TYPE_OR_MACHINE');return machine

def validate_path_syntax(path,program_data):
    require(isinstance(path,str) and isinstance(program_data,str),'PATH_TYPE')
    value=path.replace('/','\\');root=str(PureWindowsPath(program_data))
    require(not value.startswith('\\') and PureWindowsPath(value).is_absolute(),'LOCAL_ABSOLUTE_PATH_REQUIRED')
    parts=value.split('\\')
    require(re.fullmatch(r'[A-Za-z]:',parts[0]) is not None,'LOCAL_DRIVE_REQUIRED')
    require(all(p and p not in ('.','..') and not p.endswith(('.',' ')) and ':' not in p for p in parts[1:]),'PATH_ALIAS_TRAVERSAL_OR_STREAM')
    try:relative=PureWindowsPath(value).relative_to(PureWindowsPath(root))
    except ValueError:raise AttestationError('OUTSIDE_KNOWN_PROGRAM_DATA') from None
    tail=relative.parts
    require(len(tail)==5 and tuple(p.casefold() for p in tail[:3])==('microsoft','windows defender','platform') and tail[4].casefold()=='mpoav.dll','EXACT_DEFENDER_COMPONENT_PATH')
    require(VERSION.fullmatch(tail[3]) is not None,'VERSION_FORMAT')
    return {'path':str(PureWindowsPath(value)),'known_program_data':root,'version':tail[3]}

class GUID(ctypes.Structure):
    _fields_=[('Data1',W.DWORD),('Data2',W.WORD),('Data3',W.WORD),('Data4',ctypes.c_ubyte*8)]
    @classmethod
    def parse(cls,value):return cls.from_buffer_copy(uuid.UUID(value).bytes_le)

def known_program_data():
    require(os.name=='nt','WINDOWS_REQUIRED')
    shell=ctypes.WinDLL('shell32',use_last_error=True);ole=ctypes.WinDLL('ole32',use_last_error=True)
    shell.SHGetKnownFolderPath.argtypes=[ctypes.POINTER(GUID),W.DWORD,W.HANDLE,ctypes.POINTER(W.LPWSTR)];shell.SHGetKnownFolderPath.restype=ctypes.c_long
    ole.CoTaskMemFree.argtypes=[ctypes.c_void_p];value=W.LPWSTR();folder=GUID.parse(PROGRAM_DATA_ID)
    result=shell.SHGetKnownFolderPath(ctypes.byref(folder),0,None,ctypes.byref(value))
    require(result==0 and bool(value),'KNOWN_FOLDER_QUERY_FAILED')
    try:return str(PureWindowsPath(value.value))
    finally:ole.CoTaskMemFree(ctypes.cast(value,ctypes.c_void_p))

def native_process_identity():
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetCurrentProcess.restype=W.HANDLE
    kernel.IsWow64Process2.argtypes=[W.HANDLE,ctypes.POINTER(W.WORD),ctypes.POINTER(W.WORD)];kernel.IsWow64Process2.restype=W.BOOL
    process=W.WORD();native=W.WORD()
    require(kernel.IsWow64Process2(kernel.GetCurrentProcess(),ctypes.byref(process),ctypes.byref(native)),'PROCESS_MACHINE_QUERY_FAILED')
    require(process.value==0,'ATTESTATION_PROCESS_EMULATED');validate_target_machine(native.value)
    return dict(process_machine=process.value,native_machine=native.value,emulation=False)

def pe_machine(raw):
    require(type(raw) is bytes and len(raw)>=64 and raw[:2]==b'MZ','INVALID_DOS_HEADER')
    offset=struct.unpack_from('<I',raw,0x3c)[0]
    require(offset>=64 and offset+6<=len(raw) and raw[offset:offset+4]==b'PE\0\0','INVALID_PE_HEADER')
    return struct.unpack_from('<H',raw,offset+4)[0]

class FILE_INFO(ctypes.Structure):
    _fields_=[('attributes',W.DWORD),('creation',W.FILETIME),('access',W.FILETIME),('write',W.FILETIME),('volume',W.DWORD),('size_hi',W.DWORD),('size_lo',W.DWORD),('links',W.DWORD),('index_hi',W.DWORD),('index_lo',W.DWORD)]

@contextlib.contextmanager
def locked_read(path):
    """Short-lived read-only handle; refuses writes/renames during trust/hash binding."""
    import msvcrt
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,ctypes.c_void_p,W.DWORD,W.DWORD,W.HANDLE];kernel.CreateFileW.restype=W.HANDLE
    kernel.CloseHandle.argtypes=[W.HANDLE];kernel.CloseHandle.restype=W.BOOL
    handle=kernel.CreateFileW(str(path),0x80000000,1,None,3,0x08000080,None)
    require(handle not in (None,ctypes.c_void_p(-1).value),'READ_ONLY_HANDLE_FAILED')
    try:fd=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY)
    except Exception:kernel.CloseHandle(handle);raise
    with os.fdopen(fd,'rb') as stream:yield stream,W.HANDLE(msvcrt.get_osfhandle(stream.fileno()))

def handle_identity(handle):
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetFileInformationByHandle.argtypes=[W.HANDLE,ctypes.POINTER(FILE_INFO)];kernel.GetFileInformationByHandle.restype=W.BOOL
    kernel.GetFinalPathNameByHandleW.argtypes=[W.HANDLE,W.LPWSTR,W.DWORD,W.DWORD];kernel.GetFinalPathNameByHandleW.restype=W.DWORD
    info=FILE_INFO();require(kernel.GetFileInformationByHandle(handle,ctypes.byref(info)),'FILE_ID_QUERY_FAILED')
    buffer=ctypes.create_unicode_buffer(32768);size=kernel.GetFinalPathNameByHandleW(handle,buffer,len(buffer),0)
    require(0<size<len(buffer),'FINAL_HANDLE_PATH_FAILED')
    value=buffer.value;require(value.startswith('\\\\?\\') and not value.startswith('\\\\?\\UNC\\'),'FINAL_HANDLE_LOCAL_PATH')
    return dict(path=value[4:],volume_serial=info.volume,file_index=(info.index_hi<<32)|info.index_lo,bytes=(info.size_hi<<32)|info.size_lo,attributes=info.attributes)

def reject_reparse_components(path,root):
    current=Path(path);boundary=Path(root)
    while True:
        require(not (os.lstat(current).st_file_attributes & 0x400),'REPARSE_COMPONENT_REJECTED')
        if str(current).casefold()==str(boundary).casefold():break
        require(current!=current.parent,'PROGRAM_DATA_ANCESTRY_FAILED');current=current.parent

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_=[('cbStruct',W.DWORD),('pcwszFilePath',W.LPCWSTR),('hFile',W.HANDLE),('pgKnownSubject',ctypes.POINTER(GUID))]
class WINTRUST_DATA(ctypes.Structure):
    _fields_=[('cbStruct',W.DWORD),('pPolicyCallbackData',ctypes.c_void_p),('pSIPClientData',ctypes.c_void_p),('dwUIChoice',W.DWORD),('fdwRevocationChecks',W.DWORD),('dwUnionChoice',W.DWORD),('pFile',ctypes.POINTER(WINTRUST_FILE_INFO)),('dwStateAction',W.DWORD),('hWVTStateData',W.HANDLE),('pwszURLReference',W.LPCWSTR),('dwProvFlags',W.DWORD),('dwUIContext',W.DWORD),('pSignatureSettings',ctypes.c_void_p)]

def win_verify_trust(path,handle):
    library=ctypes.WinDLL('wintrust',use_last_error=True)
    library.WinVerifyTrust.argtypes=[W.HWND,ctypes.POINTER(GUID),ctypes.POINTER(WINTRUST_DATA)];library.WinVerifyTrust.restype=ctypes.c_long
    action=GUID.parse('00AAC56B-CD44-11D0-8CC2-00C04FC295EE')
    file=WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO),str(path),handle,None)
    data=WINTRUST_DATA();data.cbStruct=ctypes.sizeof(data);data.dwUIChoice=2;data.fdwRevocationChecks=1;data.dwUnionChoice=1;data.pFile=ctypes.pointer(file);data.dwStateAction=1;data.dwProvFlags=0x80
    try:status=int(library.WinVerifyTrust(W.HWND(-1),ctypes.byref(action),ctypes.byref(data)))
    finally:
        data.dwStateAction=2;closed=int(library.WinVerifyTrust(W.HWND(-1),ctypes.byref(action),ctypes.byref(data)))
    return dict(status=status,closed_status=closed,action='WINTRUST_ACTION_GENERIC_VERIFY_V2',ui='none',revocation='chain_exclude_root',same_read_only_file_handle=True)

SIGNATURE_COMMAND=r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
try {
  Import-Module -Name (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
  Import-Module -Name (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Utility/Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
  $path=$env:PM_DEFENDER_ATTEST_PATH
  $sig=Get-AuthenticodeSignature -LiteralPath $path
  function CertificateRow($cert) {
    if ($null -eq $cert) { return $null }
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$hash=([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
    $eku=@($cert.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.37'} | ForEach-Object {$_.EnhancedKeyUsages | ForEach-Object {$_.Value}})
    return @{subject=$cert.Subject;issuer=$cert.Issuer;simple_name=$cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false);thumbprint=$cert.Thumbprint;der_sha256=$hash;der_base64=[Convert]::ToBase64String($cert.RawData);serial=$cert.SerialNumber;eku=$eku}
  }
  $chain=[Security.Cryptography.X509Certificates.X509Chain]::new()
  $chain.ChainPolicy.RevocationMode=[Security.Cryptography.X509Certificates.X509RevocationMode]::Online
  $chain.ChainPolicy.RevocationFlag=[Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
  $chain.ChainPolicy.VerificationFlags=[Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
  $chain.ChainPolicy.UrlRetrievalTimeout=[TimeSpan]::FromSeconds(15)
  $null=$chain.ChainPolicy.ApplicationPolicy.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
  $valid=$false
  if ($null -ne $sig.SignerCertificate) {$valid=$chain.Build($sig.SignerCertificate)}
  $elements=@($chain.ChainElements | ForEach-Object {@{certificate=(CertificateRow $_.Certificate);status=@($_.ChainElementStatus | ForEach-Object {[string]$_.Status})}})
  @{path=$path;file_sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();status=[string]$sig.Status;signature_type=[string]$sig.SignatureType;is_os_binary=$sig.IsOSBinary;signer=(CertificateRow $sig.SignerCertificate);timestamp_signer=(CertificateRow $sig.TimeStamperCertificate);chain_valid=$valid;chain_status=@($chain.ChainStatus | ForEach-Object {[string]$_.Status});chain_elements=$elements;chain_policy=@{revocation='Online';revocation_flag='ExcludeRoot';verification_flags='NoFlag';application_policy='1.3.6.1.5.5.7.3.3'}} | ConvertTo-Json -Depth 10 -Compress
  $chain.Dispose()
} catch {
  @{signature_probe_complete=$false;error_type=$_.Exception.GetType().FullName;error_id=$_.FullyQualifiedErrorId;command=$_.InvocationInfo.MyCommand.Name} | ConvertTo-Json -Compress
  exit 1
}
'''

def validate_signature_receipt(receipt):
    require(isinstance(receipt,dict) and type(receipt.get('actual_returncode')) is int and receipt['actual_returncode']==0 and receipt.get('timed_out') is False and receipt.get('remaining_pids')==[] and receipt.get('job_assignment')=='assigned' and receipt.get('creation_suspended') is True and not any('error' in key.lower() for key in receipt),'SIGNATURE_PROCESS_FAILED')
    require(type(receipt.get('pid')) is int and receipt['pid']>0 and all(item.get('succeeded') is True for item in receipt.get('cleanup',[])),'SIGNATURE_PROCESS_OWNERSHIP')
    resume=receipt.get('resume',{})
    require(type(resume.get('previous_suspend_count')) is int and resume['previous_suspend_count']==1 and type(resume.get('confirmed_owner_pid')) is int and resume['confirmed_owner_pid']==receipt['pid'],'SIGNATURE_PROCESS_RESUME')
    if 'exit_code' in receipt:require(type(receipt['exit_code']) is int and receipt['exit_code']==receipt['actual_returncode'],'SIGNATURE_PROCESS_RC_MISMATCH')

def signature_probe(path,evidence):
    evidence=Path(evidence);evidence.mkdir(parents=True,exist_ok=False)
    helper=Path(__file__).with_name('owned_process.py');require(digest(helper.read_bytes())==OWNED_HELPER_SHA,'OWNED_PROCESS_HELPER_SHA')
    spec=importlib.util.spec_from_file_location('defender_owned_process',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    kernel=ctypes.WinDLL('kernel32',use_last_error=True);kernel.GetSystemDirectoryW.argtypes=[W.LPWSTR,W.UINT];kernel.GetSystemDirectoryW.restype=W.UINT
    buffer=ctypes.create_unicode_buffer(32768);require(0<kernel.GetSystemDirectoryW(buffer,len(buffer))<len(buffer),'SYSTEM_DIRECTORY_QUERY')
    powershell=Path(buffer.value)/'WindowsPowerShell/v1.0/powershell.exe';require(powershell.is_file(),'SYSTEM_POWERSHELL_REQUIRED')
    env={k:v for k,v in os.environ.items() if not re.search(r'TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|PRIVATE_KEY',k,re.I)}
    env['PM_DEFENDER_ATTEST_PATH']=str(path);env['TEMP']=env['TMP']=str(evidence/'temp');(evidence/'temp').mkdir()
    command=[str(powershell),'-NoProfile','-NonInteractive','-Command',SIGNATURE_COMMAND]
    with (evidence/'stdout.bin').open('wb') as stdout,(evidence/'stderr.bin').open('wb') as stderr:
        receipt=module.run_tree(command,cwd=evidence,env=env,stdout=stdout,stderr=stderr,timeout=120)
    (evidence/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    (evidence/'COMMAND.json').write_text(json.dumps(command,indent=2)+'\n',encoding='utf-8')
    validate_signature_receipt(receipt)
    result=json.loads((evidence/'stdout.bin').read_bytes().decode('utf-8-sig'),object_pairs_hook=unique)
    return result,receipt

def certificate_der_valid(row):
    require(isinstance(row,dict),'CERTIFICATE_ROW')
    try:raw=base64.b64decode(row['der_base64'],validate=True)
    except Exception:raise AttestationError('CERTIFICATE_DER_ENCODING') from None
    require(digest(raw)==row.get('der_sha256') and hashlib.sha1(raw).hexdigest().upper()==row.get('thumbprint'),'CERTIFICATE_DER_HASH')
    return raw

def validate_signature(row,file_sha):
    require(row.get('status')=='Valid' and row.get('is_os_binary') is True,'AUTHENTICODE_VALID_OS_BINARY_REQUIRED')
    require(row.get('file_sha256')==file_sha,'SIGNATURE_FILE_SHA')
    require(row.get('chain_valid') is True and row.get('chain_status')==[],'TRUSTED_CHAIN_REQUIRED')
    require(row.get('chain_policy')=={'revocation':'Online','revocation_flag':'ExcludeRoot','verification_flags':'NoFlag','application_policy':'1.3.6.1.5.5.7.3.3'},'CHAIN_POLICY_REQUIRED')
    signer=row.get('signer');certificate_der_valid(signer)
    require(signer.get('simple_name') in ('Microsoft Windows','Microsoft Windows Publisher') and 'O=Microsoft Corporation' in signer.get('subject','').split(', '),'WINDOWS_PUBLISHER_IDENTITY_REQUIRED')
    require({'1.3.6.1.5.5.7.3.3','1.3.6.1.4.1.311.10.3.6'}<=set(signer.get('eku',[])),'WINDOWS_SYSTEM_COMPONENT_EKU_REQUIRED')
    chain=row.get('chain_elements');require(isinstance(chain,list) and 2<=len(chain)<=5,'CHAIN_ELEMENTS_REQUIRED')
    for element in chain:
        require(element.get('status')==[],'CHAIN_ELEMENT_STATUS');certificate_der_valid(element.get('certificate'))
    require(chain[0]['certificate']['der_sha256']==signer['der_sha256'],'CHAIN_LEAF_BINDING')
    root=chain[-1]['certificate'];require(ROOT_CERTIFICATES.get(root['thumbprint'])==root['der_sha256'],'EXACT_OFFICIAL_MICROSOFT_ROOT_REQUIRED')
    return dict(signer_der_sha256=signer['der_sha256'],root_der_sha256=root['der_sha256'],root_thumbprint=root['thumbprint'])

def validate_attestation(row,expected_machine,expected_pin=None):
    validate_target_machine(expected_machine)
    require(isinstance(row,dict),'ATTESTATION_SCHEMA')
    syntax=validate_path_syntax(row.get('path'),row.get('known_program_data'))
    require(row.get('version')==syntax['version'],'REPORTED_VERSION_BINDING')
    before=row.get('before');after=row.get('after');require(isinstance(before,dict) and before==after,'BEFORE_AFTER_IDENTITY_CHANGED')
    require(isinstance(after,dict),'AFTER_IDENTITY_SCHEMA')
    for observed in (before,after):
        require(type(observed.get('bytes')) is int and observed['bytes']>0 and isinstance(observed.get('sha256'),str) and re.fullmatch('[0-9a-f]{64}',observed['sha256']) is not None,'BOTH_FILE_PIN_SCHEMAS')
        identity=observed.get('handle_identity',{})
        require(isinstance(identity,dict) and all(type(identity.get(key)) is int and identity[key]>=0 for key in ('volume_serial','file_index','bytes','attributes')) and identity['file_index']>0 and identity['bytes']==observed['bytes'],'BOTH_FILE_HANDLE_SCHEMAS')
    require(type(before.get('bytes')) is int and before['bytes']>0 and re.fullmatch('[0-9a-f]{64}',before.get('sha256','')) is not None,'FILE_PIN_SCHEMA')
    handle=before.get('handle_identity',{})
    require(all(type(handle.get(key)) is int and handle[key]>=0 for key in ('volume_serial','file_index','bytes','attributes')) and handle['file_index']>0 and handle['bytes']==before['bytes'],'FILE_HANDLE_IDENTITY_SCHEMA')
    require(str(PureWindowsPath(handle.get('path',''))).casefold()==syntax['path'].casefold() and not(handle['attributes'] & (0x400|0x10)),'FILE_HANDLE_PATH_OR_TYPE')
    require(type(row.get('pe_machine')) is int and row['pe_machine']==expected_machine,'DEFENDER_NATIVE_PE_REQUIRED')
    process=row.get('process_identity',{});require(type(process.get('native_machine')) is int and process['native_machine']==expected_machine and type(process.get('process_machine')) is int and process['process_machine']==0 and process.get('emulation') is False,'NATIVE_PROCESS_REQUIRED')
    require(row.get('reparse_components_rejected') is True and row.get('same_handle_final_path_verified') is True,'PATH_HANDLE_PROOF_REQUIRED')
    validate_signature_receipt(row.get('signature_process_receipt'))
    trust=row.get('win_verify_trust',{});require(type(trust.get('status')) is int and trust['status']==0 and type(trust.get('closed_status')) is int and trust['closed_status']==0 and trust.get('same_read_only_file_handle') is True,'WINVERIFYTRUST_REQUIRED')
    require(trust.get('action')=='WINTRUST_ACTION_GENERIC_VERIFY_V2' and trust.get('ui')=='none' and trust.get('revocation')=='chain_exclude_root','WINVERIFYTRUST_POLICY')
    require(str(PureWindowsPath(row.get('authenticode',{}).get('path',''))).casefold()==syntax['path'].casefold(),'SIGNATURE_PATH_BINDING')
    signer=validate_signature(row.get('authenticode',{}),before['sha256'])
    pin=dict(path=syntax['path'],known_program_data=syntax['known_program_data'],version=syntax['version'],bytes=before['bytes'],sha256=before['sha256'],pe_machine=expected_machine,**signer)
    require(expected_pin is None or (isinstance(expected_pin,dict) and type(expected_pin.get('bytes')) is int and type(expected_pin.get('pe_machine')) is int and expected_pin==pin),'DYNAMIC_EXACT_PIN_CHANGED')
    return pin

def attest(path,expected_machine,evidence_dir,expected_pin=None):
    validate_target_machine(expected_machine);program_data=known_program_data();syntax=validate_path_syntax(str(path),program_data)
    process=native_process_identity();require(process['native_machine']==expected_machine,'NATIVE_TARGET_MISMATCH')
    evidence=Path(evidence_dir);evidence.mkdir(parents=True,exist_ok=False)
    path=Path(syntax['path']);reject_reparse_components(path,program_data)
    with locked_read(path) as (stream,handle):
        identity_before=handle_identity(handle);require(str(PureWindowsPath(identity_before['path'])).casefold()==syntax['path'].casefold(),'FINAL_HANDLE_PATH_CHANGED')
        raw=stream.read();before=dict(bytes=len(raw),sha256=digest(raw),handle_identity=identity_before)
        preliminary=dict(path=syntax['path'],known_program_data=program_data,version=syntax['version'],before=before,process_identity=process,expected_native_machine=expected_machine,passed=False)
        (evidence/'PRELIMINARY_FILE_IDENTITY.json').write_text(json.dumps(preliminary,indent=2)+'\n',encoding='utf-8')
        try:machine=pe_machine(raw)
        except BaseException as error:
            preliminary.update(pe_parse_error={'type':type(error).__name__,'message':str(error)})
            (evidence/'PRELIMINARY_FILE_IDENTITY.json').write_text(json.dumps(preliminary,indent=2)+'\n',encoding='utf-8')
            raise
        preliminary['actual_pe_machine']=machine
        (evidence/'PRELIMINARY_FILE_IDENTITY.json').write_text(json.dumps(preliminary,indent=2)+'\n',encoding='utf-8')
        require(machine==expected_machine,'DEFENDER_NATIVE_PE_REQUIRED')
        trust=win_verify_trust(path,handle)
        (evidence/'WINVERIFYTRUST.json').write_text(json.dumps(trust,indent=2)+'\n',encoding='utf-8')
        signature,receipt=signature_probe(path,evidence/'signature')
        stream.seek(0);raw_after=stream.read();after=dict(bytes=len(raw_after),sha256=digest(raw_after),handle_identity=handle_identity(handle))
        row=dict(path=syntax['path'],known_program_data=program_data,version=syntax['version'],before=before,after=after,pe_machine=machine,process_identity=process,reparse_components_rejected=True,same_handle_final_path_verified=True,win_verify_trust=trust,authenticode=signature,signature_process_receipt=receipt,provider_class='Windows_OS_Defender_MpOAV_attested',mathematical_acceptance_claimed=False)
        (evidence/'RAW_ATTESTATION.json').write_text(json.dumps(row,indent=2)+'\n',encoding='utf-8')
        pin=validate_attestation(row,expected_machine,expected_pin)
        require(str(PureWindowsPath(signature['path'])).casefold()==syntax['path'].casefold(),'SIGNATURE_PATH_BINDING')
    row['passed']=True;row['dynamic_exact_pin']=pin
    (evidence/'ATTESTATION.json').write_text(json.dumps(row,indent=2)+'\n',encoding='utf-8')
    return row

def loaded_module_inventory():
    """Collect all observable module metadata before any provider classification."""
    kernel=ctypes.WinDLL('kernel32',use_last_error=True);psapi=ctypes.WinDLL('psapi',use_last_error=True)
    kernel.GetCurrentProcess.restype=W.HANDLE;process=kernel.GetCurrentProcess()
    psapi.EnumProcessModulesEx.argtypes=[W.HANDLE,ctypes.POINTER(W.HMODULE),W.DWORD,ctypes.POINTER(W.DWORD),W.DWORD];psapi.EnumProcessModulesEx.restype=W.BOOL
    psapi.GetModuleFileNameExW.argtypes=[W.HANDLE,W.HMODULE,W.LPWSTR,W.DWORD];psapi.GetModuleFileNameExW.restype=W.DWORD
    modules=(W.HMODULE*8192)();needed=W.DWORD();require(psapi.EnumProcessModulesEx(process,modules,ctypes.sizeof(modules),ctypes.byref(needed),3) and needed.value<=ctypes.sizeof(modules),'MODULE_ENUMERATION_FAILED')
    rows=[]
    for handle in modules[:needed.value//ctypes.sizeof(W.HMODULE)]:
        buffer=ctypes.create_unicode_buffer(32768)
        if not psapi.GetModuleFileNameExW(process,handle,buffer,len(buffer)):rows.append(dict(path=None,error='MODULE_PATH_QUERY_FAILED'));continue
        row=dict(path=buffer.value)
        try:
            raw=Path(buffer.value).read_bytes();row.update(bytes=len(raw),sha256=digest(raw));row['pe_machine']=pe_machine(raw)
        except Exception as error:row['error_type']=type(error).__name__
        rows.append(row)
    return rows
