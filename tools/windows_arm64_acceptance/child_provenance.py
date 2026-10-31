"""Physical native module proof, executed in each disposable ARM64 child."""
import ctypes as C
from ctypes import wintypes as W
import hashlib
import importlib
import json
from pathlib import Path
import struct
import sys

def machine(path):
    data=path.read_bytes()
    assert data[:2]==b'MZ',str(path)
    pe=struct.unpack_from('<I',data,0x3c)[0]
    assert data[pe:pe+4]==b'PE\0\0',str(path)
    return struct.unpack_from('<H',data,pe+4)[0]

def verify(site,manifest):
    site=Path(site).resolve()
    sys.path.insert(0,str(site))
    dirs=[__import__('os').add_dll_directory(str(p)) for p in site.glob('*.libs')]
    module=importlib.import_module('sage.libs.homfly')
    pyd=next(x for x in manifest if x['name'].endswith('.pyd'))
    physical=Path(module.__file__).resolve()
    assert physical==(site/pyd['name']).resolve(),(physical,pyd['name'])
    assert hashlib.sha256(physical.read_bytes()).hexdigest()==pyd['sha256']
    assert machine(physical)==0xaa64
    kernel=C.WinDLL('kernel32',use_last_error=True)
    kernel.GetCurrentProcess.restype=W.HANDLE
    process=kernel.GetCurrentProcess()
    psapi=C.WinDLL('psapi',use_last_error=True)
    modules=(C.c_void_p*4096)();needed=W.DWORD()
    psapi.EnumProcessModulesEx.argtypes=[W.HANDLE,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),W.DWORD]
    psapi.EnumProcessModulesEx.restype=W.BOOL
    psapi.GetModuleFileNameExW.argtypes=[W.HANDLE,W.HMODULE,W.LPWSTR,W.DWORD]
    psapi.GetModuleFileNameExW.restype=W.DWORD
    assert psapi.EnumProcessModulesEx(process,modules,C.sizeof(modules),C.byref(needed),3)
    assert needed.value<=C.sizeof(modules)
    loaded={}
    for handle in list(modules)[:needed.value//C.sizeof(C.c_void_p)]:
        name=C.create_unicode_buffer(32768)
        if psapi.GetModuleFileNameExW(process,handle,name,len(name)):
            path=Path(name.value).resolve()
            loaded.setdefault(path.name.casefold(),[]).append(path)
    proof=[]
    for entry in manifest:
        expected=(site/entry['name']).resolve()
        actual=loaded.get(expected.name.casefold(),[])
        assert len(actual)==1 and actual[0]==expected,(expected,actual)
        digest=hashlib.sha256(actual[0].read_bytes()).hexdigest()
        assert digest==entry['sha256'],(expected,digest,entry['sha256'])
        assert machine(actual[0])==0xaa64,str(actual[0])
        proof.append({'path':str(actual[0]),'sha256':digest,'PE_machine':'0xaa64'})
    print('PHYSICAL_PROVENANCE',json.dumps({'module':str(physical),'native_files':proof,'loaded_module_count':len(loaded)}),flush=True)
    # Retain AddDllDirectory handles through the mathematical call.
    return module,dirs
