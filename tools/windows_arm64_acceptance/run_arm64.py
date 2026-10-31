"""Bounded native Windows ARM64 replay; this file does not dispatch workflows."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import urllib.request
import venv
import zipfile

HERE = Path(__file__).resolve().parent
BINDINGS = {
    2973: {'wheel_sha256':'d29776ac86a4159737c62b7cd1c0f7fdb825fbd628a7f865066ede092dd8c58c',
           'sdist_sha256':'63a8ff4f16fca8726989d81f28cf0223f3e10f3242af042731c7cfbbdb44465a',
           'job_id':123796240303,'run_id':39386870328,'wheel_artifact':12941062896,'sdk_artifact':12941696112},
    2974: {'wheel_sha256':'1821ff9ca6c93c649f8be9ef613598db7a21438311dbeae41f51df81d5aba248',
           'sdist_sha256':'f228217f4ed1f4b37345f18b59e170fc06502b520821cf1a8229d07ccf3e0181',
           'job_id':123797762012,'run_id':39387023560,'wheel_artifact':12941771545,'sdk_artifact':12941483122},
}
SOURCE_SHA256 = '659a77b4f4b53340d24a7d6a69f4219e77ab9439a6ab8afa0156b7f6bd7af64f'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--pr',type=int,choices=sorted(BINDINGS),required=True)
    ap.add_argument('--wheelhouse',type=Path,required=True)
    ap.add_argument('--sdk',type=Path,required=True)
    ap.add_argument('--sdists',type=Path,required=True)
    ap.add_argument('--output-root',type=Path,default=Path(r'C:\arm-native-followup'))
    args=ap.parse_args()
    # Refuse x64 execution or a cross-build-only substitute before downloads,
    # compiler calls, or modifications of the supplied artifact inputs.
    if sys.platform!='win32' or platform.machine().upper() not in ('ARM64','AARCH64'):
        print('NATIVE_ARM64_REQUIRED',sys.platform,platform.machine(),flush=True)
        return 2
    process_machine=ctypes.c_ushort();native_machine=ctypes.c_ushort()
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    k.GetCurrentProcess.restype=ctypes.c_void_p
    k.IsWow64Process2.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ushort),ctypes.POINTER(ctypes.c_ushort)]
    if not k.IsWow64Process2(k.GetCurrentProcess(),ctypes.byref(process_machine),ctypes.byref(native_machine)):
        raise ctypes.WinError(ctypes.get_last_error())
    assert native_machine.value==0xaa64 and process_machine.value==0,(process_machine.value,native_machine.value)
    assert sys.version_info[:3]==(3,12,10),sys.version
    k.SetErrorMode(3)
    root=args.output_root.resolve()
    assert not root.exists(),f'Refusing pre-existing output root: {root}'
    root.mkdir();evidence=root/'evidence';evidence.mkdir()
    identity={'python':sys.executable,'version':sys.version,'platform':platform.platform(),
              'machine':platform.machine(),'process_machine':process_machine.value,'native_machine':native_machine.value,
              'original_binding':BINDINGS[args.pr],'emulator_started':False}
    (evidence/'IDENTITY.json').write_text(json.dumps(identity,indent=2),encoding='utf8')
    print('NATIVE_IDENTITY',json.dumps(identity),flush=True)
    receipts=[]
    def run(name,command,env=None,cwd=root,expected=0,timeout=600,require_stdout=()):
        before=time.monotonic()
        p=subprocess.run([str(x) for x in command],cwd=cwd,env=env,capture_output=True,timeout=timeout)
        entry={'name':name,'command':[str(x) for x in command],'cwd':str(cwd),'exit':p.returncode,
               'exit_hex32':hex(p.returncode&0xffffffff),'expected_hex32':hex(expected&0xffffffff),'seconds':time.monotonic()-before}
        for kind,payload in [('stdout',p.stdout),('stderr',p.stderr)]:
            path=evidence/f'{name}.{kind}.txt';path.write_bytes(payload)
            entry[kind]={'bytes':len(payload),'sha256':sha(path)}
        receipts.append(entry)
        (evidence/'RECEIPTS.json').write_text(json.dumps(receipts,indent=2),encoding='utf8')
        print('RECEIPT_JSON',json.dumps(entry),flush=True)
        stdout=p.stdout.decode('utf8',errors='replace')
        stderr=p.stderr.decode('utf8',errors='replace')
        print('STDOUT',name,stdout if 'build' not in name and 'wheel' not in name else stdout[-2000:],flush=True)
        print('STDERR',name,stderr,flush=True)
        assert (p.returncode&0xffffffff)==(expected&0xffffffff),entry
        assert all(marker in stdout for marker in require_stdout),(name,require_stdout)
        return p

    def wheel_native_manifest(path):
        records=[]
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if name.endswith(('.dll','.pyd')):
                    data=z.read(name);off=struct.unpack_from('<I',data,0x3c)[0]
                    assert data[off:off+4]==b'PE\0\0'
                    assert struct.unpack_from('<H',data,off+4)[0]==0xaa64,(name,'wrong PE machine')
                    records.append({'name':name,'sha256':hashlib.sha256(data).hexdigest(),'PE_machine':'0xaa64'})
        assert sum(x['name'].endswith('.pyd') for x in records)==1
        assert sum('libhomfly-' in x['name'] for x in records)==1
        assert sum('libgc-' in x['name'] for x in records)==1
        return records

    wheel=next(args.wheelhouse.glob('passagemath_homfly-*-cp312-cp312-win_arm64.whl'))
    assert sha(wheel)==BINDINGS[args.pr]['wheel_sha256']
    sdk_manifest=next(x for x in json.loads((HERE/'SDK_MEMBERS.json').read_text(encoding='utf8')) if x['pr']==args.pr)
    for entry in sdk_manifest['members']:
        p=args.sdk/entry['name'];assert sha(p)==entry['sha256'],entry['name']
    (evidence/'ORIGINAL_WHEEL.json').write_text(json.dumps({'file':wheel.name,'sha256':sha(wheel),'sdk_members_verified':len(sdk_manifest['members'])},indent=2),encoding='utf8')

    venv.EnvBuilder(with_pip=True).create(root/'venv')
    py=root/'venv/Scripts/python.exe'
    run('build-tools',[py,'-B','-m','pip','install','--disable-pip-version-check','--no-cache-dir',
        'setuptools==84.2.1','Cython==3.3.0','cysignals==1.12.6','pkgconfig==1.6.0','delvewheel==1.13.2','pefile==2024.8.26'])
    build_deps=[next(args.wheelhouse.glob('passagemath_'+name+'-*.whl')) for name in ('setup','environment','objects')]
    run('original-build-deps',[py,'-B','-m','pip','install','--no-index','--no-deps',*build_deps])
    original_site=root/'original-site'
    run('original-target-install',[py,'-B','-m','pip','install','--no-index','--no-deps','--no-compile','--target',original_site,wheel])
    TREFOIL='1 6 0 1  1 -1  2 1  0 -1  1 1  2 -1 0 1 1 1 2 1'
    original_manifest=wheel_native_manifest(wheel)
    def python_case(name,site,body,manifest,expected=0):
        code='import ctypes,os,pathlib,sys; ctypes.windll.kernel32.SetErrorMode(3); '
        code+='sys.path.insert(0,'+repr(str(HERE))+'); from child_provenance import verify; '
        code+='module,dirs=verify('+repr(str(site))+','+repr(manifest)+'); '
        code+='homfly_polynomial_string=module.homfly_polynomial_string; homfly_polynomial_dict=module.homfly_polynomial_dict; '
        required=['PHYSICAL_PROVENANCE']+(['BEFORE_CALL'] if name=='exact-original-string' else [])
        run(name,[py,'-B','-X','utf8','-c',code+body],expected=expected,timeout=60,require_stdout=required)
    python_case('exact-original-string',original_site,'print("BEFORE_CALL",flush=True); print(homfly_polynomial_string('+repr(TREFOIL)+'),flush=True)',original_manifest,0xc0000409)
    python_case('exact-original-dict',original_site,'assert homfly_polynomial_dict('+repr(TREFOIL)+')=={(-4,0):-1,(-2,0):-2,(-2,2):1}; print("DICT_OK",flush=True)',original_manifest)
    python_case('printf-count-diagnostic',original_site,'ctypes.CDLL("ucrtbase.dll")._set_printf_count_output(1); assert homfly_polynomial_string('+repr(TREFOIL)+')==" - L^-4 - 2L^-2 + M^2L^-2"; print("DIAGNOSTIC_ONLY_OK",flush=True)',original_manifest)

    # All compilation uses a fresh SDK copy. Supplied exact artifacts remain intact.
    sdk=root/'sdk-fixed';(sdk/'include').mkdir(parents=True);(sdk/'bin').mkdir()
    for entry in sdk_manifest['members']:
        src=args.sdk/entry['name'];dst=sdk/entry['name'];dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
    archive=root/'libhomfly-1.04.tar.gz'
    url='https://github.com/passagemath/passagemath/releases/download/passagemath-10.10.1.alpha1/libhomfly-1.04.tar.gz'
    with urllib.request.urlopen(url,timeout=60) as response:archive.write_bytes(response.read())
    assert sha(archive)==SOURCE_SHA256
    with tarfile.open(archive) as t:t.extractall(root/'source',filter='data')
    libsource=root/'source/libhomfly-1.04'
    # Apply the reviewed patch normally, after its complete-file SHA binding.
    patch=HERE/'patches/libhomfly-no-printf-n.patch'
    assert sha(patch)=='f820ed86cdc86ffe7b87e0917a8bb67be7d19c30404a579eab6905af7c0068f8'
    run('patch-check',['git','apply','--check',patch],cwd=libsource)
    run('patch-apply',['git','apply',patch],cwd=libsource)
    vswhere=Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
    vs=run('vs-installation',[vswhere,'-latest','-products','*','-property','installationPath']).stdout.decode('utf8').strip()
    vcvars=Path(vs)/'VC/Auxiliary/Build/vcvarsall.bat'
    bat=root/'capture-env.bat'
    bat.write_text(f'@echo off\ncall "{vcvars}" arm64 >NUL\nif errorlevel 1 exit /b 1\nset\n',encoding='ascii')
    captured=subprocess.run(['cmd.exe','/d','/c',str(bat)],capture_output=True,check=True)
    env=dict(os.environ)
    for line in captured.stdout.decode('utf8',errors='replace').splitlines():
        if '=' in line and not line.startswith('='):
            key,value=line.split('=',1);env[key.upper()]=value
    assert env.get('VSCMD_ARG_TGT_ARCH','').lower()=='arm64',env.get('VSCMD_ARG_TGT_ARCH')
    cl=shutil.which('cl.exe',path=env['PATH']);assert cl
    env.update({'DISTUTILS_USE_SDK':'1','MSSdk':'1','CIBUILDWHEEL':'1','SAGE_LOCAL':str(sdk),
                'SAGE_VENV':str(root/'venv'),'SAGE_NUM_THREADS':'4','SAGE_DEBUG':'no','PYTHONDONTWRITEBYTECODE':'1',
                'PYTHONUTF8':'1','DOT_SAGE':str(root/'dot-sage'),'PIP_DISABLE_PIP_VERSION_CHECK':'1'})
    env['INCLUDE']=str(sdk/'include')+';'+env['INCLUDE'];env['LIB']=str(sdk/'bin')+';'+env['LIB'];env['PATH']=str(sdk/'bin')+';'+env['PATH']
    # Match the successful x64 owner build: the MSVC sage.env alias branch
    # deliberately uses INCLUDE/LIB and does not use pkg-config .pc prefixes.
    definition=root/'homfly.def';definition.write_text('LIBRARY libhomfly-0.dll\nEXPORTS\n c_homfly @1\n homfly @2\n homfly_str @3\n',encoding='ascii')
    obj=root/'obj';obj.mkdir()
    run('native-arm64-dll',[cl,'/nologo','/LD','/MD','/O2','/std:c11','/DGC_DLL','/D_CRT_SECURE_NO_WARNINGS',
        '/I'+str(sdk/'include'),'/Fo'+str(obj)+'\\',*(libsource/'lib').glob('*.c'),'/link',
        '/DEF:'+str(definition),'/OUT:'+str(sdk/'bin/libhomfly-0.dll'),sdk/'bin/gc.lib'],env=env)
    pe=(sdk/'bin/libhomfly-0.dll').read_bytes();off=struct.unpack_from('<I',pe,0x3c)[0]
    assert struct.unpack_from('<H',pe,off+4)[0]==0xaa64
    src_archive=next(args.sdists.glob('passagemath_homfly-*.tar.gz'))
    assert sha(src_archive)==BINDINGS[args.pr]['sdist_sha256'],str(src_archive)
    with tarfile.open(src_archive) as t:t.extractall(root/'owner-source',filter='data')
    owner=next((root/'owner-source').glob('passagemath_homfly-*'))
    raw=root/'raw-wheels';raw.mkdir()
    fixed_wheels=evidence/'fixed-wheels';fixed_wheels.mkdir()
    run('normal-owner-wheel',[py,'-B','-m','pip','wheel','--no-index','--no-deps','--no-build-isolation','--wheel-dir',raw,owner],env=env)
    built=next(raw.glob('*.whl'));assert built.name.endswith('cp312-cp312-win_arm64.whl')
    run('normal-wheel-repair',[py,'-B','-m','delvewheel','repair','-vv','--custom-patch','--add-path',sdk/'bin','-w',fixed_wheels,built],env=env)
    fixed=next(fixed_wheels.glob('*.whl'));fixed_site=root/'fixed-site'
    fixed_manifest=wheel_native_manifest(fixed)
    assert next(x['sha256'] for x in fixed_manifest if 'libhomfly-' in x['name'])!=next(x['sha256'] for x in original_manifest if 'libhomfly-' in x['name'])
    run('normal-fixed-install',[py,'-B','-m','pip','install','--no-index','--no-deps','--no-compile','--target',fixed_site,fixed])
    python_case('fixed-wheel-default-CRT',fixed_site,'assert ctypes.CDLL("ucrtbase.dll")._get_printf_count_output()==0; assert homfly_polynomial_string('+repr(TREFOIL)+')==" - L^-4 - 2L^-2 + M^2L^-2"; assert homfly_polynomial_dict('+repr(TREFOIL)+')=={(-4,0):-1,(-2,0):-2,(-2,2):1}; print("FIXED_NATIVE_ARM64_OK",flush=True)',fixed_manifest)
    exe=root/'p_show_boundary.exe'
    run('native-boundary-build',[cl,'/nologo','/O2','/MD','/std:c11','/DGC_DLL','/D_CRT_SECURE_NO_WARNINGS',
        '/I'+str(sdk/'include'),'/I'+str(libsource/'lib'),'/Fo'+str(obj)+'\\','/Fe'+str(exe),
        HERE/'p_show_boundary.c',libsource/'lib/poly.c','/link',sdk/'bin/gc.lib'],env=env)
    data=exe.read_bytes();off=struct.unpack_from('<I',data,0x3c)[0]
    assert struct.unpack_from('<H',data,off+4)[0]==0xaa64
    print('NATIVE_BOUNDARY_PE',json.dumps({'path':str(exe),'sha256':sha(exe),'machine':'0xaa64'}),flush=True)
    run('native-boundary-run',[exe],env=env,timeout=60)
    result={'passed':True,'scope':'Two target job bindings are separate matrix runs; this result covers one exact ARM64 wheel and its normally rebuilt owner wheel',
            'identity':identity,'fixed_wheel_sha256':sha(fixed),'original_wheel_sha256':sha(wheel),
            'native_library_source_sha256':SOURCE_SHA256,'source_patch_sha256':sha(patch),
            'original_owner_sdist_sha256':sha(src_archive),'original_native_manifest':original_manifest,'fixed_native_manifest':fixed_manifest,
            'normal_owner_wheel':True,'native_ARM64_execution':True,'emulation':False,'remote_original_job_rerun':False}
    (evidence/'RESULT.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    print('FINAL_RESULT',json.dumps(result),flush=True)
    summary=os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary,'a',encoding='utf8') as f:
            f.write('Native ARM64 result\n\n```json\n'+json.dumps(result,indent=2)+'\n```\n')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
