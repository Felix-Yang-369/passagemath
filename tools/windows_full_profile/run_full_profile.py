"""Complete normal Windows modular owner build and original 14 tox suites.

The file never dispatches, publishes, uploads artifacts, changes a repository ref,
or edits an input SDK. All build writes go to one exclusive short native root.
"""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import base64
import ctypes
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import venv
import zipfile
import tomllib

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from profile_contract import OWNERS,TEST_OWNERS,ORIGINAL_EIGHT,sha,safe_name,verify_members,extract_tar,wheel_inventory,provider_wheel_tags,require_valid_import_library,complete_result,source_snapshot,source_closing,compare_units,original_tox_contract,pe_machine

def utc():return datetime.now(timezone.utc).isoformat()
def save(path,value):Path(path).write_text(json.dumps(value,indent=2,ensure_ascii=True)+'\n',encoding='utf-8')
def file_record(path):path=Path(path);return {'path':str(path),'bytes':path.stat().st_size,'sha256':sha(path)}
def pe_record(path,role):return dict(file_record(path),pe_machine=hex(pe_machine(Path(path).read_bytes())),role=role)
def decoded_members(descriptor):
    if isinstance(descriptor,list):return descriptor
    pieces=[]
    for part in descriptor['parts']:
        path=HERE/str(safe_name(part['path']))
        if sha(path)!=part['sha256']:raise ValueError('SDK text pin part mismatch')
        pieces.append(path.read_text(encoding='ascii').strip())
    raw=gzip.decompress(base64.b64decode(''.join(pieces),validate=True))
    if hashlib.sha256(raw).hexdigest()!=descriptor['uncompressed_sha256']:raise ValueError('SDK member manifest digest mismatch')
    rows=json.loads(raw)
    if len(rows)!=descriptor['count']:raise ValueError('SDK member manifest count mismatch')
    return rows

def native_identity(arch):
    if sys.platform!='win32' or sys.version_info[:3]!=(3,12,10):raise ValueError('Exact native Windows CPython3.12.10 required')
    k=ctypes.WinDLL('kernel32',use_last_error=True);k.GetCurrentProcess.restype=ctypes.c_void_p
    k.IsWow64Process2.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ushort),ctypes.POINTER(ctypes.c_ushort)];k.IsWow64Process2.restype=ctypes.c_bool
    process_machine=ctypes.c_ushort();host_machine=ctypes.c_ushort()
    if not k.IsWow64Process2(k.GetCurrentProcess(),ctypes.byref(process_machine),ctypes.byref(host_machine)):raise ctypes.WinError(ctypes.get_last_error())
    expected={'x64':0x8664,'arm64':0xaa64}[arch]
    if process_machine.value!=0 or host_machine.value!=expected:raise ValueError('Native process/runner architecture mismatch or emulation')
    k.SetErrorMode(3)
    if pe_machine(Path(sys.executable).read_bytes())!=expected:raise ValueError('Driver CPython PE architecture differs from native target')
    return {'python':sys.executable,'version':sys.version,'platform':platform.platform(),'machine':platform.machine(),'process_machine':process_machine.value,'native_machine':hex(host_machine.value),'python_pe':pe_record(sys.executable,'native build driver CPython'),'native_execution':True,'emulation':False,'emulation_scope':'This CPython process and separately gated mathematical tox CPython processes/candidate PE files. Auxiliary MSYS2/Git Bash tools are inventoried separately and may use host emulation on ARM.'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--pr',type=int,choices=(2973,2974),required=True);ap.add_argument('--arch',choices=('x64','arm64'),required=True)
    for name in ('sdk','sdists','noarch','checkout','msys-root'):ap.add_argument('--'+name,type=Path,required=True)
    ap.add_argument('--output-root',type=Path,default=Path(r'C:\pm-full'))
    args=ap.parse_args();identity=native_identity(args.arch)
    pins=json.loads((HERE/'INPUTS.json').read_text());lane=next(r for r in pins['lanes'] if r['pr']==args.pr and r['arch']==args.arch)
    primary_files=json.loads((HERE/'PRIMARY_PROVIDER_FILES.json').read_text())['files']
    root=args.output_root.resolve()
    if root.exists():raise ValueError('Refusing existing build root '+str(root))
    root.mkdir();logs=root/'logs';logs.mkdir();wheelhouse=root/'wheelhouse';wheelhouse.mkdir();raw=root/'raw';raw.mkdir();sources=root/'sources';sources.mkdir();tools=root/'third-party';tools.mkdir()
    save(root/'NATIVE_IDENTITY.json',dict(identity,original_source=lane,scope='Windows16owner/14suite',sdk_binary_inputs='preexisting public upstream artifact; not a complete native SDK rebuild'))
    print('NATIVE_IDENTITY_JSON '+json.dumps(identity),flush=True)
    if sha(HERE/'owned_process.py')!=pins['owned_process_sha256']:raise ValueError('Owned-process helper hash mismatch')
    from owned_process import run_tree
    receipts=[];builds=[];tests=[];wheel_manifests=[];owner_sources={};source_pins={};fixture_before=None;providers=None;sdk=None;helper_original=None;helper_candidate=None;native_source_ledger=None;candidate_sdk_pins=None

    def run(name,command,env=None,cwd=root,timeout=1800,strict=True):
        outdir=logs/name;outdir.mkdir()
        entry={'name':name,'command':[str(x) for x in command],'cwd':str(cwd),'started_utc':utc(),'running':True}
        save(outdir/'receipt.json',entry)
        def started(value):entry.update(value);save(outdir/'receipt.json',entry)
        print('COMMAND_START_JSON '+json.dumps(entry),flush=True)
        clock=time.monotonic()
        with (outdir/'stdout.bin').open('wb') as stdout,(outdir/'stderr.bin').open('wb') as stderr:
            try:result=run_tree(entry['command'],cwd=cwd,env=env,stdout=stdout,stderr=stderr,timeout=timeout,on_start=started)
            except BaseException as error:result={'actual_returncode':None,'timed_out':False,'remaining_pids':None,'error':{'type':type(error).__name__,'message':str(error)},'job_assignment':entry.get('job_assignment','unknown'),'cleanup_status':'owned helper raised; no fabricated cleanup success'}
        entry.update(result);entry.update({'running':False,'finished_utc':utc(),'seconds':time.monotonic()-clock,'exit':result['actual_returncode'],'stdout':file_record(outdir/'stdout.bin'),'stderr':file_record(outdir/'stderr.bin')})
        save(outdir/'receipt.json',entry);receipts.append(entry);save(root/'RECEIPTS.json',receipts)
        print('COMMAND_RECEIPT_JSON '+json.dumps(entry),flush=True)
        for stream in ('stdout','stderr'):
            print('COMMAND_LOG_BEGIN '+name+' '+stream,flush=True)
            from evidence_bundle import assert_no_sensitive_values
            assert_no_sensitive_values((outdir/(stream+'.bin')).read_bytes(),name+'/'+stream)
            with (outdir/(stream+'.bin')).open('rb') as reader:
                for block in iter(lambda:reader.read(1024*1024),b''):sys.stdout.buffer.write(block)
            sys.stdout.buffer.flush();print('\nCOMMAND_LOG_END '+name+' '+stream,flush=True)
        ok=type(entry['exit']) is int and entry['exit']==0 and not entry['timed_out'] and entry['remaining_pids']==[] and not entry.get('error') and not entry.get('remaining_query_error') and entry.get('job_assignment')=='assigned'
        if strict and not ok:raise RuntimeError('Actual command failed '+name)
        return entry

    def closing():
        rows=[]
        def attempt(name,action):
            try:
                value=action();passed=value.get('passed',True) is True
                rows.append({'name':name,'passed':passed,'result':value})
            except BaseException as error:rows.append({'name':name,'passed':False,'error':str(error),'type':type(error).__name__})
        for label,path in (('sdk',args.sdk),('sdist',args.sdists),('noarch',args.noarch)):
            attempt('original-'+label,lambda label=label,path=path:verify_members(path,decoded_members(lane[label+'_artifact']['members'])))
        for package,snapshot in source_pins.items():attempt('source-'+package,lambda package=package,snapshot=snapshot:source_closing(owner_sources[package],snapshot))
        if native_source_ledger is not None:attempt('normal-native-homfly-source',lambda:source_closing(native_source,native_source_ledger))
        if helper_candidate is not None:attempt('candidate-normal-conversion-helper',lambda:{'passed':sha(helper_candidate)==highspin['source_candidate_sha256']})
        if candidate_sdk_pins is not None:attempt('complete-new-candidate-SDK',lambda:verify_members(sdk,candidate_sdk_pins))
        def fixtures():
            after={str(p.relative_to(args.checkout)):sha(p) for pattern in ('*/tox.ini','*/known-test-failures.json') for p in (args.checkout/'pkgs').glob(pattern) if p.is_file()}
            return {'passed':fixture_before is not None and fixture_before==after,'before':fixture_before,'after':after}
        attempt('all-original-tox-and-baselines',fixtures)
        for manifest in wheel_manifests:attempt('wheel-'+Path(manifest['path']).name,lambda manifest=manifest:{'passed':Path(manifest['path']).is_file() and sha(Path(manifest['path']))==manifest['sha256']})
        if providers:
            for family in ('SDK','MSYS2','base-Python'):
                def native_family(family=family):
                    values=[r for r in providers['native_files'] if r['family']==family]
                    changed=[r['path'] for r in values if not Path(r['path']).is_file() or sha(r['path'])!=r['sha256']]
                    return {'passed':not changed,'file_count':len(values),'changed':changed}
                attempt('declared-native-'+family,native_family)
        if helper_original is not None:attempt('original-source-helper',lambda:{'passed':sha(args.checkout/'build/bin/sage-dist-helpers')==helper_original})
        value={'passed':all(r['passed'] for r in rows),'independent_closing_attempts':rows};save(root/'CLOSING.json',value);print('CLOSING_JSON '+json.dumps(value),flush=True)
        return value

    result=None

    try:
        verified={}
        for label,path in (('sdk',args.sdk),('sdist',args.sdists),('noarch',args.noarch)):
            verified[label]=verify_members(path,decoded_members(lane[label+'_artifact']['members']))
        save(root/'PUBLIC_ARTIFACT_INPUTS.json',verified)
        for patch in pins['patches']:
            if sha(HERE/'patches'/patch['name'])!=patch['sha256']:raise ValueError('Public/reviewed patch mismatch '+patch['name'])
        source_entry=run('exact-original-checkout-identity',['git','-C',str(args.checkout),'rev-parse','HEAD'])
        source_commit=Path(source_entry['stdout']['path']).read_text().strip()
        if source_commit!=lane['merge_sha']:raise ValueError('Original checkout source merge mismatch')
        run('canonical-immutable-original-source-bytes',['git','-C',str(args.checkout),'-c','core.autocrlf=false','checkout-index','--force','--all'])
        index_entry=run('original-source-index-blob-pins',['git','-C',str(args.checkout),'ls-files','-s'])
        index={line.split('\t',1)[1]:line.split()[1] for line in Path(index_entry['stdout']['path']).read_text(encoding='utf-8').splitlines() if '\t' in line}
        fixture_paths=[p for pattern in ('*/tox.ini','*/known-test-failures.json') for p in (args.checkout/'pkgs').glob(pattern) if p.is_file()]
        for path in fixture_paths:
            relative=str(path.relative_to(args.checkout)).replace('\\','/');data=path.read_bytes();blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            if index.get(relative)!=blob:raise ValueError('Original fixture differs from exact immutable Git blob '+relative)
        fixture_before={str(p.relative_to(args.checkout)):sha(p) for p in fixture_paths}
        save(root/'ORIGINAL_FIXTURE_PINS.json',fixture_before)
        original_contracts={package:original_tox_contract((args.checkout/'pkgs'/('sagemath-'+package.replace('_','-'))/'tox.ini').read_text(encoding='utf-8'),package) for package in TEST_OWNERS}
        if sum(r['test_kind']=='mathematics' for r in original_contracts.values())!=13 or original_contracts['glpk']['test_kind']!='import-only':raise ValueError('The exact original 13 math plus one import-only contract differs')
        save(root/'ORIGINAL_FULL_TOX_CONTRACTS.json',original_contracts)
        sdk=root/'sdk';shutil.copytree(args.sdk,sdk)
        cliquer=sdk/'bin/cl.exe'
        if not cliquer.is_file():raise ValueError('Original Cliquer cl.exe provider absent')
        save(root/'ORIGINAL_CLIQUER_PROVIDER.json',file_record(cliquer))
        run('create-exclusive-build-environment',[sys.executable,'-I','-B','-m','venv',root/'build-env'])
        py=root/'build-env/Scripts/python.exe'
        vswhere=Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
        vs_entry=run('actual-vs-installation',[vswhere,'-latest','-products','*','-property','installationPath'])
        vs=Path(vs_entry['stdout']['path']).read_text().strip()
        capture=root/'capture-vc-env.bat'
        capture.write_text('@echo off\ncall "'+str(Path(vs)/'VC/Auxiliary/Build/vcvarsall.bat')+'" '+('arm64' if args.arch=='arm64' else 'x64')+' >NUL\nif errorlevel 1 exit /b 1\nset PATH\nset INCLUDE\nset LIB\nset VCToolsInstallDir\nset VSCMD_ARG_TGT_ARCH\n',encoding='ascii')
        captured_entry=run('capture-actual-msvc-environment',['cmd.exe','/d','/c',str(capture)])
        captured=Path(captured_entry['stdout']['path']).read_bytes()
        env=dict(os.environ)
        for key in list(env):
            if key.upper().startswith(('SAGE_','PIP_','PYTHON')) or key.upper() in ('CPATH','CFLAGS','CXXFLAGS','LDFLAGS','LIBRARY_PATH','DISTUTILS_USE_SDK','MSSDK'):del env[key]
        selected={}
        for line in captured.decode('utf-8',errors='replace').splitlines():
            if '=' in line:
                key,value=line.split('=',1);selected[key.upper()]=value;env[key.upper()]=value
        if selected.get('VSCMD_ARG_TGT_ARCH','').lower()!=('arm64' if args.arch=='arm64' else 'x64'):raise ValueError('MSVC target mismatch')
        target='arm64' if args.arch=='arm64' else 'x64'
        native_host=Path(selected['VCTOOLSINSTALLDIR'])/'bin'/('Hostarm64' if args.arch=='arm64' else 'Hostx64')/target
        if native_host.is_dir():selected['PATH']=str(native_host)+';'+selected['PATH']
        cl=shutil.which('cl.exe',path=selected['PATH']);lib=shutil.which('lib.exe',path=selected['PATH']);dumpbin=shutil.which('dumpbin.exe',path=selected['PATH'])
        if not cl or 'Microsoft Visual Studio' not in cl or not lib:raise ValueError('Actual MSVC compiler not selected')
        msystem='ucrt64' if args.arch=='x64' else 'clangarm64';msysbin=args.msys_root/msystem/'bin'
        pkg_config=msysbin/'pkg-config.exe'
        if not pkg_config.is_file():raise ValueError('Normal native MSYS2 pkgconf missing')
        for directory in ('temp','home','dot-sage'): (root/directory).mkdir()
        env.update({'CIBUILDWHEEL':'1','SAGE_LOCAL':str(sdk),'SAGE_VENV':str(root/'build-env'),'SAGE_NUM_THREADS':'4','SAGE_DEBUG':'no','PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1','PYTHONUTF8':'1','PYTHONIOENCODING':'utf-8','PIP_DISABLE_PIP_VERSION_CHECK':'1','PIP_NO_CACHE_DIR':'1','PIP_CONFIG_FILE':os.devnull,'DOT_SAGE':str(root/'dot-sage'),'HOME':str(root/'home'),'TEMP':str(root/'temp'),'TMP':str(root/'temp'),'PKG_CONFIG':str(pkg_config),'PKG_CONFIG_PATH':str(sdk/'lib/pkgconfig'),'SAGE_PKG_CONFIG_PATH':str(sdk/'lib/pkgconfig')})
        env['PATH']=';'.join((str(Path(cl).parent),str(sdk/'bin'),str(root/'build-env/Scripts'),str(msysbin),selected['PATH']))
        env['INCLUDE']=str(sdk/'include')+';'+selected['INCLUDE'];env['LIB']=str(sdk/'bin')+';'+str(sdk/'lib')+';'+selected['LIB']
        runtime_env=dict(env)
        runtime_env['PATH']=';'.join((str(sdk/'bin'),str(root/'build-env/Scripts'),str(msysbin),selected['PATH']))
        auxiliary=[pe_record(path,role) for path,role in ((args.msys_root/'usr/bin/bash.exe','original tox/helper auxiliary MSYS2 shell'),(args.msys_root/'usr/bin/cygpath.exe','path conversion auxiliary'),(Path(shutil.which('git.exe')),'source/patch auxiliary Git'))]
        toolchain={'compiler':pe_record(cl,'native target compiler'),'librarian':pe_record(lib,'native import library producer'),'dumpbin':pe_record(dumpbin,'export reader'),'pkg_config':pe_record(pkg_config,'normal MSYS2 pkgconf metadata tool'),'auxiliary_tools':auxiliary,'preferred_native_host_tool_dir':str(native_host),'preferred_native_host_available':native_host.is_dir(),'msvc_target':target,'msys_arch_bin':str(msysbin),'normal_setuptools_msvc_initialization':True,'DISTUTILS_USE_SDK_override':False,'python_pkgconf_wheel_used':False,'auxiliary_tools_may_use_host_emulation':True,'native_math_scope':'CPython and all candidate .pyd/producer DLL files must match target; auxiliary executable PE is reported separately.'}
        if native_host.is_dir() and any(toolchain[key]['pe_machine']!=identity['native_machine'] for key in ('compiler','librarian','dumpbin')):raise ValueError('Preferred native MSVC host tool PE mismatch')
        save(root/'ACTUAL_TOOLCHAIN.json',toolchain)
        run('build-compiler-resolution',[py,'-I','-B','-c','import shutil;from pathlib import Path;p=Path(shutil.which("cl.exe")).resolve();assert p==Path('+repr(cl)+').resolve();print(p)'],env)
        run('runtime-cliquer-resolution',[py,'-I','-B','-c','import shutil;from pathlib import Path;p=Path(shutil.which("cl.exe")).resolve();assert p==Path('+repr(str(cliquer))+').resolve();print(p)'],runtime_env)
        run('actual-pkgconfig-version',[pkg_config,'--version'],env)
        run('original-sdk-pc-version-prefix',[pkg_config,'--modversion','gsl'],env)
        run('original-sdk-pc-prefix',[pkg_config,'--variable=prefix','gsl'],env)
        run('original-sdk-pc-flags',[pkg_config,'--cflags','--libs','gsl'],env,strict=False)
        run('download-pinned-build-tools',[py,'-I','-B','-m','pip','download','--only-binary=:all:','--dest',tools,*pins['third_party_build_pins']],env,timeout=900)
        # Inspect internal tags as well as filenames. A mislabeled Linux wheel
        # must never become a Windows build-tool provider.
        provider_wheels=[]
        for wheel in tools.glob('*.whl'):
            tags=provider_wheel_tags(wheel,args.arch)
            primary=primary_files.get(wheel.name)
            if primary is None:
                from email import message_from_bytes
                with zipfile.ZipFile(wheel) as archive:
                    metadata=message_from_bytes(archive.read(next(n for n in archive.namelist() if n.endswith('.dist-info/METADATA'))))
                name=metadata['Name'];version=metadata['Version']
                if not re.fullmatch(r'[A-Za-z0-9_.-]+',name+version):raise ValueError('Invalid third-party metadata project/version')
                metadata_url='https://pypi.org/pypi/'+name+'/'+version+'/json'
                with urllib.request.urlopen(metadata_url,timeout=45) as response:metadata_bytes=response.read()
                records=json.loads(metadata_bytes)['urls'];selected_files=[r for r in records if r['filename']==wheel.name]
                if len(selected_files)!=1:raise ValueError('Downloaded provider absent from official project/version metadata')
                primary={'sha256':selected_files[0]['digests']['sha256'],'url':selected_files[0]['url'],'metadata_url':metadata_url,'metadata_sha256':hashlib.sha256(metadata_bytes).hexdigest()}
            if sha(wheel)!=primary['sha256']:raise ValueError('Downloaded provider differs from primary source digest '+wheel.name)
            provider_wheels.append(dict(file_record(wheel),internal_tags=tags,official_primary_file=primary))
        save(root/'THIRD_PARTY_PROVIDER_WHEELS.json',provider_wheels)
        run('install-pinned-build-tools',[py,'-I','-B','-m','pip','install','--no-index','--no-deps','--find-links',tools,*sorted(tools.glob('*.whl'))],env,timeout=900)
        run('download-memory-allocator-source',[py,'-I','-B','-m','pip','download','--no-deps','--no-binary=:all:','--dest',tools,pins['source_build_requirement']],env,timeout=600)
        memory=next(tools.glob('memory_allocator-*.tar.gz'))
        if memory.name not in primary_files or sha(memory)!=primary_files[memory.name]['sha256']:raise ValueError('Memory allocator source differs from official pinned metadata')
        save(root/'MEMORY_ALLOCATOR_SOURCE.json',dict(file_record(memory),official_primary_file=primary_files[memory.name]))
        for wheel in args.noarch.glob('*.whl'):
            copied=wheelhouse/wheel.name;shutil.copyfile(wheel,copied)
            wheel_manifests.append(wheel_inventory(copied,args.arch,require_native=False))
        noarch_build=[p for p in wheelhouse.glob('*.whl') if p.name.startswith(('passagemath_setup-','passagemath_environment-','passagemath_repl-','passagemath_sws2rst-'))]
        run('install-original-pure-build-deps',[py,'-I','-B','-m','pip','install','--no-index','--no-deps',*noarch_build],env)
        run('normal-memory-allocator-wheel',[py,'-I','-B','-m','pip','wheel','--no-index','--no-deps','--no-build-isolation','-w',tools,memory],env)
        run('normal-memory-allocator-install',[py,'-I','-B','-m','pip','install','--no-index','--no-deps',next(tools.glob('memory_allocator-*.whl'))],env)
        env['PIP_NO_INDEX']='1';env['PIP_FIND_LINKS']=str(wheelhouse)+' '+str(tools)
        patch=lambda name:HERE/'patches'/name
        for name,cwd in (('gsl-header-windows-macro.patch',sdk/'include/gsl'),('rw-header-dll-data-import.patch',sdk/'include')):
            run(name+'-check',['git','-c','core.autocrlf=false','apply','--check',patch(name)],env,cwd)
            run(name+'-apply',['git','-c','core.autocrlf=false','apply',patch(name)],env,cwd)
        helper=args.checkout/'build/bin/sage-dist-helpers'
        helper_original=sha(helper)
        highspin=next(p for p in pins['patches'] if p['name']=='exclude-reserved-null-import-descriptor.patch')
        if sha(helper)!=highspin['source_original_sha256']:raise ValueError('Normal conversion helper baseline mismatch')
        # Apply to a fresh source/helper copy, keeping original checkout fixtures.
        helper_root=root/'helper-source';(helper_root/'build/bin').mkdir(parents=True)
        copied_helper=helper_root/'build/bin/sage-dist-helpers';shutil.copyfile(helper,copied_helper)
        run('highs-helper-source-check',['git','-c','core.autocrlf=false','apply','--check',patch(highspin['name'])],env,helper_root)
        run('highs-helper-source-apply',['git','-c','core.autocrlf=false','apply',patch(highspin['name'])],env,helper_root)
        if sha(copied_helper)!=highspin['source_candidate_sha256']:raise ValueError('Normal conversion helper candidate mismatch')
        helper_candidate=copied_helper
        cygpath=args.msys_root/'usr/bin/cygpath.exe';bash=args.msys_root/'usr/bin/bash.exe'
        def posix(path):
            entry=run('cygpath-'+str(len(receipts)),[cygpath,'-u',str(path)],env)
            return Path(entry['stdout']['path']).read_text().strip()
        helper_posix=posix(copied_helper);sdk_posix=posix(sdk)
        run('normal-source-highs-import-library',[bash,'-c','set -e; source "$1"; export SAGE_LOCAL="$2" SAGE_DESTDIR="" RUNNER_ARCH="$3"; sdh_generate_windows_lib_files highs','profile-helper',helper_posix,sdk_posix,'ARM64' if args.arch=='arm64' else 'X64'],env,timeout=600)
        save(root/'NORMAL_HIGHS_IMPORT_LIBRARY.json',require_valid_import_library(sdk/'bin/highs.lib'))
        archive=root/'libhomfly-1.04.tar.gz'
        with urllib.request.urlopen(pins['native_homfly_archive']['url'],timeout=60) as response:archive.write_bytes(response.read())
        if sha(archive)!=pins['native_homfly_archive']['sha256']:raise ValueError('Public native homfly archive mismatch')
        native_source=extract_tar(archive,root/'native-source')
        run('homfly-source-patch-check',['git','-c','core.autocrlf=false','apply','--check',patch('libhomfly-no-printf-n.patch')],env,native_source)
        run('homfly-source-patch-apply',['git','-c','core.autocrlf=false','apply',patch('libhomfly-no-printf-n.patch')],env,native_source)
        native_source_ledger=source_snapshot(native_source);save(root/'NATIVE_HOMFLY_SOURCE_LEDGER.json',native_source_ledger)
        definition=root/'homfly.def';definition.write_text('LIBRARY libhomfly-0.dll\nEXPORTS\n c_homfly @1\n homfly @2\n homfly_str @3\n',encoding='ascii');obj=root/'native-obj';obj.mkdir()
        run('normal-native-homfly-library',[cl,'/nologo','/LD','/MD','/O2','/std:c11','/DGC_DLL','/D_CRT_SECURE_NO_WARNINGS','/I'+str(sdk/'include'),'/Fo'+str(obj)+'\\',*sorted((native_source/'lib').glob('*.c')),'/link','/DEF:'+str(definition),'/OUT:'+str(sdk/'bin/libhomfly-0.dll'),sdk/'bin/gc.lib'],env,timeout=900)
        candidate_sdk_pins=[{'name':str(path.relative_to(sdk)).replace('\\','/'),'bytes':path.stat().st_size,'sha256':sha(path)} for path in sdk.rglob('*') if path.is_file()]
        save(root/'COMPLETE_CANDIDATE_SDK_PINS.json',candidate_sdk_pins)
        patch_counts={'gsl-dll-data-import.patch':0,'rankwidth-pxd-dll-data-import.patch':0}
        for package in OWNERS:
            pin=next(r for r in pins['sdist_profile'] if r['pr']==args.pr and r['package']==package)
            sdist=args.sdists/pin['sdist_member']
            if sha(sdist)!=pin['sha256']:raise ValueError('Original owner sdist mismatch '+package)
            source=extract_tar(sdist,sources/package);owner_sources[package]=source
            for name,relative in (('gsl-dll-data-import.patch','sage/libs/gsl/types.pxd'),('rankwidth-pxd-dll-data-import.patch','sage/graphs/graph_decompositions/rankwidth.pxd')):
                if (source/relative).is_file():
                    run(package+'-'+name+'-check',['git','-c','core.autocrlf=false','apply','-p2','--check',patch(name)],env,source)
                    run(package+'-'+name+'-apply',['git','-c','core.autocrlf=false','apply','-p2',patch(name)],env,source);patch_counts[name]+=1
            source_pins[package]=source_snapshot(source)
        if patch_counts!={'gsl-dll-data-import.patch':1,'rankwidth-pxd-dll-data-import.patch':1}:raise ValueError('Owner source patch placement does not match actual distributions '+repr(patch_counts))
        save(root/'CANDIDATE_OWNER_SOURCE_PINS.json',source_pins)
        alias_code='import json,os,sage.env;from pathlib import Path;from sage.env import cython_aliases;a=cython_aliases(required_modules=("gsl",),optional_modules=());assert a["GSL_LIBRARIES"]=="gsl" and a["GSL_INCDIR"]==[] and a["GSL_LIBDIR"]==[];s=Path(os.environ["SAGE_LOCAL"]);assert (s/"bin/gsl.lib").is_file() and (s/"include/gsl/gsl_types.h").is_file();assert str(s/"bin") in os.environ["LIB"] and str(s/"include") in os.environ["INCLUDE"];print(json.dumps({"module":sage.env.__file__,"aliases":a,"selected_include_provider":str(s/"include"),"selected_library_provider":str(s/"bin"),"sdk_pc_prefix_used_for_msvc_aliases":False},default=str))'
        run('actual-msvc-alias-provider',[py,'-I','-B','-c',alias_code],env)
        source_paths=root/'OWNER_SOURCE_PATHS.json';save(source_paths,{p:str(s) for p,s in owner_sources.items()})
        requirement_file=root/'NORMAL_OWNER_REQUIREMENTS.json'
        run('normal-source-requirements',[py,'-I','-B',HERE/'source_requirements.py','--sources',source_paths,'--output',requirement_file],env)
        requirements=json.loads(requirement_file.read_text())
        for package in OWNERS:
            source=owner_sources[package];out=raw/package;out.mkdir();successful={r['package'] for r in builds if r.get('accepted') is True}
            missing=[p for p in requirements[package]['build_owner_dependencies'] if p not in successful]
            if missing:
                builds.append({'package':package,'state':'blocked','exit':None,'accepted':False,'blocked_by':missing,'reason':'Declared normal source build prerequisites have no accepted source-built owner wheel'});save(root/'BUILD_RESULTS.json',builds);continue
            try:
                if package=='gsl':
                    expected=sha(owner_sources['modules']/'sage/libs/gsl/types.pxd')
                    code='from pathlib import Path;import hashlib,sys;p=Path(sys.prefix)/"Lib/site-packages/sage/libs/gsl/types.pxd";assert p.is_file();assert hashlib.sha256(p.read_bytes()).hexdigest()=='+repr(expected)+';print("NORMAL_PUBLIC_MODULES_TYPES",str(p))'
                    run('gsl-normal-public-modules-dependency',[py,'-I','-B','-c',code],env)
                build_entry=run(package+'-normal-owner-wheel',[py,'-I','-B','-m','pip','wheel','-v','--no-index','--no-deps','--no-build-isolation','-w',out,source],env,source,timeout=5400)
                built=list(out.glob('*.whl'))
                if len(built)!=1:raise ValueError('Expected exactly one normal owner wheel '+package)
                ledger=root/(package+'-original-source-ledger.json');save(ledger,source_pins[package]);discovery_path=root/(package+'-normal-discovery.json')
                run(package+'-official-source-discovery',[py,'-I','-B',HERE/'normal_discovery.py','--package',package,'--source-ledger',ledger,'--output',discovery_path],env,source)
                discovery=json.loads(discovery_path.read_text());raw_inventory=wheel_inventory(built[0],args.arch,discovery['cython_extensions'])
                generated={}
                for files in discovery['extension_source_files'].values():
                    for relative in files:
                        normalized=str(Path(relative)).replace('\\','/')
                        if normalized not in source_pins[package]['owned']:generated[normalized]=sha(source/relative)
                with zipfile.ZipFile(built[0]) as normal_wheel:
                    python_readback=[]
                    for module in discovery['python_modules']:
                        relative=module.replace('.','/')+'.py';path=source/relative
                        if normal_wheel.read(relative)!=path.read_bytes():raise ValueError('Officially discovered Python source differs/missing in normal wheel '+relative)
                        python_readback.append({'member':relative,'sha256':sha(path)})
                        if relative not in source_pins[package]['owned']:generated[relative]=sha(path)
                save(root/(package+'-NORMAL_PYTHON_SOURCE_READBACK.json'),{'officially_discovered_python_module_count':len(python_readback),'source_normal_wheel_exact_matches':python_readback})
                source_pins[package]['normal_generated_source_files']=generated;save(root/'CANDIDATE_OWNER_SOURCE_PINS.json',source_pins)
                compiled=[]
                with zipfile.ZipFile(built[0]) as wheel:
                    for name in wheel.namelist():
                        if not name.endswith('.pyd'):continue
                        matches=[p for p in (source/'build').glob('lib*/'+name) if p.is_file()]
                        if len(matches)!=1 or matches[0].read_bytes()!=wheel.read(name):raise ValueError('Normal build/raw-wheel extension bytes differ '+name)
                        compiled.append({'member':name,'normal_build_file':file_record(matches[0])})
                save(root/(package+'-RAW_BUILD_READBACK.json'),{'official_source_discovery':discovery,'raw_wheel':raw_inventory,'normal_compiled_files':compiled})
                run(package+'-normal-wheel-repair',[py,'-I','-B','-m','delvewheel','repair','-vv','--custom-patch','--add-path',str(sdk/'bin')+os.pathsep+str(msysbin),'-w',wheelhouse,built[0]],env,timeout=900)
                fixed=list(wheelhouse.glob('passagemath_'+package+'-*.whl'))
                if len(fixed)!=1:raise ValueError('Expected exactly one repaired owner wheel '+package)
                inventory=wheel_inventory(fixed[0],args.arch,discovery['cython_extensions'])
                if package=='modules':
                    with zipfile.ZipFile(fixed[0]) as wheel:
                        if wheel.read('sage/libs/gsl/types.pxd')!=(source/'sage/libs/gsl/types.pxd').read_bytes():raise ValueError('Full modules wheel did not publish the candidate types.pxd')
                wheel_manifests.append(inventory);save(root/'REBUILT_WHEEL_MANIFESTS.json',wheel_manifests)
                run(package+'-normal-build-dependency-install',[py,'-I','-B','-m','pip','install','--force-reinstall','--no-index','--no-deps','--no-compile',fixed[0]],env)
                builds.append({'package':package,'state':'built','exit':build_entry['exit'],'accepted':True,'wheel':file_record(fixed[0]),'pyd_count':inventory['pyd_count'],'normal_source_discovery':file_record(discovery_path)})
            except Exception as error:
                builds.append({'package':package,'state':'failed','exit':receipts[-1].get('exit') if receipts else None,'accepted':False,'error':str(error),'error_type':type(error).__name__,'last_actual_command':receipts[-1] if receipts else None})
            save(root/'BUILD_RESULTS.json',builds)
        # Snapshot only declared native providers; inventory is later checked in
        # every effective tox process and independently at final closing.
        native_files=[]
        for family,folder in (('SDK',sdk),('MSYS2',msysbin),('base-Python',Path(sys.base_prefix))):
            for path in folder.rglob('*'):
                if path.is_file() and path.suffix.lower() in ('.dll','.pyd','.exe'):native_files.append(dict(file_record(path.resolve()),family=family))
        providers={'sdk_root':str(sdk),'msys_arch_bin':str(msysbin),'base_python':sys.base_prefix,'native_files':native_files}
        provider_path=root/'DECLARED_NATIVE_PROVIDERS.json';save(provider_path,providers)
        wheel_manifests_path=root/'REBUILT_WHEEL_MANIFESTS.json';save(wheel_manifests_path,wheel_manifests)
        accepted={r['package'] for r in builds if r.get('accepted') is True}
        def transitive_dependencies(package):
            selected=set();pending=list(requirements[package]['test_owner_dependencies'])
            while pending:
                dependency=pending.pop()
                if dependency in selected:continue
                selected.add(dependency);pending.extend(requirements[dependency]['test_owner_dependencies'])
            return selected
        stats_dir=root/'evidence-stats';stats_dir.mkdir()
        for package in TEST_OWNERS:
            contract=original_contracts[package]
            record={'package':package,'test_kind':contract['test_kind'],'original_contract_sha256':contract['source_sha256'],'state':'blocked','exit':None,'summary_seen':False,'reported_tests':0,'provenance_passed':False,'units_matched':False,'original_target_jobs':[r['job_id'] for r in ORIGINAL_EIGHT if r['pr']==args.pr and r['arch']==args.arch and r['package']==package]}
            blockers=sorted(({package}|transitive_dependencies(package))-accepted)
            if blockers:
                record.update({'blocked_by':blockers,'reason':'Missing accepted normally rebuilt target/dependency owner; no old wheel substitution'});tests.append(record);save(root/'TEST_RESULTS.json',tests);continue
            distribution='sagemath-'+package.replace('_','-');cwd=args.checkout/'pkgs'/distribution;wheel=next(wheelhouse.glob('passagemath_'+package+'-*.whl'))
            constraints=root/(package+'-constraints.txt');lines=[]
            for owner in OWNERS:
                if owner==package:continue
                candidates=list(wheelhouse.glob('passagemath_'+owner+'-*.whl'))
                candidate=candidates[0] if len(candidates)==1 and owner in accepted else root/'missing-owner'/('passagemath_'+owner+'-missing.whl')
                lines.append('passagemath_'+owner+' @ '+candidate.resolve().as_uri())
            for candidate in args.noarch.glob('*.whl'):lines.append(candidate.name.split('-')[0]+' @ '+(wheelhouse/candidate.name).resolve().as_uri())
            constraints.write_text('\n'.join(lines)+'\n',encoding='utf-8')
            test_env=dict(runtime_env);test_env.pop('PIP_NO_INDEX',None)
            test_env.update({'PIP_FIND_LINKS':str(wheelhouse)+' '+str(tools),'PIP_CONSTRAINT':str(constraints),'PIP_BUILD_CONSTRAINT':str(constraints),'SAGE_DOCTEST_OPTIONS':'--verbose'})
            setup_env=dict(test_env);setup_env['PATH']=env['PATH']
            try:
                listed=run(package+'-original-tox-list',[py,'-I','-B','-m','tox','-l','-q'],setup_env,cwd)
                listed_text=Path(listed['stdout']['path']).read_text(encoding='utf-8',errors='replace')
                envs=[re.sub(r'sagepython-.*nopypi-norequirements','py312-norequirements',line.strip()) for line in listed_text.splitlines() if line.strip()]
                if envs!=['py312-norequirements-notest','py312-norequirements']:raise ValueError('Original complete tox environment contract differs')
                run(package+'-normal-tox-install-before-math',[py,'-I','-B','-m','tox','-v','-v','--notest','-e',','.join(envs),'--installpkg',wheel],setup_env,cwd,timeout=1800)
                run(package+'-original-effective-tox-config',[py,'-I','-B','-m','tox','config','-e','py312-norequirements','-k','commands','set_env','pass_env'],test_env,cwd)
                probe_path=root/(package+'-PRE_PROVENANCE.json')
                probe_command=[py,'-I','-B','-m','tox','exec','-e','py312-norequirements','--','python','-I','-B',HERE/'child_inventory.py','--package',package,'--wheel-manifests',wheel_manifests_path,'--provider-manifest',provider_path,'--machine',identity['native_machine'],'--output',probe_path]
                import_args=[]
                for name in contract['imports']:import_args.extend(['--import-module',name])
                probe_command=probe_command[:-2]+import_args+probe_command[-2:]
                run(package+'-effective-tox-pretest-provenance',probe_command,test_env,cwd,timeout=600)
                pre=json.loads(probe_path.read_text())
                if pre.get('passed') is not True:raise ValueError('Pretest effective tox provenance failed')
                notest_probe=None;notest_pre=None
                if contract['test_kind']=='import-only':
                    notest_path=root/(package+'-NOTEST_PRE_PROVENANCE.json');notest_probe=list(probe_command);notest_probe[notest_probe.index('-e')+1]='py312-norequirements-notest';notest_probe[-1]=notest_path
                    run(package+'-original-notest-import-pre-provenance',notest_probe,test_env,cwd,timeout=600);notest_pre=json.loads(notest_path.read_text())
                    if notest_pre.get('passed') is not True:raise ValueError('Original import-only notest environment provenance failed')
                record['provenance_passed']=True
                selected=None;stats_path=None
                if contract['test_kind']=='mathematics':
                    bash_probe_path=root/(package+'-BASH_PRE_PROVENANCE.json')
                    bash_body='set -e; cp=$1; shift; p=$(command -v python); r=$(command -v sage-runtests); export PROFILE_BASH_PYTHON="$("$cp" -w "$p")" PROFILE_BASH_SAGE_RUNTESTS="$("$cp" -w "$r")"; exec python -I -B "$@"'
                    child_arguments=probe_command[probe_command.index(HERE/'child_inventory.py')+1:];child_arguments[-1]=bash_probe_path
                    bash_probe=[py,'-I','-B','-m','tox','exec','-e','py312-norequirements','--','bash','-c',bash_body,'original-bash-resolution',cygpath,HERE/'child_inventory.py','--require-bash-resolution',*child_arguments]
                    run(package+'-original-bash-native-launcher-resolution',bash_probe,test_env,cwd,timeout=600)
                    bash_readback=json.loads(bash_probe_path.read_text())
                    if bash_readback.get('original_bash_resolution',{}).get('passed') is not True or bash_readback['installed_distribution_source_lock_sha256']!=pre['installed_distribution_source_lock_sha256']:raise ValueError('Original Bash/launcher/source identity mismatch')
                    record['original_bash_native_launcher_proven']=True
                    selected_path=root/(package+'-SELECTED_UNITS.json');contract_path=root/(package+'-ORIGINAL_CONTRACT.json');save(contract_path,contract)
                    run(package+'-normal-unit-selection',[py,'-I','-B','-m','tox','exec','-e','py312-norequirements','--','python','-I','-B',HERE/'doctest_units.py','--tox-ini',cwd/'tox.ini','--contract',contract_path,'--package',package,'--output',selected_path],test_env,cwd,timeout=600)
                    selected=json.loads(selected_path.read_text());stats_path=Path(selected['stats_path'])
                entry=run(package+'-complete-original-tox',[py,'-I','-B','-m','tox','-v','-v','-e',','.join(envs),'--installpkg',wheel],test_env,cwd,timeout=10800,strict=False)
                record['exit']=entry['exit'];record['state']='executed';record['actual_tox_receipt']=entry
                text=Path(entry['stdout']['path']).read_text(encoding='utf-8',errors='replace')+'\n'+Path(entry['stderr']['path']).read_text(encoding='utf-8',errors='replace')
                clean_execution=type(entry['exit']) is int and entry['exit']==0 and entry.get('remaining_pids')==[] and not entry.get('timed_out') and not entry.get('error') and not entry.get('remaining_query_error')
                record['summary_seen']='Total time for all tests:' in text if contract['test_kind']=='mathematics' else clean_execution
                if contract['test_kind']=='import-only':record.update({'reported_tests':0,'units_matched':clean_execution,'mathematical_test_pass_claimed':False,'original_import_only_commands':contract['active_commands']})
                if stats_path is not None and stats_path.is_file():
                    copied_stats=stats_dir/(package+'.timings2.json');shutil.copyfile(stats_path,copied_stats)
                    def unique(pairs):
                        value={}
                        for key,item in pairs:
                            if key in value:raise ValueError('Duplicate actual stats key '+key)
                            value[key]=item
                        return value
                    stats=json.loads(copied_stats.read_text(),object_pairs_hook=unique);unit_result=compare_units(selected['units'],stats,selected['baseline'])
                    save(root/(package+'-ACTUAL_UNIT_READBACK.json'),unit_result);record['units_matched']=unit_result['passed'];record['reported_tests']=unit_result['reported_tests'];record['preexisting_known_failure_units']=unit_result['known_failure_count']
                if not clean_execution:record['units_matched']=False
                record['skip_count']=None;record['skip_count_availability']='Raw original verbose skip output retained; no fabricated zero count'
                post_path=root/(package+'-POST_PROVENANCE.json');post_command=list(probe_command);post_command[-1]=post_path
                run(package+'-effective-tox-posttest-provenance',post_command,test_env,cwd,timeout=600)
                post=json.loads(post_path.read_text())
                if post.get('passed') is not True or pre['public_types_expected_sha256']!=post['public_types_expected_sha256'] or pre['installed_distribution_source_lock_sha256']!=post['installed_distribution_source_lock_sha256']:raise ValueError('Posttest installed provenance/source lock failed')
                if notest_probe is not None:
                    notest_post_path=root/(package+'-NOTEST_POST_PROVENANCE.json');notest_post_command=list(notest_probe);notest_post_command[-1]=notest_post_path
                    run(package+'-original-notest-import-post-provenance',notest_post_command,test_env,cwd,timeout=600);notest_post=json.loads(notest_post_path.read_text())
                    if notest_post.get('passed') is not True or notest_pre['installed_distribution_source_lock_sha256']!=notest_post['installed_distribution_source_lock_sha256']:raise ValueError('Original import-only notest post-provenance/source lock failed')
                    record['both_original_import_envs_provenance']=True
                if 'Error in doctesting framework' in text or re.search(r'Unhandled SIG|SIGSEGV|Process died|Timed out',text):record['units_matched']=False
            except Exception as error:
                record.update({'error':str(error),'error_type':type(error).__name__,'last_actual_command':receipts[-1] if receipts else None,'provenance_passed':False,'units_matched':False})
            tests.append(record);save(root/'TEST_RESULTS.json',tests)
        result=complete_result(builds,tests);result.update({'identity':identity,'pr':args.pr,'arch':args.arch,'original_merge_sha':source_commit,'same_vm_ephemeral_wheelhouse':True,'artifact_uploads':0,'actions_cache_writes':0,'binary_delivery':False,'native_sdk_rebuilt_from_source':False,'old_sdk_basis_plus_normal_source_fixed_homfly_and_source_fixed_import_library':True})
    except BaseException as error:
        result=complete_result(builds,tests);result.update({'passed':False,'error':str(error),'error_type':type(error).__name__,'pr':args.pr,'arch':args.arch,'identity':identity,'original_upstream_job_rerun':False})
        save(root/'FAILED_RESULT.json',result);print('FAILED_PROFILE_RESULT_JSON '+json.dumps(result),flush=True)
    finally:
        for package in OWNERS:
            if package not in {r['package'] for r in builds}:builds.append({'package':package,'state':'blocked','exit':None,'accepted':False,'reason':'Earlier preparation/framework failure; no execution claimed'})
        for package in TEST_OWNERS:
            if package not in {r['package'] for r in tests}:tests.append({'package':package,'state':'blocked','exit':None,'summary_seen':False,'reported_tests':0,'provenance_passed':False,'units_matched':False,'reason':'Earlier preparation/framework failure; no execution claimed'})
        save(root/'BUILD_RESULTS.json',builds);save(root/'TEST_RESULTS.json',tests)
        close=closing();final=complete_result(builds,tests)
        if result and result.get('error'):final.update({'error':result['error'],'error_type':result['error_type']})
        final.update({'identity':identity,'pr':args.pr,'arch':args.arch,'closing':close,'passed':final['passed'] is True and close['passed'] is True and not(final.get('error')),'lossless_text_evidence_required':True,'binary_delivery':False,'artifact_uploads':0,'actions_cache_writes':0,'native_sdk_rebuilt_from_source':False})
        save(root/'RESULT.json',final)
        try:
            from evidence_bundle import emit
            bundle=emit(root);final['lossless_text_evidence_bundle']=bundle
        except BaseException as error:
            final.update({'passed':False,'evidence_bundle_error':str(error)});save(root/'RESULT_BUNDLE_FAILURE.json',final)
        print('FINAL_PROFILE_RESULT_JSON '+json.dumps(final),flush=True)
    return 0 if final['passed'] is True else 1

if __name__=='__main__':raise SystemExit(main())
