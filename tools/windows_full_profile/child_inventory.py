"""Installed RECORD, effective tox environment and complete loaded-provider gate."""
import argparse
import base64
import csv
import ctypes
from ctypes import wintypes as w
import hashlib
import importlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import sys

def digest(data):return hashlib.sha256(data).hexdigest()
def canonical(name):return re.sub(r'[-_.]+','-',name).lower()
def windows_system_roots(windows):return [(Path(windows)/name).resolve() for name in ('System32','SysWOW64','WinSxS','SystemArm32')]
def declared_windows_system_path(path,windows):return any(Path(path).resolve().is_relative_to(folder) for folder in windows_system_roots(windows))
def verify_public_modules_types(site,expected,records,modules_installed):
    if not modules_installed:return False
    path=Path(site)/'sage/libs/gsl/types.pxd'
    assert expected and path.is_file() and digest(path.read_bytes())==expected and str(path.resolve()).casefold() in records
    return True

def verify_complete_installed_candidates(site,manifests,installed,records):
    site=Path(site);by_name={canonical(row['name']):row for row in installed};verified=[];transformed=[]
    for manifest in manifests:
        name=canonical(Path(manifest['path']).name.split('-')[0])
        if name not in by_name:continue
        count=0
        for row in manifest['files']:
            relative=row['name'];parts=relative.split('/')
            if relative.endswith('.dist-info/RECORD'):
                transformed.append({'distribution':name,'wheel_member':relative,'classification':'pip regenerates installed RECORD; complete actual installed RECORD is verified independently'});continue
            if parts[0].endswith('.data'):
                if len(parts)>2 and parts[1] in ('purelib','platlib'):relative='/'.join(parts[2:])
                elif len(parts)>2 and parts[1]=='scripts':
                    transformed.append({'distribution':name,'wheel_member':relative,'classification':'normal pip script installation; actual mathematical launcher separately requires installed RECORD/PE/native-Python shebang'});continue
                else:raise AssertionError('Unclassified installed wheel relocation '+row['name'])
            path=(site/relative).resolve();key=str(path).casefold()
            if not path.is_relative_to(site.resolve()) or not path.is_file() or key not in records or records[key]['sha256']!=row['sha256'] or digest(path.read_bytes())!=row['sha256'] or path.stat().st_size!=row['bytes']:raise AssertionError('Installed candidate wheel member/RECORD missing or changed '+name+':'+relative)
            count+=1
        verified.append({'distribution':name,'wheel_sha256':manifest['sha256'],'required_original_wheel_members_verified':count})
    for path in (site/'sage').rglob('*'):
        if path.is_file() and path.suffix.lower() in ('.py','.pyx','.pxd','.pxi','.pyd','.dll','.h'):
            key=str(path.resolve()).casefold()
            if path.is_symlink() or key not in records or records[key]['sha256']!=digest(path.read_bytes()):raise AssertionError('Unrecorded actual installed Sage source/native file '+str(path))
    return {'passed':True,'installed_candidates':verified,'normal_transformed_installation_members':transformed,'actual_Sage_namespace_code_scan_complete':True}

def declared_dependency_graph(distributions,package):
    try:from packaging.requirements import Requirement
    except ImportError:from pip._vendor.packaging.requirements import Requirement
    by_name={canonical(d.metadata['Name']):d for d in distributions}
    if len(by_name)!=len(distributions):raise AssertionError('Duplicate installed distribution names')
    root='passagemath-'+package.replace('_','-');pending=[(root,'test')];visited=set();edges=[]
    while pending:
        name,extra=pending.pop()
        if (name,extra) in visited:continue
        visited.add((name,extra))
        if name not in by_name:raise AssertionError('Original declared dependency is missing '+name)
        distribution=by_name[name]
        for raw in distribution.requires or []:
            requirement=Requirement(raw)
            if requirement.marker and not requirement.marker.evaluate({'extra':extra}):continue
            dependency=canonical(requirement.name)
            if dependency not in by_name:raise AssertionError('Original declared dependency is missing '+raw)
            if requirement.specifier and not requirement.specifier.contains(by_name[dependency].version,prereleases=True):raise AssertionError('Original declared dependency version mismatch '+raw)
            edges.append({'from':name,'from_extra':extra,'requirement':raw,'to':dependency,'actual_version':by_name[dependency].version})
            pending.append((dependency,''));pending.extend((dependency,e) for e in requirement.extras)
    return {name for name,extra in visited},edges
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--package',required=True);ap.add_argument('--import-module',action='append',required=True);ap.add_argument('--wheel-manifests',type=Path,required=True);ap.add_argument('--provider-manifest',type=Path,required=True);ap.add_argument('--machine',required=True);ap.add_argument('--require-bash-resolution',action='store_true');ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert sys.platform=='win32'
    prefix=Path(sys.prefix).resolve();base=Path(sys.base_prefix).resolve();site=(prefix/'Lib/site-packages').resolve()
    assert prefix!=base and sys.version_info[:3]==(3,12,10)
    assert Path(os.environ['HOME']).resolve()==prefix and os.environ['SAGE_DOC']=='/doesnotexist'
    assert Path(os.environ['KNOWN_TEST_FAILURES']).resolve()==(Path.cwd()/'known-test-failures.json').resolve()
    for item in sys.path:
        assert item and (Path(item).resolve().is_relative_to(prefix) or Path(item).resolve().is_relative_to(base)),('foreign Python import path',item)
    manifests=json.loads(args.wheel_manifests.read_text());providers=json.loads(args.provider_manifest.read_text())
    expected={}
    for manifest in manifests:
        for row in manifest['files']:
            key=row['name'].replace('/','\\').casefold()
            if key in expected and expected[key]!=row['sha256']:raise AssertionError('Conflicting cross-owner wheel member '+key)
            expected[key]=row['sha256']
    records={};installed=[];modules_installed=False;external_sources=[];installed_native=[]
    distributions=list(importlib.metadata.distributions(path=[str(site)]));reachable,dependency_edges=declared_dependency_graph(distributions,args.package)
    candidate_owners={'passagemath-'+name.replace('_','-') for name in ('objects','categories','graphs','rankwidth','cddlib','glpk','highs','planarity','homfly','cliquer','combinat','modules','gsl','plot','cmr','m4ri_m4rie')}
    for distribution in distributions:
        name=distribution.metadata['Name'];version=distribution.version
        modules_installed|=name.lower().replace('_','-')=='passagemath-modules'
        text=distribution.read_text('RECORD')
        if text is None:raise AssertionError('Installed distribution lacks RECORD '+name)
        seen=set();count=0
        for relative,hashvalue,size in csv.reader(io.StringIO(text)):
            path=Path(distribution.locate_file(relative)).resolve();key=str(path).casefold()
            if relative in seen or not path.is_relative_to(prefix) or not path.is_file():raise AssertionError('Invalid installed RECORD member '+relative)
            seen.add(relative)
            if not hashvalue:
                if not(relative.endswith('.dist-info/RECORD') or relative.endswith('.pyc')):raise AssertionError('Unhashed installed member '+relative)
                continue
            data=path.read_bytes();algorithm,value=hashvalue.split('=',1)
            if algorithm not in ('sha256','sha384','sha512'):raise AssertionError('Unsupported installed digest '+algorithm)
            if base64.urlsafe_b64encode(hashlib.new(algorithm,data).digest()).rstrip(b'=').decode()!=value or len(data)!=int(size):raise AssertionError('Installed RECORD mismatch '+relative)
            digest256=digest(data)
            if path.suffix.lower() in ('.pyd','.dll'):
                offset=struct.unpack_from('<I',data,0x3c)[0]
                assert data[:2]==b'MZ' and data[offset:offset+4]==b'PE\0\0' and struct.unpack_from('<H',data,offset+4)[0]==int(args.machine,16),('Installed native dependency PE mismatch',str(path))
                installed_native.append({'path':str(path),'distribution':name,'version':version,'sha256':digest256,'pe_machine':args.machine})
            if key in records and records[key]['sha256']!=digest256:raise AssertionError('Conflicting installed distribution owners')
            records[key]={'sha256':digest256,'distribution':name,'version':version};count+=1
            if path.is_relative_to(site):
                local=str(path.relative_to(site)).casefold()
                if local in expected and '.dist-info\\' not in local and expected[local]!=digest256:raise AssertionError('Rebuilt wheel/installed source mismatch '+local)
                if local.startswith('sage\\') and path.suffix.lower() in ('.py','.pyx','.pxd','.pxi','.pyd','.dll') and local not in expected:
                    if canonical(name) in candidate_owners or canonical(name) not in reachable:raise AssertionError('Installed Sage code is absent from rebuilt owners/original declared test dependencies '+local)
                    records[key]['provider_class']='original_declared_test_dependency'
                    external_sources.append({'distribution':name,'version':version,'relative_site_path':local,'sha256':digest256,'bytes':len(data)})
        installed.append({'name':name,'version':version,'RECORD_sha256':digest(text.encode()),'verified_hashed_record_files':count,'original_declared_dependency':canonical(name) in reachable,'provider_class':'candidate_owner' if canonical(name) in candidate_owners else 'original_declared_test_dependency' if canonical(name) in reachable else 'venv_tooling'})
    installed_complete=verify_complete_installed_candidates(site,manifests,installed,records)
    imported=[]
    for name in args.import_module:
        module=importlib.import_module(name);module_path=Path(module.__file__).resolve();module_key=str(module_path).casefold();assert module_path.is_relative_to(site) and module_key in records and records[module_key]['sha256']==digest(module_path.read_bytes())
        local=str(module_path.relative_to(site)).casefold();assert local in expected or records[module_key].get('provider_class')=='original_declared_test_dependency',('Unowned imported Sage module',name)
        imported.append({'name':name,'path':str(module_path),'sha256':records[module_key]['sha256'],'RECORD_owner':records[module_key]})
    expected_types=expected.get('sage\\libs\\gsl\\types.pxd')
    types_verified=verify_public_modules_types(site,expected_types,records,modules_installed)
    declared={str(Path(r['path']).resolve()).casefold():r for r in providers['native_files']}
    sdk=Path(providers['sdk_root']).resolve();msys=Path(providers['msys_arch_bin']).resolve();windows=Path(os.environ['WINDIR']).resolve()
    os_roots=windows_system_roots(windows)
    selected_cl=shutil.which('cl.exe');expected_cl=(sdk/'bin/cl.exe').resolve()
    assert selected_cl and Path(selected_cl).resolve()==expected_cl,('runtime Cliquer provider',selected_cl)
    assert str(expected_cl).casefold() in declared and digest(expected_cl.read_bytes())==declared[str(expected_cl).casefold()]['sha256']
    kernel=ctypes.WinDLL('kernel32',use_last_error=True);psapi=ctypes.WinDLL('psapi',use_last_error=True)
    kernel.GetCurrentProcess.restype=w.HANDLE;process=kernel.GetCurrentProcess()
    kernel.IsWow64Process2.argtypes=[w.HANDLE,ctypes.POINTER(w.WORD),ctypes.POINTER(w.WORD)];kernel.IsWow64Process2.restype=w.BOOL
    process_machine=w.WORD();native_machine=w.WORD();assert kernel.IsWow64Process2(process,ctypes.byref(process_machine),ctypes.byref(native_machine))
    assert process_machine.value==0 and native_machine.value==int(args.machine,16),('Mathematical tox CPython emulation/target mismatch',process_machine.value,native_machine.value)
    psapi.EnumProcessModulesEx.argtypes=[w.HANDLE,ctypes.POINTER(w.HMODULE),w.DWORD,ctypes.POINTER(w.DWORD),w.DWORD];psapi.EnumProcessModulesEx.restype=w.BOOL
    psapi.GetModuleFileNameExW.argtypes=[w.HANDLE,w.HMODULE,w.LPWSTR,w.DWORD];psapi.GetModuleFileNameExW.restype=w.DWORD
    modules=(w.HMODULE*8192)();needed=w.DWORD()
    assert psapi.EnumProcessModulesEx(process,modules,ctypes.sizeof(modules),ctypes.byref(needed),3) and needed.value<=ctypes.sizeof(modules)
    loaded=[];sage_native=0
    for handle in modules[:needed.value//ctypes.sizeof(w.HMODULE)]:
        buffer=ctypes.create_unicode_buffer(32768);assert psapi.GetModuleFileNameExW(process,handle,buffer,len(buffer))
        path=Path(buffer.value).resolve();data=path.read_bytes();offset=struct.unpack_from('<I',data,0x3c)[0];assert data[offset:offset+4]==b'PE\0\0'
        machine=struct.unpack_from('<H',data,offset+4)[0];value=digest(data);key=str(path).casefold();relative=None
        if path.is_relative_to(site):
            assert key in records and records[key]['sha256']==value
            relative=str(path.relative_to(site));local=relative.casefold()
            if local in expected:assert expected[local]==value;sage_native+=1;kind='rebuilt_owner_wheel'
            elif records[key].get('provider_class')=='original_declared_test_dependency':kind='original_declared_test_dependency'
            else:assert not local.startswith('sage\\');kind='installed_third_party_RECORD'
            assert machine==int(args.machine,16)
        elif path==Path(sys.executable).resolve():
            assert machine==int(args.machine,16);kind='test_venv_CPython_launcher'
        elif any(path.is_relative_to(folder) for folder in os_roots):kind='Windows_OS_declared_system_subtree'
        elif path.is_relative_to(base) or path.is_relative_to(sdk) or path.is_relative_to(msys):
            assert key in declared and declared[key]['sha256']==value,('undeclared native provider',str(path))
            assert machine==int(args.machine,16)
            kind='base_CPython' if path.is_relative_to(base) else 'declared_SDK' if path.is_relative_to(sdk) else 'normal_MSYS2_runtime'
        else:raise AssertionError('Loaded native provider outside all declared roots: '+str(path))
        loaded.append({'path':str(path),'relative_site_path':relative,'sha256':value,'pe_machine':hex(machine),'provider_class':kind})
    assert sage_native>0
    source_lock=digest(json.dumps({'installed':installed,'external_sources':external_sources,'dependency_edges':dependency_edges,'installed_native':installed_native},sort_keys=True).encode())
    result={'passed':True,'package':args.package,'python':sys.executable,'version':sys.version,'machine':platform.machine(),'process_machine':process_machine.value,'native_machine':hex(native_machine.value),'emulation':False,'emulation_scope':'This actual mathematical/import-only tox CPython process, not auxiliary Bash/Git executables. Every loaded non-OS provider and candidate wheel PE also has the exact native target machine.','prefix':str(prefix),'base_prefix':str(base),'imported_original_contract_modules':imported,'sys_path':sys.path,'effective_env':{key:os.environ.get(key) for key in ('HOME','SAGE_DOC','KNOWN_TEST_FAILURES','SAGE_LOCAL','DOT_SAGE','PATH','INCLUDE','LIB')},'runtime_cliquer_path':str(expected_cl),'installed_distributions_RECORD_verified':installed,'original_declared_dependency_edges':dependency_edges,'original_declared_test_dependency_source_files':external_sources,'installed_distribution_source_lock_sha256':source_lock,'complete_loaded_native_inventory':loaded,'loaded_rebuilt_owner_files':sage_native,'modules_distribution_present':modules_installed,'public_modules_types_matches_wheel_source_RECORD':types_verified,'public_types_expected_sha256':expected_types,'scope':'Actual effective tox environment before complete mathematical tests; no source overlay'}
    result['all_installed_native_PE_files']=installed_native
    result['declared_OS_system_subtrees']=[str(p) for p in os_roots]
    result['complete_installed_candidate_wheel_members']=installed_complete
    if args.require_bash_resolution:
        python=Path(os.environ['PROFILE_BASH_PYTHON']).resolve();runner=Path(os.environ['PROFILE_BASH_SAGE_RUNTESTS']).resolve()
        assert python==Path(sys.executable).resolve() and python==prefix/'Scripts/python.exe',('Original Bash resolved another Python',str(python))
        assert runner.is_file() and runner.is_relative_to(prefix/'Scripts'),('Original Bash resolved another sage-runtests',str(runner))
        runner_key=str(runner).casefold();assert runner_key in records and records[runner_key]['sha256']==digest(runner.read_bytes()),('Mathematical launcher lacks installed RECORD ownership',str(runner))
        data=runner.read_bytes();runner_pe=None
        if data[:2]==b'MZ':
            offset=struct.unpack_from('<I',data,0x3c)[0];assert data[offset:offset+4]==b'PE\0\0';runner_pe=hex(struct.unpack_from('<H',data,offset+4)[0]);assert int(runner_pe,16)==int(args.machine,16)
            shebangs=re.findall(rb'#!([^\r\n]+)',data);assert any(str(python).casefold() in line.decode('utf-8',errors='replace').casefold() for line in shebangs),('Native mathematical launcher does not bind this tox Python',str(runner))
        else:
            first=data.splitlines()[0].decode('utf-8');assert first.startswith('#!') and (first.strip()=='#!/usr/bin/env python' or str(python).casefold() in first.casefold()),('Mathematical script shebang does not select this tox Python',first)
        result['original_bash_resolution']={'passed':True,'python':str(python),'python_sha256':digest(python.read_bytes()),'sage_runtests':str(runner),'sage_runtests_sha256':digest(data),'sage_runtests_PE_machine':runner_pe,'sage_runtests_RECORD_owner':records[runner_key],'native_Python_process_machine':process_machine.value,'native_Python_host_machine':hex(native_machine.value),'unmodified_original_math_command':True}
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print('CHILD_PROVENANCE_JSON '+json.dumps(result),flush=True)
    return 0

if __name__=='__main__':raise SystemExit(main())
