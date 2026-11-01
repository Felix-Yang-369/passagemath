"""Installed RECORD, effective tox environment and complete loaded-provider gate."""
import argparse
import base64
import csv
import configparser
import ctypes
from ctypes import wintypes as w
import hashlib
import importlib
import importlib.metadata
import importlib.util
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

def load_trusted_sibling_helpers():
    """Load only validation helpers by exact path under isolated Python (-I).

    The helper directory is never added to scientific import search paths.
    """
    before=list(sys.path);root=Path(__file__).resolve().parent
    for name in ('os_provider_contract','debugpy_universal_auxiliary'):
        path=root/(name+'.py')
        spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        sys.modules[name]=module
        assert Path(module.__file__).resolve()==path
    assert sys.path==before

def original_notest_phase(package,extras,contract_sha256,source_bytes,environment,require_bash):
    allowed=('categories','cddlib','cliquer','cmr','combinat','graphs','gsl','highs','homfly','modules','planarity','plot','rankwidth')
    assert package in allowed and extras==[] and type(require_bash) is bool and not require_bash
    assert isinstance(source_bytes,bytes) and digest(source_bytes)==contract_sha256
    parser=configparser.ConfigParser(interpolation=None);parser.read_string(source_bytes.decode('utf-8'))
    original=[line.strip() for line in parser.get('tox','envlist').splitlines() if line.strip() and not line.lstrip().startswith('#')]
    renamed=[re.sub(r'sagepython-.*nopypi-norequirements','py312-norequirements',line) for line in original]
    assert environment in renamed and environment.endswith('-notest')
    return {'verified':True,'package':package,'environment':environment,'source_sha256':contract_sha256,'requested_extras':[],'require_bash':False,'mathematical_acceptance_claimed':False}

def native_consumption_contract(package,imports,contract_sha256,loaded_count,require_bash=False,notest_phase=None):
    assert type(loaded_count) is int and loaded_count>=0
    assert type(require_bash) is bool
    notest=notest_phase is not None
    if notest:
        assert isinstance(notest_phase,dict) and notest_phase.get('verified') is True and notest_phase.get('package')==package and package!='glpk' and notest_phase.get('environment','').endswith('-notest') and notest_phase.get('requested_extras')==[] and notest_phase.get('require_bash') is False and not require_bash
        assert re.fullmatch('[a-f0-9]{64}',notest_phase.get('source_sha256','')) and contract_sha256 is None
    original=(package=='glpk' and imports==['sage.libs.glpk'] and contract_sha256=='88eef253884e879e6c1f81aa19214ea471b5a845b367bfb4cf4a6f99c0fa4eef' and not require_bash)
    assert original or (package!='glpk' and contract_sha256 is None), 'The import-only SHA flag is restricted to the exact original GLPK contract'
    assert original or notest or (imports and loaded_count>0), 'Mathematical suite environment did not import and load a rebuilt native owner'
    return {'original_import_only':original,'original_notest':notest,'original_notest_phase':notest_phase,'original_contract_sha256':contract_sha256,'cold_original_namespace':(original or notest) and loaded_count==0,'candidate_native_consumer_required':not(original or notest),'candidate_native_consumer_loaded':loaded_count>0,'mathematical_acceptance_claimed':False,'mathematical_tests_executed':False}
def windows_system_roots(windows):return [(Path(windows)/name).resolve() for name in ('System32','SysWOW64','WinSxS','SystemArm32')]
def declared_windows_system_path(path,windows):return any(Path(path).resolve().is_relative_to(folder) for folder in windows_system_roots(windows))

def load_debugger_auxiliary_manifest(path):
    raw=Path(path).read_bytes()
    assert digest(raw)=='029cf773201bd7e927bd835c4d1466843e59f3815debebd85fc3b070b1f4370a'
    value=json.loads(raw)
    assert value['schema']=='official-debugpy-auxiliary-native-v1' and value['project']=='debugpy' and value['version']=='1.8.22'
    return value

def debugger_auxiliary_record(manifest,distribution,version,relative,data,target_machine):
    if canonical(distribution)!='debugpy' or version!=manifest['version']:return None
    architecture={'0x8664':'x64','0xaa64':'arm64'}[target_machine]
    producer=manifest['architectures'][architecture]
    assert producer['native_target_machine']==target_machine
    matches=[row for row in producer['auxiliary_native_files'] if row['name']==relative]
    if not matches:return None
    assert len(matches)==1 and relative.startswith('debugpy/_vendored/pydevd/pydevd_attach_to_process/') and Path(relative).suffix.lower() in ('.dll','.exe')
    row=matches[0]
    assert row['provider_class']=='unloaded_official_debugger_attachment_auxiliary' and type(row['bytes']) is int and len(data)==row['bytes'] and digest(data)==row['sha256']
    offset=struct.unpack_from('<I',data,0x3c)[0]
    assert data[:2]==b'MZ' and data[offset:offset+4]==b'PE\0\0' and hex(struct.unpack_from('<H',data,offset+4)[0])==row['pe_machine']
    original=producer.get('wheel',producer.get('source_archive'))
    return dict(row,distribution='debugpy',version=version,official_source_filename=original['filename'],official_source_sha256=original['sha256'],official_source_url=original['url'],official_metadata_sha256=manifest['metadata_sha256'],native_target_machine=target_machine,mathematical_native_consumer=False)

def require_unloaded_debugger_auxiliaries(auxiliaries,loaded_paths):
    loaded={str(Path(path).resolve()).casefold() for path in loaded_paths}
    for row in auxiliaries:assert str(Path(row['path']).resolve()).casefold() not in loaded, ('Cross-architecture debugger auxiliary was loaded into the native process',row['path'])
    return True
def verify_public_modules_types(site,expected,records,modules_installed):
    if not modules_installed:return False
    path=Path(site)/'sage/libs/gsl/types.pxd'
    assert expected and path.is_file() and digest(path.read_bytes())==expected and str(path.resolve()).casefold() in records
    return True

def verify_complete_installed_candidates(site,manifests,installed,records,prefix=None):
    from pathlib import PurePosixPath
    def reject_links(path):
        path=Path(path)
        for component in (path,*path.parents):
            if component.is_symlink() or (hasattr(component,'is_junction') and component.is_junction()):raise AssertionError('Linked normal installation path '+str(component))
    raw_site=Path(site).absolute();raw_prefix=Path(prefix).absolute() if prefix is not None else raw_site.parent.parent
    reject_links(raw_site);reject_links(raw_prefix)
    site=raw_site.resolve();prefix=raw_prefix.resolve()
    assert site.is_relative_to(prefix),'Installed site is outside the declared normal prefix'
    by_name={canonical(row['name']):row for row in installed};verified=[];transformed=[];relocated=[];schemes={}
    assert len(by_name)==len(installed),'Duplicate installed distribution identities'
    seen_distributions=set()
    for manifest in manifests:
        name=canonical(Path(manifest['path']).name.split('-')[0])
        if name not in by_name:continue
        if name in seen_distributions:raise AssertionError('Duplicate installed candidate wheel identity '+name)
        seen_distributions.add(name);count=0;seen_members=set();seen_paths=set()
        for row in manifest['files']:
            relative=row['name'];parsed=PurePosixPath(relative);parts=relative.split('/')
            if not relative or '\\' in relative or ':' in relative or parsed.is_absolute() or '..' in parsed.parts or str(parsed)!=relative:raise AssertionError('Unsafe/noncanonical wheel installation member '+relative)
            if relative.casefold() in seen_members:raise AssertionError('Duplicate/case-colliding wheel installation member '+relative)
            seen_members.add(relative.casefold())
            if type(row.get('bytes')) is not int or row['bytes']<0:raise AssertionError('Non-integer wheel member length '+relative)
            target_root=site;classification=None
            if relative.endswith('.dist-info/RECORD'):
                transformed.append({'distribution':name,'wheel_member':relative,'classification':'pip regenerates installed RECORD; complete actual installed RECORD is verified independently'});continue
            if parts[0].endswith('.data'):
                if len(parts)>2 and parts[1] in ('purelib','platlib'):
                    relative='/'.join(parts[2:]);classification='normal pip '+parts[1]+' relocation to site'
                elif len(parts)>2 and parts[1]=='data':
                    relative='/'.join(parts[2:]);target_root=prefix;classification='normal pip data relocation to actual prefix'
                elif len(parts)>2 and parts[1]=='headers':
                    from pip._internal.locations import get_scheme
                    pip_version=importlib.metadata.version('pip')
                    if pip_version!='26.2.2':raise AssertionError('Unreviewed pip headers scheme version '+pip_version)
                    if name not in schemes:
                        normal=get_scheme(name) if prefix==Path(sys.prefix).resolve() else get_scheme(name,prefix=str(prefix))
                        reject_links(Path(normal.headers).absolute());headers=Path(normal.headers).resolve()
                        if not headers.is_relative_to(prefix):raise AssertionError('Normal pip headers scheme escapes actual prefix')
                        schemes[name]={'pip_version':pip_version,'headers':str(headers),'prefix':str(prefix),'normal_get_scheme_provider':get_scheme.__module__}
                    relative='/'.join(parts[2:]);target_root=Path(schemes[name]['headers']);classification='normal pinned pip headers installation scheme'
                elif len(parts)>2 and parts[1]=='scripts':
                    transformed.append({'distribution':name,'wheel_member':relative,'classification':'normal pip script installation; actual mathematical launcher separately requires installed RECORD/PE/native-Python shebang'});continue
                else:raise AssertionError('Unclassified installed wheel relocation '+row['name'])
            unresolved=target_root/relative;reject_links(unresolved);path=unresolved.resolve();key=str(path).casefold()
            if key in seen_paths:raise AssertionError('Duplicate normal installed destination '+str(path))
            seen_paths.add(key)
            if not path.is_relative_to(target_root) or not path.is_relative_to(prefix) or not path.is_file() or path.is_symlink() or key not in records or records[key]['sha256']!=row['sha256'] or digest(path.read_bytes())!=row['sha256'] or path.stat().st_size!=row['bytes']:raise AssertionError('Installed candidate wheel member/RECORD missing or changed '+name+':'+relative)
            if classification:relocated.append({'distribution':name,'wheel_member':row['name'],'installed_path':str(path),'installed_root':str(target_root),'sha256':row['sha256'],'classification':classification})
            count+=1
        verified.append({'distribution':name,'wheel_sha256':manifest['sha256'],'required_original_wheel_members_verified':count})
    for path in (site/'sage').rglob('*'):
        if path.is_symlink() or (hasattr(path,'is_junction') and path.is_junction()):raise AssertionError('Linked actual installed Sage namespace member '+str(path))
        if path.is_file() and path.suffix.lower() in ('.py','.pyx','.pxd','.pxi','.pyd','.dll','.h'):
            key=str(path.resolve()).casefold()
            if path.is_symlink() or key not in records or records[key]['sha256']!=digest(path.read_bytes()):raise AssertionError('Unrecorded actual installed Sage source/native file '+str(path))
    return {'passed':True,'installed_candidates':verified,'normal_transformed_installation_members':transformed,'normal_relocated_installation_members':relocated,'pinned_pip_header_schemes':schemes,'actual_prefix':str(prefix),'actual_site':str(site),'actual_Sage_namespace_code_scan_complete':True}

def declared_dependency_graph(distributions,package,requested_extras=None):
    try:from packaging.requirements import Requirement
    except ImportError:from pip._vendor.packaging.requirements import Requirement
    by_name={canonical(d.metadata['Name']):d for d in distributions}
    if len(by_name)!=len(distributions):raise AssertionError('Duplicate installed distribution names')
    extras=['test'] if requested_extras is None else requested_extras
    assert isinstance(extras,list) and all(isinstance(extra,str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]*',extra) for extra in extras) and len(set(extras))==len(extras)
    root='passagemath-'+package.replace('_','-');pending=[(root,'')]+[(root,extra) for extra in extras];visited=set();edges=[]
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
def _validate(args,early_inventory):
    from os_provider_contract import defender,record,validate_declaration,attest_declared,snapshot_loaded,save
    assert sys.platform=='win32'
    native_identity=defender().native_process_identity()
    assert native_identity['native_machine']==int(args.machine,16)
    prefix=Path(sys.prefix).resolve();base=Path(sys.base_prefix).resolve();site=(prefix/'Lib/site-packages').resolve()
    assert prefix!=base and sys.version_info[:3]==(3,12,10)
    assert Path(os.environ['HOME']).resolve()==prefix and os.environ['SAGE_DOC']=='/doesnotexist'
    expected_known=(args.expected_known_failures if args.expected_known_failures is not None else Path.cwd()/'known-test-failures.json').resolve()
    assert expected_known.is_relative_to(Path.cwd().resolve()) and expected_known.name.startswith('known-test-failures') and expected_known.suffix=='.json'
    assert Path(os.environ['KNOWN_TEST_FAILURES']).resolve()==expected_known
    extras=json.loads(args.requested_extras_json)
    assert isinstance(extras,list) and all(isinstance(extra,str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]*',extra) for extra in extras) and len(set(extras))==len(extras)
    notest_phase=None
    if args.original_notest_contract_sha256 is not None:notest_phase=original_notest_phase(args.package,extras,args.original_notest_contract_sha256,(Path.cwd()/'tox.ini').read_bytes(),prefix.name,args.require_bash_resolution)
    assert args.import_module or notest_phase is not None, 'Empty original imports are restricted to a proven original notest phase'
    for item in sys.path:
        assert item and (Path(item).resolve().is_relative_to(prefix) or Path(item).resolve().is_relative_to(base)),('foreign Python import path',item)
    manifests=json.loads(args.wheel_manifests.read_text());providers=json.loads(args.provider_manifest.read_text())
    os_declaration=providers['attested_windows_defender_components']
    validate_declaration(os_declaration,int(args.machine,16),args.output.parent)
    assert record(args.output.parent/'ATTESTED_WINDOWS_OS_PROVIDERS.json')==providers['attested_windows_defender_declaration_file']
    debugger_manifest=load_debugger_auxiliary_manifest(Path(__file__).resolve().parent/'debugpy_native_auxiliary.json')
    expected={}
    for manifest in manifests:
        for row in manifest['files']:
            key=row['name'].replace('/','\\').casefold()
            if key in expected and expected[key]!=row['sha256']:raise AssertionError('Conflicting cross-owner wheel member '+key)
            expected[key]=row['sha256']
    records={};installed=[];modules_installed=False;external_sources=[];installed_native=[];debugger_auxiliaries=[]
    distributions=list(importlib.metadata.distributions(path=[str(site)]));reachable,dependency_edges=declared_dependency_graph(distributions,args.package,extras)
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
            auxiliary=None
            if path.is_relative_to(site):
                auxiliary=debugger_auxiliary_record(debugger_manifest,name,version,str(path.relative_to(site)).replace('\\','/'),data,args.machine)
                if auxiliary is None:
                    from debugpy_universal_auxiliary import universal_auxiliary_record
                    auxiliary=universal_auxiliary_record(site,canonical(name),version,str(path.relative_to(site)).replace('\\','/'),data,args.machine,native_identity,early_inventory)
                if auxiliary is not None:debugger_auxiliaries.append(dict(auxiliary,path=str(path),observed_loaded_in_provenance_process=False))
            if path.suffix.lower() in ('.pyd','.dll'):
                offset=struct.unpack_from('<I',data,0x3c)[0]
                assert data[:2]==b'MZ' and data[offset:offset+4]==b'PE\0\0'
                actual_machine=hex(struct.unpack_from('<H',data,offset+4)[0])
                if actual_machine!=args.machine:assert auxiliary is not None and (path.suffix.lower()=='.dll' or auxiliary.get('provider_class')=='unloaded_official_debugger_foreign_ABI_auxiliary'),('Installed native dependency PE mismatch',str(path))
                installed_native.append({'path':str(path),'distribution':name,'version':version,'sha256':digest256,'pe_machine':actual_machine,'provider_class':auxiliary['provider_class'] if actual_machine!=args.machine else 'normal_installed_native_provider','native_target_verified':actual_machine==args.machine})
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
    installed_complete=verify_complete_installed_candidates(site,manifests,installed,records,prefix=prefix)
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
    actual_inventory=snapshot_loaded(Path(str(args.output)+'.LOADED_BEFORE_CLASSIFICATION.json'),early_inventory['phase'])
    assert actual_inventory['complete'] is True,'Actual loaded inventory contains unresolved path/hash/PE errors'
    loaded=[];sage_native=0;unknown=[];os_attestations=[]
    for observed in actual_inventory['entries']:
        path=Path(observed['path']).resolve();data=path.read_bytes();offset=struct.unpack_from('<I',data,0x3c)[0];assert data[offset:offset+4]==b'PE\0\0'
        machine=struct.unpack_from('<H',data,offset+4)[0];value=digest(data);key=str(path).casefold();relative=None
        assert value==observed['sha256'] and machine==observed['pe_machine'],('Loaded native inventory changed before classification',str(path))
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
        elif key in os_declaration['pins']:
            evidence=args.output.parent/'os-attestation/child'/args.output.name/hashlib.sha256(key.encode()).hexdigest()[:16]
            attestation=attest_declared(path,os_declaration,int(args.machine,16),evidence)
            assert machine==int(args.machine,16)
            kind='Windows_OS_Defender_MpOAV_attested';os_attestations.append(record(evidence/'ATTESTATION.json'))
        else:
            unknown.append({'path':str(path),'sha256':value,'pe_machine':hex(machine),'error':'Loaded native provider outside all declared roots'})
            kind='unknown_rejected_native_provider'
        loaded.append({'path':str(path),'relative_site_path':relative,'sha256':value,'pe_machine':hex(machine),'provider_class':kind})
    save(Path(str(args.output)+'.LOADED_CLASSIFICATION.json'),{'complete_observable_inventory':actual_inventory,'classified':loaded,'unknown_rejected':unknown,'OS_component_attestations':os_attestations,'passed':not unknown})
    assert not unknown,('Loaded native providers outside all declared roots',unknown)
    foreign_debugger_auxiliaries=[row for row in debugger_auxiliaries if row['pe_machine']!=args.machine]
    require_unloaded_debugger_auxiliaries(foreign_debugger_auxiliaries,[row['path'] for row in loaded])
    consumption=native_consumption_contract(args.package,args.import_module,args.original_import_only_contract_sha256,sage_native,args.require_bash_resolution,notest_phase)
    source_lock=digest(json.dumps({'installed':installed,'external_sources':external_sources,'dependency_edges':dependency_edges,'installed_native':installed_native},sort_keys=True).encode())
    result={'passed':True,'package':args.package,'python':sys.executable,'version':sys.version,'machine':platform.machine(),'process_machine':process_machine.value,'native_machine':hex(native_machine.value),'emulation':False,'emulation_scope':'This actual mathematical/import-only tox CPython process, not auxiliary Bash/Git executables. Every loaded non-OS provider and candidate wheel PE also has the exact native target machine.','prefix':str(prefix),'base_prefix':str(base),'imported_original_contract_modules':imported,'sys_path':sys.path,'effective_env':{key:os.environ.get(key) for key in ('HOME','SAGE_DOC','KNOWN_TEST_FAILURES','SAGE_LOCAL','DOT_SAGE','PATH','INCLUDE','LIB')},'runtime_cliquer_path':str(expected_cl),'installed_distributions_RECORD_verified':installed,'original_declared_dependency_edges':dependency_edges,'original_declared_test_dependency_source_files':external_sources,'installed_distribution_source_lock_sha256':source_lock,'complete_loaded_native_inventory':loaded,'loaded_rebuilt_owner_files':sage_native,'modules_distribution_present':modules_installed,'public_modules_types_matches_wheel_source_RECORD':types_verified,'public_types_expected_sha256':expected_types,'scope':'Actual effective tox environment before complete mathematical tests; no source overlay'}
    result['all_installed_native_PE_files']=installed_native
    result['unloaded_cross_architecture_official_debugger_auxiliaries']=foreign_debugger_auxiliaries
    result['declared_debugger_auxiliary_manifest_sha256']='029cf773201bd7e927bd835c4d1466843e59f3815debebd85fc3b070b1f4370a'
    result['declared_ARM64_universal_debugger_auxiliary_manifest_sha256']='c29e633a7efc39a16a5b443b404995f8aa5b6dd7b3c3e194a290fd73a83ef9a6'
    result['native_file_inventory_scope']='Every installed .pyd/.dll is checked. Exact official unloaded debugger attachment files and the exact ARM64 CPython 3.12-incompatible vendored CPython 3.9 extensions have separately pinned rules; all candidate/current-ABI Python extensions and all actually loaded non-OS files retain the native target machine.'
    result['native_consumption_contract']=consumption
    result['original_effective_tox_extras']=extras;result['expected_original_known_failures']=str(expected_known)
    result['declared_OS_system_subtrees']=[str(p) for p in os_roots]
    result['attested_windows_defender_components']={'same_run_declaration':providers['attested_windows_defender_declaration_file'],'actual_phase_attestations':os_attestations,'provider_class':'Windows_OS_Defender_MpOAV_attested'}
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

def main():
    load_trusted_sibling_helpers()
    ap=argparse.ArgumentParser();ap.add_argument('--package',required=True);ap.add_argument('--import-module',action='append',default=[]);ap.add_argument('--wheel-manifests',type=Path,required=True);ap.add_argument('--provider-manifest',type=Path,required=True);ap.add_argument('--machine',required=True);ap.add_argument('--require-bash-resolution',action='store_true');ap.add_argument('--original-import-only-contract-sha256');ap.add_argument('--original-notest-contract-sha256');ap.add_argument('--requested-extras-json',default='["test"]');ap.add_argument('--expected-known-failures',type=Path);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    from os_provider_contract import snapshot_loaded,save
    phase='BASH_PRE' if args.require_bash_resolution else 'POST' if 'POST' in args.output.name.upper() else 'PRE'
    error=None
    try:
        early=snapshot_loaded(Path(str(args.output)+'.LOADED_AT_ENTRY.json'),phase)
        assert early['complete'] is True,'Entry loaded inventory contains unresolved metadata'
        return _validate(args,early)
    except BaseException as failure:
        error={'type':type(failure).__name__,'message':str(failure)}
        save(Path(str(args.output)+'.ERROR.json'),{'passed':False,'phase':phase,'error':error})
        raise
    finally:
        try:
            final=snapshot_loaded(Path(str(args.output)+'.LOADED_AT_EXIT.json'),phase)
            if final['complete'] is not True and error is None:raise AssertionError('Exit loaded inventory contains unresolved metadata')
        except BaseException as failure:
            save(Path(str(args.output)+'.FINAL_INVENTORY_ERROR.json'),{'passed':False,'error':str(failure),'original_error':error})
            if error is None:raise

if __name__=='__main__':raise SystemExit(main())
