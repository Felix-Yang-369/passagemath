"""Same-run signed Windows OS component pins; no arbitrary host allowlist."""
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path

DEFENDER_HELPER_SHA256='6a957c2dfac392ff8f5755d4ea31885eb886bbca1e1319119d504f4dc8122727'
SCHEMA='same-run-native-Windows-Defender-MpOAV-v1'

def require(value,message):
    if not value:raise AssertionError(message)
def record(path):
    path=Path(path);return {'path':str(path),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf8')
def read(path):
    def unique(pairs):
        result={}
        for key,value in pairs:require(key not in result,'Duplicate OS-provider JSON key');result[key]=value
        return result
    return json.loads(Path(path).read_text(encoding='utf8'),object_pairs_hook=unique)
def defender():
    source=Path(__file__).resolve().with_name('defender_os_provider.py')
    require(record(source)['sha256']==DEFENDER_HELPER_SHA256,'Windows OS attestation helper source changed')
    spec=importlib.util.spec_from_file_location('pinned_defender_attestation',source)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
def key(path):return str(Path(path).resolve()).casefold()

def snapshot_loaded(path,phase):
    """Persist every observable row before deciding whether inventory is complete."""
    D=defender();rows=D.loaded_module_inventory()
    value={'schema':'durable-loaded-native-inventory-before-provider-classification-v1',
           'pid':os.getpid(),'phase':phase,'observed_utc':datetime.now(timezone.utc).isoformat(),
           'helper_sha256':DEFENDER_HELPER_SHA256,'entries':rows,
           'complete':bool(rows) and all(isinstance(row.get('path'),str) and type(row.get('bytes')) is int and row['bytes']>0
               and isinstance(row.get('sha256'),str) and len(row['sha256'])==64 and type(row.get('pe_machine')) is int
               and not row.get('error') and not row.get('error_type') for row in rows)}
    save(path,value);return value

def create_declaration(root,target_machine,context):
    """Attest installed native candidates once; child processes independently recheck."""
    D=defender();D.validate_target_machine(target_machine)
    require(D.native_process_identity()['native_machine']==target_machine,'OS declaration controller is not the native target')
    root=Path(root).resolve();program_data=D.known_program_data()
    value={'schema':SCHEMA,'completed':False,'helper_sha256':DEFENDER_HELPER_SHA256,
           'native_target_machine':target_machine,'run_root':str(root),'context':context,
           'known_program_data':program_data,'inspected_installed_files':[], 'pins':{}}
    destination=root/'ATTESTED_WINDOWS_OS_PROVIDERS.json';save(destination,value)
    directory=Path(program_data)/'Microsoft/Windows Defender/Platform'
    if directory.is_dir():
        for version in sorted(directory.iterdir()):
            path=version/'MpOAV.dll'
            if not path.is_file():continue
            inspected={'path':str(path),'selected':False}
            value['inspected_installed_files'].append(inspected);save(destination,value)
            if D.VERSION.fullmatch(version.name) is None:
                inspected['reason']='Noncanonical installed alias is never an allowed loaded provider'
                save(destination,value);continue
            try:
                syntax=D.validate_path_syntax(str(path),program_data)
                raw=path.read_bytes();machine=D.pe_machine(raw)
                inspected.update(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),pe_machine=machine)
                if machine!=target_machine:
                    inspected['reason']='Installed non-native file is not an allowed loaded provider';save(destination,value);continue
                evidence=root/'os-attestation/parent-before'/syntax['version']
                result=D.attest(path,target_machine,evidence)
                pin=result['dynamic_exact_pin'];canonical=key(path)
                require(canonical not in value['pins'],'Duplicate OS component path')
                value['pins'][canonical]={'pin':pin,'parent_attestation':record(evidence/'ATTESTATION.json')}
                inspected.update(selected=True,parent_attestation=record(evidence/'ATTESTATION.json'))
            except BaseException as error:
                inspected['error']={'type':type(error).__name__,'message':str(error)};save(destination,value);raise
            save(destination,value)
    value['completed']=True;save(destination,value)
    validate_declaration(value,target_machine,root)
    return value

def validate_declaration(value,target_machine,root):
    D=defender();D.validate_target_machine(target_machine)
    require(isinstance(value,dict) and value.get('schema')==SCHEMA and value.get('completed') is True,'Incomplete or unknown same-run OS declaration')
    require(value.get('helper_sha256')==DEFENDER_HELPER_SHA256,'OS declaration helper differs')
    require(type(value.get('native_target_machine')) is int and value['native_target_machine']==target_machine,'OS declaration target differs')
    root=Path(root).resolve();require(Path(value.get('run_root','')).resolve()==root,'OS declaration belongs to another execution root')
    require(value.get('known_program_data')==D.known_program_data(),'OS declaration KnownFolder differs')
    context=value.get('context');require(isinstance(context,dict) and set(context)=={'run_id','run_attempt','job','arch'} and all(isinstance(v,str) and v for v in context.values()),'OS declaration run identity missing')
    require(context['arch']=={0x8664:'x64',0xaa64:'arm64'}[target_machine],'OS declaration architecture label differs')
    pins=value.get('pins');require(isinstance(pins,dict),'OS declaration pins are not a mapping')
    for canonical,row in pins.items():
        require(isinstance(row,dict) and set(row)=={'pin','parent_attestation'},'OS pin schema differs')
        pin=row['pin'];require(canonical==key(pin['path']),'OS pin canonical path differs')
        D.validate_path_syntax(pin['path'],value['known_program_data'])
        source=row['parent_attestation'];path=Path(source['path']).resolve()
        require(path.is_relative_to(root/'os-attestation/parent-before') and record(path)==source,'Parent OS attestation evidence missing or changed')
        D.validate_attestation(read(path),target_machine,pin)
    return value

def attest_declared(path,declaration,target_machine,evidence_dir):
    D=defender();canonical=key(path)
    require(canonical in declaration['pins'],'Unknown native provider is not a same-run signed OS component')
    row=declaration['pins'][canonical]
    return D.attest(path,target_machine,evidence_dir,expected_pin=row['pin'])

def close_declaration(value,target_machine,root,phase):
    rows=[];root=Path(root).resolve()
    try:validate_declaration(value,target_machine,root)
    except BaseException as error:rows.append({'name':'declaration-integrity','passed':False,'error':str(error)})
    for canonical,row in value.get('pins',{}).items():
        try:
            name=hashlib.sha256(canonical.encode()).hexdigest()[:16]
            actual=attest_declared(row['pin']['path'],value,target_machine,root/'os-attestation'/phase/name)
            rows.append({'path':row['pin']['path'],'passed':actual.get('passed') is True,'attestation':record(root/'os-attestation'/phase/name/'ATTESTATION.json')})
        except BaseException as error:rows.append({'path':row.get('pin',{}).get('path'),'passed':False,'error':str(error),'error_type':type(error).__name__})
    return {'passed':all(row['passed'] for row in rows),'independent_attestations':rows,'pin_count':len(value.get('pins',{}))}
