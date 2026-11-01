"""Exact unused foreign-ABI members of the official debugpy universal wheel."""
import csv
import hashlib
import importlib.machinery
import io
import json
from pathlib import Path,PurePosixPath
import struct
import sys

MANIFEST_SHA256='c29e633a7efc39a16a5b443b404995f8aa5b6dd7b3c3e194a290fd73a83ef9a6'
METADATA_SHA256='dad0ffa81756bcf79a9ef2961c532e411545c608159378446f087e6a2f2ea41a'
WHEEL_SHA256='4dd4392ed3702eec530a3831379d4081d539c3e2a407db6d98b6f38d31f4da98'
def digest(raw):return hashlib.sha256(raw).hexdigest()
def require(value,message):
    if not value:raise AssertionError(message)
def load_manifest():
    raw=Path(__file__).resolve().with_name('debugpy_arm64_universal_auxiliary.json').read_bytes()
    require(digest(raw)==MANIFEST_SHA256,'Official ARM debugger auxiliary table changed')
    return json.loads(raw)

def universal_auxiliary_record(site,distribution,version,relative,data,target_machine,native_identity,inventory):
    if distribution!='debugpy' or version!='1.8.22' or target_machine!='0xaa64':return None
    manifest=load_manifest();rows=[r for r in manifest['potential_auxiliary_files'] if r['relative_site_path']==relative]
    if not rows:return None
    require(len(rows)==1,'Duplicate debugger auxiliary row');row=rows[0]
    expected=manifest['required_actual_target']
    require(type(native_identity.get('process_machine')) is int and native_identity['process_machine']==0
            and type(native_identity.get('native_machine')) is int and native_identity['native_machine']==0xaa64
            and native_identity.get('emulation') is False,'Actual debugger provenance process is not native ARM64')
    require(sys.version_info[:3]==(3,12,10) and sys.implementation.cache_tag==expected['cache_tag']
            and list(importlib.machinery.EXTENSION_SUFFIXES)==expected['extension_suffixes'],'Actual Python ABI differs from the exact auxiliary rule')
    require(inventory.get('complete') is True and inventory.get('phase') in ('PRE','BASH_PRE','POST') and bool(inventory.get('entries')),'Complete actual phase loaded inventory is unavailable')
    relative_path=PurePosixPath(relative)
    require(str(relative_path)==relative and not relative_path.is_absolute() and '..' not in relative_path.parts and ':' not in relative,'Unsafe auxiliary member path')
    path=Path(site).joinpath(*relative_path.parts);cursor=path
    while True:
        require(not cursor.is_symlink() and not cursor.is_junction(),'Linked debugger auxiliary path')
        if cursor==Path(site):break
        require(cursor!=cursor.parent,'Auxiliary path escapes site');cursor=cursor.parent
    require(path.resolve().is_relative_to(Path(site).resolve()) and path.read_bytes()==data,'Observed auxiliary is not the exact installed member')
    require(type(row['bytes']) is int and len(data)==row['bytes'] and digest(data)==row['sha256'],'Official debugger auxiliary bytes differ')
    offset=struct.unpack_from('<I',data,0x3c)[0]
    require(data[:2]==b'MZ' and data[offset:offset+4]==b'PE\0\0' and hex(struct.unpack_from('<H',data,offset+4)[0])==row['pe_machine'],'Official debugger auxiliary PE differs')
    info=Path(site)/'debugpy-1.8.22.dist-info'
    require(digest((info/'METADATA').read_bytes())==METADATA_SHA256 and digest((info/'WHEEL').read_bytes())==WHEEL_SHA256,'Installed distribution is not the original official universal producer')
    record=(info/'RECORD').read_bytes();matching=[r for r in csv.reader(io.StringIO(record.decode('utf8'))) if r[0].replace('\\','/')==relative]
    require(matching==[row['original_wheel_RECORD_row']],'Exact official auxiliary RECORD row differs')
    loaded=inventory['entries'];wanted=str(path.resolve()).casefold()
    require(not any(str(Path(r['path']).resolve()).casefold()==wanted or r['sha256']==row['sha256'] for r in loaded),'Debugger auxiliary is actually loaded')
    if relative.endswith('.pyd'):
        require(relative_path.name not in {row['normal_module_stem']+suffix for suffix in importlib.machinery.EXTENSION_SUFFIXES},'A current ABI import candidate cannot use the unused auxiliary rule')
    return {'name':relative,'path':str(path.resolve()),'bytes':row['bytes'],'sha256':row['sha256'],'pe_machine':row['pe_machine'],
            'provider_class':'unloaded_official_debugger_foreign_ABI_auxiliary','distribution':'debugpy','version':version,
            'official_source_filename':manifest['wheel']['filename'],'official_source_sha256':manifest['wheel']['sha256'],
            'official_source_url':manifest['wheel']['url'],'exact_official_RECORD_row':row['original_wheel_RECORD_row'],
            'installed_RECORD_sha256':digest(record),'native_target_machine':target_machine,'mathematical_native_consumer':False,
            'actual_phase':inventory['phase'],'native_actual_process_verified':True,'observed_loaded_in_provenance_process':False}
