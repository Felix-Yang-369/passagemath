"""Pure input, archive, wheel and result guards for the complete Windows profile."""
from pathlib import Path, PurePosixPath
import hashlib
import struct
import tarfile
import zipfile
import re
import math

OWNERS=('objects','categories','graphs','rankwidth','cddlib','glpk','highs','planarity','homfly','cliquer','combinat','modules','gsl','plot','cmr','m4ri_m4rie')
TEST_OWNERS=('categories','cddlib','cliquer','cmr','combinat','glpk','graphs','gsl','highs','homfly','modules','planarity','plot','rankwidth')
ORIGINAL_EIGHT=(
    {'pr':2973,'arch':'x64','package':'homfly','job_id':123796240378},
    {'pr':2973,'arch':'arm64','package':'homfly','job_id':123796240303},
    {'pr':2973,'arch':'x64','package':'rankwidth','job_id':123796240407},
    {'pr':2973,'arch':'x64','package':'gsl','job_id':123796240343},
    {'pr':2974,'arch':'x64','package':'homfly','job_id':123797762027},
    {'pr':2974,'arch':'arm64','package':'homfly','job_id':123797762012},
    {'pr':2974,'arch':'x64','package':'rankwidth','job_id':123797762008},
    {'pr':2974,'arch':'x64','package':'gsl','job_id':123797761937})

def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def safe_name(name):
    path=PurePosixPath(name)
    if not name or '\\' in name or ':' in name or path.is_absolute() or '..' in path.parts:
        raise ValueError('Unsafe archive/input path: '+repr(name))
    return path

def verify_members(root,pins):
    root=Path(root).resolve();seen=set()
    for pin in pins:
        relative=safe_name(pin['name']);key=str(relative).casefold()
        if key in seen:raise ValueError('Duplicate/case-colliding member: '+str(relative))
        seen.add(key);path=root/str(relative)
        if not path.resolve().is_relative_to(root) or not path.is_file() or path.is_symlink():raise ValueError('Missing/unsafe input '+str(path))
        if path.stat().st_size!=pin['bytes'] or sha(path)!=pin['sha256']:raise ValueError('Input hash mismatch '+str(path))
    actual=set()
    for path in root.rglob('*'):
        if path.is_symlink() or (hasattr(path,'is_junction') and path.is_junction()):raise ValueError('Unexpected input symlink/junction')
        if not path.is_file():continue
        key=str(path.relative_to(root)).replace('\\','/').casefold()
        if key in actual:raise ValueError('Actual input case collision')
        actual.add(key)
    if actual!=seen:raise ValueError('Unexpected/missing input files '+repr(sorted(actual^seen)))
    return {'verified_members':len(seen),'root':str(root),'unexpected_actual_files':0,'case_collisions':0,'symlinks_and_junctions':0}

def extract_tar(archive,destination):
    destination=Path(destination).resolve();destination.mkdir()
    with tarfile.open(archive) as source:
        members=source.getmembers();seen=set();tops=set()
        for member in members:
            relative=safe_name(member.name);key=str(relative).casefold()
            if member.issym() or member.islnk() or not(member.isfile() or member.isdir()):raise ValueError('Nonregular tar member '+member.name)
            if key in seen:raise ValueError('Duplicate tar member '+member.name)
            seen.add(key);tops.add(relative.parts[0])
            out=destination/str(relative)
            if not out.resolve().is_relative_to(destination):raise ValueError('Escaping tar member')
            if member.isdir():out.mkdir(parents=True,exist_ok=True)
            else:
                out.parent.mkdir(parents=True,exist_ok=True)
                with source.extractfile(member) as reader:out.write_bytes(reader.read())
    if len(tops)!=1:raise ValueError('Expected one source root')
    return destination/next(iter(tops))

def pe_machine(data):
    if len(data)<64 or data[:2]!=b'MZ':raise ValueError('Not a PE object')
    offset=struct.unpack_from('<I',data,0x3c)[0]
    if data[offset:offset+4]!=b'PE\0\0':raise ValueError('Missing PE signature')
    return struct.unpack_from('<H',data,offset+4)[0]

def wheel_inventory(path,arch,discovered_extensions=None,require_native=True):
    expected={'x64':0x8664,'arm64':0xaa64}[arch]
    native=[];files=[];extension_modules=set()
    import csv,io,base64
    with zipfile.ZipFile(path) as wheel:
        names=set();content={}
        for member in wheel.infolist():
            canonical=str(safe_name(member.filename.rstrip('/')))
            if canonical!=member.filename.rstrip('/'):raise ValueError('Noncanonical wheel member')
            key=canonical.casefold()
            if key in names or ((member.external_attr>>16)&0o170000)==0o120000:raise ValueError('Duplicate/colliding/symlink wheel member')
            names.add(key)
            if member.is_dir():continue
            data=wheel.read(member);row={'name':member.filename,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()};files.append(row)
            content[member.filename]=data
            if member.filename.lower().endswith(('.pyd','.dll')):
                machine=pe_machine(data)
                if machine!=expected:raise ValueError('Wrong PE architecture '+member.filename)
                row=dict(row,pe_machine=hex(machine));native.append(row)
                if member.filename.endswith('.pyd'):extension_modules.add(member.filename.split('.')[0])
        record_names=[n for n in content if n.endswith('.dist-info/RECORD')]
        if len(record_names)!=1:raise ValueError('Exactly one wheel RECORD required')
        record_name=record_names[0];records=set()
        for name,digest,size in csv.reader(io.StringIO(content[record_name].decode('utf-8'))):
            if name in records or name not in content:raise ValueError('Duplicate/missing wheel RECORD file')
            records.add(name);data=content[name]
            if not digest:
                if name!=record_name:raise ValueError('Unhashed non-RECORD wheel file')
            else:
                algorithm,value=digest.split('=',1)
                if algorithm!='sha256' or base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()!=value or len(data)!=int(size):raise ValueError('Wheel RECORD digest/length mismatch '+name)
        if records!=set(content):raise ValueError('Wheel RECORD omits files')
        if discovered_extensions is not None:
            expected={name.replace('.','/') for name in discovered_extensions}
            if extension_modules!=expected:raise ValueError('Official source discovery/wheel extension mismatch '+repr(sorted(extension_modules^expected)))
    if require_native and not native:raise ValueError('Native owner wheel has no PE files')
    return {'path':str(path),'sha256':sha(path),'native':native,'files':files,'pyd_count':len(extension_modules),'all_wheel_record_files_verified':True,'record_file_count':len(records)}

def provider_wheel_tags(path,arch):
    with zipfile.ZipFile(path) as wheel:
        records=[n for n in wheel.namelist() if n.endswith('.dist-info/WHEEL')]
        if len(records)!=1:raise ValueError('Ambiguous wheel metadata')
        tags=re.findall(r'^Tag: (.+)$',wheel.read(records[0]).decode('utf-8').replace('\r',''),re.M)
    suffix='win_amd64' if arch=='x64' else 'win_arm64'
    def supported(tag):
        fields=tag.split('-')
        if len(fields)!=3:return False
        python,abi,platform=fields
        if platform not in ('any',suffix):return False
        if abi=='abi3':
            return bool(re.fullmatch(r'cp3[0-9]+',python)) and 2<=int(python[3:])<=12
        if abi=='cp312':return python=='cp312' and platform==suffix
        if abi!='none':return False
        return all(part in ('py3','cp312') or (bool(re.fullmatch(r'py3[0-9]+',part)) and int(part[3:])<=12) or part=='py2' and 'py3' in python.split('.') for part in python.split('.'))
    if not tags or not all(supported(tag) for tag in tags):
        raise ValueError('Third-party wheel internal platform mismatch '+Path(path).name)
    return tags

def require_valid_import_library(path):
    data=Path(path).read_bytes()
    if data[:8]!=b'!<arch>\n':raise ValueError('Not a COFF archive')
    members=[];pos=8
    while pos<len(data):
        header=data[pos:pos+60]
        if len(header)!=60 or header[-2:]!=b'`\n':raise ValueError('Malformed archive header')
        size=int(header[48:58]);members.append((pos,header[:16].rstrip(),pos+60,size));pos+=60+size+(size&1)
    if pos!=len(data):raise ValueError('Archive member length mismatch')
    offsets={m[0] for m in members};tables=[m for m in members if m[1]==b'/']
    if len(tables)!=2:raise ValueError('Two COFF symbol directories required')
    first=data[tables[0][2]:tables[0][2]+tables[0][3]];count=struct.unpack_from('>I',first)[0]
    refs=struct.unpack_from('>'+str(count)+'I',first,4);names=first[4+4*count:].split(b'\0')
    if len(names)<count or any(not n or o not in offsets for n,o in zip(names[:count],refs)):raise ValueError('Invalid first COFF symbol directory')
    second=data[tables[1][2]:tables[1][2]+tables[1][3]];members_count=struct.unpack_from('<I',second)[0];refs=struct.unpack_from('<'+str(members_count)+'I',second,4)
    count2=struct.unpack_from('<I',second,4+4*members_count)[0];start=8+4*members_count;indexes=struct.unpack_from('<'+str(count2)+'H',second,start);names2=second[start+2*count2:].split(b'\0')
    if len(names2)<count2 or any(o not in offsets for o in refs) or any(not n or not(1<=i<=members_count) for n,i in zip(names2[:count2],indexes)):raise ValueError('Invalid second COFF symbol directory')
    if count!=count2 or b'Highs_create' not in names[:count] or b'__imp_Highs_create' not in names[:count]:raise ValueError('Expected HiGHS API absent from import library')
    return {'path':str(path),'sha256':sha(path),'archive_members':len(members),'linker_symbols':count,'second_directory_members':members_count,'both_directories_valid':True}

def complete_result(builds,tests):
    build_names=[r['package'] for r in builds];test_names=[r['package'] for r in tests]
    strict_zero=lambda x:type(x) is int and x==0
    positive=lambda x:type(x) is int and x>0
    def actual_scope(row):
        if row.get('test_kind')=='import-only':
            return row.get('package')=='glpk' and row.get('original_contract_sha256')=='88eef253884e879e6c1f81aa19214ea471b5a845b367bfb4cf4a6f99c0fa4eef' and type(row.get('reported_tests')) is int and row['reported_tests']==0 and row.get('units_matched') is True and row.get('summary_seen') is True and row.get('both_original_import_envs_provenance') is True
        return row.get('summary_seen') is True and positive(row.get('reported_tests')) and row.get('units_matched') is True
    checks={'exact_16_owners':len(build_names)==len(OWNERS) and set(build_names)==set(OWNERS),'exact_14_full_tox_jobs':len(test_names)==len(TEST_OWNERS) and set(test_names)==set(TEST_OWNERS),'exact_13_math_plus_original_glpk_import_only':all((r.get('test_kind')=='import-only' if r['package']=='glpk' else r.get('test_kind')=='mathematics') for r in tests),'all_normal_owner_builds_exit0':all(strict_zero(r.get('exit')) and r.get('accepted') is True for r in builds),'all_original_full_tox_exit0':all(strict_zero(r.get('exit')) for r in tests),'actual_original_test_scopes':all(actual_scope(r) for r in tests),'native_installed_provenance':all(r.get('provenance_passed') is True for r in tests)}
    return {'passed':all(checks.values()),'checks':checks,'builds':builds,'tests':tests,'original_upstream_jobs_rerun':False,'scope':'Original Windows modular profile: 16 owners and 14 original full tox jobs, comprising 13 mathematics suites and one GLPK import-only job; not an all-Sage native Windows port'}

def original_tox_contract(body,package):
    section=body.split('[testenv]',1)[1].split('\n[testenv:',1)[0]
    commands=section.split('\ncommands =',1)[1]
    active='\n'.join(line for line in commands.splitlines() if line.strip() and not line.lstrip().startswith('#'))
    imports=[]
    for match in re.finditer(r'import\s+(sage\.[A-Za-z0-9_.]+(?:\s*,\s*sage\.[A-Za-z0-9_.]+)*)',active):imports.extend(x.strip() for x in match.group(1).split(','))
    math=active.split('sage-runtests',1)[1] if 'sage-runtests' in active else None
    digest=hashlib.sha256(body.encode('utf-8')).hexdigest()
    if math is None:
        if package!='glpk' or digest!='88eef253884e879e6c1f81aa19214ea471b5a845b367bfb4cf4a6f99c0fa4eef' or imports!=['sage.libs.glpk']:raise ValueError('Undeclared import-only original contract')
        return {'package':package,'test_kind':'import-only','source_sha256':digest,'active_commands':active,'imports':imports,'mathematical_tests':0,'targets':[],'environment':None}
    environment=re.search(r'--environment(?:=|\s+)([^\s]+)',math).group(1)
    if environment not in imports:imports.append(environment)
    positional=re.search(r'\{posargs:([^}]+)\}',math)
    if positional:targets=positional.group(1).split()
    else:targets=[token.rstrip("'\"") for token in math.split() if token.startswith(('sage/','./sage/')) or token=='--installed']
    if not targets:raise ValueError('Original mathematical targets missing')
    optional=re.search(r'--optional=([^\s]+)',math)
    return {'package':package,'test_kind':'mathematics','source_sha256':digest,'active_commands':active,'imports':list(dict.fromkeys(imports)),'environment':environment,'targets':targets,'probe_all':bool(re.search(r'--probe\s+all(?:\s|$)',math)),'optional':optional.group(1) if optional else None,'initial':'--initial' in math,'force_lib':'--force-lib' in math,'installed':'--installed' in targets}

def source_snapshot(source):
    source=Path(source);owned={};generated_metadata={}
    for path in source.rglob('*'):
        if not path.is_file():continue
        relative=str(path.relative_to(source)).replace('\\','/')
        generated=relative in ('PKG-INFO','setup.cfg') or any(p.endswith('.egg-info') for p in path.relative_to(source).parts)
        (generated_metadata if generated else owned)[relative]=sha(path)
    return {'owned':owned,'archive_generated_metadata':generated_metadata,'ownership_rule':'All original sdist regular files are locked except the explicitly classified generated PKG-INFO/setup.cfg/egg-info metadata; normal new build outputs are separate.'}

def source_closing(source,snapshot):
    source=Path(source);changed=[]
    for relative,digest in snapshot['owned'].items():
        path=source/relative
        if not path.is_file() or sha(path)!=digest:changed.append({'path':relative,'expected':digest,'actual':sha(path) if path.is_file() else None})
    for relative,digest in snapshot.get('normal_generated_source_files',{}).items():
        path=source/relative
        if not path.is_file() or sha(path)!=digest:changed.append({'path':relative,'expected':digest,'actual':sha(path) if path.is_file() else None,'normal_generated_source':True})
    metadata=[{'path':relative,'before':digest,'after':sha(source/relative) if (source/relative).is_file() else None} for relative,digest in snapshot['archive_generated_metadata'].items() if not (source/relative).is_file() or sha(source/relative)!=digest]
    return {'passed':not changed,'owned_file_count':len(snapshot['owned']),'changed_owned_files':changed,'generated_archive_metadata_deltas':metadata}

def compare_units(expected,stats,baseline):
    names=[r['basename'] for r in expected];checks={'nonempty_selection':len(names)>0,'no_duplicate_selected_units':len(names)==len(set(names)),'exact_stats_unit_set':set(names)==set(stats)}
    rows=[];total=0
    for name in names:
        item=stats.get(name,{});n=item.get('ntests');wall=item.get('walltime');failed=item.get('failed',False)
        valid_n=type(n) is int and n>=0
        valid_wall=type(wall) in (int,float) and math.isfinite(wall) and 0<wall<1e6
        known=baseline.get(name,{}).get('failed') is True
        valid_fail=type(failed) is bool and (failed is False or known)
        if valid_n:total+=n
        rows.append({'basename':name,'ntests':n,'walltime':wall,'failed':failed,'preexisting_known_failure':known,'valid':valid_n and valid_wall and valid_fail})
    checks.update({'all_units_have_actual_stats':all(r['valid'] for r in rows),'positive_reported_tests':total>0})
    return {'passed':all(checks.values()),'checks':checks,'reported_tests':total,'units':rows,'known_failure_count':sum(r['failed'] is True and r['preexisting_known_failure'] for r in rows),'missing_units':sorted(set(names)-set(stats)),'extra_units':sorted(set(stats)-set(names))}
