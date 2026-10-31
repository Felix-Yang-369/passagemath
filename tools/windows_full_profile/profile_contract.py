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

def root_wheel_metadata_name(wheel,leaf):
    if leaf not in ('WHEEL','METADATA','RECORD'):raise ValueError('Unknown wheel metadata leaf')
    names=[member.filename for member in wheel.infolist() if len(PurePosixPath(member.filename).parts)==2 and PurePosixPath(member.filename).parts[0].endswith('.dist-info') and PurePosixPath(member.filename).name==leaf and not member.is_dir()]
    if len(names)!=1:raise ValueError('Ambiguous/missing root '+leaf+' metadata in '+str(wheel.filename))
    return names[0]

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
        record_name=root_wheel_metadata_name(wheel,'RECORD');records=set()
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
        metadata_name=root_wheel_metadata_name(wheel,'WHEEL')
        tags=re.findall(r'^Tag: (.+)$',wheel.read(metadata_name).decode('utf-8').replace('\r',''),re.M)
    suffix='win_amd64' if arch=='x64' else 'win_arm64'
    try:
        from packaging.tags import cpython_tags,compatible_tags,parse_tag
    except ImportError:
        from pip._vendor.packaging.tags import cpython_tags,compatible_tags,parse_tag
    # Each WHEEL Tag is an alternative, including separately expanded py2/py3
    # entries. Use PyPA's CPython3.12 target tags while retaining the explicit
    # same-platform boundary that rejects the mislabeled pkgconf wheel.
    declared=set()
    for tag in tags:declared.update(parse_tag(tag))
    supported=set(cpython_tags(python_version=(3,12),platforms=[suffix]))
    supported.update(compatible_tags(python_version=(3,12),interpreter='cp312',platforms=[suffix]))
    if not declared or any(tag.platform not in ('any',suffix) for tag in declared) or not declared.intersection(supported):
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
    environments=[dict(environment,package=row['package']) for row in tests for environment in row.get('environments',[])]
    strict_zero=lambda x:type(x) is int and x==0
    positive=lambda x:type(x) is int and x>0
    def actual_scope(row):
        if row.get('test_kind')=='import-only':
            return row.get('package')=='glpk' and row.get('original_contract_sha256')=='88eef253884e879e6c1f81aa19214ea471b5a845b367bfb4cf4a6f99c0fa4eef' and type(row.get('reported_tests')) is int and row['reported_tests']==0 and row.get('units_matched') is True and row.get('summary_seen') is True and row.get('both_original_import_envs_provenance') is True
        return row.get('summary_seen') is True and positive(row.get('reported_tests')) and row.get('units_matched') is True
    def environment_scope(row):
        common=(row.get('summary_seen') is True and row.get('units_matched') is True
                and row.get('actual_original_commands_complete') is True
                and type(row.get('actual_test_command_count')) is int
                and type(row.get('source_effective_command_count')) is int
                and row['actual_test_command_count']==row['source_effective_command_count']>=0)
        if row.get('kind')=='mathematics':
            return (common and positive(row.get('reported_tests'))
                    and row.get('original_bash_native_launcher_proven') is True
                    and row['actual_test_command_count']>0)
        return (common and type(row.get('reported_tests')) is int and row['reported_tests']==0
                and row.get('mathematical_acceptance_claimed') is False)
    checks={'exact_16_owners':len(build_names)==len(OWNERS) and set(build_names)==set(OWNERS),'exact_14_full_tox_jobs':len(test_names)==len(TEST_OWNERS) and set(test_names)==set(TEST_OWNERS),'exact_13_math_plus_original_glpk_import_only':all((r.get('test_kind')=='import-only' if r['package']=='glpk' else r.get('test_kind')=='mathematics') for r in tests),'all_normal_owner_builds_exit0':all(strict_zero(r.get('exit')) and r.get('accepted') is True for r in builds),'all_original_full_tox_exit0':all(strict_zero(r.get('exit')) for r in tests),'actual_original_test_scopes':all(actual_scope(r) for r in tests),'native_installed_provenance':all(r.get('provenance_passed') is True for r in tests)}
    checks.update({'exact_32_original_environments':len(environments)==32 and len({(r['package'],r['name']) for r in environments})==32,
                   'exact_17_original_mathematical_environments':sum(r.get('kind')=='mathematics' for r in environments)==17,
                   'all_original_environment_scopes_bound':all(row.get('complete_original_environment_scope') is True for row in tests),
                   'all_32_have_actual_results':len(environments)==32 and all(r.get('state')=='executed' and type(r.get('exit')) is int for r in environments),
                   'all_32_actual_results_exit0':len(environments)==32 and all(strict_zero(r.get('exit')) for r in environments),
                   'all_32_source_provenance_and_acceptance':len(environments)==32 and all(r.get('accepted') is True and r.get('pre_provenance_passed') is True and r.get('post_provenance_passed') is True for r in environments),
                   'every_environment_has_actual_original_scope_evidence':len(environments)==32 and all(environment_scope(r) for r in environments),
                   'all_original_factor_baselines_unchanged':all(row.get('fixtures_closing',{}).get('passed') is True for row in tests)})
    return {'passed':all(checks.values()),'checks':checks,'builds':builds,'tests':tests,'original_upstream_jobs_rerun':False,'scope':'Original Windows modular profile: 16 owners and 14 complete original tox jobs, comprising all 32 declared environments and 17 mathematical phases; not an all-Sage native Windows port'}

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
        return {'package':package,'test_kind':'import-only','source_sha256':digest,'active_commands':active,'imports':imports,'mathematical_tests':0,'targets':[],'environment':None,'source_environments':original_source_tox_environments(body),'environment_targets':original_environment_targets(body,package)}
    environment=re.search(r'--environment(?:=|\s+)([^\s]+)',math).group(1)
    if environment not in imports:imports.append(environment)
    positional=re.search(r'\{posargs:([^}]+)\}',math)
    if positional:targets=positional.group(1).split()
    else:targets=[token.rstrip("'\"") for token in math.split() if token.startswith(('sage/','./sage/')) or token=='--installed']
    if not targets:raise ValueError('Original mathematical targets missing')
    optional=re.search(r'--optional=([^\s]+)',math)
    return {'package':package,'test_kind':'mathematics','source_sha256':digest,'active_commands':active,'imports':list(dict.fromkeys(imports)),'environment':environment,'targets':targets,'probe_all':bool(re.search(r'--probe\s+all(?:\s|$)',math)),'optional':optional.group(1) if optional else None,'initial':'--initial' in math,'force_lib':'--force-lib' in math,'installed':'--installed' in targets,'source_environments':original_source_tox_environments(body),'environment_targets':original_environment_targets(body,package)}

def original_source_tox_environments(body):
    """Literal original envlist and the exact original Windows sed conversion."""
    import configparser
    config=configparser.ConfigParser(interpolation=None,strict=True);config.read_string(body)
    source=[]
    for line in config.get('tox','envlist').splitlines():
        value=line.split('#',1)[0].strip()
        if not value:continue
        if not re.fullmatch(r'sagepython-sagewheels-nopypi-norequirements(?:-[a-z0-9]+)*',value):raise ValueError('Unsupported original envlist entry '+value)
        source.append(value)
    if not source or len(source)!=len(set(source)):raise ValueError('Empty/duplicate original tox envlist')
    mapped=[re.sub(r'sagepython-.*nopypi-norequirements','py312-norequirements',name) for name in source]
    if len(mapped)!=len(set(mapped)):raise ValueError('Original sed conversion collides')
    return [{'original':a,'name':b} for a,b in zip(source,mapped)]

def select_original_tox_journal(journal,body,selected_names,work):
    """Retain selected results and classify normal tox's unexecuted journals.

    Exact primary witnesses: both GLPK --notest and complete --result-json.
    Source-defined inactive aliases and packaging metadata may be lazy {} rows.
    Only the observed external-wheel packaging freeze is a nonempty extra row.
    """
    import configparser
    import math
    config=configparser.ConfigParser(interpolation=None,strict=True);config.read_string(body)
    source=original_source_tox_environments(body)
    expected=[row['name'] for row in source]
    if list(selected_names)!=expected:raise ValueError('Journal selected scope differs from literal original source')
    names={row['original'] for row in source}
    for section in config.sections():
        if section.startswith('testenv:'):
            name=section[len('testenv:'):]
            if not re.fullmatch(r'[A-Za-z0-9_.-]+',name):raise ValueError('Nonliteral original source testenv name')
            names.add(name)
    lazy=set(names)|{'.pkg_external_sdist_meta'}
    # Normal graphs journal also creates a lazy bare polyhedra factor. Derive
    # these names from literal original extras/setenv selectors, never a prefix.
    for section in ('testenv','pkgenv'):
        if not config.has_section(section):continue
        for key in ('extras','setenv','set_env'):
            for line in config.get(section,key,fallback='').splitlines():
                line=line.split('#',1)[0].strip()
                if ':' not in line:continue
                condition=line.split(':',1)[0].strip()
                if re.fullmatch(r'!?[a-z0-9_]+(?:-!?[a-z0-9_]+)*(?:\s*,\s*!?[a-z0-9_]+(?:-!?[a-z0-9_]+)*)*',condition):
                    lazy.update(term.lstrip('!').strip() for alternative in condition.split(',') for term in alternative.strip().split('-'))
    for name in names:
        if name.startswith('.pkg-'):lazy.add(name+'_sdist_meta')
        elif name.startswith('sagepython'):
            lazy.update(('.pkg-'+name,'.pkg-'+name+'_sdist_meta'))
    if not isinstance(journal,dict) or journal.get('reportversion')!='1':raise ValueError('Unsupported actual tox journal schema')
    actual=journal.get('testenvs')
    if not isinstance(actual,dict) or not set(expected)<=set(actual):raise ValueError('Actual journal omits a selected original environment')
    selected={};classified=[]
    for name,row in actual.items():
        if not isinstance(row,dict):raise ValueError('Actual journal environment is not an object')
        if name in expected:
            result=row.get('result')
            if (not isinstance(result,dict) or type(result.get('success')) is not bool
                    or type(result.get('exit_code')) is not int or type(result.get('skipped')) is not bool
                    or type(result.get('duration')) not in (int,float)
                    or not math.isfinite(result['duration']) or result['duration']<0):
                raise ValueError('Selected original environment lacks a real typed result '+name)
            selected[name]=row;classified.append({'name':name,'classification':'selected_original_environment','actual_result':result})
        elif row=={} and name in lazy:
            classified.append({'name':name,'classification':'source_defined_inactive_empty_journal'})
        elif name=='.pkg_external':
            if set(row)!={'python','installed_packages','setup'}:raise ValueError('External packaging journal has unknown/test/result fields')
            python=row['python'];packages=row['installed_packages'];setup=row['setup']
            python_keys={'implementation','version_info','version','is_64','sysplatform','extra_version_info','free_threaded','debug','machine','executable'}
            if (not isinstance(python,dict) or set(python)!=python_keys
                    or python['implementation']!='CPython' or python['version_info']!=[3,12,10,'final',0]
                    or python['is_64'] is not True or python['sysplatform']!='win32'
                    or python['extra_version_info'] is not None or python['free_threaded'] is not False or python['debug'] is not False
                    or not all(isinstance(python[k],str) and python[k] for k in ('version','machine','executable'))
                    or not isinstance(packages,list) or not all(isinstance(p,str) for p in packages)
                    or not isinstance(setup,list) or len(setup)!=1):raise ValueError('Invalid observed external packaging schema')
            command=setup[0]
            if not isinstance(command,dict):raise ValueError('External packaging command is not an object')
            argv=command.get('command')
            wanted=Path(work)/'.pkg_external/Scripts/python.exe'
            if (not isinstance(argv,list) or len(argv)!=5 or not all(isinstance(x,str) for x in argv)
                    or Path(argv[0]).resolve()!=wanted.resolve() or argv[1:]!=['-m','pip','freeze','--all']
                    or command.get('run_id')!='freeze' or type(command.get('retcode')) is not int
                    or command['retcode']!=0):raise ValueError('External packaging executes an unobserved command')
            classified.append({'name':name,'classification':'observed_normal_external_wheel_packaging_freeze','command':argv,'retcode':command['retcode']})
        else:raise ValueError('Unknown or actually executed extra tox journal '+name)
    return {'selected':{name:selected[name] for name in expected},'classification':{
        'passed':True,'selected_environment_names':expected,'all_raw_environment_names':list(actual),
        'source_defined_lazy_names':sorted(lazy),'rows':classified,'no_extra_test_environment_execution':True}}


def source_requested_extras(body,original_environment):
    """Resolve the simple factor expressions actually used by these source files."""
    import configparser
    config=configparser.ConfigParser(interpolation=None,strict=True);config.read_string(body)
    factors=set(original_environment.split('-'));values=[]
    for line in config.get('testenv','extras',fallback='').splitlines():
        line=line.split('#',1)[0].strip()
        if not line:continue
        if ':' in line:
            condition,line=line.split(':',1);alternatives=condition.split(',');include=False
            for alternative in alternatives:
                terms=alternative.strip().split('-')
                if not all(re.fullmatch(r'!?[a-z0-9_]+',term) for term in terms):raise ValueError('Unsupported original extra factor '+condition)
                include|=all((term[1:] not in factors) if term.startswith('!') else (term in factors) for term in terms)
            if not include:continue
        for extra in line.split():
            if not re.fullmatch(r'[A-Za-z0-9_-]+',extra):raise ValueError('Unsupported original extra '+extra)
            values.append(extra.lower().replace('_','-'))
    if len(values)!=len(set(values)):raise ValueError('Duplicate original extras')
    return sorted(values)

def original_environment_targets(body,package):
    return [dict(row,kind='import-only' if package=='glpk' else 'notest' if row['name'].endswith('-notest') else 'mathematics',requested_extras=source_requested_extras(body,row['original'])) for row in original_source_tox_environments(body)]

def source_known_failure_basename(body,original_environment):
    """Resolve only the baseline template and factor variables in original source."""
    import configparser
    config=configparser.ConfigParser(interpolation=None,strict=True);config.read_string(body)
    factors=set(original_environment.split('-'));assignments={}
    for raw in config.get('testenv','setenv').splitlines():
        raw=raw.split('#',1)[0].strip()
        if not raw or '=' not in raw:continue
        left,value=raw.split('=',1);left=left.strip();value=value.strip()
        if ':' in left:
            condition,key=left.rsplit(':',1);include=False
            for alternative in condition.split(','):
                terms=alternative.strip().split('-')
                if not all(re.fullmatch(r'!?[a-z0-9_]+',term) for term in terms):raise ValueError('Unsupported baseline factor '+condition)
                include|=all((term[1:] not in factors) if term.startswith('!') else term in factors for term in terms)
            if not include:continue
            left=key.strip()
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',left):raise ValueError('Unsupported source environment assignment')
        assignments[left]=value
    template=assignments.get('KNOWN_TEST_FAILURES')
    if template is None or not template.startswith(('{toxinidir}/','{toxinidir}\\')):raise ValueError('Original baseline template is not rooted in its source configuration')
    suffix=template[len('{toxinidir}'):].lstrip('/\\')
    def replace(match):
        name=match.group(1);value=assignments.get(name,match.group(2) or '')
        if value and not re.fullmatch(r'--[a-z0-9_-]+',value):raise ValueError('Original baseline factor value is not a literal suffix')
        return value
    suffix=re.sub(r'\{env:([A-Za-z_][A-Za-z0-9_]*)(?::([^}]*))?\}',replace,suffix)
    if not re.fullmatch(r'known-test-failures(?:--[a-z0-9_-]+)?\.json',suffix):raise ValueError('Unresolved/escaping original baseline suffix')
    return suffix

def resolved_original_tox_matrix(body,package,listed_text,effective,config_directory,work_directory):
    """Bind normal tox JSON resolution to all literal original environments."""
    source=original_environment_targets(body,package);names=[row['name'] for row in source]
    listed=[re.sub(r'sagepython-.*nopypi-norequirements','py312-norequirements',line.strip()) for line in listed_text.splitlines() if line.strip()]
    if listed!=names:raise ValueError('Normal tox -l differs from literal source envlist/sed conversion')
    environments=effective.get('env')
    if not isinstance(environments,dict) or set(environments)!=set(names):raise ValueError('Normal effective tox JSON omits/adds original environments')
    directory=Path(config_directory).resolve();work=Path(work_directory).resolve();result=[];stats=set();contract=original_tox_contract(body,package)
    for target in source:
        name=target['name'];actual=environments[name]
        if actual.get('env_name')!=name:raise ValueError('Effective tox name differs')
        extras=actual.get('extras');commands=actual.get('commands');env=actual.get('set_env');before_commands=actual.get('commands_pre',[]);after_commands=actual.get('commands_post',[])
        if not isinstance(extras,list) or any(not isinstance(x,str) for x in extras) or len(extras)!=len(set(extras)) or sorted(x.lower().replace('_','-') for x in extras)!=target['requested_extras']:raise ValueError('Effective extras differ from original source factors '+name)
        if any(not isinstance(value,list) or any(not isinstance(x,str) for x in value) for value in (commands,before_commands,after_commands)) or not isinstance(env,dict):raise ValueError('Malformed normal effective commands/environment')
        if before_commands or after_commands:raise ValueError('These immutable original Windows profiles have no pre/post test commands; source contract changed')
        mathematical=[line for line in commands if 'sage-runtests' in line]
        if bool(mathematical)!=(target['kind']=='mathematics') or len(mathematical)>1:raise ValueError('Original mathematical/notest/import-only phase differs '+name)
        prefix=(work/name).resolve();home=Path(env['HOME']).resolve();dot=Path(env['DOT_SAGE']).resolve();known=Path(env['KNOWN_TEST_FAILURES']).resolve()
        if home!=prefix or Path(env['TOX_ENV_DIR']).resolve()!=prefix or dot!=prefix/'.sage' or env.get('SAGE_DOC')!='/doesnotexist':raise ValueError('Original private environment mapping differs '+name)
        if dot in stats:raise ValueError('Original environments share mutable Sage statistics')
        stats.add(dot)
        expected_known=directory/source_known_failure_basename(body,target['original'])
        if known!=expected_known:raise ValueError('Effective original baseline differs from exact source factor template '+name)
        imports=[]
        for command in commands:
            for match in re.finditer(r'import\s+(sage\.[A-Za-z0-9_.]+(?:\s*,\s*sage\.[A-Za-z0-9_.]+)*)',command):imports.extend(x.strip() for x in match.group(1).split(','))
        if mathematical:
            if contract['environment'] not in imports:imports.append(contract['environment'])
            found=re.findall(r'--environment(?:=|\s+)([A-Za-z0-9_.]+)',mathematical[0])
            if found!=[contract['environment']]:raise ValueError('Effective original Sage namespace differs '+name)
        if package=='glpk' and imports!=['sage.libs.glpk']:raise ValueError('Original GLPK import-only contract differs')
        result.append(dict(target,imports=list(dict.fromkeys(imports)),prefix=str(prefix),known_failures=str(known),dot_sage=str(dot),commands=commands,commands_pre=before_commands,commands_post=after_commands,effective_set_env=env,original_contract_sha256=contract['source_sha256']))
    return {'package':package,'source_sha256':contract['source_sha256'],'source_environments':source,'environments':result,'exact_source_envlist_and_sed':True,'normal_effective_commands_extras_and_known_failures':True,'environment_count':len(result),'mathematical_environment_count':sum(row['kind']=='mathematics' for row in result)}

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
