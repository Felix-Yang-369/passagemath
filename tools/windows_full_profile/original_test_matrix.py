"""The literal 14 original tox jobs: 32 environments and 17 mathematical phases."""
import json
import os
from pathlib import Path
import re
import shutil

from profile_contract import (OWNERS,TEST_OWNERS,ORIGINAL_EIGHT,compare_units,
    original_environment_targets,resolved_original_tox_matrix,select_original_tox_journal,sha)


def unique_object(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise ValueError('Duplicate actual JSON key '+key)
        value[key]=item
    return value


def read_json(path):return json.loads(Path(path).read_text(encoding='utf-8'),object_pairs_hook=unique_object)


def clean_receipt(entry):
    return (type(entry.get('exit')) is int and type(entry.get('actual_returncode')) is int
            and entry['exit']==entry['actual_returncode']==0
            and entry.get('running') is False
            and entry.get('remaining_pids')==[] and entry.get('timed_out') is False
            and not entry.get('error') and not entry.get('remaining_query_error')
            and entry.get('job_assignment')=='assigned')


def journal_success(row):
    result=row.get('result',{})
    return (result.get('success') is True and type(result.get('exit_code')) is int
            and result['exit_code']==0 and result.get('skipped') is False)


def journal_text(row):
    return '\n'.join(str(command.get(stream,'')) for command in row.get('test',[])
                     for stream in ('output','err'))


def terminal_failure_headers(text):
    # Original sage/doctest/reporting.py SHA79354638e9f5e10d88fca708b8822d3b46bde104da3a895487b2d414090da3e8.
    # report_head emits these unindented postscript failure messages. Successful
    # verbose examples mentioning signals are not terminal failure evidence.
    return re.findall(r'(?m)^sage -t[^\r\n]*#[^\r\n]*(?:Timed out|Killed due to|Bad exit:|Testing error:|in doctesting framework|Tab character found|Source line number found)[^\r\n]*',text)


def fixture_snapshot(directory):
    directory=Path(directory)
    return {path.name:sha(path) for path in sorted(directory.glob('known-test-failures*.json'))
            if path.is_file()}


def fixture_closing(directory,before,source_sha):
    attempts=[];directory=Path(directory)
    for name in sorted(set(before)|{p.name for p in directory.glob('known-test-failures*.json')}|{'tox.ini'}):
        try:
            path=directory/name;actual=sha(path) if path.is_file() else None
            expected=source_sha if name=='tox.ini' else before.get(name)
            attempts.append({'path':str(path),'expected_sha256':expected,'actual_sha256':actual,'passed':actual==expected})
        except Exception as error:attempts.append({'path':str(directory/name),'passed':False,'error':str(error)})
    return {'passed':all(row['passed'] for row in attempts),'independent_attempts':attempts}


def allowed_dependency_diagnostic(package,bootstrap,failed_environments):
    """Only original declared external-dependency failures can run unverified."""
    if (type(bootstrap.get('exit')) is not int or type(bootstrap.get('actual_returncode')) is not int
            or bootstrap['exit']!=bootstrap['actual_returncode'] or bootstrap['exit']!=1
            or bootstrap.get('running') is not False
            or bootstrap.get('timed_out') is not False or bootstrap.get('remaining_pids')!=[]
            or bootstrap.get('job_assignment')!='assigned'
            or bootstrap.get('error') or bootstrap.get('remaining_query_error')):return False
    if package not in ('cddlib','highs','graphs'):return False
    if package=='graphs' and set(failed_environments)!={'py312-norequirements-modules-pari'}:return False
    if package in ('cddlib','highs') and set(failed_environments)!={'py312-norequirements'}:return False
    text='\n'.join(Path(bootstrap[stream]['path']).read_bytes().decode('utf-8',errors='replace') for stream in ('stdout','stderr'))
    if re.search(r'THESE PACKAGES DO NOT MATCH THE HASHES|\b(?:sha256|hash|digest)\b[^\n]*(?:mismatch|differ)|(?:wrong|mismatched)[^\n]*(?:architecture|machine|PE)|\bLNK1112\b|machine type[^\n]*conflicts with target machine type|\bintegrity\b|source[^\n]*(?:changed|mismatch)|not a supported wheel|CERTIFICATE_VERIFY_FAILED|ProxyError|ReadTimeout|Temporary failure in name resolution|NewConnectionError|Failed to establish a new connection',text,re.I):return False
    missing=r'(?:No matching distribution found for|Could not find a version that satisfies the requirement)\s+passagemath-'
    if package=='graphs':
        return bool(re.search(missing+r'pari\b|cannot find an installation of PARI/GP',text,re.I))
    if package=='cddlib' and all(re.search(pattern,text,re.I) for pattern in (
            # The actual localized pip/MSVC stream has already mojibaked the
            # opening quote plus N into the exact UTF-8 witness U+6DE3 (淣).
            r'fatal error C1083[^\n]*(?:NTL|淣TL)[/\\]ZZ\.h[^\n]*No such file or directory',
            r'Failed building wheel for passagemath-ntl\b',
            r"Failed to build ['\"]passagemath-flint['\"] when installing build dependencies for passagemath-flint\b")):
        return True
    return bool(re.search(missing+r'(?:polyhedra|ppl)\b|fatal error[^\n]*ppl\.hh[^\n]*No such file or directory',text,re.I))


def execute_original_jobs(*,root,checkout,py,wheelhouse,tools,noarch,contracts,accepted,
        requirements,runtime_env,build_env,identity,manifests_path,provider_path,
        cygpath,here,pins,pr,arch,run,save,file_record,tests):
    """Use normal tox resolution; never omit a literal original environment."""
    root=Path(root);checkout=Path(checkout);here=Path(here)
    stats_dir=root/'evidence-stats';stats_dir.mkdir(exist_ok=True)
    matrices={};all_targets=[]
    for package in TEST_OWNERS:
        targets=contracts[package]['environment_targets'];all_targets.extend(dict(row,package=package) for row in targets)
    if len(all_targets)!=32 or sum(row['kind']=='mathematics' for row in all_targets)!=17:raise ValueError('Original profile must retain all 32 environments / 17 mathematical phases')
    save(root/'ORIGINAL_32_ENVIRONMENT_TARGETS.json',{'environments':all_targets,'total':32,'mathematics':17})

    def dependencies(package):
        selected=set();pending=list(requirements[package]['test_owner_dependencies'])
        while pending:
            item=pending.pop()
            if item in selected:continue
            selected.add(item);pending.extend(requirements[item]['test_owner_dependencies'])
        return selected

    for package in TEST_OWNERS:
        contract=contracts[package];cwd=checkout/'pkgs'/('sagemath-'+package.replace('_','-'))
        targets=contracts[package]['environment_targets']
        record={'package':package,'test_kind':contract['test_kind'],'original_contract_sha256':contract['source_sha256'],
                'state':'blocked','exit':None,'summary_seen':False,'reported_tests':0,'provenance_passed':False,
                'units_matched':False,'original_environment_names':[r['name'] for r in targets],
                'environments':[dict(t,state='blocked',exit=None,pre_provenance_passed=False,post_provenance_passed=False,accepted=False) for t in targets],
                'original_target_jobs':[r['job_id'] for r in ORIGINAL_EIGHT if r['pr']==pr and r['arch']==arch and r['package']==package]}
        before=None;post_targets=[];env_rows=record['environments'];matrix=None;test_env=None;common=None;literal=None
        try:
            body=(cwd/'tox.ini').read_text(encoding='utf-8')
            if sha(cwd/'tox.ini')!=contract['source_sha256']:raise ValueError('Original source tox bytes changed before this job')
            before=fixture_snapshot(cwd);record['original_factor_baselines_before']=before
            blockers=sorted(({package}|dependencies(package))-accepted)
            if blockers:record.update({'blocked_by':blockers,'reason':'Missing accepted normal candidate owner, no old substitution'});continue
            wheel=next(wheelhouse.glob('passagemath_'+package+'-*.whl'))
            constraints=root/(package+'-constraints.txt');lines=[]
            for owner in OWNERS:
                if owner==package:continue
                candidates=list(wheelhouse.glob('passagemath_'+owner+'-*.whl'))
                candidate=candidates[0] if len(candidates)==1 and owner in accepted else root/'missing-owner'/('passagemath_'+owner+'-missing.whl')
                lines.append('passagemath_'+owner+' @ '+candidate.resolve().as_uri())
            for original in noarch.glob('*.whl'):
                provider=wheelhouse/original.name
                if provider.is_file():lines.append(original.name.split('-')[0]+' @ '+provider.resolve().as_uri())
            constraints.write_text('\n'.join(lines)+'\n',encoding='utf-8')
            test_env=dict(runtime_env);test_env.pop('PYTHONPATH',None);test_env.pop('PIP_NO_INDEX',None)
            test_env.update({'PIP_INDEX_URL':'https://pypi.org/simple','PIP_FIND_LINKS':str(wheelhouse)+' '+str(tools),'PIP_CONSTRAINT':str(constraints),'PIP_BUILD_CONSTRAINT':str(constraints),'PIP_CONFIG_FILE':os.devnull,'PIP_USER':'0','PYTHONNOUSERSITE':'1','PYTHONDONTWRITEBYTECODE':'1','TOX_USER_CONFIG_FILE':os.devnull,'SAGE_DOCTEST_OPTIONS':'--verbose'})
            private=root/'private-test-state'/package
            for key,relative in {'APPDATA':'roaming','LOCALAPPDATA':'local','USERPROFILE':'home','JUPYTER_CONFIG_DIR':'jupyter-config','JUPYTER_DATA_DIR':'jupyter-data','JUPYTER_RUNTIME_DIR':'jupyter-runtime','IPYTHONDIR':'ipython','MPLCONFIGDIR':'matplotlib','XDG_CACHE_HOME':'xdg-cache','XDG_CONFIG_HOME':'xdg-config','XDG_DATA_HOME':'xdg-data','PIP_CACHE_DIR':'pip-cache','TEMP':'temp','TMP':'temp'}.items():
                directory=private/relative;directory.mkdir(parents=True,exist_ok=True);test_env[key]=str(directory)
            drive,tail=os.path.splitdrive(test_env['USERPROFILE']);test_env['HOMEDRIVE']=drive;test_env['HOMEPATH']=tail
            private_keys=('APPDATA','LOCALAPPDATA','USERPROFILE','HOMEDRIVE','HOMEPATH','JUPYTER_CONFIG_DIR','JUPYTER_DATA_DIR','JUPYTER_RUNTIME_DIR','IPYTHONDIR','MPLCONFIGDIR','XDG_CACHE_HOME','XDG_CONFIG_HOME','XDG_DATA_HOME','PIP_CACHE_DIR','PYTHONNOUSERSITE','PYTHONDONTWRITEBYTECODE','PIP_CONFIG_FILE','PIP_USER','PIP_INDEX_URL','PIP_FIND_LINKS','PIP_CONSTRAINT','PIP_BUILD_CONSTRAINT','SAGE_DOCTEST_OPTIONS','SAGE_LOCAL','PYTHONIOENCODING','PYTHONUTF8','TOX_USER_CONFIG_FILE')
            pass_override='testenv.pass_env+='+'\n'.join(private_keys)
            state_override='testenv.set_env+=DOT_SAGE={envdir}/.sage'
            work=root/'tox-work'/package
            common=[py,'-I','-B','-m','tox','--workdir',work,'--override',pass_override,'--override',state_override]
            setup_env=dict(test_env);setup_env['PATH']=build_env['PATH']
            listed=run(package+'-original-tox-list',[*common,'-l','-q'],setup_env,cwd)
            listed_text=Path(listed['stdout']['path']).read_text(encoding='utf-8')
            envs=[r['name'] for r in targets]
            if [re.sub(r'sagepython-.*nopypi-norequirements','py312-norequirements',line.strip()) for line in listed_text.splitlines() if line.strip()]!=envs:raise ValueError('Actual tox -l does not match all literal source environments')
            effective_path=root/(package+'-EFFECTIVE_TOX_CONFIG.json')
            effective=run(package+'-normal-effective-all-environments',[*common,'config','-e',','.join(envs),'--format','json','-k','env_name','extras','set_env','commands','commands_pre','commands_post'],test_env,cwd)
            effective_path.write_bytes(Path(effective['stdout']['path']).read_bytes())
            matrix=resolved_original_tox_matrix(body,package,listed_text,read_json(effective_path),cwd,work)
            save(root/(package+'-RESOLVED_ORIGINAL_MATRIX.json'),matrix);matrices[package]=matrix
            by_name={row['name']:row for row in matrix['environments']}
            for row in env_rows:
                row.update(by_name[row['name']]);baseline=Path(row['known_failures']);before.setdefault(baseline.name,None)
                row['original_baseline_before']={'path':str(baseline),'sha256':before[baseline.name],'expected_absent':before[baseline.name] is None}
            save(root/'TEST_RESULTS.json',[*tests,record])
            base=[*common,'-v','-v','-e',','.join(envs),'--installpkg',wheel]
            bootstrap_path=root/(package+'-BOOTSTRAP_TOX_REPORT.json')
            bootstrap=run(package+'-normal-all-environment-bootstrap',[*base,'--notest','--result-json',bootstrap_path],setup_env,cwd,timeout=1800,strict=False)
            record['normal_bootstrap_receipt']=bootstrap
            bootstrap_journal=select_original_tox_journal(read_json(bootstrap_path),body,envs,work)
            save(root/(package+'-BOOTSTRAP_JOURNAL_CLASSIFICATION.json'),bootstrap_journal['classification'])
            bootstrap_envs=bootstrap_journal['selected']
            failed=[];hard_failure=False
            pip_version=next(x.split('==',1)[1] for x in pins['third_party_build_pins'] if x.startswith('pip=='))
            pip_wheel=next(tools.glob('pip-'+pip_version+'-*.whl'))
            for row in env_rows:
                name=row['name'];label=package+'-'+name
                if not journal_success(bootstrap_envs[name]):
                    failed.append(name);row.update({'state':'dependency-bootstrap-failed','bootstrap_result':bootstrap_envs[name].get('result'),'accepted':False});continue
                try:
                    run(label+'-same-pip-version',[*common,'exec','-e',name,'--','python','-I','-B','-c','from importlib.metadata import version;value=version("pip");assert value=='+repr(pip_version)+';print("ORIGINAL_SEEDED_PIP_VERSION",value)'],test_env,cwd,timeout=600)
                    run(label+'-normal-pip-record',[*common,'exec','-e',name,'--','python','-I','-B','-m','pip','install','--no-index','--no-deps','--no-compile','--force-reinstall',pip_wheel],test_env,cwd,timeout=600)
                    arguments=['--package',package,'--wheel-manifests',manifests_path,'--provider-manifest',provider_path,'--machine',identity['native_machine'],'--requested-extras-json',json.dumps(row['requested_extras']),'--expected-known-failures',row['known_failures']]
                    for module in row['imports']:arguments.extend(['--import-module',module])
                    if package=='glpk':arguments.extend(['--original-import-only-contract-sha256',contract['source_sha256']])
                    elif row['kind']=='notest':arguments.extend(['--original-notest-contract-sha256',contract['source_sha256']])
                    pre_path=root/(label+'-PRE_PROVENANCE.json')
                    probe=[*common,'exec','-e',name,'--','python','-I','-B',here/'child_inventory.py',*arguments,'--output',pre_path]
                    run(label+'-effective-pre-provenance',probe,test_env,cwd,timeout=600);pre=read_json(pre_path)
                    if pre.get('passed') is not True:raise ValueError('Actual environment pre-provenance failed')
                    row.update({'pre_provenance_passed':True,'state':'pre-proven','pre_provenance':file_record(pre_path)})
                    post_targets.append({'row':row,'probe':probe,'pre':pre,'path':root/(label+'-POST_PROVENANCE.json'),'label':label})
                    run(label+'-pip-check-pre',[*common,'exec','-e',name,'--','python','-I','-B','-m','pip','check'],test_env,cwd,timeout=600)
                    if row['kind']=='mathematics':
                        bash_path=root/(label+'-BASH_PRE_PROVENANCE.json')
                        bash='set -e; cp=$1; shift; p=$(command -v python); r=$(command -v sage-runtests); export PROFILE_BASH_PYTHON="$("$cp" -w "$p")" PROFILE_BASH_SAGE_RUNTESTS="$("$cp" -w "$r")"; exec python -I -B "$@"'
                        run(label+'-original-bash-launcher',[*common,'exec','-e',name,'--','bash','-c',bash,'original-bash-resolution',cygpath,here/'child_inventory.py','--require-bash-resolution',*arguments,'--output',bash_path],test_env,cwd,timeout=600)
                        bash_proof=read_json(bash_path)
                        if bash_proof.get('original_bash_resolution',{}).get('passed') is not True or bash_proof['installed_distribution_source_lock_sha256']!=pre['installed_distribution_source_lock_sha256']:raise ValueError('Original Bash/native launcher identity differs')
                        row['original_bash_native_launcher_proven']=True
                        selected_path=root/(label+'-SELECTED_UNITS.json');contract_path=root/(label+'-ORIGINAL_CONTRACT.json');save(contract_path,contract)
                        run(label+'-normal-unit-selection',[*common,'exec','-e',name,'--','python','-I','-B',here/'doctest_units.py','--tox-ini',cwd/'tox.ini','--contract',contract_path,'--package',package,'--output',selected_path],test_env,cwd,timeout=600)
                        selected=read_json(selected_path)
                        if Path(selected['effective_known_failures']).resolve()!=Path(row['known_failures']).resolve() or Path(selected['stats_path']).resolve()!=Path(row['dot_sage'])/'timings2.json':raise ValueError('Selected units use another environment baseline/statistics')
                        row['selected_units']=file_record(selected_path);row['_selected']=selected
                except Exception as error:
                    hard_failure=True;row.update({'state':'pre-provenance-failed','pre_provenance_passed':False,'accepted':False,'error':str(error),'error_type':type(error).__name__})
            dependency_diagnostic=bool(failed) and allowed_dependency_diagnostic(package,bootstrap,failed)
            record['bootstrap_failed_environments']=failed;record['dependency_failure_diagnostic']=dependency_diagnostic
            if hard_failure or (failed and not dependency_diagnostic):raise ValueError('Original job blocked by failed provenance or an undeclared bootstrap failure')
            if not failed and not clean_receipt(bootstrap):raise ValueError('Bootstrap process did not close cleanly')
            report_path=root/(package+'-ACTUAL_TOX_REPORT.json')
            literal=run(package+'-complete-original-tox',[*base,'--result-json',report_path],test_env,cwd,timeout=10800,strict=False)
            # Store actual RC before all subsequent JSON/source/stat readback.
            record.update({'state':'executed','exit':literal['exit'],'actual_tox_receipt':literal})
            save(root/(package+'-ACTUAL_EXECUTION_RECEIPT.json'),{'package':package,'exit':literal['exit'],'receipt':literal,'unverified_environments':failed})
            actual_journal=select_original_tox_journal(read_json(report_path),body,envs,work)
            save(root/(package+'-ACTUAL_JOURNAL_CLASSIFICATION.json'),actual_journal['classification'])
            actual_envs=actual_journal['selected']
            actual_results=[]
            for row in env_rows:
                actual=actual_envs[row['name']];result=actual.get('result',{})
                row.update({'state':'executed','exit':result.get('exit_code'),'actual_tox_environment_result':result})
                actual_results.append({'name':row['name'],'kind':row['kind'],'actual_result':result,'exit':result.get('exit_code')})
            save(root/(package+'-ACTUAL_ENVIRONMENT_RESULTS.json'),{'package':package,'job_exit':literal['exit'],'actual_environments':actual_results,'all_environment_return_codes_retained_before_proof_readback':True})
            for row in env_rows:
                try:
                    name=row['name'];actual=actual_envs[name];result=actual.get('result',{});row.update({'state':'executed','exit':result.get('exit_code'),'actual_tox_environment_result':result})
                    command_text=journal_text(actual);row['actual_test_command_count']=len(actual.get('test',[]))
                    row['source_effective_command_count']=sum(len(by_name[name].get(key,[])) for key in ('commands_pre','commands','commands_post'))
                    row['summary_seen']='Total time for all tests:' in command_text if row['kind']=='mathematics' else journal_success(actual)
                    row['reported_tests']=0;row['units_matched']=False
                    if row['kind']=='mathematics' and row.get('_selected'):
                        selected=row['_selected'];stats=Path(selected['stats_path'])
                        if stats.is_file():
                            copied=stats_dir/(package+'-'+name+'.timings2.json');shutil.copyfile(stats,copied)
                            units=compare_units(selected['units'],read_json(copied),selected['baseline']);save(root/(package+'-'+name+'-ACTUAL_UNIT_READBACK.json'),units)
                            row.update({'units_matched':units['passed'],'reported_tests':units['reported_tests'],'preexisting_known_failure_units':units['known_failure_count'],'actual_stats':file_record(copied)})
                    elif row['kind']!='mathematics':row['units_matched']=journal_success(actual);row['mathematical_acceptance_claimed']=False
                    # Verbose successful doctests legitimately exercise signal_name(SIGSEGV).
                    # Only authoritative unindented failed-unit summary headers classify
                    # a framework/native termination; actual return code/statistics remain gates.
                    terminal=terminal_failure_headers(command_text)
                    row['framework_or_native_terminal_headers']=terminal
                    row['framework_or_native_failure_seen']=bool(terminal)
                    row['actual_original_commands_complete']=journal_success(actual) and row['actual_test_command_count']==row['source_effective_command_count']
                    row['accepted']=bool(row.get('pre_provenance_passed') and journal_success(actual) and row['summary_seen'] and row['units_matched'] and row['actual_original_commands_complete'] and not row['framework_or_native_failure_seen'])
                    if name in failed:row.update({'accepted':False,'pre_provenance_passed':False,'mathematical_acceptance_claimed':False,'unverified_after_normal_dependency_failure':True})
                except Exception as proof_error:
                    row.update({"accepted":False,"units_matched":False,"proof_readback_error":str(proof_error),"proof_readback_error_type":type(proof_error).__name__})
        except Exception as error:record.update({'error':str(error),'error_type':type(error).__name__,'provenance_passed':False,'units_matched':False})
        finally:
            for target in post_targets:
                row=target['row'];name=row['name']
                try:
                    command=list(target['probe']);command[-1]=target['path'];run(target['label']+'-effective-post-provenance',command,test_env,cwd,timeout=600)
                    post=read_json(target['path']);pre=target['pre']
                    if post.get('passed') is not True or post['installed_distribution_source_lock_sha256']!=pre['installed_distribution_source_lock_sha256'] or post['public_types_expected_sha256']!=pre['public_types_expected_sha256']:raise ValueError('Actual posttest source/provider closure differs')
                    run(target['label']+'-pip-check-post',[*common,'exec','-e',name,'--','python','-I','-B','-m','pip','check'],test_env,cwd,timeout=600)
                    row['post_provenance_passed']=True;row['post_provenance']=file_record(target['path'])
                except Exception as error:row.update({'post_provenance_passed':False,'accepted':False,'post_error':str(error),'post_error_type':type(error).__name__})
            for row in env_rows:
                row.pop('_selected',None)
                if not row.get('post_provenance_passed'):row['accepted']=False
            if before is not None:
                try:record['fixtures_closing']=fixture_closing(cwd,before,contract['source_sha256'])
                except Exception as error:record['fixtures_closing']={'passed':False,'error':str(error)}
            else:record['fixtures_closing']={'passed':False,'error':'Original fixture inventory unavailable'}
            record['provenance_passed']=all(row.get('pre_provenance_passed') is True and row.get('post_provenance_passed') is True for row in env_rows)
            record['units_matched']=all(row.get('accepted') is True for row in env_rows)
            mathematical=[row for row in env_rows if row['kind']=='mathematics']
            record['reported_tests']=sum(row.get('reported_tests',0) for row in mathematical)
            record['summary_seen']=all(row.get('summary_seen') is True for row in mathematical) if mathematical else all(row.get('accepted') is True for row in env_rows)
            record['all_original_environments_have_actual_results']=all(row.get('state')=='executed' and type(row.get('exit')) is int for row in env_rows)
            record['complete_original_environment_scope']=matrix is not None and [row['name'] for row in env_rows]==record['original_environment_names']
            record['both_original_import_envs_provenance']=package=='glpk' and len(env_rows)==2 and record['provenance_passed']
            record['accepted']=bool(literal and clean_receipt(literal) and not record.get('error') and record['provenance_passed'] and record['units_matched'] and record['fixtures_closing']['passed'] and record['all_original_environments_have_actual_results'])
            record['skip_count']=None;record['skip_count_availability']='Original per-environment verbose raw output retained; no fabricated zero count'
            tests.append(record);save(root/'TEST_RESULTS.json',tests)
    return {'tests':tests,'resolved_matrices':matrices,'expected_environment_count':32,'expected_mathematical_environment_count':17}
