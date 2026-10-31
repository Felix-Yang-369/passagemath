"""Select units through Sage's normal controller, then compare actual stats."""
import argparse
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sys

def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate JSON/statistics key '+key)
        result[key]=value
    return result

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--tox-ini',type=Path,required=True);ap.add_argument('--contract',type=Path,required=True);ap.add_argument('--package',required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    from sage.doctest.control import DocTestController,DocTestDefaults
    from sage.env import SAGE_LIB,DOT_SAGE
    body=args.tox_ini.read_text(encoding='utf-8');contract=json.loads(args.contract.read_text())
    if hashlib.sha256(args.tox_ini.read_bytes()).hexdigest()!=contract['source_sha256'] or contract['test_kind']!='mathematics':raise ValueError('Original mathematical contract hash/kind mismatch')
    environment=contract['environment']
    baseline_path=Path(os.environ['KNOWN_TEST_FAILURES'])
    kwargs={'force_lib':contract['force_lib'],'initial':contract['initial'],'verbose':True,'environment':environment,'probe':contract['probe_all'],'baseline_stats_path':str(baseline_path)}
    if contract['optional'] is not None:kwargs['optional']=contract['optional']
    targets=contract['targets'];kwargs['installed']=contract['installed']
    original_cwd=Path.cwd();os.chdir(SAGE_LIB)
    files=[]
    for target in targets:
        if target=='--installed':continue
        found=glob.glob(target);files.extend(found if found else [target])
    options=DocTestDefaults(runtest_default=True,**kwargs)
    controller=DocTestController(options,files)
    controller.add_files();controller.expand_files_into_sources();controller.filter_sources();controller.sort_sources()
    units=[]
    for source in controller.sources:
        path=Path(source.path).resolve()
        if not path.is_relative_to(Path(SAGE_LIB).resolve()):raise ValueError('Selected unit outside actual installed Sage library')
        units.append({'basename':source.basename,'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    if not units or len({r['basename'] for r in units})!=len(units):raise ValueError('Empty/duplicate selected unit inventory')
    stats=Path(DOT_SAGE)/'timings2.json'
    if stats.exists():raise ValueError('Unexpected preexisting actual suite stats file')
    baseline=json.loads(baseline_path.read_text(),object_pairs_hook=unique_object) if baseline_path.exists() else {}
    result={'package':args.package,'environment':environment,'original_tox_ini':str(args.tox_ini),'original_tox_sha256':hashlib.sha256(args.tox_ini.read_bytes()).hexdigest(),'effective_home':os.environ.get('HOME'),'effective_dot_sage':str(DOT_SAGE),'effective_SAGE_DOC':os.environ.get('SAGE_DOC'),'effective_known_failures':str(baseline_path),'baseline_exists':baseline_path.exists(),'baseline':baseline,'stats_path':str(stats),'selection_api':'DocTestDefaults(runtest_default=True) + DocTestController.add_files/expand_files_into_sources/filter_sources/sort_sources','units':units,'selected_unit_count':len(units)}
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print('SELECTED_UNITS_JSON '+json.dumps(result),flush=True)
    os.chdir(original_cwd)
    return 0

if __name__=='__main__':raise SystemExit(main())
