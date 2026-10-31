"""Normal sage_setup.find discovery after normal owner generation has run."""
import argparse
import json
from pathlib import Path

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--package',required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--source-ledger',type=Path,required=True);args=ap.parse_args()
    from sage_setup.find import find_python_sources
    distribution='sagemath-'+args.package.replace('_','-')
    packages,modules,extensions=find_python_sources('.',('sage','passagemath_'+args.package),distributions=[distribution])
    names=[extension.name for extension in extensions]
    if len(names)!=len(set(names)) or not names:raise ValueError('Empty/duplicate normal source discovery')
    foreign=[];owned=[];original=json.loads(args.source_ledger.read_text())['owned']
    for path in Path('sage').rglob('*.pyx'):
        if str(path).replace('\\','/') not in original:continue
        first=path.read_text(encoding='utf-8').splitlines()[0]
        row={'member':str(path).replace('\\','/'),'distribution_marker':first}
        (owned if first=='# sage_setup: distribution = '+distribution else foreign).append(row)
    generated=[]
    if args.package=='modules':
        generated=['sage.ext.interpreters.wrapper_'+name for name in ('cc','cdf','rdf','rr')]
        expected_foreign={'sage/modules/numpy_util.pyx','sage/matrix/matrix_modn_dense_double.pyx','sage/matrix/matrix_modn_dense_float.pyx'}
        if {r['member'] for r in foreign}!=expected_foreign:raise ValueError('Modules foreign source ownership differs')
        if len(names)!=105 or not set(generated).issubset(names):raise ValueError('Normal complete modules discovery must contain 105 extensions including four generated interpreters')
    result={'distribution':distribution,'packages':packages,'python_modules':modules,'cython_extensions':names,'extension_source_files':{extension.name:extension.sources for extension in extensions},'owned_pyx':owned,'foreign_pyx':foreign,'normal_generated_interpreters':generated,'official_source_discovery':True}
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print('NORMAL_OWNER_DISCOVERY_JSON '+json.dumps(result),flush=True)
    return 0

if __name__=='__main__':raise SystemExit(main())
