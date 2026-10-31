"""Normal setuptools package discovery and source/installed ownership for Sage_setup."""
import argparse
import base64
import csv
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import sys
import zipfile

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from profile_contract import sha,wheel_inventory


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--source',type=Path,required=True);ap.add_argument('--wheel',type=Path,required=True);ap.add_argument('--arch',choices=('x64','arm64'),required=True);ap.add_argument('--installed',action='store_true');ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    source=args.source.resolve();wheel=args.wheel.resolve()
    from setuptools.config.pyprojecttoml import read_configuration
    config=read_configuration(str(source/'pyproject.toml'),expand=True)
    packages=set(config['tool']['setuptools']['packages'])
    all_sources={str(path.relative_to(source)).replace('\\','/'):sha(path) for path in (source/'sage_setup').rglob('*.py')}
    owned={name:digest for name,digest in all_sources.items() if str(Path(name).parent).replace('\\','.') in packages}
    unselected=[name for name in all_sources if name not in owned]
    if len(owned)!=34 or len(unselected)!=4 or any(not name.startswith('sage_setup/autogen/flint/') for name in unselected):raise ValueError('Unchanged normal original Sage_setup ownership differs')
    inventory=wheel_inventory(wheel,args.arch,require_native=False)
    with zipfile.ZipFile(wheel) as z:
        actual={name for name in z.namelist() if name.startswith('sage_setup/') and name.endswith('.py')}
        if actual!=set(owned):raise ValueError('Normal Sage_setup wheel omits/adds declared Python modules')
        for name,digest in owned.items():
            if hashlib.sha256(z.read(name)).hexdigest()!=digest:raise ValueError('Source/new Sage_setup wheel mismatch '+name)
        expected='a2c98530492f39d9097a6f24178f118f90ba73049c602de141f557677183b37b'
        if owned.get('sage_setup/command/sage_build_ext_minimal.py')!=expected:raise ValueError('Reviewed MSVC UTF8 source helper differs')
        installed=None
        if args.installed:
            prefix=Path(sys.prefix).resolve();site=prefix/'Lib/site-packages'
            import sage_setup.command.sage_build_ext_minimal as owner
            path=Path(owner.__file__).resolve()
            if not path.is_relative_to(site) or sha(path)!=expected:raise ValueError('Installed Sage_setup does not consume its normal reviewed wheel')
            dist=importlib.metadata.distribution('passagemath-setup');records={}
            for name,hashvalue,size in csv.reader(io.StringIO(dist.read_text('RECORD'))):
                file=Path(dist.locate_file(name)).resolve()
                if not file.is_relative_to(prefix) or not file.is_file():raise ValueError('Invalid installed Sage_setup RECORD')
                if not hashvalue:
                    if not name.endswith('.dist-info/RECORD'):raise ValueError('Unhashed installed Sage_setup file')
                    continue
                data=file.read_bytes();algorithm,value=hashvalue.split('=',1)
                if algorithm!='sha256' or base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()!=value or len(data)!=int(size):raise ValueError('Installed Sage_setup RECORD digest differs')
                records[str(file).casefold()]=hashlib.sha256(data).hexdigest()
            for name,digest in owned.items():
                file=(site/name).resolve()
                if not file.is_file() or sha(file)!=digest or records.get(str(file).casefold())!=digest:raise ValueError('Installed complete Sage_setup source missing/different '+name)
            installed={'prefix':str(prefix),'actual_helper':str(path),'helper_sha256':sha(path),'complete_installed_owned_modules':len(owned),'normal_RECORD_verified':True,'private_source_overlay':False}
    result={'passed':True,'source':str(source),'wheel':inventory,'normal_setuptools_packages':sorted(packages),'normal_declared_owned_Python_modules':owned,'unselected_source_modules_under_unchanged_config':unselected,'installed':installed,'source_helper_sha256':expected}
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print('NORMAL_SETUP_SOURCE_PROOF_JSON '+json.dumps(result),flush=True)
    return 0


if __name__=='__main__':raise SystemExit(main())
