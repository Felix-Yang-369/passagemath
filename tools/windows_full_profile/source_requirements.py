"""Read normal owner build/test requirements with actual marker evaluation."""
import argparse
from email import message_from_bytes
import json
from pathlib import Path
import tomllib
from packaging.requirements import Requirement

OWNERS=('objects','categories','graphs','rankwidth','cddlib','glpk','highs','planarity','homfly','cliquer','combinat','modules','gsl','plot','cmr','m4ri_m4rie')
def selected(requirements,extra):
    result=[]
    for raw in requirements:
        requirement=Requirement(raw)
        if requirement.marker and not requirement.marker.evaluate({'extra':extra}):continue
        name=requirement.name.lower().replace('_','-')
        if not name.startswith('passagemath-'):continue
        owner=name[len('passagemath-'):].replace('-','_')
        if owner in OWNERS:result.append(owner)
    return sorted(set(result))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--sources',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    source_paths=json.loads(args.sources.read_text());rows={}
    for owner,path in source_paths.items():
        root=Path(path);project=tomllib.loads((root/'pyproject.toml').read_text());build=project.get('build-system',{}).get('requires',[])
        metadata=message_from_bytes((root/'PKG-INFO').read_bytes());runtime=metadata.get_all('Requires-Dist',[])
        rows[owner]={'build_raw':build,'runtime_raw':runtime,'build_owner_dependencies':[d for d in selected(build,'') if d!=owner],'test_owner_dependencies':[d for d in selected(runtime,'test') if d!=owner]}
    args.output.write_text(json.dumps(rows,indent=2)+'\n',encoding='utf-8');print('NORMAL_REQUIREMENTS_JSON '+json.dumps(rows),flush=True)
    return 0

if __name__=='__main__':raise SystemExit(main())
