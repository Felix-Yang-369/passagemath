"""Lossless text-evidence frames for normal GitHub job logs, without uploads."""
from pathlib import Path
import base64
import gzip
import hashlib
import io
import json
import os
import tarfile

def sha(data):return hashlib.sha256(data).hexdigest()
def assert_no_sensitive_values(data,label):
    secrets=[value.encode() for key,value in os.environ.items() if len(value)>=12 and any(word in key.upper() for word in ('TOKEN','SECRET','PASSWORD'))]
    if any(secret in data for secret in secrets):raise ValueError('Sensitive runtime value detected; refusing to print '+label)
def bundle_bytes(files):
    manifest=[{'path':name,'bytes':len(data),'sha256':sha(data)} for name,data in sorted(files.items())]
    metadata=(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n').encode()
    stream=io.BytesIO()
    with gzip.GzipFile(fileobj=stream,mode='wb',mtime=0) as compressed:
        with tarfile.open(fileobj=compressed,mode='w|') as archive:
            for name,data in [('EVIDENCE_MANIFEST.json',metadata),*sorted(files.items())]:
                relative=Path(name)
                if relative.is_absolute() or '..' in relative.parts or '\\' in name or ':' in name:raise ValueError('Unsafe evidence member')
                info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o644;info.mtime=0;archive.addfile(info,io.BytesIO(data))
    return stream.getvalue(),manifest,sha(metadata)

def emit(root):
    root=Path(root)
    paths=set(root.glob('*.json'))|set(root.glob('logs/*/*.bin'))|set(root.glob('logs/*/receipt.json'))|set(root.glob('evidence-stats/*.json'))
    # Explicit OS-attestation evidence contains fixed PowerShell source, native
    # signature receipts and raw text stdout/stderr, including failed probes.
    for pattern in ('os-attestation/**/*.json','os-attestation/**/*.bin','os-attestation/**/*.ps1'):
        paths.update(root.glob(pattern))
    files={str(p.relative_to(root)).replace('\\','/'):p.read_bytes() for p in paths if p.is_file()}
    if not files:raise ValueError('No text evidence to preserve')
    # Only explicit text-evidence locations are selected. Wheels, SDKs, native
    # binaries, source trees and credentials are never included in this bundle.
    for name,data in files.items():assert_no_sensitive_values(data,name)
    body,manifest,manifest_sha=bundle_bytes(files)
    path=root/'TEXT_EVIDENCE.tar.gz';path.write_bytes(body)
    encoded=base64.b64encode(body).decode('ascii');chunks=[encoded[i:i+23040] for i in range(0,len(encoded),23040)]
    header={'schema':'passagemath-lossless-text-evidence-v1','encoding':'base64(gzip(tar))','compressed_bytes':len(body),'compressed_sha256':sha(body),'manifest_sha256':manifest_sha,'file_count':len(manifest),'chunk_count':len(chunks),'max_data_chars_per_frame':23040,'includes_compiled_binaries':False,'artifact_uploads':0}
    print('EVIDENCE_BUNDLE_START_JSON '+json.dumps(header),flush=True)
    for index,chunk in enumerate(chunks,1):print('EVIDENCE_CHUNK_JSON '+json.dumps({'i':index,'n':len(chunks),'data':chunk},separators=(',',':')),flush=True)
    print('EVIDENCE_BUNDLE_END_JSON '+json.dumps(header),flush=True)
    return header
