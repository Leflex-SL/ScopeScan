import json
import sys
import threading
from datetime import UTC, datetime

import pytest

from scopescan.grype_adapter import GrypeAdapter
from scopescan.syft_adapter import SyftAdapter, source


def fake(tmp_path, engine, *, mode="normal"):
    program = tmp_path / f"fake-{engine}.py"
    program.write_text('''import json,os,sys,time
args=sys.argv[1:]
engine,mode=''' + repr((engine, mode)) + '''
assert 'HTTP_PROXY' not in os.environ and 'SECRET_SENTINEL' not in os.environ
assert not os.environ.get('PATH')
assert os.environ['HOME'] != os.environ.get('SENTINEL_HOME','bad')
if args[0]=='version':
 print(json.dumps({'version':'1.54.0' if engine=='syft' else '0.119.0'}));sys.exit(0)
if mode=='silent': time.sleep(30)
if mode=='oversized': print('x'*8000010);sys.exit(0)
if engine=='syft':
 assert args[0]=='scan' and args[-2:]==['-o','cyclonedx-json']
 assert os.environ['SYFT_CHECK_FOR_APP_UPDATE']=='false'
 print(json.dumps({'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'components':[{'type':'library','name':'openssl','bom-ref':'one','version':'3.0','purl':'pkg:deb/debian/openssl@3.0?arch=amd64'}]}))
else:
 assert args[0].startswith('sbom:') and args[-2:]==['-o','json']
 assert os.environ['GRYPE_DB_AUTO_UPDATE']=='false'
 assert os.environ['GRYPE_CHECK_FOR_APP_UPDATE']=='false'
 with open(args[0][5:],encoding='utf-8') as stream: json.load(stream)
 print(json.dumps({'matches':[],'descriptor':{'name':'grype','version':'0.119.0','db':{'built':''' + repr(datetime.now(UTC).isoformat()) + ''','schemaVersion':'6','checksum':'xxh64:123','valid':True,'path':os.environ['GRYPE_DB_CACHE_DIR']+'/vulnerability.db'}}}))
''', encoding="utf-8")
    return (sys.executable, str(program))


def sbom():
    return json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}).encode()


def test_actual_fake_python_syft_uses_explicit_source_private_environment(tmp_path, monkeypatch):
    archive = tmp_path / "image.tar"
    archive.write_bytes(b"fixture")
    monkeypatch.setenv("SCOPESCAN_SOFTWARE_ROOTS", str(tmp_path))
    monkeypatch.setenv("HTTP_PROXY", "http://alice:secret@proxy.example")
    monkeypatch.setenv("SECRET_SENTINEL", "should-not-be-in-child")
    value = SyftAdapter(fake(tmp_path, "syft")).execute("oci-archive:" + str(archive), timeout=30)
    assert value["components"][0]["name"] == "openssl" and value["engine_version"] == "1.54.0"


def test_actual_fake_python_grype_no_updates_and_managed_sbom(tmp_path, monkeypatch):
    (tmp_path / "vulnerability.db").write_bytes(b"fixture database")
    monkeypatch.setenv("SCOPESCAN_GRYPE_DB_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("GRYPE_DB_AUTO_UPDATE", "true")
    value = GrypeAdapter(fake(tmp_path, "grype")).execute(sbom(), timeout=30)
    assert value["status"] == "complete" and value["database"]["schemaVersion"] == "6" and len(value["database_sha256"]) == 64


def test_silent_process_cancellation_is_shared_runner(tmp_path, monkeypatch):
    monkeypatch.setenv("SCOPESCAN_GRYPE_DB_CACHE_DIR", str(tmp_path))
    cancel = threading.Event()
    timer = threading.Timer(3, cancel.set)
    timer.start()
    try:
        with pytest.raises(ValueError, match="cancelled"):
            GrypeAdapter(fake(tmp_path, "grype", mode="silent")).execute(sbom(), timeout=30, cancel=cancel)
    finally:
        timer.cancel()


def test_oversized_process_output_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("SCOPESCAN_GRYPE_DB_CACHE_DIR", str(tmp_path))
    with pytest.raises(ValueError, match="budget"):
        GrypeAdapter(fake(tmp_path, "grype", mode="oversized")).execute(sbom(), timeout=30)


def test_sources_no_implicit_daemon_registry_or_worker_arbitrary_files(tmp_path, monkeypatch):
    monkeypatch.delenv("SCOPESCAN_SOFTWARE_ROOTS", raising=False)
    for value in ("nginx:latest", "docker:nginx", "registry:example.org/image", "dir:" + str(tmp_path), "registry:https://user:password@example.org/image"):
        with pytest.raises(ValueError):
            source(value)
    assert source("registry:example.org/image@sha256:" + "a" * 64, allow_registry=True).startswith("registry:")
    monkeypatch.setenv("SCOPESCAN_SOFTWARE_ROOTS", str(tmp_path / "allowed"))
    with pytest.raises(ValueError, match="outside"):
        source("dir:" + str(tmp_path))
