from __future__ import annotations

import threading
import time

import pytest

from scopescan import jobs, service


def test_fast_completions_release_all_references(monkeypatch):
    monkeypatch.setattr(jobs.service, "execute", lambda scan_id, cancel: None)
    queue = jobs.ScanQueue(2)
    try:
        for scan_id in range(100):
            queue.submit(scan_id)
        queue.shutdown(wait=True)
        assert queue.active_ids() == []
        assert queue._futures == {}
        assert queue._cancels == {}
    finally:
        queue.shutdown(wait=True)


def test_deletion_waits_for_worker_final_write(monkeypatch):
    started, release = threading.Event(), threading.Event()
    calls = []

    def execute(scan_id, cancel):
        started.set()
        assert release.wait(5)
        assert cancel.is_set()
        calls.append("worker final write")

    monkeypatch.setattr(jobs.service, "execute", execute)
    monkeypatch.setattr(jobs.db, "delete_scan", lambda scan_id: calls.append("delete"))
    queue = jobs.ScanQueue(1)
    try:
        queue.submit(1)
        assert started.wait(5)
        assert queue.request_delete(1)
        assert calls == []
        with pytest.raises(ValueError, match="borrado"):
            queue.submit(1)
        release.set()
        queue.shutdown(wait=True)
        assert calls == ["worker final write", "delete"]
        assert queue._deleting == set()
    finally:
        release.set()
        queue.shutdown(wait=True)


def test_enrichments_share_worker_budget_and_release(monkeypatch):
    started, release = threading.Event(), threading.Event()
    second_started = threading.Event()

    def first():
        started.set()
        release.wait(5)

    queue = jobs.ScanQueue(1)
    try:
        assert queue.submit_enrichment(1, "nvd", first)
        assert started.wait(5)
        assert not queue.submit_enrichment(1, "nvd", first)
        assert queue.submit_enrichment(2, "nvd", second_started.set)
        time.sleep(.05)
        assert not second_started.is_set()
        with pytest.raises(ValueError, match="enriquecimientos"):
            queue.request_delete(1)
        release.set()
        queue.wait_for(2)
        queue.shutdown(wait=True)
        assert second_started.is_set()
        assert queue._enrichments == {}
    finally:
        release.set()
        queue.shutdown(wait=True)


def test_queued_cancellation_is_seen_before_execution(monkeypatch):
    started, release = threading.Event(), threading.Event()
    cancellations = []

    def execute(scan_id, cancel):
        if scan_id == 1:
            started.set()
            assert release.wait(5)
        else:
            cancellations.append(cancel.is_set())

    monkeypatch.setattr(jobs.service, "execute", execute)
    queue = jobs.ScanQueue(1)
    try:
        queue.submit(1)
        assert started.wait(5)
        queue.submit(2)
        assert queue.cancel(2)
        release.set()
        queue.wait_for(2)
        assert cancellations == [True]
    finally:
        release.set()
        queue.shutdown(wait=True)


def test_service_pre_cancelled_scan_never_builds_command(monkeypatch):
    cancel = threading.Event()
    cancel.set()
    statuses = []
    monkeypatch.setattr(service.db, "get_scan", lambda _id: {"id": 1})
    monkeypatch.setattr(service.db, "set_status", lambda _id, status, **kw: statuses.append(status))
    monkeypatch.setattr(service.nmap_runner, "build_argv",
                        lambda **kw: pytest.fail("Cancelled scan must not build a command"))
    service.execute(1, cancel=cancel)
    assert statuses == ["cancelled"]


def test_scan_and_enrichment_share_worker_limit(monkeypatch):
    started, release, enrichment_started = threading.Event(), threading.Event(), threading.Event()

    def scan(scan_id, cancel):
        started.set()
        assert release.wait(5)

    monkeypatch.setattr(jobs.service, "execute", scan)
    queue = jobs.ScanQueue(1)
    try:
        queue.submit(1)
        assert started.wait(5)
        assert queue.submit_enrichment(2, "nvd", enrichment_started.set)
        assert not enrichment_started.wait(.05)
        release.set()
        queue.wait_for(2)
        assert enrichment_started.is_set()
    finally:
        release.set()
        queue.shutdown(wait=True)


def test_submission_after_shutdown_does_not_leak_events():
    queue = jobs.ScanQueue(1)
    queue.shutdown(wait=True)
    with pytest.raises(RuntimeError):
        queue.submit(1)
    assert not queue._cancels
    assert not queue._futures
