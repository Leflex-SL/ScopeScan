"""Cola de escaneos en segundo plano.

El panel web no puede bloquearse media hora esperando a nmap, asi que los
escaneos corren en hilos. Son procesos externos: el trabajo real lo hace nmap,
el hilo solo espera, con lo que el GIL no estorba.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor

from . import db, service
from .config import MAX_CONCURRENT_SCANS

log = logging.getLogger("scopescan.jobs")


class ScanQueue:
    """Ejecuta escaneos con un limite de concurrencia y permite cancelarlos."""

    def __init__(self, max_workers: int = MAX_CONCURRENT_SCANS) -> None:
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="scopescan")
        self._cancels: dict[int, threading.Event] = {}
        self._futures: dict[int, Future] = {}
        self._enrichments: dict[tuple[int, str], Future] = {}
        self._deleting: set[int] = set()
        self._lock = threading.RLock()

    def submit(self, scan_id: int) -> None:
        cancel = threading.Event()
        with self._lock:
            if scan_id in self._deleting:
                raise ValueError("Escaneo pendiente de borrado")
            if scan_id in self._futures and not self._futures[scan_id].done():
                return  # ya esta en cola o corriendo
            future = self._pool.submit(self._run, scan_id, cancel)
            self._cancels[scan_id] = cancel
            self._futures[scan_id] = future
            future.add_done_callback(lambda done: self._completed(scan_id, done))

    def _completed(self, scan_id: int, future: Future) -> None:
        with self._lock:
            if self._futures.get(scan_id) is not future:
                return
            self._futures.pop(scan_id, None)
            self._cancels.pop(scan_id, None)
            if future.cancelled() and scan_id not in self._deleting:
                db.set_status(scan_id, "cancelled", error="Cancelado antes de empezar")
            if scan_id in self._deleting:
                db.delete_scan(scan_id)
                self._deleting.discard(scan_id)

    def _run(self, scan_id: int, cancel: threading.Event) -> None:
        try:
            service.execute(scan_id, cancel=cancel)
        except Exception as exc:  # el hilo no debe morir en silencio
            log.exception("Escaneo %s fallido", scan_id)
            db.set_status(scan_id, "failed", error=f"Error interno: {exc}")

    def submit_enrichment(
        self, scan_id: int, kind: str, func: Callable, *args, **kwargs
    ) -> bool:
        """Use the same worker budget for scans and enrichment operations."""
        key = (scan_id, kind)
        with self._lock:
            if scan_id in self._deleting or key in self._enrichments:
                return False
            future = self._pool.submit(func, *args, **kwargs)
            self._enrichments[key] = future
            future.add_done_callback(lambda done: self._enrichment_completed(key, done))
            return True

    def _enrichment_completed(self, key: tuple[int, str], future: Future) -> None:
        with self._lock:
            if self._enrichments.get(key) is future:
                if db.get_scan(key[0]) is not None:
                    if future.cancelled():
                        db.set_enrichment_status(*key, "cancelled", "Cancelado antes de empezar")
                    elif future.exception() is not None:
                        db.set_enrichment_status(*key, "failed", str(future.exception()))
                self._enrichments.pop(key, None)
        if not future.cancelled() and future.exception() is not None:
            log.error("Enriquecimiento %s fallido: %s", key, future.exception())

    def is_enrichment_active(self, scan_id: int) -> bool:
        with self._lock:
            return any(key[0] == scan_id for key in self._enrichments)

    def wait_for(self, scan_id: int, timeout: float = 5) -> None:
        with self._lock:
            futures = [future for key, future in self._enrichments.items() if key[0] == scan_id]
            if scan_id in self._futures:
                futures.append(self._futures[scan_id])
        for future in futures:
            future.result(timeout=timeout)

    def request_delete(self, scan_id: int) -> bool:
        """Delete after the active worker finishes; reject active enrichments."""
        with self._lock:
            if self.is_enrichment_active(scan_id):
                raise ValueError("Hay enriquecimientos activos; espera antes de borrar")
            self._deleting.add(scan_id)
            future = self._futures.get(scan_id)
            if future is not None:
                try:
                    db.request_scan_deletion(scan_id, defer=True)
                except ValueError:
                    self._deleting.discard(scan_id)
                    raise
                self._cancels[scan_id].set()
                # Do not cancel the future: status updates must finish before deletion.
                return True
            try:
                db.delete_scan(scan_id)
                return False
            finally:
                self._deleting.discard(scan_id)

    def cancel(self, scan_id: int) -> bool:
        """Pide la cancelacion. True si el escaneo estaba vivo."""
        with self._lock:
            event = self._cancels.get(scan_id)
            if event is not None:
                event.set()
                return True
            return False

    def is_active(self, scan_id: int) -> bool:
        with self._lock:
            return scan_id in self._cancels

    def active_ids(self) -> list[int]:
        with self._lock:
            return sorted(self._cancels)

    def shutdown(self, wait: bool = False) -> None:
        with self._lock:
            events = list(self._cancels.values())
        for event in events:
            event.set()
        self._pool.shutdown(wait=wait, cancel_futures=True)


def enqueue_enrichment(scan_id, kind, options):
    from .durable_jobs import enqueue
    from .operation_grants import ACTIVE_KINDS, capture
    with db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        scan = conn.execute("SELECT status,deletion_pending FROM scans WHERE id=?", (scan_id,)).fetchone()
        allowed_statuses = {"done"} if kind in ACTIVE_KINDS else {"done","failed","cancelled"}
        if scan is None or scan["status"] not in allowed_statuses or scan["deletion_pending"]:
            raise ValueError("Scan unavailable for enrichment")
        if conn.execute("SELECT 1 FROM durable_jobs WHERE scan_id=? AND kind='enrichment' AND json_extract(payload,'$.kind')=? AND status IN ('queued','running')", (scan_id, kind)).fetchone():
            return None
        grant = capture(conn, scan_id, kind, options)
        payload = {"scan_id":scan_id,"kind":kind,"options":options}
        if grant is not None:
            payload["grant"] = grant
        job_id = enqueue("enrichment", payload, scan_id=scan_id,
                         retry_safe=kind != "metasploit-exploit", conn=conn)
        conn.execute("INSERT INTO enrichment_jobs(scan_id,kind,status,error,updated_at) VALUES (?,?,'queued','',?) ON CONFLICT(scan_id,kind) DO UPDATE SET status='queued',error='',updated_at=excluded.updated_at", (scan_id, kind, db.now()))
        return job_id


class DurableQueue:
    """Production facade. Submissions persist; only a separate worker executes."""

    def submit(self, scan_id):
        from .durable_jobs import enqueue
        with db.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            scan = conn.execute("SELECT status,deletion_pending FROM scans WHERE id=?", (scan_id,)).fetchone()
            if scan is None or scan["deletion_pending"] or scan["status"] not in {"queued", "running"}:
                raise ValueError("Scan is missing, terminal or pending deletion")
            job_id = enqueue("scan", {"scan_id": scan_id}, scan_id=scan_id,
                             idempotency_key=f"scan:{scan_id}", conn=conn)
            conn.execute("UPDATE durable_jobs SET available_at=0,error='' WHERE id=? AND status='queued'", (job_id,))
            return job_id

    def submit_enrichment(self, scan_id, kind, func, *args, **kwargs):
        mapping = {
            "nvd": ("include_firmware",), "windows": ("host", "local"),
            "linux": ("host", "user", "port", "local"),
            "metasploit-exploit": ("host", "port", "module_path"),
        }
        options = dict(zip(mapping.get(kind, ()), args[1:], strict=True))
        options.update(kwargs)
        return enqueue_enrichment(scan_id,kind,options) is not None

    def is_active(self, scan_id):
        with db.connect() as conn:
            return conn.execute("SELECT 1 FROM durable_jobs WHERE scan_id=? AND kind='scan' AND status IN ('queued','running')", (scan_id,)).fetchone() is not None

    def active_ids(self):
        with db.connect() as conn:
            return [row[0] for row in conn.execute("SELECT DISTINCT scan_id FROM durable_jobs WHERE kind='scan' AND status IN ('queued','running') AND scan_id IS NOT NULL ORDER BY scan_id")]

    def is_enrichment_active(self, scan_id):
        with db.connect() as conn:
            return conn.execute("SELECT 1 FROM durable_jobs WHERE scan_id=? AND kind='enrichment' AND status IN ('queued','running')", (scan_id,)).fetchone() is not None

    def cancel(self, scan_id):
        from .durable_jobs import cancel
        with db.connect() as conn:
            ids = [row[0] for row in conn.execute("SELECT id FROM durable_jobs WHERE scan_id=? AND status IN ('queued','running')", (scan_id,))]
        outcomes = [cancel(job_id) for job_id in ids]
        return any(outcomes)

    def request_delete(self, scan_id):
        import time
        with db.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE scans SET deletion_pending=1 WHERE id=?", (scan_id,))
            conn.execute("UPDATE durable_jobs SET cancel_requested=1,status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END WHERE scan_id=? AND status IN ('queued','running')", (scan_id,))
            live = conn.execute("SELECT 1 FROM durable_jobs WHERE scan_id=? AND status='running' AND lease_until>=?", (scan_id, time.time())).fetchone()
            if live is None:
                db._delete_scan_rows(conn, scan_id)
            return live is not None

    def wait_for(self, scan_id, timeout=5):
        import time
        end = time.monotonic() + timeout
        while self.is_active(scan_id) or self.is_enrichment_active(scan_id):
            if time.monotonic() >= end:
                raise TimeoutError("Start scopescan worker to execute queued jobs")
            time.sleep(.05)

    def shutdown(self, wait=False):
        # Web shutdown cannot cancel work owned by another process.
        pass


# ScanQueue remains an explicit in-process harness for embedding/tests only.
QUEUE = DurableQueue()
