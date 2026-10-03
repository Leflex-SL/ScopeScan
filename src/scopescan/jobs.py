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


# Cola compartida por el panel y por la CLI dentro de un mismo proceso.
QUEUE = ScanQueue()
