"""Cola de escaneos en segundo plano.

El panel web no puede bloquearse media hora esperando a nmap, asi que los
escaneos corren en hilos. Son procesos externos: el trabajo real lo hace nmap,
el hilo solo espera, con lo que el GIL no estorba.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor

from . import db, service
from .config import MAX_CONCURRENT_SCANS

log = logging.getLogger("medscan.jobs")


class ScanQueue:
    """Ejecuta escaneos con un limite de concurrencia y permite cancelarlos."""

    def __init__(self, max_workers: int = MAX_CONCURRENT_SCANS) -> None:
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="medscan")
        self._cancels: dict[int, threading.Event] = {}
        self._futures: dict[int, Future] = {}
        self._lock = threading.Lock()

    def submit(self, scan_id: int) -> None:
        cancel = threading.Event()
        with self._lock:
            if scan_id in self._futures and not self._futures[scan_id].done():
                return  # ya esta en cola o corriendo
            self._cancels[scan_id] = cancel
            future = self._pool.submit(self._run, scan_id, cancel)
            self._futures[scan_id] = future

    def _run(self, scan_id: int, cancel: threading.Event) -> None:
        try:
            service.execute(scan_id, cancel=cancel)
        except Exception as exc:  # el hilo no debe morir en silencio
            log.exception("Escaneo %s fallido", scan_id)
            db.set_status(scan_id, "failed", error=f"Error interno: {exc}")
        finally:
            with self._lock:
                self._cancels.pop(scan_id, None)

    def cancel(self, scan_id: int) -> bool:
        """Pide la cancelacion. True si el escaneo estaba vivo."""
        with self._lock:
            event = self._cancels.get(scan_id)
            future = self._futures.get(scan_id)

        # Si aun no ha arrancado, basta con quitarlo de la cola.
        if future is not None and future.cancel():
            db.set_status(scan_id, "cancelled", error="Cancelado antes de empezar")
            with self._lock:
                self._cancels.pop(scan_id, None)
            return True

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
