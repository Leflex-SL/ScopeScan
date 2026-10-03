"""SQLite feed reservations and refresh ownership shared by independent workers."""

from __future__ import annotations

import math
import time
import uuid

from . import db


class FeedInterrupted(RuntimeError):
    pass


def check_interrupt(cancel=None, deadline=None, *, monotonic=time.monotonic):
    if cancel and cancel():
        raise FeedInterrupted("Consulta de feed cancelada")
    if deadline is not None and monotonic() >= deadline:
        raise FeedInterrupted("Se agoto el tiempo de consulta del feed")


def interruptible_wait(
    seconds, *, cancel=None, deadline=None, sleep=time.sleep, monotonic=time.monotonic
):
    end = monotonic() + max(0, seconds)
    while monotonic() < end:
        check_interrupt(cancel, deadline, monotonic=monotonic)
        sleep(min(0.1, end - monotonic()))
    check_interrupt(cancel, deadline, monotonic=monotonic)


def _schema(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS feed_requests (bucket TEXT, at REAL)")
    conn.execute("CREATE INDEX IF NOT EXISTS feed_requests_bucket ON feed_requests(bucket,at)")
    conn.execute("CREATE TABLE IF NOT EXISTS feed_backoff (bucket TEXT PRIMARY KEY, until REAL)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS feed_refresh_leases "
        "(key TEXT PRIMARY KEY, owner TEXT NOT NULL, until REAL NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS feed_refresh_state "
        "(key TEXT PRIMARY KEY, attempted_at REAL NOT NULL, error TEXT NOT NULL)"
    )


class SharedFeedBudget:
    def __init__(
        self,
        *,
        bucket="nvd",
        capacity=5,
        window=30.0,
        clock=time.time,
        monotonic=time.monotonic,
        sleep=time.sleep,
    ):
        if type(capacity) is not int or not 1 <= capacity <= 5 or window < 30:
            raise ValueError(
                "El presupuesto conservador permite hasta 5 solicitudes por 30 segundos"
            )
        self.bucket, self.capacity, self.window = bucket, capacity, window
        self.clock, self.monotonic, self.sleep = clock, monotonic, sleep

    def reserve(self, *, cancel=None, deadline=None):
        while True:
            check_interrupt(cancel, deadline, monotonic=self.monotonic)
            now = self.clock()
            with db.connect() as conn:
                _schema(conn)
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "DELETE FROM feed_requests WHERE bucket=? AND at<=?",
                    (self.bucket, now - self.window),
                )
                rows = list(
                    conn.execute(
                        "SELECT at FROM feed_requests WHERE bucket=? ORDER BY at", (self.bucket,)
                    )
                )
                backoff = conn.execute(
                    "SELECT until FROM feed_backoff WHERE bucket=?", (self.bucket,)
                ).fetchone()
                wait = max(0.0, backoff[0] - now) if backoff else 0.0
                if len(rows) >= self.capacity:
                    wait = max(wait, rows[0][0] + self.window - now)
                if wait <= 0:
                    conn.execute("INSERT INTO feed_requests VALUES (?,?)", (self.bucket, now))
                    return
            interruptible_wait(
                wait, cancel=cancel, deadline=deadline, sleep=self.sleep, monotonic=self.monotonic
            )

    def defer(self, seconds):
        if isinstance(seconds, bool) or not math.isfinite(float(seconds)):
            raise ValueError("Pausa del proveedor invalida")
        with db.connect() as conn:
            _schema(conn)
            conn.execute(
                "INSERT INTO feed_backoff VALUES (?,?) ON CONFLICT(bucket) DO UPDATE "
                "SET until=max(until,excluded.until)",
                (self.bucket, self.clock() + max(0.0, float(seconds))),
            )


def claim_refresh(key, *, ttl=180.0, owner=None):
    owner = owner or uuid.uuid4().hex
    with db.connect() as conn:
        _schema(conn)
        conn.execute("BEGIN IMMEDIATE")
        now = time.time()
        row = conn.execute(
            "SELECT owner,until FROM feed_refresh_leases WHERE key=?", (key,)
        ).fetchone()
        if row and row[1] > now and row[0] != owner:
            return None
        conn.execute(
            "INSERT INTO feed_refresh_leases VALUES (?,?,?) ON CONFLICT(key) DO UPDATE "
            "SET owner=excluded.owner,until=excluded.until",
            (key, owner, now + ttl),
        )
    return owner


def release_refresh(key, owner):
    with db.connect() as conn:
        _schema(conn)
        conn.execute("DELETE FROM feed_refresh_leases WHERE key=? AND owner=?", (key, owner))


def record_refresh(key, error=""):
    with db.connect() as conn:
        _schema(conn)
        conn.execute(
            "INSERT INTO feed_refresh_state VALUES (?,?,?) ON CONFLICT(key) DO UPDATE "
            "SET attempted_at=excluded.attempted_at,error=excluded.error",
            (key, time.time(), error[:500]),
        )


def last_refresh(key):
    with db.connect() as conn:
        _schema(conn)
        return conn.execute("SELECT * FROM feed_refresh_state WHERE key=?", (key,)).fetchone()
