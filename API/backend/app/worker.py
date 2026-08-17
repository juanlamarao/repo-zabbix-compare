from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from .collector import collect_baseline, collect_current_cycle
from .config import get_settings
from .db import close_pool, ensure_schema, get_pool

LOCK_KEY = 82736418


async def run() -> None:
    await ensure_schema()
    pool = await get_pool()
    settings = get_settings()

    while True:
        try:
            async with pool.acquire() as lock_conn:
                locked = await lock_conn.fetchval("SELECT pg_try_advisory_lock($1)", LOCK_KEY)
                if not locked:
                    await asyncio.sleep(5)
                    continue

                try:
                    requested = await lock_conn.fetchrow(
                        "SELECT id FROM baselines WHERE status='REQUESTED' ORDER BY created_at LIMIT 1"
                    )
                    if requested:
                        await collect_baseline(requested["id"])
                    else:
                        active = await lock_conn.fetchrow(
                            "SELECT id FROM baselines WHERE status='FROZEN' ORDER BY frozen_at DESC LIMIT 1"
                        )
                        if active:
                            # A baseline may be frozen days before the Zabbix 7 target exists.
                            # In that phase the validator must remain idle, not create failed cycles.
                            if not settings.new_zabbix_url or not settings.new_zabbix_token:
                                await asyncio.sleep(2)
                                continue

                            force = await lock_conn.fetchval(
                                "SELECT COALESCE((SELECT (value #>> '{}')::boolean FROM app_meta WHERE key='force_cycle'),false)"
                            )
                            last = await lock_conn.fetchval(
                                "SELECT max(finished_at) FROM cycles WHERE baseline_id=$1 AND status='COMPLETE'",
                                active["id"],
                            )
                            due = (
                                last is None
                                or (datetime.now(timezone.utc) - last).total_seconds()
                                >= settings.collection_interval_seconds
                            )
                            if force or due:
                                await lock_conn.execute(
                                    """
                                    INSERT INTO app_meta(key,value) VALUES('force_cycle','false'::jsonb)
                                    ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()
                                    """
                                )
                                await collect_current_cycle(active["id"])
                finally:
                    await lock_conn.execute("SELECT pg_advisory_unlock($1)", LOCK_KEY)
        except Exception as exc:
            print(f"worker error: {exc}", flush=True)

        await asyncio.sleep(2)


if __name__ == "__main__":
    try:
        asyncio.run(run())
    finally:
        try:
            asyncio.run(close_pool())
        except Exception:
            pass
