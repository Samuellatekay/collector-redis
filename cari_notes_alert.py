#!/usr/bin/env python3
"""Cari endpoint Notes milik ALERT di IRIS kamu (hanya membaca, tidak mengubah apa pun).

Pemakaian (dari folder aplikasi analisis, setelah build ulang):
    docker compose run --rm app python cari_notes_alert.py            # cari lewat spesifikasi OpenAPI
    docker compose run --rm app python cari_notes_alert.py 123        # + coba GET pada alert ID 123

Skrip hanya mengirim GET. API key tidak ditampilkan. Tempel seluruh keluarannya ke chat.
"""
import asyncio
import json
import os
import sys

from iris_client import IrisClient

SPEC_PATHS = (
    "/api/v2/openapi.json", "/api/v2/swagger.json", "/openapi.json", "/swagger.json",
    "/api/openapi.json", "/api/v2/docs/openapi.json", "/api/v2/spec", "/api/v2/openapi",
)
ALERT_CANDIDATES = (
    "/api/v2/alerts/{id}",
    "/api/v2/alerts/{id}/notes",
    "/api/v2/alerts/{id}/notes-directories",
    "/api/v2/alerts/{id}/note",
    "/api/v2/alerts/{id}/comments",
)


def short(text: str, n: int = 300) -> str:
    return " ".join(text.split())[:n]


async def get(client, path: str):
    try:
        r = await client._client.get(path)
    except Exception as exc:
        return None, f"{type(exc).__name__}: {str(exc)[:120]}"
    return r, None


async def find_spec(client) -> int:
    print("== 1. Mencari spesifikasi OpenAPI ==")
    found = 0
    for path in SPEC_PATHS:
        r, err = await get(client, path)
        if err:
            print(f"  {path}: {err}")
            continue
        ctype = r.headers.get("content-type", "")
        print(f"  {path}: HTTP {r.status_code} ({ctype.split(';')[0]})")
        if r.status_code != 200 or "json" not in ctype:
            continue
        try:
            spec = r.json()
        except ValueError:
            continue
        paths = spec.get("paths") if isinstance(spec, dict) else None
        if not isinstance(paths, dict):
            continue
        found += 1
        print(f"  -> spesifikasi ditemukan di {path}: {len(paths)} path")
        hits = [
            (p, sorted(m.upper() for m in ops if m.lower() in {"get", "post", "put", "patch", "delete"}))
            for p, ops in paths.items()
            if "alert" in p.lower() and ("note" in p.lower() or "comment" in p.lower())
        ]
        if not hits:
            print("  -> tidak ada path alert yang memuat 'note' atau 'comment'")
        for p, methods in hits:
            print(f"     {','.join(methods):12} {p}")
            for method in methods:
                op = paths[p].get(method.lower()) or {}
                body = (((op.get("requestBody") or {}).get("content") or {}).get("application/json") or {}).get("schema")
                if body:
                    print(f"        body {method}: {short(json.dumps(body), 400)}")
        break
    if not found:
        print("  (tidak ada spesifikasi yang terbaca; lanjut ke langkah 2 atau pakai F12 -> Network)")
    return found


async def probe_alert(client, alert_id: str) -> None:
    print(f"\n== 2. Mencoba GET pada alert {alert_id} ==")
    for template in ALERT_CANDIDATES:
        path = template.format(id=alert_id)
        r, err = await get(client, path)
        if err:
            print(f"  {path}: {err}")
            continue
        ctype = r.headers.get("content-type", "").split(";")[0]
        line = f"  {path}: HTTP {r.status_code} ({ctype})"
        if r.status_code == 200 and "json" in ctype:
            try:
                data = r.json()
            except ValueError:
                data = None
            if isinstance(data, dict) and template.endswith("{id}"):
                keys = sorted(data.keys())
                line += f"\n     kunci respons: {', '.join(keys)[:400]}"
            elif data is not None:
                line += f"\n     isi: {short(json.dumps(data), 300)}"
        print(line)


async def main() -> int:
    client = IrisClient.from_env(os.environ)
    if client is None:
        print("IRIS_ENABLED=false di lingkungan ini.")
        return 1
    try:
        print(f"IRIS: {client._client.base_url}  (api_version={client.api_version})\n")
        await find_spec(client)
        if len(sys.argv) > 1:
            await probe_alert(client, sys.argv[1])
        print("\nSelesai. Tempel seluruh keluaran ini ke chat.")
    finally:
        await client.aclose()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))