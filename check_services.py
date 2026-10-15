#!/usr/bin/env python3
"""Read-only smoke checks for the collector's Redis, OpenCTI, and GLPI connections."""
from __future__ import annotations

import argparse
import ipaddress
import sys

import requests


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ip",
        help="optionally check an existing IPv4/IPv6 observable and GLPI asset",
    )
    parser.add_argument(
        "--test-label",
        help="check for an OpenCTI indicator and GLPI ticket containing this label",
    )
    parser.add_argument(
        "--publish-enrichment",
        action="store_true",
        help="re-enrich the selected existing observable and publish one enrichment event",
    )
    args = parser.parse_args()
    if args.publish_enrichment and not args.ip:
        parser.error("--publish-enrichment requires --ip")
    if args.ip:
        try:
            ip = str(ipaddress.ip_address(args.ip))
        except ValueError:
            parser.error("--ip must be a valid IPv4 or IPv6 address")
    else:
        ip = None

    import collector
    import enrichment
    from pycti import OpenCTIApiClient

    failures = 0

    def report(status: str, component: str, detail: str) -> None:
        nonlocal failures
        print(f"[{status:5}] {component:10} {detail}", flush=True)
        if status == "GAGAL":
            failures += 1

    try:
        report("OK" if collector.r.ping() else "GAGAL", "Redis", "PING berhasil")
    except Exception as exc:
        report("GAGAL", "Redis", f"{type(exc).__name__}: {str(exc)[:160]}")

    client = None
    observable = None
    try:
        client = OpenCTIApiClient(collector.OPENCTI_URL, collector.OPENCTI_TOKEN)
        if ip:
            found = client.stix_cyber_observable.list(
                types=["IPv4-Addr" if ":" not in ip else "IPv6-Addr"],
                filters={
                    "mode": "and",
                    "filters": [{"key": "value", "values": [ip], "operator": "eq"}],
                    "filterGroups": [],
                },
                first=100,
            )
            observable = next(
                (item for item in (found or [])
                 if item.get("observable_value") == ip),
                None,
            )
            report(
                "OK" if observable else "CEK",
                "OpenCTI",
                "API dapat diakses; Observable ditemukan" if observable
                else f"API dapat diakses, tetapi Observable {ip} tidak ditemukan",
            )
            if observable:
                context = enrichment.opencti_context(client, observable)
                indicators = context.get("indicators", [])
                external = [item for item in indicators if item.get("source") != "collector"]
                labels = context.get("labels") or []
                score = context.get("score")
                report(
                    "OK" if external else "CEK",
                    "Intel",
                    f"indicator eksternal={len(external)}, score={score}, labels={labels or 'tidak ada'}",
                )
                if args.publish_enrichment:
                    token = collector.glpi_session()
                    try:
                        doc = enrichment.enrich_one(
                            client, collector.r, observable, collector.GLPI, token
                        )
                        if doc is None:
                            report("GAGAL", "OpenCTI enrichment", "Observable tidak bisa diperkaya")
                        else:
                            collector.push("enrichment-events", "enrichment", doc)
                            report(
                                "OK",
                                "OpenCTI enrichment",
                                f"event diterbitkan ke Redis; score={doc['reputation'].get('opencti_score')}, "
                                f"labels={doc['reputation'].get('labels') or 'tidak ada'}",
                            )
                    finally:
                        collector.glpi_kill(token)
        else:
            client.stix_cyber_observable.list(first=1)
            report("OK", "OpenCTI", "API dapat diakses dan query Observable berhasil")
        if args.test_label:
            indicators = client.indicator.list(search=args.test_label, first=100) or []
            indicator_found = any(
                args.test_label in str(item.get("description") or "")
                for item in indicators if isinstance(item, dict)
            )
            report(
                "OK" if indicator_found else "CEK",
                "OpenCTI test",
                "Indicator uji ditemukan" if indicator_found else "menunggu Indicator uji",
            )
    except Exception as exc:
        report("GAGAL", "OpenCTI", f"{type(exc).__name__}: {str(exc)[:160]}")

    token = None
    try:
        token = collector.glpi_session()
        if ip:
            asset = enrichment.asset_info(ip, collector.GLPI, token)
            if asset.get("error"):
                report("GAGAL", "GLPI", f"pencarian aset gagal: {asset['error']}")
            else:
                report(
                    "OK",
                    "GLPI",
                    f"API dapat diakses; aset {'ditemukan' if asset.get('found') else 'tidak ditemukan'} untuk {ip}",
                )
        else:
            report("OK", "GLPI", "sesi API berhasil dibuat")
        if args.test_label:
            response = requests.get(
                f"{collector.GLPI_URL}/search/Ticket",
                headers=collector.glpi_headers(token),
                params={
                    "criteria[0][field]": 1,
                    "criteria[0][searchtype]": "contains",
                    "criteria[0][value]": args.test_label,
                    "range": "0-49",
                    "forcedisplay[0]": 2,
                    "forcedisplay[1]": 1,
                },
                timeout=20,
            )
            if response.status_code not in (200, 206):
                report("GAGAL", "GLPI test", f"HTTP {response.status_code} saat mencari tiket uji")
            else:
                rows = response.json().get("data", []) or []
                ticket_found = any(
                    args.test_label in str(row.get("1") or "")
                    for row in rows if isinstance(row, dict)
                )
                report(
                    "OK" if ticket_found else "CEK",
                    "GLPI test",
                    "tiket uji ditemukan" if ticket_found else "menunggu tiket uji",
                )
    except Exception as exc:
        report("GAGAL", "GLPI", f"{type(exc).__name__}: {str(exc)[:160]}")
    finally:
        if token:
            collector.glpi_kill(token)

    print("Collector: semua koneksi wajib OK" if not failures
          else f"Collector: {failures} koneksi wajib gagal")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
