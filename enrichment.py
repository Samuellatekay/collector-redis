"""
Modul enrichment untuk collector.

Untuk setiap observable BARU di OpenCTI (IPv4-Addr, IPv6-Addr, Domain-Name) dikumpulkan:
  - reputation  : skor OpenCTI + label, AbuseIPDB (opsional), VirusTotal (opsional)
  - geolocation : ip-api.com (gratis) atau ipinfo.io (jika IPINFO_TOKEN diisi)
                  + relasi 'located-at' yang sudah ada di OpenCTI
  - asset       : pencarian Computer di GLPI berdasarkan IP
  - domain_age  : RDAP (gratis), fallback VirusTotal
Hasil dikirim ke Redis list `enrichment-events`.
"""
import os
import json
import time
import logging
import ipaddress
import re
from datetime import datetime, timedelta, timezone

import requests

log = logging.getLogger("enrichment")
COLLECTOR_MARK = "[from-collector]"

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
VT_DELAY = int(os.getenv("VT_DELAY", "16"))                 # free tier: 4 request/menit
MAX_PER_CYCLE = int(os.getenv("ENRICH_MAX_PER_CYCLE", "20"))
CACHE_TTL = int(os.getenv("ENRICH_CACHE_TTL", "86400"))     # detik
ENRICH_DELAY = int(os.getenv("ENRICH_DELAY_SECONDS", "120"))  # beri waktu connector OpenCTI
CONNECTOR_WAIT_SECONDS = max(0, int(os.getenv("ENRICH_CONNECTOR_WAIT_SECONDS", "45")))
CONNECTOR_CACHE_TTL = max(1, int(os.getenv("ENRICH_CONNECTOR_CACHE_TTL", "1")))
ASSET_ENABLED = os.getenv("ENRICH_ASSET", "true").lower() == "true"

OBS_TYPES = ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "StixFile"]
HTTP_TIMEOUT = 20

# ------------------------------------------------------------------ util
def _get_json(url, headers=None, params=None):
    try:
        res = requests.get(url, headers=headers, params=params,
                           timeout=HTTP_TIMEOUT, allow_redirects=True)
        if res.status_code == 200:
            return res.json()
        log.debug("GET %s -> %s", url, res.status_code)
    except (requests.RequestException, ValueError) as e:
        log.warning("GET %s gagal: %s", url, e)
    return None


def is_public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def file_hash(obs):
    hashes = obs.get("hashes") or {}
    if not isinstance(hashes, dict):
        return None
    supported = {
        "sha512": ("SHA-512", 128),
        "sha256": ("SHA-256", 64),
        "sha1": ("SHA-1", 40),
        "md5": ("MD5", 32),
    }
    for key, (algorithm, length) in supported.items():
        for name, value in hashes.items():
            normalized = str(name).lower().replace("-", "").replace("_", "")
            if normalized == key and isinstance(value, str):
                value = value.strip().lower()
                if len(value) == length and all(c in "0123456789abcdef" for c in value):
                    return {"algorithm": algorithm, "value": value}
    return None


# ------------------------------------------------------------------ OpenCTI context
def _opencti_score(stix):
    if not isinstance(stix, dict):
        return None
    if stix.get("x_opencti_score") is not None:
        return stix["x_opencti_score"]
    for extension in (stix.get("extensions") or {}).values():
        if isinstance(extension, dict) and extension.get("score") is not None:
            return extension["score"]
    return None


def _opencti_labels(stix):
    labels = stix.get("objectLabel") or [] if isinstance(stix, dict) else []
    return [
        label["value"] for label in labels
        if isinstance(label, dict) and label.get("value")
    ]


def _normalize_author(value):
    if isinstance(value, str):
        name = value.strip()
        return {"name": name} if name else None
    if isinstance(value, list):
        authors = []
        for item in value:
            normalized = _normalize_author(item)
            if isinstance(normalized, list):
                authors.extend(normalized)
            elif normalized:
                authors.append(normalized)
        return authors or None
    if not isinstance(value, dict):
        return None
    if value.get("name") or value.get("id"):
        return {key: value[key] for key in ("id", "name") if value.get(key)}
    for key in ("edges", "nodes", "items", "data"):
        if key in value:
            return _normalize_author(value[key])
    return None


def _opencti_json_value(value, depth=0):
    if isinstance(value, str):
        return value[:2000]
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if depth >= 3:
        return None
    if isinstance(value, list):
        return [
            item for item in (
                _opencti_json_value(item, depth + 1) for item in value[:50]
            ) if item is not None
        ]
    if isinstance(value, dict):
        return {
            str(key)[:120]: cleaned
            for key, item in list(value.items())[:50]
            if key not in {"from", "to", "objects", "object"}
            and (cleaned := _opencti_json_value(item, depth + 1)) is not None
        }
    return str(value)[:500]


def _opencti_entity_summary(entity):
    if not isinstance(entity, dict):
        return None
    summary = {
        key: cleaned
        for key, value in entity.items()
        if key not in {
            "createdBy", "created_by", "objectLabel", "object_label",
            "objectMarking", "object_marking", "externalReferences",
            "external_references", "from", "to", "objects", "object",
        }
        and (cleaned := _opencti_json_value(value)) is not None
    }
    description = entity.get("description")
    if isinstance(description, str) and description:
        summary["description"] = description[:1200]
    pattern = entity.get("pattern")
    if isinstance(pattern, str) and pattern:
        summary["pattern"] = pattern[:1200]
    score = _opencti_score(entity)
    if score is not None:
        summary["score"] = score
    labels = _opencti_labels(entity)
    if labels:
        summary["labels"] = labels[:30]
    references = entity.get("externalReferences") or entity.get("external_references")
    if isinstance(references, list):
        summary["external_references"] = [
            {key: reference[key][:500] if isinstance(reference.get(key), str)
             else reference[key]
             for key in ("source_name", "external_id", "url", "description")
             if reference.get(key)}
            for reference in references[:10]
            if isinstance(reference, dict)
        ]
    created_by = _normalize_author(
        entity.get("createdBy") or entity.get("created_by")
    )
    if created_by:
        summary["created_by"] = created_by
    object_markings = entity.get("objectMarking") or entity.get("object_marking")
    if isinstance(object_markings, list):
        summary["object_markings"] = [
            item for item in (
                _opencti_entity_summary(marking) for marking in object_markings[:20]
            ) if item
        ]
    hashes = entity.get("hashes")
    if isinstance(hashes, dict):
        summary["hashes"] = {
            str(key): str(value)[:256]
            for key, value in list(hashes.items())[:20]
            if value is not None
        }
    return summary or None


CONNECTOR_INVENTORY_QUERY = """
query CollectorConnectorInventory {
  connectors {
    id
    name
    active
    connector_type
    connector_scope
    connector_state
  }
}
"""


def connector_inventory(client):
    try:
        result = client.query(CONNECTOR_INVENTORY_QUERY)
        data = result.get("data") if isinstance(result, dict) else None
        if not isinstance(data, dict) or "connectors" not in data:
            errors = result.get("errors") if isinstance(result, dict) else None
            raise ValueError(f"OpenCTI did not return connector inventory: {errors or result}")
        connectors = data["connectors"]
        if not isinstance(connectors, list):
            raise ValueError("OpenCTI connector inventory is not a list")
    except Exception as exc:
        log.exception("Daftar connector OpenCTI gagal dibaca")
        return [], f"{type(exc).__name__}: {str(exc)[:200]}"
    if any(not isinstance(item, dict) for item in connectors):
        log.error("OpenCTI connector inventory contains a non-object entry")
        return [], "OpenCTI connector inventory contains an invalid entry"
    log.info("OpenCTI connector inventory loaded count=%d", len(connectors))
    return connectors, None


def _connector_scope(connector):
    scope = connector.get("connector_scope") or connector.get("scope") or []
    if isinstance(scope, str):
        return {item.strip().lower() for item in scope.split(",") if item.strip()}
    if isinstance(scope, list):
        return {str(item).strip().lower() for item in scope if item}
    return set()


def connector_lookup_status(client, r, obs, connectors, inventory_error=None):
    entity_type = str(obs.get("entity_type") or "").lower()
    report = []
    applicable = []
    for connector in connectors:
        kind = str(connector.get("connector_type") or connector.get("type") or "").upper()
        name = str(connector.get("name") or connector.get("id") or "OpenCTI connector")
        active = connector.get("active") is not False
        scope = _connector_scope(connector)
        if kind == "EXTERNAL_IMPORT":
            report.append({
                "name": name, "type": kind,
                "status": "indexed_lookup" if active else "inactive",
                "details": "IOC dicari pada data feed yang sudah diimpor ke OpenCTI"
                           if active else "connector tidak aktif",
            })
        elif kind == "INTERNAL_ENRICHMENT":
            if not active:
                report.append({"name": name, "type": kind, "status": "inactive"})
            elif scope and entity_type not in scope and "all" not in scope:
                report.append({"name": name, "type": kind, "status": "out_of_scope"})
            else:
                applicable.append(connector)
        elif kind:
            report.append({"name": name, "type": kind, "status": "not_a_lookup_connector"})

    if inventory_error:
        report.append({
            "name": "OpenCTI connector inventory", "type": "system",
            "status": "error", "details": inventory_error,
        })

    work_items = []
    observable_id = obs.get("id")
    for connector in applicable:
        connector_id = str(connector.get("id") or "")
        name = str(connector.get("name") or connector_id or "Internal enrichment")
        entry = {"name": name, "type": "INTERNAL_ENRICHMENT"}
        if not observable_id or not connector_id:
            entry.update(status="error", details="observable atau connector ID tidak tersedia")
            report.append(entry)
            continue
        cache_key = f"enrich:connector:v1:{observable_id}:{connector_id}"
        cached = r.get(cache_key)
        if cached:
            try:
                previous = json.loads(cached)
                if isinstance(previous, dict):
                    previous["cached"] = True
                    report.append(previous)
                    continue
            except (TypeError, ValueError):
                log.warning("Cache status connector rusak key=%s", cache_key)
        try:
            work_id = client.stix_cyber_observable.ask_for_enrichment(
                id=observable_id, connector_id=connector_id
            )
            entry.update(status="queued", work_id=str(work_id))
            report.append(entry)
            work_items.append((entry, cache_key, str(work_id)))
        except Exception as exc:
            log.exception("Gagal meminta enrichment connector=%s observable=%s",
                          name, observable_id)
            entry.update(status="error", details=f"{type(exc).__name__}: {str(exc)[:200]}")
            report.append(entry)

    deadline = time.monotonic() + CONNECTOR_WAIT_SECONDS
    pending = list(work_items)
    while pending:
        for item in list(pending):
            entry, _, work_id = item
            try:
                work = client.work.get_work(work_id) or {}
                status = str(work.get("status") or "").lower()
                errors = work.get("errors")
                if status in {"complete", "completed"}:
                    entry["status"] = "failed" if errors else "completed"
                    if errors:
                        entry["details"] = str(errors)[:300]
                    pending.remove(item)
                elif status in {"error", "failed", "cancelled"}:
                    entry["status"] = "failed"
                    if errors:
                        entry["details"] = str(errors)[:300]
                    pending.remove(item)
            except Exception as exc:
                log.exception("Status work OpenCTI gagal dibaca work_id=%s", work_id)
                entry["status"] = "error"
                entry["details"] = f"{type(exc).__name__}: {str(exc)[:200]}"
                pending.remove(item)
        remaining = deadline - time.monotonic()
        if pending and remaining > 0:
            time.sleep(min(1, remaining))
        else:
            break

    for entry, _, _ in pending:
        entry["status"] = "timeout"
        entry["details"] = f"belum selesai dalam {CONNECTOR_WAIT_SECONDS} detik"
    for entry, cache_key, _ in work_items:
        entry.pop("work_id", None)
        try:
            r.setex(cache_key, CONNECTOR_CACHE_TTL, json.dumps(entry, default=str))
        except Exception:
            log.exception("Gagal menyimpan status connector %s ke cache", entry.get("name"))
    return report


def opencti_context(client, obs):
    ctx = {
        "score": _opencti_score(obs),
        "labels": _opencti_labels(obs),
        "indicators": [],
        "related_entities": [],
        "relationships": [],
        "events": [],
        "sightings": [],
        "locations": [],
        "sources": [],
        "external_import_match_count": 0,
    }
    if obs.get("id"):
        ctx["observable"] = _opencti_entity_summary(obs) or {}
        hash_info = file_hash(obs) if obs.get("entity_type") == "StixFile" else None
        ctx["observable"]["value"] = (
            hash_info["value"] if hash_info else obs.get("observable_value")
        )

    seen_indicators = set()
    indicator_records = []

    def add_indicator(indicator):
        if not isinstance(indicator, dict):
            return False
        identity = indicator.get("id") or (
            indicator.get("name"), indicator.get("pattern")
        )
        if identity in seen_indicators:
            return False
        seen_indicators.add(identity)
        indicator_records.append(indicator)
        score = _opencti_score(indicator)
        labels = _opencti_labels(indicator)
        is_collector_indicator = str(indicator.get("description") or "").startswith(
            COLLECTOR_MARK
        )
        created_by = (
            indicator.get("createdBy")
            or indicator.get("created_by")
            or indicator.get("creator")
            or indicator.get("author")
        )
        if not created_by and indicator.get("id"):
            try:
                result = client.query(
                    """
                    query CollectorIndicatorAuthor($id: String!) {
                      indicator(id: $id) {
                        createdBy {
                          id
                          name
                        }
                      }
                    }
                    """,
                    {"id": indicator["id"]},
                )
                data = result.get("data") if isinstance(result, dict) else None
                author_data = data.get("indicator") if isinstance(data, dict) else None
                if isinstance(author_data, dict):
                    created_by = author_data.get("createdBy")
            except Exception:
                log.exception("Author indicator OpenCTI gagal dibaca id=%s", indicator["id"])
        created_by = _normalize_author(created_by)
        references = indicator.get("externalReferences") or indicator.get("external_references") or []
        references = [
            {key: ref[key] for key in ("source_name", "url", "external_id", "description")
             if ref.get(key)}
            for ref in references[:20] if isinstance(ref, dict)
        ] if isinstance(references, list) else []
        indicator_details = _opencti_entity_summary(indicator) or {}
        ctx["indicators"].append({
            **indicator_details,
            "id": indicator.get("id"), "name": indicator.get("name"),
            "score": score, "labels": labels,
            "source": "collector" if is_collector_indicator else created_by or "opencti",
            "created_by": created_by, "external_references": references,
            "pattern": str(indicator.get("pattern") or "")[:2000] or None,
            "description": str(indicator.get("description") or "")[:2000] or None,
            "indicator_types": indicator.get("indicator_types") or [],
            "x_mitre_id": indicator.get("x_mitre_id"),
            "confidence": indicator.get("confidence"),
            "valid_from": indicator.get("valid_from"),
            "valid_until": indicator.get("valid_until"),
            "created": indicator.get("created"),
            "modified": indicator.get("modified"),
            "first_seen": indicator.get("first_seen"),
            "last_seen": indicator.get("last_seen"),
            "revoked": indicator.get("revoked"),
            "kill_chain_phases": indicator.get("kill_chain_phases") or [],
        })
        if created_by and not is_collector_indicator:
            ctx["sources"].append(created_by)
        ctx["sources"].extend(
            ref["source_name"] for ref in references if ref.get("source_name")
        )
        if not is_collector_indicator:
            ctx["external_import_match_count"] += 1
        if score is not None and not is_collector_indicator:
            try:
                if ctx["score"] is None or float(score) > float(ctx["score"]):
                    ctx["score"] = score
            except (TypeError, ValueError):
                if ctx["score"] is None:
                    ctx["score"] = score
        ctx["labels"] = list(dict.fromkeys([*ctx["labels"], *labels]))
        return True

    def add_indicators_by_value(value):
        if not value:
            return
        candidates = {}
        pattern_filters = {
            "mode": "and",
            "filters": [{
                "key": "pattern",
                "values": [str(value)],
                "operator": "contains",
            }],
            "filterGroups": [],
        }
        for search_args in (
            {"search": str(value), "first": 100},
            {"filters": pattern_filters, "first": 100},
        ):
            try:
                results = client.indicator.list(**search_args) or []
            except Exception:
                log.exception(
                    "Pencarian indicator OpenCTI berdasarkan IOC gagal "
                    "value=%s query=%s",
                    value,
                    "pattern" if "filters" in search_args else "search",
                )
                continue
            for indicator in results:
                if isinstance(indicator, dict):
                    identity = indicator.get("id") or (
                        indicator.get("name"), indicator.get("pattern")
                    )
                    candidates.setdefault(identity, indicator)

        exact_pattern = re.compile(
            rf"""=\s*(?:'{re.escape(str(value))}'|"{re.escape(str(value))}")(?=\s|\]|\)|$)""",
            re.IGNORECASE,
        )
        for indicator in candidates.values():
            pattern = str(indicator.get("pattern") or "")
            if exact_pattern.search(pattern):
                add_indicator(indicator)

    observable_id = obs.get("id")
    observable_value = obs.get("observable_value")
    if not observable_value:
        observable_value = (file_hash(obs) or {}).get("value")
    if not observable_id:
        add_indicators_by_value(observable_value)
    else:
        try:
            rels = client.stix_core_relationship.list(
                fromId=observable_id, relationship_type="located-at", first=10)
            for rel in rels or []:
                to = rel.get("to") or {}
                ctx["locations"].append({
                    "type": to.get("entity_type"),
                    "name": to.get("name"),
                    "latitude": to.get("latitude"),
                    "longitude": to.get("longitude"),
                })
        except Exception as exc:
            log.debug("Relasi located-at gagal dibaca: %s", exc)

    indicator_ids = set()
    if observable_id:
        for direction in ("fromId", "toId"):
            try:
                relations = client.stix_core_relationship.list(
                    **{direction: observable_id}, relationship_type="based-on", first=100
                )
            except Exception as exc:
                log.debug("Relasi indicator based-on gagal dibaca (%s): %s", direction, exc)
                continue
            for relation in relations or []:
                for endpoint in (relation.get("from"), relation.get("to")):
                    if (isinstance(endpoint, dict)
                            and str(endpoint.get("entity_type") or "").lower() == "indicator"
                            and endpoint.get("id")):
                        indicator_ids.add(str(endpoint["id"]))
    for indicator_id in sorted(indicator_ids):
        try:
            add_indicator(client.indicator.read(id=indicator_id))
        except Exception as exc:
            log.debug("Indicator OpenCTI %s gagal dibaca: %s", indicator_id, exc)
    if not ctx["indicators"]:
        add_indicators_by_value(observable_value)

    related_entities = {}
    relationships = {}
    events = {}
    sightings = {}
    source_ids = []
    if observable_id:
        source_ids.append(str(observable_id))
    source_ids.extend(
        str(indicator["id"])
        for indicator in indicator_records
        if indicator.get("id")
    )
    source_ids = list(dict.fromkeys(source_ids))
    related_data_truncated = len(source_ids) > 21
    source_ids = source_ids[:21]
    for source_id in source_ids:
        for direction in ("fromId", "toId"):
            try:
                related = client.stix_core_relationship.list(
                    **{direction: source_id}, first=100
                ) or []
            except Exception as exc:
                log.debug(
                    "Relasi OpenCTI entity=%s direction=%s gagal dibaca: %s",
                    source_id, direction, exc,
                )
                continue
            if len(related) >= 100:
                related_data_truncated = True
            for relation in related:
                if not isinstance(relation, dict):
                    continue
                endpoints = {
                    name: _opencti_entity_summary(relation.get(name))
                    for name in ("from", "to")
                }
                relation_type = relation.get("relationship_type")
                endpoint_ids = tuple(
                    (endpoints[name] or {}).get("id") for name in ("from", "to")
                )
                identity = relation.get("id") or (
                    relation_type, endpoint_ids,
                )
                if identity not in relationships:
                    relationship = _opencti_entity_summary(relation) or {}
                    relationship.update({
                        "relationship_type": relation_type,
                        "from": endpoints["from"],
                        "to": endpoints["to"],
                    })
                    relationships[identity] = relationship

                for name in ("from", "to"):
                    entity = endpoints[name]
                    if not entity:
                        continue
                    entity_id = entity.get("id")
                    entity_type = str(entity.get("entity_type") or "").casefold()
                    if (
                        not entity_id
                        or str(entity_id) == source_id
                        or entity_type in {"indicator", "stix-core-relationship",
                                           "stix-sighting-relationship"}
                        or entity_id == observable_id
                    ):
                        continue
                    if entity_type in {"event", "x-opencti-event"}:
                        events.setdefault(str(entity_id), entity)
                        continue
                    related_entities.setdefault(str(entity_id), entity)

        sighting_api = getattr(client, "stix_sighting_relationship", None)
        if sighting_api is not None:
            for direction in ("fromId", "toId"):
                try:
                    related_sightings = sighting_api.list(
                        **{direction: source_id}, first=100
                    ) or []
                except Exception as exc:
                    log.debug(
                        "Sighting OpenCTI entity=%s direction=%s gagal dibaca: %s",
                        source_id, direction, exc,
                    )
                    continue
                if len(related_sightings) >= 100:
                    related_data_truncated = True
                for sighting in related_sightings:
                    if not isinstance(sighting, dict):
                        continue
                    sighting_id = sighting.get("id")
                    identity = sighting_id or (
                        sighting.get("fromId"), sighting.get("toId"),
                        sighting.get("first_seen"), sighting.get("last_seen"),
                    )
                    if identity in sightings:
                        continue
                    summary = _opencti_entity_summary(sighting) or {}
                    summary.update({
                        "id": sighting_id,
                        "from": _opencti_entity_summary(sighting.get("from")),
                        "to": _opencti_entity_summary(sighting.get("to")),
                    })
                    sightings[identity] = summary

    if (
        len(relationships) > 100 or len(related_entities) > 50
        or len(events) > 50 or len(sightings) > 50
    ):
        related_data_truncated = True
    ctx["relationships"] = list(relationships.values())[:100]
    ctx["related_entities"] = list(related_entities.values())[:50]
    ctx["events"] = list(events.values())[:50]
    ctx["sightings"] = list(sightings.values())[:50]
    ctx["indicator_match_count"] = len(seen_indicators)
    ctx["related_entity_count"] = len(related_entities)
    ctx["relationship_count"] = len(relationships)
    ctx["event_count"] = len(events)
    ctx["sighting_count"] = len(sightings)
    ctx["related_data_truncated"] = related_data_truncated
    return ctx


# ------------------------------------------------------------------ Geolocation
def geolocation(ip):
    if not is_public_ip(ip):
        return {"available": False, "reason": "private/reserved IP"}

    if IPINFO_TOKEN:
        d = _get_json(f"https://ipinfo.io/{ip}", params={"token": IPINFO_TOKEN})
        if d:
            lat = lon = None
            if d.get("loc"):
                lat, lon = [float(x) for x in d["loc"].split(",")]
            return {
                "available": True, "provider": "ipinfo",
                "country": d.get("country"), "region": d.get("region"),
                "city": d.get("city"), "org": d.get("org"),
                "timezone": d.get("timezone"),
                "location": {"lat": lat, "lon": lon} if lat is not None else None,
            }
        return {"available": False}

    # ip-api.com: gratis, HTTP saja, non-komersial, 45 request/menit
    fields = "status,country,countryCode,regionName,city,lat,lon,isp,org,as,hosting,proxy,mobile,timezone"
    d = _get_json(f"http://ip-api.com/json/{ip}", params={"fields": fields})
    if d and d.get("status") == "success":
        return {
            "available": True, "provider": "ip-api",
            "country": d.get("countryCode"), "country_name": d.get("country"),
            "region": d.get("regionName"), "city": d.get("city"),
            "isp": d.get("isp"), "org": d.get("org"), "asn": d.get("as"),
            "hosting": d.get("hosting"), "proxy": d.get("proxy"),
            "mobile": d.get("mobile"), "timezone": d.get("timezone"),
            "location": {"lat": d.get("lat"), "lon": d.get("lon")},
        }
    return {"available": False}
    

# ------------------------------------------------------------------ Reputation
def abuseipdb(ip):
    if not ABUSEIPDB_KEY or not is_public_ip(ip):
        return None
    d = _get_json("https://api.abuseipdb.com/api/v2/check",
                  headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                  params={"ipAddress": ip, "maxAgeInDays": 90})
    if d and d.get("data"):
        x = d["data"]
        return {
            "confidence_score": x.get("abuseConfidenceScore"),
            "total_reports": x.get("totalReports"),
            "last_reported": x.get("lastReportedAt"),
            "usage_type": x.get("usageType"),
            "isp": x.get("isp"),
            "is_tor": x.get("isTor"),
        }
    return None


def virustotal(kind, value):
    """kind: 'ip_addresses', 'domains', atau 'files'."""
    if not VT_API_KEY:
        return None
    time.sleep(VT_DELAY)  # jaga rate limit free tier
    d = _get_json(f"https://www.virustotal.com/api/v3/{kind}/{value}",
                  headers={"x-apikey": VT_API_KEY})
    return (d or {}).get("data", {}).get("attributes")


def verdict(opencti_score, abuse, vt_stats):
    malicious = (vt_stats or {}).get("malicious", 0)
    suspicious = (vt_stats or {}).get("suspicious", 0)
    abuse_score = (abuse or {}).get("confidence_score") or 0
    score = opencti_score or 0
    if abuse_score >= 75 or malicious >= 5 or score >= 80:
        return "malicious"
    if abuse_score >= 25 or malicious >= 1 or suspicious >= 1 or score >= 50:
        return "suspicious"
    if abuse is None and not vt_stats and not score:
        return "unknown"
    return "clean"


# ------------------------------------------------------------------ Domain age
def domain_age(domain, vt_attrs=None):
    created, source = None, None
    parts = domain.split(".")
    for i in range(max(len(parts) - 1, 1)):
        candidate = ".".join(parts[i:])
        data = _get_json(f"https://rdap.org/domain/{candidate}")
        if data:
            for ev in data.get("events", []):
                if ev.get("eventAction") == "registration":
                    created, source = ev.get("eventDate"), "rdap"
                    break
            if created:
                break
    if not created and vt_attrs and vt_attrs.get("creation_date"):
        created = datetime.fromtimestamp(vt_attrs["creation_date"], timezone.utc).isoformat()
        source = "virustotal"
    if not created:
        return {"available": False}
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return {"available": False}
    days = (datetime.now(timezone.utc) - dt).days
    return {"available": True, "created": dt.isoformat(), "age_days": days,
            "is_newly_registered": days < 30, "source": source}


# ------------------------------------------------------------------ Asset info (GLPI)
def _glpi_ip_search_fields(options):
    fields = set()

    def visit(value, key=None):
        if isinstance(value, dict):
            option_id = value.get("id") or key
            field_name = re.sub(r"[^a-z0-9]", "", str(value.get("field") or "").lower())
            label = re.sub(r"[^a-z0-9]", "", str(value.get("name") or "").lower())
            is_ip_field = (
                field_name in {"ip", "ipaddress", "ipv4", "ipv6", "ipv4address", "ipv6address"}
                or label in {"ip", "ipaddress", "ipv4", "ipv6", "ipv4address", "ipv6address"}
            )
            if is_ip_field and str(option_id).isdigit():
                fields.add(str(option_id))
            for child_key, child in value.items():
                if isinstance(child, (dict, list)):
                    visit(child, child_key)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(options)
    return sorted(fields, key=int)


def _glpi_ip_values(value):
    if isinstance(value, dict):
        for key in ("ip", "address", "value", "name"):
            if value.get(key) is not None:
                yield from _glpi_ip_values(value[key])
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _glpi_ip_values(item)
        return
    if not isinstance(value, str):
        return
    candidates = re.findall(
        r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"
        r"|(?<![0-9A-Fa-f:])[0-9A-Fa-f:]*:[0-9A-Fa-f:]+(?:/\d{1,3})?",
        value,
    )
    for candidate in candidates:
        try:
            yield str(ipaddress.ip_interface(candidate).ip if "/" in candidate
                      else ipaddress.ip_address(candidate))
        except ValueError:
            continue


def _glpi_records(payload):
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("data", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                return [value]
        return [payload]
    return []


def _network_name_search_fields(glpi, token):
    try:
        options_response = requests.get(
            f"{glpi['url']}/listSearchOptions/NetworkName",
            headers=glpi["headers"](token),
            timeout=30,
        )
        options_response.raise_for_status()
        options = options_response.json()
        item_type_fields = _glpi_search_fields(options, {"itemtype", "item type"})
        item_id_fields = _glpi_search_fields(options, {"items_id", "item id"})
        id_fields = _glpi_search_fields(options, {"id"})
        if not item_type_fields or not item_id_fields or not id_fields:
            log.warning("GLPI NetworkName search options omit ID, item type, or item ID")
            return None
        return item_type_fields[0], item_id_fields[0], id_fields[0]
    except (requests.RequestException, ValueError) as exc:
        log.warning("GLPI NetworkName search options gagal dibaca: %s", exc)
        return None


def _network_name_ids(item_type, item_id, glpi, token, search_fields):
    if not search_fields:
        return []
    item_type_field, item_id_field, id_field = search_fields
    try:
        params = {
            "range": "0-49",
            "criteria[0][field]": item_id_field,
            "criteria[0][searchtype]": "equals",
            "criteria[0][value]": str(item_id),
            "criteria[1][field]": item_type_field,
            "criteria[1][searchtype]": "equals",
            "criteria[1][value]": item_type,
            "criteria[1][link]": "AND",
            "forcedisplay[0]": id_field,
            "forcedisplay[1]": item_id_field,
            "forcedisplay[2]": item_type_field,
        }
        response = requests.get(
            f"{glpi['url']}/search/NetworkName",
            headers=glpi["headers"](token),
            params=params,
            timeout=30,
        )
        if response.status_code not in (200, 206):
            raise requests.HTTPError(
                f"GLPI NetworkName search returned HTTP {response.status_code}"
            )
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        log.warning(
            "GLPI NetworkName lookup itemtype=%s id=%s gagal: %s",
            item_type, item_id, exc,
        )
        return []

    ids = set()
    for row in _glpi_records(payload):
        row_type = row.get(item_type_field, row.get(int(item_type_field)))
        row_item_id = row.get(item_id_field, row.get(int(item_id_field)))
        network_name_id = row.get(id_field, row.get(int(id_field))) or row.get("id")
        if (
            network_name_id
            and str(row_type).casefold() == item_type.casefold()
            and str(row_item_id) == str(item_id)
        ):
            ids.add(str(network_name_id))
    return sorted(ids)


def _network_name_ip_addresses(network_name_id, glpi, token):
    try:
        response = requests.get(
            f"{glpi['url']}/NetworkName/{network_name_id}/IPAddress",
            headers=glpi["headers"](token),
            timeout=30,
        )
        response.raise_for_status()
        ip_addresses = _glpi_records(response.json())
    except (requests.RequestException, ValueError) as exc:
        log.warning(
            "IPAddress GLPI network name=%s gagal dibaca: %s",
            network_name_id, exc,
        )
        return set()
    return {
        address
        for item in ip_addresses
        for address in _glpi_ip_values(item)
    }


def _classify_ip_addresses(addresses):
    private_networks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("fc00::/7"),
    )
    classified = {
        "private_ip_addresses": [],
        "public_ip_addresses": [],
        "other_ip_addresses": [],
    }
    for value in addresses:
        address = ipaddress.ip_address(value)
        if address.is_global:
            category = "public_ip_addresses"
        elif any(
            address.version == network.version and address in network
            for network in private_networks
        ):
            category = "private_ip_addresses"
        else:
            category = "other_ip_addresses"
        classified[category].append(str(address))
    return {
        key: sorted(set(values), key=lambda value: (
            ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))
        ))
        for key, values in classified.items()
    }


def _computer_ip_addresses(computer_id, glpi, token):
    addresses = set()
    try:
        response = requests.get(
            f"{glpi['url']}/Computer/{computer_id}/NetworkPort",
            headers=glpi["headers"](token),
            timeout=30,
        )
        response.raise_for_status()
        ports = _glpi_records(response.json())
    except (requests.RequestException, ValueError) as exc:
        log.warning("NetworkPort aset GLPI id=%s gagal dibaca: %s", computer_id, exc)
        ports = []

    requests_remaining = 20
    network_name_search_fields = _network_name_search_fields(glpi, token)
    network_name_ids = set(_network_name_ids(
        "Computer", computer_id, glpi, token, network_name_search_fields
    ))
    for port in ports[:10]:
        addresses.update(_glpi_ip_values(port))
        port_id = port.get("id") or port.get("networkports_id")
        if not port_id:
            continue
        network_name_ids.update(_network_name_ids(
            "NetworkPort", port_id, glpi, token, network_name_search_fields
        ))
        if requests_remaining <= 0:
            continue
        try:
            response = requests.get(
                f"{glpi['url']}/NetworkPort/{port_id}/NetworkName",
                headers=glpi["headers"](token),
                timeout=30,
            )
            requests_remaining -= 1
            response.raise_for_status()
            network_names = _glpi_records(response.json())
        except (requests.RequestException, ValueError) as exc:
            log.warning("NetworkName GLPI port=%s gagal dibaca: %s", port_id, exc)
            continue

        for network_name in network_names[:5]:
            addresses.update(_glpi_ip_values(network_name))
            network_name_id = network_name.get("id") or network_name.get("networknames_id")
            if network_name_id:
                network_name_ids.add(str(network_name_id))

    for network_name_id in sorted(network_name_ids):
        if requests_remaining <= 0:
            break
        addresses.update(_network_name_ip_addresses(network_name_id, glpi, token))
        requests_remaining -= 1

    return sorted(
        addresses,
        key=lambda value: (ipaddress.ip_address(value).version,
                           int(ipaddress.ip_address(value))),
    )[:32]


def _glpi_search_fields(options, accepted_names):
    fields = set()
    accepted_names = {re.sub(r"[^a-z0-9]", "", name.lower()) for name in accepted_names}

    def visit(value, key=None):
        if isinstance(value, dict):
            option_id = value.get("id") or key
            field_name = re.sub(
                r"[^a-z0-9]", "", str(value.get("field") or "").lower()
            )
            label = re.sub(r"[^a-z0-9]", "", str(value.get("name") or "").lower())
            if (field_name in accepted_names or label in accepted_names) and str(option_id).isdigit():
                fields.add(str(option_id))
            for child_key, child in value.items():
                if isinstance(child, (dict, list)):
                    visit(child, child_key)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(options)
    return sorted(fields, key=int)


def asset_info(ip, glpi, token):
    if not ASSET_ENABLED or token is None:
        return {"found": False, "items": [], "error": "GLPI asset lookup is disabled"}
    try:
        options_response = requests.get(
            f"{glpi['url']}/listSearchOptions/NetworkPort",
            headers=glpi["headers"](token),
            timeout=30,
        )
        options_response.raise_for_status()
        ip_fields = _glpi_ip_search_fields(options_response.json())
        if not ip_fields:
            raise ValueError("GLPI NetworkPort search options do not expose an IP field")

        params = {"range": "0-9"}
        for index, field_id in enumerate(ip_fields):
            params[f"criteria[{index}][field]"] = field_id
            params[f"criteria[{index}][searchtype]"] = "contains"
            params[f"criteria[{index}][value]"] = ip
            if index:
                params[f"criteria[{index}][link]"] = "OR"
        display_fields = list(dict.fromkeys(["2", "20", "21", *ip_fields]))
        for index, field_id in enumerate(display_fields):
            params[f"forcedisplay[{index}]"] = field_id
        res = requests.get(f"{glpi['url']}/search/NetworkPort",
                           headers=glpi["headers"](token), params=params, timeout=30)
        res.raise_for_status()
        response_data = res.json()
    except (requests.RequestException, ValueError) as e:
        log.warning("GLPI asset search gagal: %s", e)
        return {"found": False, "items": [], "error": str(e)}
    if res.status_code not in (200, 206):
        log.warning("GLPI asset search status %s: %s", res.status_code, res.text[:150])
        return {
            "found": False,
            "items": [],
            "error": f"GLPI search returned HTTP {res.status_code}",
        }

    items = []
    search_errors = []

    def computer_asset(computer_id, base):
        item = {
            "id": computer_id,
            "name": base.get("name"),
            "location": base.get("location"),
            "type": base.get("type"),
            "status": base.get("status"),
            "user": base.get("user"),
            "ip": base.get("ip") or ip,
            "ip_addresses": [],
            "private_ip_addresses": [],
            "public_ip_addresses": [],
            "other_ip_addresses": [],
            "serial_number": None,
            "asset_tag": None,
            "operating_system": None,
            "owner": base.get("user"),
            "manufacturer": None,
            "model": None,
            "entity": None,
            "group": None,
            "contact": None,
            "contact_number": None,
            "description": None,
            "created_at": None,
            "updated_at": None,
            "purchase_date": None,
        }
        if not computer_id:
            return item
        try:
            details_res = requests.get(
                f"{glpi['url']}/Computer/{computer_id}",
                headers=glpi["headers"](token),
                params={"expand_dropdowns": "true"},
                timeout=30,
            )
            details_res.raise_for_status()
            details = details_res.json()
            item["name"] = details.get("name") or item["name"]
            base_ips = list(_glpi_ip_values(base.get("ip")))
            item["ip_addresses"] = list(dict.fromkeys([
                *base_ips, *_computer_ip_addresses(computer_id, glpi, token)
            ]))[:32]
            item.update(_classify_ip_addresses(item["ip_addresses"]))
            item["ip"] = (
                ip if ip in item["ip_addresses"] or not item["ip_addresses"]
                else item["ip_addresses"][0]
            )
            item["serial_number"] = details.get("serial")
            item["asset_tag"] = details.get("otherserial")
            item["status"] = _glpi_dropdown_name(
                details.get("states_id"), "State", glpi, token
            ) or item["status"]
            item["location"] = _glpi_dropdown_name(
                details.get("locations_id"), "Location", glpi, token
            ) or details.get("location") or item["location"]
            item["type"] = _glpi_dropdown_name(
                details.get("computertypes_id"), "ComputerType", glpi, token
            ) or details.get("type") or item["type"]
            item["manufacturer"] = _glpi_dropdown_name(
                details.get("manufacturers_id"), "Manufacturer", glpi, token
            )
            item["model"] = _glpi_dropdown_name(
                details.get("computermodels_id"), "ComputerModel", glpi, token
            )
            item["entity"] = _glpi_dropdown_name(
                details.get("entities_id"), "Entity", glpi, token
            )
            item["group"] = _glpi_dropdown_name(
                details.get("groups_id"), "Group", glpi, token
            )
            item["contact"] = details.get("contact")
            item["contact_number"] = details.get("contact_num")
            item["description"] = details.get("comment")
            item["created_at"] = details.get("date_creation")
            item["updated_at"] = details.get("date_mod")
            item["purchase_date"] = details.get("date_buy")
            item["user"] = details.get("users_id") or details.get("user") or item["user"]
            item["owner"] = item["user"]
            try:
                os_relation = requests.get(
                    f"{glpi['url']}/Computer/{computer_id}/Item_OperatingSystem",
                    headers=glpi["headers"](token),
                    params={"expand_dropdowns": "true"},
                    timeout=30,
                )
                os_relation.raise_for_status()
                relations = os_relation.json()
                if isinstance(relations, dict):
                    relations = relations.get("data", [relations])
                os_data = relations[0] if isinstance(relations, list) and relations else {}
                os_name = _glpi_dropdown_name(
                    os_data.get("operatingsystems_id"),
                    "OperatingSystem",
                    glpi,
                    token,
                )
                if not os_name:
                    os_name = _glpi_dropdown_name(
                        details.get("operatingsystems_id"),
                        "OperatingSystem",
                        glpi,
                        token,
                    ) or details.get("os")
                os_version = _glpi_dropdown_name(
                    os_data.get("operatingsystemversions_id"),
                    "OperatingSystemVersion",
                    glpi,
                    token,
                ) or _glpi_dropdown_name(
                    details.get("operatingsystemversions_id"),
                    "OperatingSystemVersion",
                    glpi,
                    token,
                ) or details.get("os_version")
                item["operating_system"] = " ".join(
                    str(value) for value in (os_name, os_version) if value
                ) or None
            except (requests.RequestException, ValueError) as exc:
                log.warning("OS aset GLPI id=%s gagal dibaca: %s", computer_id, exc)
            owner = item["user"]
            if isinstance(owner, dict):
                owner = owner.get("name") or owner.get("id")
            if isinstance(owner, (int, str)) and str(owner).isdigit() and int(owner) > 0:
                try:
                    user_res = requests.get(
                        f"{glpi['url']}/User/{owner}",
                        headers=glpi["headers"](token),
                        params={"expand_dropdowns": "true"},
                        timeout=30,
                    )
                    user_res.raise_for_status()
                    user = user_res.json()
                    owner = " ".join(
                        str(value) for value in (user.get("firstname"), user.get("realname"))
                        if value
                    ) or user.get("name") or owner
                except (requests.RequestException, ValueError) as exc:
                    log.warning("Pemilik aset GLPI user=%s gagal dibaca: %s", owner, exc)
            item["owner"] = owner
        except (requests.RequestException, ValueError) as exc:
            log.warning("Detail aset GLPI id=%s gagal: %s", computer_id, exc)
        return item

    if not isinstance(response_data, dict):
        return {"found": False, "items": [], "error": "GLPI search returned an invalid response"}
    for row in response_data.get("data", []) or []:
        if not isinstance(row, dict):
            continue
        ips = [
            row.get(field_id, row.get(int(field_id)))
            for field_id in ip_fields
        ]
        matching_ips = list(dict.fromkeys(_glpi_ip_values(ips)))
        item_type = row.get("20", row.get(20))
        if ip not in matching_ips or str(item_type).lower() != "computer":
            continue
        computer_id = row.get("21", row.get(21))
        if not computer_id:
            continue
        items.append(computer_asset(computer_id, {"ip": matching_ips}))

    if not items:
        page_size = 100
        start = 0
        total = None
        seen_computers = set()
        while total is None or start < total:
            end = start + page_size - 1
            try:
                addresses_response = requests.get(
                    f"{glpi['url']}/IPAddress",
                    headers={
                        **glpi["headers"](token),
                        "Range": f"items={start}-{end}",
                    },
                    params={"range": f"{start}-{end}"},
                    timeout=30,
                )
                if addresses_response.status_code not in (200, 206):
                    raise requests.HTTPError(
                        f"GLPI IPAddress list returned HTTP {addresses_response.status_code}"
                    )
                addresses_payload = addresses_response.json()
            except (requests.RequestException, ValueError) as e:
                log.warning("GLPI IPAddress list gagal: %s", e)
                search_errors.append(str(e))
                break

            addresses = (
                addresses_payload if isinstance(addresses_payload, list)
                else addresses_payload.get("data", [])
                if isinstance(addresses_payload, dict) else []
            )
            if not isinstance(addresses, list) or not addresses:
                break
            content_range = addresses_response.headers.get("Content-Range", "")
            total_match = re.search(r"/(\d+)$", content_range)
            if total_match:
                total = int(total_match.group(1))

            for address in addresses:
                if not isinstance(address, dict):
                    continue
                if ip not in set(_glpi_ip_values(address.get("name"))):
                    continue
                item_type = str(address.get("mainitemtype") or "").lower()
                computer_id = address.get("mainitems_id")
                if item_type != "computer" or not computer_id:
                    continue
                if str(computer_id) in seen_computers:
                    continue
                seen_computers.add(str(computer_id))
                items.append(computer_asset(computer_id, {"ip": ip}))
                log.info(
                    "GLPI IPAddress cocok ip=%s address=%s computer=%s",
                    ip, address.get("id"), computer_id,
                )

            start += page_size
            if total is None and len(addresses) < page_size:
                break

    error = "; ".join(search_errors) or None
    return {"found": bool(items), "items": items, "error": error}


def asset_info_by_name(host_name, glpi, token):
    if not ASSET_ENABLED or token is None:
        return {"found": False, "items": [], "error": "GLPI asset lookup is disabled"}
    host_name = str(host_name or "").strip()
    if not host_name:
        return {"found": False, "items": [], "error": "hostname is empty"}

    try:
        options_response = requests.get(
            f"{glpi['url']}/listSearchOptions/Computer",
            headers=glpi["headers"](token),
            timeout=30,
        )
        options_response.raise_for_status()
        name_fields = _glpi_search_fields(options_response.json(), {"name", "computername"})
        if not name_fields:
            raise ValueError("GLPI Computer search options do not expose a name field")

        params = {
            "range": "0-49",
            "criteria[0][field]": name_fields[0],
            "criteria[0][searchtype]": "equals",
            "criteria[0][value]": host_name,
            "forcedisplay[0]": "2",
            "forcedisplay[1]": name_fields[0],
        }
        response = requests.get(
            f"{glpi['url']}/search/Computer",
            headers=glpi["headers"](token),
            params=params,
            timeout=30,
        )
        if response.status_code not in (200, 206):
            raise requests.HTTPError(
                f"GLPI Computer search returned HTTP {response.status_code}"
            )
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("GLPI Computer search returned an invalid response")
    except (requests.RequestException, ValueError) as exc:
        log.warning("GLPI hostname asset search gagal: %s", exc)
        return {"found": False, "items": [], "error": str(exc)}

    matching = []
    for row in payload.get("data", []) or []:
        if not isinstance(row, dict):
            continue
        name = row.get(name_fields[0], row.get(int(name_fields[0])))
        computer_id = row.get("2", row.get(2)) or row.get("id")
        if (computer_id and isinstance(name, str)
                and name.strip().casefold() == host_name.casefold()):
            matching.append((computer_id, name.strip()))

    matching = list(dict.fromkeys(matching))
    if not matching:
        return {"found": False, "items": [], "error": None}
    if len(matching) != 1:
        return {
            "found": False,
            "items": [],
            "error": f"GLPI hostname lookup is ambiguous ({len(matching)} exact matches)",
        }

    computer_id, name = matching[0]
    item = {
        "id": computer_id,
        "name": name,
        "ip": None,
        "ip_addresses": [],
        "private_ip_addresses": [],
        "public_ip_addresses": [],
        "other_ip_addresses": [],
        "location": None,
        "type": None,
        "status": None,
        "user": None,
        "owner": None,
        "serial_number": None,
        "asset_tag": None,
        "operating_system": None,
        "manufacturer": None,
        "model": None,
        "entity": None,
        "group": None,
        "contact": None,
        "contact_number": None,
        "description": None,
        "created_at": None,
        "updated_at": None,
        "purchase_date": None,
    }
    try:
        details_response = requests.get(
            f"{glpi['url']}/Computer/{computer_id}",
            headers=glpi["headers"](token),
            params={"expand_dropdowns": "true"},
            timeout=30,
        )
        details_response.raise_for_status()
        details = details_response.json()
        item["name"] = details.get("name") or name
        item["ip_addresses"] = _computer_ip_addresses(computer_id, glpi, token)
        item.update(_classify_ip_addresses(item["ip_addresses"]))
        item["ip"] = item["ip_addresses"][0] if item["ip_addresses"] else None
        item["serial_number"] = details.get("serial")
        item["asset_tag"] = details.get("otherserial")
        item["status"] = _glpi_dropdown_name(
            details.get("states_id"), "State", glpi, token
        )
        item["location"] = _glpi_dropdown_name(
            details.get("locations_id"), "Location", glpi, token
        )
        item["type"] = _glpi_dropdown_name(
            details.get("computertypes_id"), "ComputerType", glpi, token
        )
        item["manufacturer"] = _glpi_dropdown_name(
            details.get("manufacturers_id"), "Manufacturer", glpi, token
        )
        item["model"] = _glpi_dropdown_name(
            details.get("computermodels_id"), "ComputerModel", glpi, token
        )
        item["entity"] = _glpi_dropdown_name(
            details.get("entities_id"), "Entity", glpi, token
        )
        item["group"] = _glpi_dropdown_name(
            details.get("groups_id"), "Group", glpi, token
        )
        item["contact"] = details.get("contact")
        item["contact_number"] = details.get("contact_num")
        item["description"] = details.get("comment")
        item["created_at"] = details.get("date_creation")
        item["updated_at"] = details.get("date_mod")
        item["purchase_date"] = details.get("date_buy")
        owner = details.get("users_id") or details.get("user")
        if isinstance(owner, dict):
            owner = owner.get("name") or owner.get("id")
        if isinstance(owner, (int, str)) and str(owner).isdigit() and int(owner) > 0:
            try:
                user_response = requests.get(
                    f"{glpi['url']}/User/{owner}",
                    headers=glpi["headers"](token),
                    params={"expand_dropdowns": "true"},
                    timeout=30,
                )
                user_response.raise_for_status()
                user = user_response.json()
                owner = " ".join(
                    str(value) for value in (user.get("firstname"), user.get("realname"))
                    if value
                ) or user.get("name") or owner
            except (requests.RequestException, ValueError) as exc:
                log.warning("Pemilik aset GLPI user=%s gagal dibaca: %s", owner, exc)
        item["user"] = owner
        item["owner"] = owner
        try:
            os_response = requests.get(
                f"{glpi['url']}/Computer/{computer_id}/Item_OperatingSystem",
                headers=glpi["headers"](token),
                params={"expand_dropdowns": "true"},
                timeout=30,
            )
            os_response.raise_for_status()
            os_relations = os_response.json()
            if isinstance(os_relations, dict):
                os_relations = os_relations.get("data", [os_relations])
            os_data = os_relations[0] if isinstance(os_relations, list) and os_relations else {}
            os_name = _glpi_dropdown_name(
                os_data.get("operatingsystems_id"), "OperatingSystem", glpi, token
            ) or _glpi_dropdown_name(
                details.get("operatingsystems_id"), "OperatingSystem", glpi, token
            ) or details.get("os")
            os_version = _glpi_dropdown_name(
                os_data.get("operatingsystemversions_id"),
                "OperatingSystemVersion",
                glpi,
                token,
            ) or _glpi_dropdown_name(
                details.get("operatingsystemversions_id"),
                "OperatingSystemVersion",
                glpi,
                token,
            ) or details.get("os_version")
            item["operating_system"] = " ".join(
                str(value) for value in (os_name, os_version) if value
            ) or None
        except (requests.RequestException, ValueError) as exc:
            log.warning("OS aset GLPI id=%s gagal dibaca: %s", computer_id, exc)
    except (requests.RequestException, ValueError) as exc:
        log.warning("Detail aset GLPI id=%s gagal: %s", computer_id, exc)

    return {"found": True, "items": [item], "error": None}


def _glpi_dropdown_name(value, endpoint, glpi, token):
    if value is None or value == 0 or value == "":
        return None
    if isinstance(value, dict):
        name = value.get("name")
        if name:
            return str(name)
        value = value.get("id")
        if value is None:
            return None
    if isinstance(value, str) and not value.isdigit():
        return value
    try:
        response = requests.get(
            f"{glpi['url']}/{endpoint}/{value}",
            headers=glpi["headers"](token),
            params={"expand_dropdowns": "true"},
            timeout=30,
        )
        response.raise_for_status()
        dropdown = response.json()
        return dropdown.get("name") if isinstance(dropdown, dict) else None
    except (requests.RequestException, ValueError) as e:
        log.warning("GLPI dropdown %s id=%s gagal dibaca: %s", endpoint, value, e)
        return None


# ------------------------------------------------------------------ Orkestrasi
def enrich_one(client, r, obs, glpi, token, include_asset=True, connector_results=None):
    etype = obs["entity_type"]
    hash_info = file_hash(obs) if etype == "StixFile" else None
    value = hash_info["value"] if hash_info else obs.get("observable_value")
    if etype == "StixFile" and not hash_info:
        log.info("StixFile %s dilewati: tidak memiliki hash MD5/SHA-1/SHA-256/SHA-512 valid",
                 obs.get("id", "-"))
        return None
    if obs.get("id"):
        try:
            refreshed = client.stix_cyber_observable.read(id=obs["id"])
            if isinstance(refreshed, dict):
                obs = refreshed
        except Exception:
            log.exception("Observable OpenCTI gagal dibaca ulang setelah enrichment id=%s",
                          obs["id"])
    ctx = opencti_context(client, obs)
    if connector_results is not None:
        ctx["connectors"] = connector_results

    cache_key = f"enrich:cache:{etype}:{value}"
    cached = r.get(cache_key)
    if cached:
        ext = json.loads(cached)
    else:
        ext = {}
        if etype in ("IPv4-Addr", "IPv6-Addr"):
            ext["geolocation"] = geolocation(value)
            ab = abuseipdb(value)
            vt = virustotal("ip_addresses", value)
            vt_stats = (vt or {}).get("last_analysis_stats")
            ext["reputation"] = {
                "abuseipdb": ab,
                "virustotal": {"stats": vt_stats, "reputation": (vt or {}).get("reputation")}
                if vt else None,
            }
            ext["_vt_stats"] = vt_stats
            ext["_abuse"] = ab
        elif etype == "Domain-Name":
            vt = virustotal("domains", value)
            vt_stats = (vt or {}).get("last_analysis_stats")
            ext["reputation"] = {
                "abuseipdb": None,
                "virustotal": {"stats": vt_stats, "reputation": (vt or {}).get("reputation"),
                               "categories": (vt or {}).get("categories")} if vt else None,
            }
            ext["domain_age"] = domain_age(value, vt)
            ext["_vt_stats"] = vt_stats
            ext["_abuse"] = None
        else:  # StixFile
            vt = virustotal("files", value)
            vt_stats = (vt or {}).get("last_analysis_stats")
            ext["reputation"] = {
                "abuseipdb": None,
                "virustotal": {
                    "stats": vt_stats,
                    "reputation": (vt or {}).get("reputation"),
                    "meaningful_name": (vt or {}).get("meaningful_name"),
                    "type_description": (vt or {}).get("type_description"),
                } if vt else None,
            }
            ext["_vt_stats"] = vt_stats
            ext["_abuse"] = None
        r.setex(cache_key, CACHE_TTL, json.dumps(ext, default=str))

    doc = {
        "type": "enrichment",
        "entity_type": etype,
        "value": value,
        "created_at": obs.get("created_at"),
        "opencti": ctx,
        "reputation": ext.get("reputation") or {},
    }
    if obs.get("id"):
        doc["id"] = obs["id"]
    reputation = doc["reputation"]
    vt_data = reputation.get("virustotal")
    vt_stats = ext.get("_vt_stats") or (
        vt_data.get("stats") if isinstance(vt_data, dict) else None
    )
    provider_status = reputation.get("provider_status")
    provider_status = dict(provider_status) if isinstance(provider_status, dict) else {}
    if etype in ("IPv4-Addr", "IPv6-Addr"):
        provider_status.setdefault(
            "abuseipdb",
            "API key belum dikonfigurasi" if not ABUSEIPDB_KEY else
            "tidak berlaku untuk IP private/reserved" if not is_public_ip(value) else
            "data ditemukan" if ext.get("_abuse") or reputation.get("abuseipdb") else
            "tidak ada record atau API gagal; periksa log collector",
        )
    else:
        provider_status.setdefault("abuseipdb", "lookup IP saja; tidak berlaku untuk IOC ini")
    provider_status.setdefault(
        "virustotal",
        "API key belum dikonfigurasi" if not VT_API_KEY else
        "data ditemukan" if vt_data else
        "tidak ada record atau API gagal; periksa log collector",
    )
    reputation["provider_status"] = provider_status
    if hash_info:
        doc["file_hash"] = hash_info
    doc["reputation"]["opencti_score"] = ctx["score"]
    doc["reputation"]["labels"] = ctx["labels"]
    doc["reputation"]["verdict"] = verdict(ctx["score"], ext.get("_abuse"), ext.get("_vt_stats"))

    if etype in ("IPv4-Addr", "IPv6-Addr"):
        doc["geolocation"] = ext.get("geolocation") or {"available": False}
        if include_asset:
            doc["asset"] = asset_info(value, glpi, token)   # selalu fresh, tidak di-cache
    elif etype == "Domain-Name":
        doc["domain_age"] = ext.get("domain_age") or {"available": False}
    return doc


def collect_enrichment(client, r, push, glpi, state_key="collector:state"):
    last = r.hget(state_key, "enrich_last") or "1970-01-01T00:00:00.000Z"
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=ENRICH_DELAY)
              ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    filters = {
        "mode": "and",
        "filters": [
            {"key": "created_at", "values": [last], "operator": "gt"},
            {"key": "created_at", "values": [cutoff], "operator": "lt"},
        ],
        "filterGroups": [],
    }
    items = client.stix_cyber_observable.list(
        types=OBS_TYPES, filters=filters,
        orderBy="created_at", orderMode="asc", first=MAX_PER_CYCLE)
    if not items:
        log.info("Enrichment: tidak ada observable baru")
        return

    token = None
    if ASSET_ENABLED and any(i["entity_type"] in ("IPv4-Addr", "IPv6-Addr") for i in items):
        try:
            token = glpi["session"]()
        except Exception as e:
            log.warning("Sesi GLPI untuk asset info gagal: %s", e)

    connectors, inventory_error = connector_inventory(client)
    done = 0
    try:
        for obs in items:
            try:
                connector_results = connector_lookup_status(
                    client, r, obs, connectors, inventory_error
                )
                doc = enrich_one(
                    client, r, obs, glpi, token,
                    connector_results=connector_results,
                )
                if doc is not None:
                    push("enrichment-events", "enrichment", doc)
                    done += 1
            except Exception as e:
                log.error("Enrichment %s gagal: %s", obs.get("observable_value"), e)
            r.hset(state_key, "enrich_last", obs["created_at"])
    finally:
        if token:
            glpi["kill"](token)
    log.info("Enrichment: %d observable diperkaya", done)
