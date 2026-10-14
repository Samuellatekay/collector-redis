import os
import time
import json
import logging
import random
from datetime import datetime, timezone

import redis
from dotenv import load_dotenv

# Load environment variables from .env.local
load_dotenv(dotenv_path='./.env') or load_dotenv(dotenv_path='./.env.example')

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("simple_collector")

# --- Konfigurasi Redis dari Environment Variables ---
REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASS = os.getenv("REDIS_PASS", "")
REDIS_DB = int(os.getenv("REDIS_DB", "2"))

# --- Inisialisasi Klien Redis ---
def make_redis(**extra):
    return redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASS,
        db=REDIS_DB,
        decode_responses=True,
        socket_keepalive=True,
        health_check_interval=30,
        **extra,
    )

r = make_redis()

# --- Fungsi untuk mengirim data ke Redis ---
def push(key, source, doc):
    doc["@timestamp"] = datetime.now(timezone.utc).isoformat()
    doc["source_system"] = source
    try:
        r.rpush(key, json.dumps(doc, default=str))
        log.info(f"Data PUSHED to Redis key '{key}': {json.dumps(doc, default=str, indent=2)}")
    except redis.RedisError as e:
        log.error(f"Failed to PUSH to Redis key '{key}': {e}")

# --- Fungsi Simulasi Pengambilan Data OpenCTI ---
def simulate_opencti_data():
    indicator_id = f"indicator-{random.randint(1000, 9999)}"
    ip_address = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    score = random.randint(30, 90)
    
    data = {
        "id": indicator_id,
        "type": "indicator",
        "name": f"Suspicious IP from Simulator: {ip_address}",
        "pattern": f"[ipv4-addr:value = '{ip_address}']",
        "pattern_type": "stix",
        "valid_from": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "simulated_relations": [ # Contoh relasi sederhana
            {"relationship_type": "indicates", "target_ip": ip_address}
        ]
    }
    log.info(f"SIMULATING OpenCTI data: {json.dumps(data, indent=2)}")
    push("opencti-events", "simulated-opencti", data)

# --- Fungsi Simulasi Pengambilan Data GLPI ---
def simulate_glpi_data():
    ticket_id = random.randint(10000, 99999)
    status_choices = ["new", "assigned", "closed"]
    status = random.choice(status_choices)

    data = {
        "id": ticket_id,
        "type": "ticket",
        "title": f"Simulated GLPI Ticket: System Alert {ticket_id}",
        "status": status,
        "date_mod": datetime.now(timezone.utc).isoformat(),
    }
    log.info(f"SIMULATING GLPI data: {json.dumps(data, indent=2)}")
    push("glpi-logs", "simulated-glpi", data)

# --- Fungsi Simulasi Pengambilan Data Enrichment ---
def simulate_enrichment_data():
    observable_value = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    country_codes = ["ID", "US", "DE", "JP"]
    country = random.choice(country_codes)
    reputation_score = random.randint(10, 100)

    data = {
        "id": f"obs-{random.randint(1000, 9999)}",
        "type": "enrichment",
        "entity_type": "IPv4-Addr",
        "value": observable_value,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "opencti": {"score": random.randint(0, 100)},
        "reputation": {"opencti_score": reputation_score, "verdict": "suspicious"},
        "geolocation": {"available": True, "country": country, "city": "Simulated City"}
    }
    log.info(f"SIMULATING Enrichment data: {json.dumps(data, indent=2)}")
    push("enrichment-events", "simulated-enrichment", data)

# --- Main loop ---
if __name__ == "__main__":
    log.info("Starting simple data collector simulation...")
    log.info(f"Connecting to Redis at {REDIS_HOST}:{REDIS_PORT}, DB: {REDIS_DB}")

    # Cek koneksi Redis
    try:
        r.ping()
        log.info("Successfully connected to Redis.")
    except redis.exceptions.ConnectionError as e:
        log.critical(f"Could not connect to Redis: {e}. Please ensure Redis is running and accessible.")
        exit(1)

    cycle_count = 0
    while True:
        cycle_count += 1
        log.info(f"--- Simulation Cycle {cycle_count} ---")
        
        # Simulasi OpenCTI
        if random.random() < 0.7: # 70% chance to simulate OpenCTI data
            simulate_opencti_data()
        
        # Simulasi GLPI
        if random.random() < 0.5: # 50% chance to simulate GLPI data
            simulate_glpi_data()

        # Simulasi Enrichment
        if random.random() < 0.6: # 60% chance to simulate Enrichment data
            simulate_enrichment_data()

        sleep_time = random.uniform(5, 15) # Jeda acak antara 5-15 detik
        log.info(f"Sleeping for {sleep_time:.2f} seconds...")
        time.sleep(sleep_time)
