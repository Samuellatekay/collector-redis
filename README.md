# Collector OpenCTI + GLPI <-> Redis <-> Logstash

## 1. Redis (VM-1, /etc/redis/redis.conf)
    bind 0.0.0.0
    protected-mode yes
    requirepass GantiPasswordKuat
    maxmemory 512mb
    maxmemory-policy noeviction
    sudo systemctl restart redis-server
    sudo ufw allow from <IP_DOCKER_HOST> to any port 6379
    sudo ufw allow from <IP_LOGSTASH>   to any port 6379

## 2. GLPI
Setup > General > API: aktifkan REST API + login with user token.
Buat App-Token (API clients) dan ambil User-Token (Remote access keys).

## 3. Jalankan collector
    cd collector
    cp .env.example .env     # isi nilainya
    docker compose up -d --build
    docker logs -f opencti-glpi-collector

## 4. Logstash (VM-2)
Salin logstash/collector.conf ke /etc/logstash/conf.d/ lalu restart Logstash.

## 5. Tes arah masuk
    redis-cli -h 192.168.1.10 -a PASS -n 2 rpush outbound-glpi \
      '{"action":"create_ticket","title":"Tes","content":"Halo GLPI","urgency":3}'

    redis-cli -h 192.168.1.10 -a PASS -n 2 rpush outbound-opencti \
      '{"action":"create_indicator","name":"Tes IP","pattern":"[ipv4-addr:value = '"'"'203.0.113.5'"'"']","score":60}'

Pesan gagal ada di list outbound-glpi:failed / outbound-opencti:failed.

## 6. Enrichment (Reputation, Geolocation, Asset Info, Domain Age)
Collector memperkaya observable baru OpenCTI (IP & domain) dan mengirim ke list `enrichment-events`.

| Data | Sumber |
|---|---|
| Reputation | skor+label OpenCTI, AbuseIPDB (ABUSEIPDB_KEY), VirusTotal (VT_API_KEY) |
| Geolocation | ip-api.com (gratis) atau ipinfo.io (IPINFO_TOKEN) + relasi located-at OpenCTI |
| Asset Info | GLPI Computer yang IP-nya cocok |
| Domain Age | RDAP (gratis), fallback VirusTotal |

Template Elasticsearch agar peta/tanggal terbaca benar (jalankan sekali di Kibana Dev Tools):

    PUT _index_template/enrichment
    {
      "index_patterns": ["enrichment-*"],
      "template": { "mappings": { "properties": {
        "geolocation": { "properties": { "location": { "type": "geo_point" } } },
        "domain_age":  { "properties": { "created": { "type": "date" } } }
      } } }
    }
