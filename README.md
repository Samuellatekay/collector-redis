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

## 4. Pantau alur data OpenCTI/GLPI
Jalankan dari folder yang berisi `docker-compose.yml` dan `.env`:

    docker compose --profile tools run --build --rm flow-viewer

Viewer akan menampilkan payload lengkap yang baru melewati Redis, termasuk perintah
menuju OpenCTI/GLPI (`outbound-opencti`, `outbound-glpi`) serta data yang dibaca
dari OpenCTI/GLPI (`opencti-events`, `glpi-logs`). Viewer hanya menggunakan Redis
`REDIS_HOST`, `REDIS_PORT` (default 6379), `REDIS_PASS`, dan `REDIS_DB` (default 2)
dari `.env`; ia tidak menghapus pesan dari antrean. Hentikan dengan `Ctrl+C`.
Redis harus mengizinkan koneksi dari container Compose dan perintah `MONITOR`.

## 5. Logstash (VM-2)
Salin logstash/collector.conf ke /etc/logstash/conf.d/ lalu restart Logstash.

## 6. Tes arah masuk
    redis-cli -h 192.168.1.10 -a PASS -n 2 rpush outbound-glpi \
      '{"action":"create_ticket","title":"Tes","content":"Halo GLPI","urgency":3}'

    redis-cli -h 192.168.1.10 -a PASS -n 2 rpush outbound-opencti \
      '{"action":"create_indicator","name":"Tes IP","pattern":"[ipv4-addr:value = '"'"'203.0.113.5'"'"']","score":60}'

Pesan gagal ada di list outbound-glpi:failed / outbound-opencti:failed.

## 7. Enrichment (Reputation, Geolocation, Asset Info, Domain Age)
Collector memperkaya observable baru OpenCTI (IP, domain, dan file hash) dan mengirim ke list `enrichment-events`.

| Data | Sumber |
|---|---|
| Reputation | skor+label OpenCTI, AbuseIPDB (ABUSEIPDB_KEY), VirusTotal (VT_API_KEY) |
| Geolocation | ip-api.com (gratis) atau ipinfo.io (IPINFO_TOKEN) + relasi located-at OpenCTI |
| Asset Info | GLPI Computer yang IP-nya cocok |
| Domain Age | RDAP (gratis), fallback VirusTotal |
| File hash | SHA-512, SHA-256, SHA-1, atau MD5 dari observable StixFile; reputasi file via VirusTotal |

Alert dengan IP membuat indikator IP di OpenCTI dan tiket GLPI. Collector mencocokkan IP
tersebut dengan Computer inventaris GLPI dan menambahkan Name, User/pemilik, serial number,
operating system, dan status ke isi tiket. Informasi aset dikelola di GLPI, bukan diambil
dari inventaris Wazuh. Alert file integrity dengan hash membuat indikator `StixFile` di
OpenCTI; hash tidak dipakai untuk pencarian aset GLPI.

Event indikator OpenCTI di `opencti-events` menyertakan `score` dan `relations`.
Relasi memuat relasi masuk maupun keluar, dengan tipe relasi dan ringkasan entitas
`from`/`to`.

Polling OpenCTI/GLPI dan live stream indikator hanya meneruskan indikator atau tiket
yang deskripsi/judulnya diawali penanda `[from-collector]`, yaitu data yang dibuat
melalui collector dari antrean masuk. Data lain dari OpenCTI/GLPI tidak diteruskan
oleh jalur tersebut. Proses enrichment (`enrichment-events`) tetap memindai observable
baru sesuai konfigurasi enrichment dan tidak dibatasi oleh penanda ini.

Polling GLPI berjalan setiap 1 detik. OpenCTI memakai live stream bila
`OPENCTI_STREAM_ID` tersedia; jika tidak, polling fallback berjalan setiap 1 detik.
Jeda dihitung antarpemulaian siklus, sehingga panggilan API yang memakan waktu lebih
dari satu detik tetap membatasi frekuensi aktual. Enrichment tetap berjalan tiap
60 detik secara default.

Template Elasticsearch agar peta/tanggal terbaca benar (jalankan sekali di Kibana Dev Tools):

    PUT _index_template/enrichment
    {
      "index_patterns": ["enrichment-*"],
      "template": { "mappings": { "properties": {
        "geolocation": { "properties": { "location": { "type": "geo_point" } } },
        "domain_age":  { "properties": { "created": { "type": "date" } } }
      } } }
    }
