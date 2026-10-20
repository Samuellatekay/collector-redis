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

## 4a. Tes end-to-end dari Beats ke IRIS
Jalankan dari server aplikasi/collector yang memiliki Docker Compose dan dapat
mencapai input Beats Logstash:

    docker compose up -d --build collector
    bash test-stack.sh --beats-host <IP-atau-hostname-Logstash> --ip 38.60.253.35 --level 12 --yes

Skrip mengirim satu alert Wazuh sintetis lewat Beats port 5044 menggunakan Filebeat
Docker image. Event memakai rule level 12 agar pipeline mengirim alert asli ke Redis
`analysis-in` dan membuat clone ke `outbound-opencti` serta `outbound-glpi`. Skrip
kemudian menunggu Indicator dan ticket uji ditemukan, record aplikasi muncul di
PostgreSQL, enrichment masuk ke record, dan alert tercatat di IRIS. AI tetap berjalan
sesuai konfigurasi aplikasi, tetapi skrip tidak menunggu hasil AI dan status AI tidak
memengaruhi kelulusan tes.
`--yes` wajib karena tes membuat objek nyata di OpenCTI, GLPI, dan IRIS; hapus objek
uji setelah selesai. Tes tidak mengirim trafik ke IP `--ip`.
Karena Observable contoh mungkin sudah melewati cursor polling collector, skrip
meminta collector memperkaya ulang hanya IP uji tersebut dan menerbitkan satu
`enrichment-events`; cursor global tidak diubah. Waktu tunggu dibatasi sekitar
30 detik untuk konfirmasi collector dan 60 detik untuk aplikasi/IRIS; AI tidak ditunggu.

Nilai default:

    APP_DIR=/home/haikal/Analisis-Log-by-AI-LLM
    WAZUH_LOGSTASH_PORT=5044
    FILEBEAT_IMAGE=docker.elastic.co/beats/filebeat:8.17.0

Level Wazuh uji bisa diubah dengan `--level 12` sampai `--level 16`.
Pipeline contoh hanya merutekan level `>=12` ke OpenCTI, GLPI, dan `analysis-in`;
level lebih rendah tidak akan menguji seluruh alur kecuali ambang di Logstash
juga diubah.

Ganti host, port, direktori aplikasi, atau image dengan opsi/variabel tersebut jika
lingkungan berbeda. Pipeline Beats yang diberikan tidak mengaktifkan TLS; bila
Logstash menggunakan TLS, konfigurasi Filebeat tes perlu ditambah CA/certificate.

## 5. Logstash (VM-2)
Salin logstash/collector.conf ke /etc/logstash/conf.d/ lalu restart Logstash.

## 6. Tes arah masuk
    redis-cli -h 192.168.1.10 -a PASS -n 2 rpush outbound-glpi \
      '{"action":"create_ticket","title":"Tes","content":"Halo GLPI","urgency":3}'

Untuk mencari aset GLPI berdasarkan IP dari aplikasi analisis dan menerbitkan hasilnya
ke `enrichment-events`:

    redis-cli -h 192.168.1.10 -a PASS -n 2 rpush outbound-glpi \
      '{"action":"lookup_asset","ip":"192.168.51.143"}'

    redis-cli -h 192.168.1.10 -a PASS -n 2 rpush outbound-opencti \
      '{"action":"create_indicator","name":"Tes IP","pattern":"[ipv4-addr:value = '"'"'203.0.113.5'"'"']","score":60}'

Pesan gagal ada di list outbound-glpi:failed / outbound-opencti:failed.

## 7. Enrichment (Reputation, Geolocation, Asset Info, Domain Age)
Collector memperkaya observable baru OpenCTI (IP, domain, dan file hash) dan mengirim ke list `enrichment-events`.

| Data | Sumber |
|---|---|
| Reputation | skor+label OpenCTI, AbuseIPDB (ABUSEIPDB_KEY), VirusTotal (VT_API_KEY) |
| Geolocation | ip-api.com (gratis) atau ipinfo.io (IPINFO_TOKEN) + relasi located-at OpenCTI |
| Asset Info | GLPI Computer yang IP-nya cocok melalui NetworkPort atau relasi IPAddress, termasuk detail inventaris terkait |
| Domain Age | RDAP (gratis), fallback VirusTotal |
| File hash | SHA-512, SHA-256, SHA-1, atau MD5 dari observable StixFile; reputasi file via VirusTotal |

Lookup rutin observable baru juga mengambil inventory connector, menjalankan Internal
Enrichment yang aktif dan sesuai scope, lalu menyertakan seluruh status connector pada
event enrichment—bukan hanya lookup yang diminta per-IP oleh aplikasi.

Untuk setiap IP sumber/tujuan, domain, dan hash file dari aplikasi analisis, aksi
`lookup_enrichment` pada `outbound-opencti` memicu pencarian observable/indicator yang
cocok serta lookup connector. Daftar semua **Internal Enrichment** dan
**External Import** yang terdeteksi, termasuk status aktif/scope dan hasil job enrichment,
dikirim di `enrichment-events` untuk ditampilkan IRIS. Inventory dibaca dari GraphQL
`connectors`; SDK `connector.list()` hanya memberi konfigurasi worker tanpa tipe connector.

**External Import** bukan API lookup per IOC. Feed dicari melalui indicator dan external
reference yang sudah terindeks di OpenCTI; status inventory tetap ditampilkan per feed,
tetapi match tidak dapat dikaitkan ke feed tertentu jika metadata sumbernya tidak ada.
Feed harus berhasil sinkronisasi dan token OpenCTI collector harus diizinkan melihat
inventory serta meminta enrichment.

Batas tunggu job Internal Enrichment default 45 detik dan cache status connector 24 jam.
Nilainya dapat diubah dengan `ENRICH_CONNECTOR_WAIT_SECONDS` dan
`ENRICH_CONNECTOR_CACHE_TTL` di `.env`.

Skor dan label OpenCTI diambil dari Indicator yang memiliki relasi `based-on` ke observable,
karena atribut tersebut tersimpan pada Indicator, bukan selalu pada objek IP/domain/hash.
Enrichment alert juga menyertakan metadata Observable dan Indicator, entitas/relasi STIX
terkait, serta Events/Sightings yang terhubung jika tersedia. IRIS tetap menampilkan
catatan `Observable ditemukan di OpenCTI, tetapi belum ada indicator terkait.` apabila
Observable cocok tetapi lookup tidak menemukan Indicator.
Skor Indicator buatan collector sendiri dikecualikan dari reputasi agar severity Wazuh tidak
disalahartikan sebagai verdict intelijen eksternal.

Alert dengan IP membuat indikator IP di OpenCTI dan tiket GLPI. Collector mencocokkan IP
tersebut dengan Computer inventaris GLPI, termasuk alamat yang disimpan sebagai IPAddress
dan ditautkan langsung ke Computer maupun melalui relasi Computer → NetworkPort →
NetworkName → IPAddress, lalu menambahkan Name, User/pemilik, serial number,
operating system, dan status ke isi tiket. Informasi aset dikelola di GLPI, bukan diambil
dari inventaris Wazuh. Pada event enrichment, collector mengirim daftar IP lengkap beserta
kategori IP privat (RFC1918/IPv6 ULA), publik (global), dan lainnya agar IRIS menampilkannya
terpisah. Operating system dibaca dari relasi **Computer → Operating systems**
di GLPI, termasuk nama OS dan versi jika tersedia. Alert file integrity dengan hash membuat indikator `StixFile` di
OpenCTI; hash tidak dipakai untuk pencarian aset GLPI. Untuk setiap alert Wazuh,
aplikasi juga dapat meminta pencarian Computer GLPI berdasarkan hostname agent yang
cocok persis dan unik, sehingga aset sensor dapat ditampilkan terpisah dari IP
sumber/penyerang.

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
