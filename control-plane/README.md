# JITER Zero-Config Control Plane

Ringan, tanpa dependensi eksternal (`node >= 18`), dan sepenuhnya *swappable* — bisa dijalankan di **Vercel Serverless Functions**, terhubung ke **Supabase PostgreSQL**, atau langsung di **VPS / Docker** kamu sendiri.

Tugasnya sederhana: ketika user Android menekan tombol **GO**, APK otomatis memanggil `POST /api/v1/session/bootstrap` untuk mengambil daftar node VPS Relay Jakarta/Singapura yang paling sehat + policy default developer, memilih node dengan ping terendah, lalu langsung menyalakan tunnel terenkripsi tanpa user perlu mengetik konfigurasi apa pun.

---

## Opsi Deploy 1 — Vercel + Environment Variables (Tercepat, 2 Menit)

1. Deploy folder `control-plane/` ke Vercel (`vercel --cwd control-plane`).
2. Tambahkan Environment Variables di project Vercel:
   - `JITER_RELAY_NODES_JSON`:
     ```json
     [
       {
         "id": "jkt-1",
         "region": "JKT-1",
         "host": "IP_VPS_JAKARTA_KAMU",
         "port": 51820,
         "psk": "JITER_PSK_VPS_JAKARTA",
         "priority": 1,
         "enabled": true
       },
       {
         "id": "sg-1",
         "region": "SG-1",
         "host": "IP_VPS_SINGAPURA_KAMU",
         "port": 51820,
         "psk": "JITER_PSK_VPS_SINGAPURA",
         "priority": 2,
         "enabled": true
       }
     ]
     ```
   - *(Opsional disarankan)* `JITER_APP_KEY`: token rahasia agar hanya APK JITER resmi yang bisa bootstrap.

## Opsi Deploy 2 — Vercel + Supabase Database (Manajemen Node Dinamis)

1. Jalankan `control-plane/supabase/schema.sql` di SQL Editor Supabase kamu.
2. Masukkan daftar node VPS kamu ke tabel `public.jiter_relay_nodes`.
3. Isi Environment Variables di Vercel:
   - `SUPABASE_URL=https://<project-ref>.supabase.co`
   - `SUPABASE_SERVICE_ROLE_KEY=<service-role-key>` (disimpan HANYA di server Vercel, **jangan** ditanam di APK!)
   - *(Opsional)* `JITER_APP_KEY=<app-key>`

## Opsi Deploy 3 — Self-Hosted Node.js di VPS

```bash
cd control-plane
JITER_RELAY_HOST=203.0.113.10 \
JITER_RELAY_REGION=JKT-1 \
JITER_RELAY_PSK=isi-psk-vps \
PORT=8787 node server.js
```

## Menyambungkan ke Build APK Android (Developer Build)

Inject URL Control Plane saat build APK sehingga user langsung zero-config begitu install:

```bash
cd android
gradle assembleDebug -PjiterControlPlaneUrl=https://your-control-plane.vercel.app
```

Atau ganti secara live saat testing lewat **Menu Developer Tersembunyi** di APK (ketuk judul **JITER** 5 kali).

## Jalankan Unit Test Lokal

```bash
npm --prefix control-plane test
```
