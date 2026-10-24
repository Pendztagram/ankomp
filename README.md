# 🛠️ Tech Repair Analyzer

Aplikasi web (Streamlit) untuk menganalisa kerusakan komputer & laptop, baik **hardware** maupun **software**.

## Fitur
| Tab | Fungsi |
|---|---|
| 🩺 Diagnosa Gejala | Sistem pakar berbobot: pilih gejala → peringkat kemungkinan penyebab, tingkat keyakinan, langkah tes, solusi, estimasi biaya (Rp) |
| 📜 Analisa Log | Upload/paste log (Event Viewer, dmesg, syslog, BSOD, SMART) → deteksi pola error otomatis |
| 📊 Skor Kesehatan | Hitung skor kesehatan per komponen (suhu, storage, baterai, RAM, boot, stabilitas) + radar chart |
| 🖥️ Monitor Live | CPU/RAM/Disk/Baterai/Suhu/Proses dari mesin yang menjalankan app (via psutil) |
| 📚 Referensi | Kode BSOD, beep code BIOS, cheat sheet perintah diagnosa |
| 📝 Laporan | Export laporan Markdown |

## Jalankan lokal
```bash
pip install -r requirements.txt
streamlit run app.py
```
> Untuk Monitor Live, jalankan **lokal** di komputer yang ingin dicek. Jika di-deploy ke cloud, yang terbaca adalah server, bukan perangkat pengguna.

## Deploy via GitHub + Streamlit Community Cloud
1. Buat repo GitHub, upload `app.py`, `requirements.txt`, `README.md`.
2. Buka https://share.streamlit.io → **New app** → pilih repo, branch `main`, file `app.py`.
3. Klik **Deploy**.

## Menambah aturan diagnosa
Edit list `RULES` di `app.py` (bobot gejala `s`, langkah `fix`, estimasi biaya `cost`).

> Hasil bersifat panduan awal, bukan pengganti pemeriksaan teknisi langsung. Estimasi biaya bersifat kasar.
