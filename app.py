"""Tech Repair Analyzer - analisa kerusakan komputer/laptop (hardware & software)."""
import re
import base64
import datetime as dt

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

try:
    import psutil
except ImportError:  # app tetap jalan tanpa monitor live
    psutil = None

st.set_page_config(page_title="Tech Repair Analyzer", page_icon="🛠️", layout="wide")

# ---------------------------------------------------------------- DATA GEJALA
SYMPTOMS = {
    "no_power": "Tidak ada tanda hidup sama sekali (lampu/kipas mati)",
    "black_screen_fan_on": "Kipas/lampu menyala tapi layar hitam",
    "boot_no_display": "Menyala tapi tidak muncul logo/BIOS",
    "beep": "Mengeluarkan bunyi beep saat dinyalakan",
    "no_boot_os": "Muncul 'No bootable device' / OS tidak ditemukan",
    "bootloop": "Restart terus / stuck di logo (boot loop)",
    "slow_boot": "Booting sangat lambat",
    "random_restart": "Restart/mati sendiri tanpa peringatan",
    "bsod": "Blue Screen (BSOD) / kernel panic",
    "freeze": "Hang / freeze berkala",
    "slow_general": "Lambat secara umum",
    "disk_100": "Disk usage 100% terus-menerus",
    "clicking_hdd": "Hard disk berbunyi klik / berdecit",
    "storage_full": "Penyimpanan hampir penuh",
    "ram_high": "Pemakaian RAM tinggi tanpa alasan jelas",
    "app_crash": "Aplikasi sering crash / not responding",
    "update_fail": "Windows Update / update sistem gagal berulang",
    "popups": "Iklan/pop-up aneh, homepage berubah",
    "virus": "Antivirus mendeteksi ancaman / file terenkripsi",
    "overheat": "Panas berlebihan",
    "fan_loud": "Kipas sangat berisik / selalu kencang",
    "battery_fast": "Baterai cepat habis",
    "no_charge": "Baterai tidak mengisi / charger tidak terdeteksi",
    "wifi_drop": "WiFi sering putus",
    "no_wifi": "Adaptor WiFi/Bluetooth tidak terdeteksi",
    "screen_flicker": "Layar berkedip",
    "lines_screen": "Garis/bercak pada layar",
    "artifact": "Artefak grafis (kotak-kotak, warna aneh) saat game/render",
    "usb_not_detected": "Port USB tidak mendeteksi perangkat",
    "sound_no": "Suara tidak keluar / audio error",
    "keyboard_fail": "Keyboard/touchpad sebagian tidak berfungsi",
    "liquid": "Pernah terkena cairan / tumpahan",
    "time_reset": "Jam/tanggal BIOS reset sendiri",
}

# s = bobot gejala (1-3). cost = estimasi Rp (min, max)
RULES = [
    dict(id="paste", name="Thermal paste kering / pendingin kotor", kind="Hardware", sev=2,
         s=dict(overheat=3, fan_loud=2, random_restart=2, freeze=1, slow_general=1),
         test="Cek suhu idle & load (HWiNFO/`sensors`). Idle >60°C atau load >90°C = indikasi kuat.",
         fix=["Bersihkan debu heatsink & kipas dengan blower", "Ganti thermal paste (& thermal pad)",
              "Pastikan ventilasi tidak tertutup; gunakan cooling pad", "Set power plan ke Balanced"], cost=(75_000, 250_000)),
    dict(id="hdd", name="Hard disk (HDD) rusak / bad sector", kind="Hardware", sev=3,
         s=dict(clicking_hdd=3, disk_100=2, slow_boot=2, no_boot_os=2, freeze=1, bsod=1),
         test="Baca SMART (CrystalDiskInfo / `smartctl -a`). Reallocated/Pending sector >0 = mulai rusak.",
         fix=["BACKUP DATA SEGERA", "Clone ke SSD baru (Macrium/Clonezilla)", "Jangan jalankan chkdsk /r pada disk yang sekarat sebelum backup"],
         cost=(400_000, 1_200_000)),
    dict(id="ssd", name="SSD aus / filesystem korup", kind="Hardware", sev=3,
         s=dict(bsod=2, no_boot_os=2, disk_100=1, freeze=1, slow_boot=1, app_crash=1),
         test="Cek SMART: Percentage Used, Media Errors, Available Spare. Jalankan `chkdsk /f`.",
         fix=["Backup data", "Update firmware SSD", "Aktifkan TRIM", "Ganti SSD jika Percentage Used >90% atau ada media error"],
         cost=(450_000, 1_500_000)),
    dict(id="ram", name="RAM bermasalah", kind="Hardware", sev=3,
         s=dict(bsod=3, random_restart=2, app_crash=2, beep=2, boot_no_display=2, freeze=1),
         test="Jalankan Windows Memory Diagnostic / MemTest86 min. 2 pass. Coba 1 keping bergantian.",
         fix=["Bersihkan kontak RAM (penghapus pensil/IPA)", "Tes slot & keping bergantian",
              "Matikan XMP/overclock", "Ganti RAM yang error"], cost=(250_000, 800_000)),
    dict(id="psu", name="PSU / adaptor / jalur daya bermasalah", kind="Hardware", sev=3,
         s=dict(no_power=3, random_restart=2, no_charge=2, black_screen_fan_on=1, freeze=1),
         test="Ukur output adaptor dengan multimeter, coba adaptor/PSU lain yang kompatibel.",
         fix=["Ganti charger/PSU", "Cek jack DC (longgar/patah)", "Cek kabel & konektor"], cost=(150_000, 700_000)),
    dict(id="battery", name="Baterai menurun / rusak", kind="Hardware", sev=1,
         s=dict(battery_fast=3, no_charge=2, random_restart=1),
         test="`powercfg /batteryreport` → bandingkan Design vs Full Charge Capacity (<60% = ganti).",
         fix=["Kalibrasi baterai", "Ganti baterai original/berkualitas", "Batasi charge 80% bila ada fitur battery care"],
         cost=(250_000, 1_000_000)),
    dict(id="malware", name="Malware / adware", kind="Software", sev=2,
         s=dict(popups=3, virus=3, slow_general=2, ram_high=2, disk_100=1, wifi_drop=1),
         test="Scan Malwarebytes + Defender Offline; cek Task Manager/Autoruns untuk proses mencurigakan.",
         fix=["Scan penuh & Defender Offline scan", "Hapus ekstensi browser & program asing",
              "Cek Autoruns", "Jika parah: backup data lalu install ulang OS"], cost=(0, 200_000)),
    dict(id="oscorrupt", name="File sistem OS korup", kind="Software", sev=2,
         s=dict(bootloop=3, update_fail=3, no_boot_os=2, bsod=2, app_crash=1),
         test="`sfc /scannow` lalu `DISM /Online /Cleanup-Image /RestoreHealth`.",
         fix=["SFC + DISM", "Startup Repair / System Restore", "Repair install (in-place upgrade)", "Install ulang bersih"],
         cost=(0, 200_000)),
    dict(id="driver", name="Driver bermasalah / tidak kompatibel", kind="Software", sev=1,
         s=dict(screen_flicker=2, wifi_drop=2, no_wifi=2, sound_no=2, usb_not_detected=1, bsod=1),
         test="Device Manager: cari tanda seru; cek Event Viewer. Rollback driver terakhir.",
         fix=["Update/rollback driver dari situs vendor", "Gunakan DDU untuk driver GPU",
              "Install chipset driver terbaru", "Update BIOS bila perlu"], cost=(0, 100_000)),
    dict(id="bloat", name="Software menumpuk / storage penuh", kind="Software", sev=1,
         s=dict(storage_full=3, slow_general=2, update_fail=2, slow_boot=1, ram_high=1),
         test="Cek storage (WinDirStat), daftar startup, dan layanan latar belakang.",
         fix=["Disk Cleanup & hapus file besar", "Nonaktifkan startup program", "Sisakan ruang kosong ≥15%"], cost=(0, 0)),
    dict(id="panel", name="Panel LCD / kabel fleksibel rusak", kind="Hardware", sev=2,
         s=dict(lines_screen=3, screen_flicker=2, black_screen_fan_on=2),
         test="Sambungkan monitor eksternal: jika normal → panel/kabel LCD bermasalah.",
         fix=["Cek/ganti kabel fleksibel LCD", "Ganti panel LCD"], cost=(600_000, 2_500_000)),
    dict(id="gpu", name="GPU bermasalah (overheat/solder retak)", kind="Hardware", sev=3,
         s=dict(artifact=3, screen_flicker=1, freeze=1, bsod=1, overheat=1),
         test="Stress test (FurMark) & monitor suhu; coba driver bersih.",
         fix=["Bersihkan & repaste GPU", "Turunkan overclock", "Reflow/reballing oleh teknisi", "Ganti kartu grafis"],
         cost=(500_000, 3_000_000)),
    dict(id="mobo", name="Motherboard / jalur daya board", kind="Hardware", sev=3,
         s=dict(no_power=2, boot_no_display=2, usb_not_detected=2, liquid=3, beep=1, black_screen_fan_on=1),
         test="Lepas semua periferal & tes minimal (CPU+1 RAM). Periksa korosi & komponen terbakar.",
         fix=["Bersihkan korosi dengan IPA + ultrasonic", "Ganti komponen SMD (IC/MOSFET) oleh teknisi", "Ganti motherboard"],
         cost=(500_000, 3_500_000)),
    dict(id="wlan", name="Kartu WiFi / antena", kind="Hardware", sev=1,
         s=dict(no_wifi=3, wifi_drop=3),
         test="Cek di Device Manager/`lspci`; tes dengan USB WiFi.",
         fix=["Reseat kartu WiFi & kabel antena", "Ganti modul WiFi (M.2)"], cost=(100_000, 300_000)),
    dict(id="keyboard", name="Keyboard / touchpad rusak atau kena cairan", kind="Hardware", sev=1,
         s=dict(keyboard_fail=3, liquid=2),
         test="Tes dengan keyboard eksternal & keyboard tester online.",
         fix=["Bersihkan konektor", "Ganti keyboard/touchpad"], cost=(150_000, 700_000)),
    dict(id="cmos", name="Baterai CMOS lemah / BIOS bermasalah", kind="Hardware", sev=1,
         s=dict(time_reset=3, bootloop=1, boot_no_display=1),
         test="Ukur baterai CR2032 (harus >2.9V).",
         fix=["Ganti baterai CMOS", "Reset & flash BIOS terbaru"], cost=(20_000, 150_000)),
]

# ---------------------------------------------------------------- POLA LOG
PATTERNS = [
    (r"0x0000007b|INACCESSIBLE_BOOT_DEVICE", "BSOD INACCESSIBLE_BOOT_DEVICE", "Storage/Driver", "Cek mode SATA (AHCI/RAID) di BIOS, kabel/disk, driver storage."),
    (r"CRITICAL_PROCESS_DIED|0x000000ef", "BSOD CRITICAL_PROCESS_DIED", "OS/Storage", "Jalankan SFC/DISM, cek SMART disk, driver baru-baru ini."),
    (r"MEMORY_MANAGEMENT|0x0000001a", "BSOD MEMORY_MANAGEMENT", "RAM", "Tes RAM dengan MemTest86; matikan XMP."),
    (r"PAGE_FAULT_IN_NONPAGED_AREA|0x00000050", "BSOD PAGE_FAULT_IN_NONPAGED_AREA", "RAM/Driver", "Tes RAM, update/rollback driver."),
    (r"WHEA_UNCORRECTABLE_ERROR|0x00000124", "WHEA Uncorrectable Error", "CPU/Motherboard/PSU", "Cek suhu, matikan overclock/undervolt, cek PSU."),
    (r"DPC_WATCHDOG_VIOLATION|0x00000133", "DPC Watchdog Violation", "Driver/SSD", "Update firmware SSD & driver storage/chipset."),
    (r"IRQL_NOT_LESS_OR_EQUAL|0x0000000a|0x000000d1", "IRQL_NOT_LESS_OR_EQUAL / driver fault", "Driver/RAM", "Identifikasi driver di dump (WhoCrashed/BlueScreenView)."),
    (r"SYSTEM_SERVICE_EXCEPTION|0x0000003b", "SYSTEM_SERVICE_EXCEPTION", "Driver/Software", "Update driver GPU, scan malware."),
    (r"Kernel-Power.*\b41\b|unexpected shutdown|dirty shutdown", "Mati mendadak (Kernel-Power 41)", "PSU/Panas/Baterai", "Cek suhu, charger/PSU, dan baterai."),
    (r"thermal|overheat|throttl|temperature above threshold", "Indikasi overheating / throttling", "Pendingin", "Bersihkan debu, ganti thermal paste."),
    (r"bad block|reallocated|pending sector|SMART.*(fail|pred|error)|uncorrectable", "Indikasi disk rusak (SMART/bad sector)", "Storage", "Backup segera, ganti disk."),
    (r"\\Device\\Harddisk\d|disk.*(error|retry)|ntfs.*(corrupt|error)|Buffer I/O error|ata\d+.*(error|failed)|EXT4-fs error", "Error I/O disk / filesystem", "Storage", "chkdsk/fsck, cek kabel & SMART."),
    (r"nvlddmkm|display driver .*stopped responding|amdkmdag|TDR|GPU (hang|fault)", "Driver/GPU reset (TDR)", "GPU", "Bersihkan driver (DDU), cek suhu GPU, turunkan OC."),
    (r"Out of memory|oom-killer|Low memory|virtual memory", "Kehabisan memori", "RAM/Software", "Tambah RAM, cek memory leak, perbesar pagefile."),
    (r"Defender.*(threat|malware)|trojan|ransom|virus|malware", "Indikasi malware", "Keamanan", "Scan offline, isolasi dari jaringan."),
    (r"WLAN.*(disconnect|fail)|wifi.*(disconnect|timeout)|firmware crashed|iwlwifi", "Masalah WiFi/driver wireless", "WiFi", "Update driver, cek power saving adapter, reseat modul."),
    (r"battery.*(critical|low|failure)|charger.*(not|fail)", "Masalah baterai/charger", "Baterai", "Cek battery report & adaptor."),
]

# ---------------------------------------------------------------- FUNGSI
def rp(n: int) -> str:
    return f"Rp {n:,.0f}".replace(",", ".")


def diagnose(sel: set, dev: dict):
    out = []
    for r in RULES:
        total = sum(r["s"].values())
        hit = sum(w for k, w in r["s"].items() if k in sel)
        if not hit:
            continue
        n = sum(1 for k in r["s"] if k in sel)
        conf = min(1.0, hit / total * (1 + 0.12 * (n - 1)))
        i = r["id"]
        if i == "hdd" and dev["storage"] != "HDD": conf *= 0.2
        if i == "ssd" and dev["storage"] == "HDD": conf *= 0.3
        if i == "battery" and dev["type"] == "Desktop PC": conf = 0
        if i == "paste" and dev["age"] >= 3: conf *= 1.2
        if i == "cmos" and dev["age"] >= 4: conf *= 1.3
        if i == "battery" and dev["age"] >= 2: conf *= 1.15
        if i == "keyboard" and dev["type"] == "Desktop PC": conf *= 0.5
        if i == "panel" and dev["type"] == "Desktop PC": conf *= 0.5
        conf = min(conf, 0.97)
        if conf > 0.10:
            out.append({**r, "conf": conf})
    return sorted(out, key=lambda x: -x["conf"])


def analyze_log(text: str):
    lines = text.splitlines()[:300_000]
    res = []
    for rx, title, area, adv in PATTERNS:
        c = re.compile(rx, re.I)
        m = [(i + 1, l.strip()[:220]) for i, l in enumerate(lines) if c.search(l)]
        if m:
            res.append(dict(title=title, area=area, advice=adv, count=len(m), samples=m[:5]))
    return sorted(res, key=lambda x: -x["count"])


def safe(fn, default=None):
    """Jalankan pembacaan sensor; kembalikan default bila tidak didukung (mis. di server cloud)."""
    try:
        return fn()
    except Exception:
        return default


def clamp(x, lo=0, hi=100):
    return max(lo, min(hi, x))


def health_scores(v: dict):
    th = clamp(100 - max(0, v["t_idle"] - 45) * 2.5) * 0.4 + clamp(100 - max(0, v["t_load"] - 75) * 3.5) * 0.6
    st_ = 100.0
    st_ -= min(60, v["realloc"] * 1.5) + (30 if v["pending"] > 0 else 0)
    st_ -= max(0, 100 - v["life"]) * 0.6
    st_ -= 15 if v["usage"] > 90 else (7 if v["usage"] > 80 else 0)
    mem = 100 - (30 if v["ram"] > 85 else 15 if v["ram"] > 70 else 0) - (40 if v["memerr"] else 0)
    boot = clamp(100 - max(0, v["boot"] - 30) * 0.8)
    stab = clamp(100 - v["crash"] * 12)
    sc = {"Termal": th, "Storage": st_, "Memori": mem, "Boot": boot, "Stabilitas": stab}
    w = {"Termal": .2, "Storage": .25, "Memori": .15, "Boot": .1, "Stabilitas": .2}
    if v["laptop"]:
        bat = clamp(v["bat"] - (10 if v["cycles"] > 500 else 0) - (10 if v["cycles"] > 1000 else 0))
        sc["Baterai"], w["Baterai"] = bat, .1
    sc = {k: round(clamp(x)) for k, x in sc.items()}
    overall = sum(sc[k] * w[k] for k in sc) / sum(w.values())
    return sc, round(overall)


def verdict(score):
    if score >= 85: return "🟢 Sehat", "Perangkat dalam kondisi baik. Lakukan perawatan rutin."
    if score >= 65: return "🟡 Perlu perhatian", "Ada komponen mulai menurun; jadwalkan pengecekan & pembersihan."
    if score >= 40: return "🟠 Berisiko", "Beberapa komponen bermasalah. Backup data dan perbaiki segera."
    return "🔴 Kritis", "Risiko kegagalan tinggi. BACKUP DATA SEKARANG dan bawa ke teknisi."


# ---------------------------------------------------------------- SIDEBAR
with st.sidebar:
    st.title("🛠️ Repair Analyzer")
    st.caption("Analisa kerusakan hardware & software")
    dev = dict(
        type=st.selectbox("Jenis perangkat", ["Laptop", "Desktop PC", "All-in-One"]),
        brand=st.text_input("Merk / model", placeholder="mis. ASUS A456U"),
        os=st.selectbox("Sistem operasi", ["Windows 11", "Windows 10", "Linux", "macOS", "Lainnya"]),
        storage=st.selectbox("Jenis penyimpanan utama", ["HDD", "SSD/NVMe", "HDD + SSD"]),
        age=st.slider("Umur perangkat (tahun)", 0, 15, 3),
    )
    st.info("Hasil adalah panduan awal. Estimasi biaya kasar & bervariasi per kota.")

st.title("🛠️ Tech Repair Analyzer")
tabs = st.tabs(["🩺 Diagnosa Gejala", "🤖 Tanya AI", "📜 Analisa Log", "📊 Skor Kesehatan", "🖥️ Monitor Live", "📚 Referensi", "📝 Laporan"])

# ---------------------------------------------------------------- TAB 1
with tabs[0]:
    st.subheader("Pilih gejala yang dialami")
    sel = st.multiselect("Gejala", list(SYMPTOMS), format_func=SYMPTOMS.get, placeholder="Ketik/cari gejala...")
    notes = st.text_area("Catatan tambahan (kronologi, kejadian sebelum rusak)", height=70)
    if sel:
        res = diagnose(set(sel), dev)
        st.session_state.update(diag=res, sel=sel, notes=notes)
        if not res:
            st.warning("Tidak ada penyebab yang cocok. Tambahkan gejala lain.")
        else:
            top = res[:8]
            colors = ["#e4572e" if r["kind"] == "Hardware" else "#2e86e4" for r in top]
            fig = go.Figure(go.Bar(x=[r["conf"] * 100 for r in top][::-1], y=[r["name"] for r in top][::-1],
                                   orientation="h", marker_color=colors[::-1],
                                   text=[f"{r['conf'] * 100:.0f}%" for r in top][::-1], textposition="outside"))
            fig.update_layout(height=60 + 48 * len(top), margin=dict(l=0, r=30, t=30, b=0),
                              title="Tingkat keyakinan (merah = hardware, biru = software)",
                              xaxis=dict(range=[0, 110], title="%"))
            st.plotly_chart(fig, use_container_width=True)
            hw = sum(r["conf"] for r in res if r["kind"] == "Hardware")
            sw = sum(r["conf"] for r in res if r["kind"] == "Software")
            c1, c2, c3 = st.columns(3)
            c1.metric("Dugaan utama", res[0]["name"][:28])
            c2.metric("Kecenderungan", "Hardware" if hw > sw else "Software", f"HW {hw:.1f} : SW {sw:.1f}", delta_color="off")
            c3.metric("Urgensi tertinggi", {1: "Rendah", 2: "Sedang", 3: "Tinggi"}[max(r["sev"] for r in res[:3])])
            if any(r["id"] in ("hdd", "ssd") and r["conf"] > .35 for r in res):
                st.error("⚠️ Ada indikasi kerusakan penyimpanan. **Backup data sebelum melakukan apa pun.**")
            for r in top:
                with st.expander(f"{'🔧' if r['kind'] == 'Hardware' else '💻'} {r['name']} — {r['conf'] * 100:.0f}%"):
                    st.progress(r["conf"])
                    st.markdown(f"**Tes pembeda:** {r['test']}")
                    st.markdown("**Langkah perbaikan:**\n" + "\n".join(f"{i + 1}. {s}" for i, s in enumerate(r["fix"])))
                    lo, hi = r["cost"]
                    st.markdown(f"**Estimasi biaya:** {'Gratis (DIY)' if hi == 0 else rp(lo) + ' – ' + rp(hi)}")
    else:
        st.info("Pilih minimal satu gejala untuk memulai diagnosa.")


# ---------------------------------------------------------------- TAB AI
AI_SYSTEM = """Kamu adalah teknisi komputer & laptop senior (hardware dan software) yang berbicara dalam Bahasa Indonesia yang jelas.
Aturan:
- Analisa keluhan pengguna secara bebas, tidak terpaku pada daftar tetap. Jika info kurang, ajukan maksimal 3 pertanyaan klarifikasi yang paling penting.
- Format jawaban: (1) Dugaan penyebab berurut dari paling mungkin + alasan, (2) Tes untuk membedakan penyebab, (3) Langkah perbaikan bertahap dari yang paling aman, (4) Estimasi biaya kasar dalam Rupiah bila relevan, (5) Kapan harus ke teknisi.
- Selalu ingatkan BACKUP DATA sebelum langkah berisiko (format, chkdsk /r, flash BIOS, bongkar perangkat).
- Peringatkan bahaya keselamatan (baterai menggembung, listrik, cairan).
- Bila memakai hasil pencarian web, sebutkan sumbernya secara singkat. Jangan mengarang perintah/kode error; katakan jika tidak yakin.
- Jawaban ringkas, praktis, dan berurutan."""


def build_context():
    p = [f"Perangkat: {dev['type']} {dev['brand']}, OS {dev['os']}, storage {dev['storage']}, umur {dev['age']} tahun."]
    if st.session_state.get("sel"):
        p.append("Gejala terpilih di aplikasi: " + "; ".join(SYMPTOMS[x] for x in st.session_state["sel"]))
    if st.session_state.get("diag"):
        p.append("Dugaan sistem pakar: " + "; ".join(f"{r['name']} ({r['conf'] * 100:.0f}%)" for r in st.session_state["diag"][:3]))
    if st.session_state.get("log"):
        p.append("Temuan log: " + "; ".join(f"{f['title']} x{f['count']}" for f in st.session_state["log"][:6]))
    if st.session_state.get("health"):
        sc, ov = st.session_state["health"]
        p.append(f"Skor kesehatan {ov}/100: " + ", ".join(f"{k} {v}" for k, v in sc.items()))
    return "\n".join(p)


def stream_ai(client, model, messages, web):
    kw = dict(model=model, max_tokens=2500, system=AI_SYSTEM, messages=messages)
    if web:
        kw["tools"] = [{"type": "web_search_20250305", "name": "web_search", "max_uses": 4}]
    with client.messages.stream(**kw) as stream:
        for t in stream.text_stream:
            yield t


GEMINI_MODELS = ["gemini-3.8-flash", "gemini-3.5-flash-lite", "gemini-3.6-flash", "gemini-3.1-flash-lite", "gemini-4-argon (berbayar)"]
GEMINI_FALLBACKS = ["gemini-3.8-flash", "gemini-3.5-flash-lite", "gemini-3.6-flash", "gemini-3.1-flash-lite"]


def gemini_chat(key, model, history, text, img, web):
    """Panggil Gemini via REST (gratis lewat Google AI Studio). Return (teks, sumber, catatan)."""
    import requests
    contents = [{"role": "user" if m["role"] == "user" else "model", "parts": [{"text": m["content"]}]} for m in history]
    parts = [{"text": text}]
    if img:
        parts.insert(0, {"inline_data": {"mime_type": img.type or "image/png", "data": base64.b64encode(img.getvalue()).decode()}})
    contents.append({"role": "user", "parts": parts})
    body = {"systemInstruction": {"parts": [{"text": AI_SYSTEM}]}, "contents": contents}
    if web:
        body["tools"] = [{"google_search": {}}]
    hdr = {"x-goog-api-key": key, "Content-Type": "application/json"}
    note = ""

    def post(mdl, bd):
        return requests.post(f"https://generativelanguage.googleapis.com/v1beta/models/{mdl}:generateContent",
                             headers=hdr, json=bd, timeout=90)

    # coba model pilihan, lalu fallback bila model sudah dihentikan (404)
    r = None
    for mdl in [model] + [m for m in GEMINI_FALLBACKS if m != model]:
        r = post(mdl, body)
        if r.status_code != 200 and web and r.status_code != 404:  # ulang tanpa Google Search
            nb = {k: v for k, v in body.items() if k != "tools"}
            r2 = post(mdl, nb)
            if r2.status_code == 200:
                r, note = r2, "Pencarian internet tidak tersedia untuk key/model ini, jawaban tanpa web search."
        if r.status_code not in (404, 429):
            if mdl != model and r.status_code == 200:
                note = (note + f" Model `{model}` tidak tersedia/kuota habis, memakai `{mdl}`.").strip()
            break
    if r.status_code != 200:
        try:
            msg = r.json()["error"]["message"]
        except Exception:
            msg = r.text
        raise RuntimeError(f"HTTP {r.status_code}: {msg[:300]}")
    cand = r.json()["candidates"][0]
    txt = "".join(p_.get("text", "") for p_ in cand.get("content", {}).get("parts", []))
    chunks = cand.get("groundingMetadata", {}).get("groundingChunks", [])
    src = [(c["web"].get("title", "sumber"), c["web"]["uri"]) for c in chunks if "web" in c]
    return txt or "(AI tidak mengembalikan jawaban)", src, note


with tabs[1]:
    st.subheader("🤖 Tanya AI Teknisi")
    st.caption("Ceritakan keluhan dengan bahasa bebas. AI menganalisa dan bisa mencari solusi terbaru di internet.")
    prov = st.radio("Penyedia AI", ["Google Gemini (gratis)", "Anthropic Claude (berbayar)"], horizontal=True)
    is_gem = prov.startswith("Google")
    sec_name = "GEMINI_API_KEY" if is_gem else "ANTHROPIC_API_KEY"
    api_key = safe(lambda: st.secrets[sec_name], "")
    if not api_key:
        api_key = st.text_input(f"{'Gemini' if is_gem else 'Anthropic'} API key", type="password",
                                help="Gemini: gratis di aistudio.google.com/apikey. Untuk deploy permanen simpan di Streamlit Secrets, jangan di GitHub.")
        if is_gem:
            st.caption("🔑 Ambil key gratis di https://aistudio.google.com/apikey (login Google, tanpa kartu kredit).")
    o1, o2, o3 = st.columns([2, 2, 2])
    if is_gem:
        model = o1.selectbox("Model", GEMINI_MODELS, help="Argon hanya untuk akun berbayar; key gratis akan ditolak.").split(" ")[0]
    else:
        model = o1.text_input("Model", safe(lambda: st.secrets["ANTHROPIC_MODEL"], "claude-sonnet-5-5"))
    use_web = o2.toggle("🌐 Cari solusi di internet", True)
    use_ctx = o3.toggle("Sertakan hasil diagnosa/log/skor", True)
    shot = st.file_uploader("Foto/screenshot error (opsional)", type=["png", "jpg", "jpeg", "webp"])
    if "chat" not in st.session_state:
        st.session_state["chat"] = []
    if st.button("🗑️ Mulai percakapan baru"):
        st.session_state["chat"] = []
    for m in st.session_state["chat"]:
        with st.chat_message(m["role"]):
            st.markdown(m["content"])
    q = st.chat_input("Contoh: laptop saya mati sendiri setelah 10 menit main game, kipas kencang...")
    if q:
        if not api_key:
            st.error("Masukkan API key terlebih dahulu.")
        else:
            with st.chat_message("user"):
                st.markdown(q)
                if shot:
                    st.image(shot, width=280)
            text = (f"[Konteks perangkat]\n{build_context()}\n\n[Keluhan]\n{q}") if use_ctx else q
            hist = st.session_state["chat"][-12:]
            try:
                with st.chat_message("assistant"):
                    if is_gem:
                        with st.spinner("AI sedang menganalisa..."):
                            ans, src, note = gemini_chat(api_key, model, hist, text, shot, use_web)
                        st.markdown(ans)
                        if src:
                            st.caption("Sumber: " + " • ".join(f"[{t}]({u})" for u, t in dict((u, t) for t, u in src).items()))
                        if note:
                            st.caption(note)
                    else:
                        import anthropic
                        client = anthropic.Anthropic(api_key=api_key)
                        content = text
                        if shot:
                            content = [{"type": "image", "source": {"type": "base64", "media_type": shot.type or "image/png",
                                                                    "data": base64.b64encode(shot.getvalue()).decode()}},
                                       {"type": "text", "text": text}]
                        ans = st.write_stream(stream_ai(client, model, hist + [{"role": "user", "content": content}], use_web))
                st.session_state["chat"] += [{"role": "user", "content": q}, {"role": "assistant", "content": ans}]
            except ImportError:
                st.error("Modul `anthropic` belum terpasang. Pastikan ada di requirements.txt.")
            except Exception as e:
                st.error(f"Gagal menghubungi AI: {type(e).__name__}: {str(e)[:300]}")
                if "429" in str(e):
                    st.caption("Kuota gratis habis sementara (batas per menit/hari). Tunggu sebentar lalu coba lagi.")

# ---------------------------------------------------------------- TAB 2
with tabs[2]:
    st.subheader("Analisa log otomatis")
    st.caption("Export Event Viewer (.txt/.csv/.evtx→teks), `dmesg`, `journalctl`, hasil `smartctl`, atau teks BSOD.")
    up = st.file_uploader("Upload file log", type=["txt", "log", "csv"])
    pasted = st.text_area("…atau paste isi log", height=150)
    text = up.getvalue().decode("utf-8", errors="ignore") if up else pasted
    if text.strip():
        found = analyze_log(text)
        st.session_state["log"] = found
        st.caption(f"{len(text.splitlines()):,} baris dianalisa")
        if not found:
            st.success("Tidak ditemukan pola error yang dikenali.")
        else:
            st.dataframe(pd.DataFrame([{"Temuan": f["title"], "Area": f["area"], "Jumlah": f["count"], "Saran": f["advice"]} for f in found]),
                         hide_index=True, use_container_width=True)
            for f in found:
                with st.expander(f"{f['title']} ({f['count']}×)"):
                    st.markdown(f"**Saran:** {f['advice']}")
                    st.code("\n".join(f"L{n}: {l}" for n, l in f["samples"]), language="text")

# ---------------------------------------------------------------- TAB 3
with tabs[3]:
    st.subheader("Skor kesehatan perangkat")
    snap = st.session_state.get("snap", {})
    a, b, c = st.columns(3)
    with a:
        t_idle = st.number_input("Suhu CPU idle (°C)", 20, 110, 45)
        t_load = st.number_input("Suhu CPU saat load (°C)", 30, 115, 80)
        boot = st.number_input("Waktu boot (detik)", 5, 600, 40)
    with b:
        realloc = st.number_input("SMART Reallocated sectors", 0, 100000, 0)
        pending = st.number_input("SMART Pending sectors", 0, 100000, 0)
        life = st.slider("Sisa umur SSD (%)", 0, 100, 100, help="Isi 100 jika HDD / tidak diketahui")
        usage = st.slider("Penggunaan storage (%)", 0, 100, int(snap.get("disk", 60)))
    with c:
        ram = st.slider("Rata-rata pemakaian RAM (%)", 0, 100, int(snap.get("ram", 50)))
        memerr = st.checkbox("MemTest menemukan error")
        crash = st.number_input("Jumlah crash/BSOD/restart sendiri per bulan", 0, 100, 0)
        is_laptop = dev["type"] != "Desktop PC"
        bat = st.slider("Kesehatan baterai (Full/Design %)", 0, 100, 85, disabled=not is_laptop)
        cycles = st.number_input("Siklus baterai", 0, 5000, 200, disabled=not is_laptop)
    sc, overall = health_scores(dict(t_idle=t_idle, t_load=t_load, boot=boot, realloc=realloc, pending=pending, life=life,
                                    usage=usage, ram=ram, memerr=memerr, crash=crash, laptop=is_laptop, bat=bat, cycles=cycles))
    st.session_state["health"] = (sc, overall)
    g1, g2 = st.columns([1, 1])
    with g1:
        gf = go.Figure(go.Indicator(mode="gauge+number", value=overall, title={"text": "Skor total"},
                                    gauge=dict(axis=dict(range=[0, 100]), bar=dict(color="#222"),
                                               steps=[dict(range=[0, 40], color="#e4572e"), dict(range=[40, 65], color="#f2a65a"),
                                                      dict(range=[65, 85], color="#f2d45a"), dict(range=[85, 100], color="#5ab55a")])))
        gf.update_layout(height=300, margin=dict(t=60, b=10))
        st.plotly_chart(gf, use_container_width=True)
        lbl, msg = verdict(overall)
        st.markdown(f"### {lbl}\n{msg}")
    with g2:
        k = list(sc)
        rf = go.Figure(go.Scatterpolar(r=[sc[x] for x in k] + [sc[k[0]]], theta=k + [k[0]], fill="toself"))
        rf.update_layout(polar=dict(radialaxis=dict(range=[0, 100])), height=330, margin=dict(t=30, b=10), showlegend=False)
        st.plotly_chart(rf, use_container_width=True)
    weak = [f"**{n}** ({s}/100)" for n, s in sc.items() if s < 70]
    if weak:
        st.warning("Komponen perlu perhatian: " + ", ".join(weak))

# ---------------------------------------------------------------- TAB 4
with tabs[4]:
    st.subheader("Monitor live (mesin yang menjalankan aplikasi ini)")
    if psutil is None:
        st.error("Modul psutil belum terpasang: `pip install psutil`")
    else:
        st.caption("Jalankan app secara lokal di perangkat yang ingin dicek. Di cloud, data yang tampil adalah milik server.")
        if st.button("🔄 Refresh / ambil snapshot", type="primary") or "snap" not in st.session_state:
            vm, du = psutil.virtual_memory(), safe(lambda: psutil.disk_usage("/"))
            st.session_state["snap"] = dict(cpu=psutil.cpu_percent(interval=0.8), ram=vm.percent, disk=du.percent if du else 0)
        sn = st.session_state["snap"]
        vm, sw, du = psutil.virtual_memory(), psutil.swap_memory(), psutil.disk_usage("/")
        m = st.columns(4)
        m[0].metric("CPU", f"{sn['cpu']:.0f}%", f"{psutil.cpu_count()} thread", delta_color="off")
        m[1].metric("RAM", f"{vm.percent:.0f}%", f"{vm.used / 2**30:.1f}/{vm.total / 2**30:.1f} GB", delta_color="off")
        m[2].metric("Swap", f"{sw.percent:.0f}%")
        m[3].metric("Disk /", f"{du.percent:.0f}%", f"{du.free / 2**30:.0f} GB bebas", delta_color="off")
        bt = safe(lambda: psutil.sensors_battery())
        if bt:
            st.info(f"🔋 Baterai {bt.percent:.0f}% — {'sedang dicas' if bt.power_plugged else 'memakai baterai'}")
        temps = safe(lambda: psutil.sensors_temperatures(), {})
        if temps:
            rows = [dict(Sensor=n, Label=e.label or n, Suhu=e.current) for n, es in temps.items() for e in es]
            st.markdown("**Suhu sensor**")
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        else:
            st.caption("Sensor suhu tidak tersedia di OS ini (Windows: gunakan HWiNFO / Core Temp).")
        boot_ts = safe(lambda: psutil.boot_time())
        if boot_ts:
            st.caption(f"Uptime: {str(dt.datetime.now() - dt.datetime.fromtimestamp(boot_ts)).split('.')[0]}")
        procs = []
        for p in psutil.process_iter(["name", "memory_percent", "cpu_percent"]):
            try: procs.append(p.info)
            except Exception: pass
        dfp = pd.DataFrame(procs).dropna().sort_values("memory_percent", ascending=False).head(10)
        st.markdown("**Top 10 proses (RAM)**")
        st.dataframe(dfp.rename(columns={"name": "Proses", "memory_percent": "RAM %", "cpu_percent": "CPU %"}).round(1),
                     hide_index=True, use_container_width=True)
        st.caption("Nilai RAM & disk otomatis dipakai sebagai default di tab Skor Kesehatan.")

# ---------------------------------------------------------------- TAB 5
with tabs[5]:
    st.subheader("Referensi cepat")
    r1, r2 = st.tabs(["Kode BSOD", "Beep code BIOS"])
    bsod = pd.DataFrame([
        ("0x0000007B", "INACCESSIBLE_BOOT_DEVICE", "Mode SATA/AHCI salah, disk/driver storage"),
        ("0x0000001A", "MEMORY_MANAGEMENT", "RAM rusak / driver"),
        ("0x00000050", "PAGE_FAULT_IN_NONPAGED_AREA", "RAM, driver, disk"),
        ("0x0000000A", "IRQL_NOT_LESS_OR_EQUAL", "Driver bermasalah / RAM"),
        ("0x000000EF", "CRITICAL_PROCESS_DIED", "File sistem korup / disk"),
        ("0x00000124", "WHEA_UNCORRECTABLE_ERROR", "CPU, PSU, overclock, suhu"),
        ("0x00000133", "DPC_WATCHDOG_VIOLATION", "Driver / firmware SSD"),
        ("0x0000003B", "SYSTEM_SERVICE_EXCEPTION", "Driver GPU / software"),
        ("0x0000009F", "DRIVER_POWER_STATE_FAILURE", "Driver power / baterai / sleep"),
        ("0x000000F4", "CRITICAL_OBJECT_TERMINATION", "Disk/kabel SATA rusak"),
    ], columns=["Kode", "Nama", "Penyebab umum"])
    r1.dataframe(bsod, hide_index=True, use_container_width=True)
    beep = pd.DataFrame([
        ("1 pendek", "Normal (POST sukses) pada banyak BIOS"),
        ("Pendek berulang / terus-menerus", "RAM tidak terdeteksi atau PSU bermasalah"),
        ("1 panjang 2 pendek (Award)", "Masalah VGA / kartu grafis"),
        ("1 panjang 3 pendek (AMI)", "Error memori video/RAM"),
        ("2 pendek (AMI)", "Parity error memori"),
        ("5 pendek (AMI)", "Error prosesor"),
        ("6 pendek (AMI)", "Keyboard controller / gate A20"),
        ("8 pendek (AMI)", "Memori display bermasalah"),
    ], columns=["Pola bunyi", "Arti umum"])
    r2.dataframe(beep, hide_index=True, use_container_width=True)
    r2.caption("Pola berbeda tiap vendor BIOS (AMI/Award/Phoenix/Dell/HP/Lenovo). Cek manual motherboard.")
    st.markdown("**Cheat sheet perintah diagnosa**")
    st.dataframe(pd.DataFrame([
        ("Windows", "sfc /scannow", "Perbaiki file sistem"),
        ("Windows", "DISM /Online /Cleanup-Image /RestoreHealth", "Perbaiki image Windows"),
        ("Windows", "chkdsk C: /f /r", "Cek & perbaiki disk"),
        ("Windows", "mdsched.exe", "Tes RAM"),
        ("Windows", "powercfg /batteryreport", "Laporan kesehatan baterai"),
        ("Windows", "powercfg /energy", "Analisa pemborosan daya"),
        ("Windows", "wmic diskdrive get model,status", "Status disk singkat"),
        ("Windows", "perfmon /report", "Laporan performa sistem"),
        ("Linux", "sudo smartctl -a /dev/sda", "SMART disk"),
        ("Linux", "sensors", "Suhu & kipas (lm-sensors)"),
        ("Linux", "journalctl -p 3 -xb", "Error boot terakhir"),
        ("Linux", "sudo dmesg --level=err,warn", "Pesan kernel"),
        ("Linux", "sudo memtester 2G 1", "Tes RAM"),
        ("Linux", "upower -i $(upower -e | grep BAT)", "Info baterai"),
    ], columns=["OS", "Perintah", "Fungsi"]), hide_index=True, use_container_width=True)

# ---------------------------------------------------------------- TAB 6
with tabs[6]:
    st.subheader("Laporan diagnosa")
    now = dt.datetime.now().strftime("%d %B %Y %H:%M")
    md = [f"# Laporan Diagnosa Perangkat\n_{now}_\n",
          f"- Perangkat: {dev['type']} {dev['brand']}\n- OS: {dev['os']}\n- Storage: {dev['storage']}\n- Umur: {dev['age']} tahun\n"]
    if st.session_state.get("sel"):
        md.append("## Gejala\n" + "\n".join(f"- {SYMPTOMS[s]}" for s in st.session_state["sel"]))
        if st.session_state.get("notes"):
            md.append(f"\nCatatan: {st.session_state['notes']}")
        md.append("\n## Dugaan penyebab")
        for r in st.session_state.get("diag", [])[:6]:
            lo, hi = r["cost"]
            md.append(f"### {r['name']} ({r['conf'] * 100:.0f}%, {r['kind']})\n- Tes: {r['test']}\n"
                      + "\n".join(f"- {f}" for f in r["fix"])
                      + f"\n- Estimasi: {'Gratis' if hi == 0 else rp(lo) + ' - ' + rp(hi)}")
    if st.session_state.get("log"):
        md.append("\n## Temuan log\n" + "\n".join(f"- {f['title']} ({f['count']}×): {f['advice']}" for f in st.session_state["log"]))
    if st.session_state.get("health"):
        sc, ov = st.session_state["health"]
        md.append(f"\n## Skor kesehatan: {ov}/100 ({verdict(ov)[0]})\n" + "\n".join(f"- {k}: {v}/100" for k, v in sc.items()))
    if st.session_state.get("chat"):
        last = [m for m in st.session_state["chat"] if m["role"] == "assistant"][-1]["content"]
        md.append("\n## Saran AI Teknisi (terakhir)\n" + last)
    report = "\n".join(md)
    st.markdown(report)
    st.download_button("⬇️ Unduh laporan (.md)", report, file_name="laporan_diagnosa.md", mime="text/markdown")
