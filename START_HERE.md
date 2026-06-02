# 🎓 AD Analyzer - Hocaya Sunmak İçin

## ⚡ 3 Adımda Başla

### 1️⃣ Admin User Oluştur
```bash
python setup_admin.py
```

Çıktı:
```
[OK] Admin user ready!
[*] Username: admin
[*] Password: admin123
```

### 2️⃣ App'ı Çalıştır
```bash
python app.py
```

### 3️⃣ Açıl
- **Site:** http://localhost:5000
- **Admin:** http://localhost:5000/admin/login
  - Username: `admin`
  - Password: `admin123`

---

## 🎯 Ne Göstereceksin?

### Landing Page (/)
- Hero section - "Secure Your Active Directory"
- 6 feature cards
- CTA buttons
- Subscribe modal

### Pricing (/pricing)
3 plan:
- **Starter** - $29/month
- **Professional** - $99/month (popular)
- **Enterprise** - Custom

### Demo Reports (/demo)
3 realistic AD audit reports:
- 🔴 **Acme Corp** - CRITICAL (35/100)
- 🟠 **TechCorp** - HIGH (58/100)
- 🟡 **Example.org** - MEDIUM (72/100)

### Admin Panel (/admin/login)
- Dashboard - Stats & metrics
- Subscribers - Email signups
- Professional UI

---

## 📦 Hocaya Sunmak İçin

```bash
# Seçenek 1: Laptop'unda göster (en kolay)
python app.py
# Hocaya http://localhost:5000 açıl

# Seçenek 2: Online deploy et (şu anki hali ile)
# GitHub'a push et → Render'a deploy et
# Hocaya canlı URL ver
```

---

## 🔐 Proje İçeriği

```
ad_analyzer/
├── app.py                    # Flask app (main)
├── wsgi.py                   # Production server
├── setup_admin.py            # Admin setup
├── requirements.txt          # Dependencies
├── render.yaml               # Render.com config
├── templates/
│   ├── index.html           # Landing page
│   ├── pricing.html         # Pricing table
│   ├── demo.html            # Demo reports
│   ├── features.html        # Features page
│   └── admin_*.html         # Admin pages
└── admin.db                 # SQLite database
```

---

## 🚀 Opsiyonel: Online Deploy (5 Dakika)

Canlı site göstermek istersen:

### 1. GitHub'a Push Et
```bash
git init
git add .
git commit -m "AD Analyzer - Ders Projesi"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/ad-analyzer.git
git push -u origin main
```

### 2. Render'e Deploy Et
1. render.com'a git
2. "New Web Service" tıkla
3. GitHub repo bağla
4. "Deploy" tıkla
5. 2-3 dakikada hazır

**Canlı URL:** `https://ad-analyzer-xxxxx.onrender.com`

---

## ❓ Sık Sorulan Sorular

**Q: Database nerede?**
A: `admin.db` - SQLite, otomatik oluşturulur

**Q: Admin şifresi değişebilir mi?**
A: Evet, admin panelde değiştirebilir

**Q: Email'ler nereye kaydediliyor?**
A: Database'e kaydediliyor (admin panel'de görünür)

**Q: Renk değiştirebilir miyim?**
A: Evet, `templates/index.html` line 25'teki `#0066cc` değişdir

---

## ✅ Hocaya Sunmadan Önce Checklist

- [ ] `python setup_admin.py` çalıştırdım
- [ ] `python app.py` çalıştı
- [ ] http://localhost:5000 açıldı
- [ ] Admin login'i test ettim (admin/admin123)
- [ ] Demo reports'ı kontrol ettim (/demo)
- [ ] Pricing sayfasını gördüm (/pricing)

---

## 💡 Eğer Sorun Olursa

**Port 5000 kullanılıyor?**
```bash
python app.py --port 8000
```

**Admin şifresi unuttun?**
```bash
# admin.db'yi sil, yenisini oluştur
rm admin.db
python setup_admin.py
python app.py
```

**Import error?**
```bash
pip install -r requirements.txt
```

---

## 📝 Bu Dosya Ne İçin?

Bu rehber hocanın ortasında "nasıl çalıştırırım?" diye sormayı önlemek için.

**TL;DR:**
```bash
python setup_admin.py
python app.py
# Visit: http://localhost:5000
```

**That's it!** 🎉

---

Başarılar! 🚀
