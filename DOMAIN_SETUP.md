# 🌍 Domain Setup & Deployment Guide

## Şu Anki Durum
```
Localhost: http://localhost:5000 (Dev)
Veritabanı: SQLite (admin.db)
Framework: Flask
```

---

## DOMAIN MANTIK: Nasıl Çalışıyor?

### Senaryo 1: Localhost (Şu Anda)
```
http://localhost:5000/
  ├─ / → Landing page
  ├─ /pricing → Pricing
  ├─ /demo → Demo reports
  ├─ /admin/login → Admin login
  └─ /admin/dashboard → Admin panel
```

**Veritabanı:** `admin.db` (local SQLite)
**Giriş:** username + password

---

### Senaryo 2: Production (Domain)
```
https://adanalyzer.io/
  ├─ / → Landing page (pazarlama)
  ├─ /pricing → Pricing
  ├─ /demo → Demo
  ├─ /admin/login → Admin login (adanalyzer.io)
  └─ /admin/dashboard → Admin panel
```

**Veritabanı:** PostgreSQL (cloud üzerine)
**Giriş:** Aynı (username + password)

---

### Senaryo 3: Subdomain (Gelişmiş)
```
adanalyzer.io/                 → Marketing site
admin.adanalyzer.io/           → Admin panel only
api.adanalyzer.io/             → API endpoints
```

**Yapı:**
```python
# app.py içinde
@app.route('/admin/login', subdomain='admin')  # admin.domain.com/login
@app.route('/api/data', subdomain='api')       # api.domain.com/data
```

---

## BAŞLAMA ADIMları

### 1️⃣ DEV (Localhost) - Şu Anda
```bash
cd ad_analyzer
python -m venv venv
source venv/Scripts/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Açıl: `http://localhost:5000`

**Admin Test:**
- URL: `http://localhost:5000/admin/login`
- Username: Herhangi biri (veritabanında yok, hata verecek)

---

### 2️⃣ PRODUCTION (Domain Satın Alma)

#### A) Domain Satın Al
```
godaddy.com, namecheap.com, domain.com
Örnek: adanalyzer.io ($10-15/yıl)
```

#### B) Hosting Seç
**En İyi Seçenekler:**

**Option 1: PaaS (En Kolay)**
```
Heroku, Railway, Render
- Yazıp push et
- Otomatik deploy
- Database included
```

**Option 2: VPS (En İyi)**
```
DigitalOcean, Linode, Vultr ($6-20/ay)
- Full kontrol
- Custom domain
- Email, SSL hepsi var
```

**Option 3: AWS/Azure/GCP**
```
- Scalable
- Production-grade
- Pahalı olabilir
```

---

### 3️⃣ Domain Bağlantısı

**DNS Settings (Domain Provider):**
```
A Record:    points to → 123.45.67.89 (Server IP)
CNAME:       www → adanalyzer.io
MX Record:   mail settings (email için)
```

**SSL Sertifikası (HTTPS):**
```
Let's Encrypt (FREE)
certbot install → otomatik yenilenir
```

---

## PRODUCTION DEPLOYMENT

### 1. VPS Kurulum (DigitalOcean örneği)

```bash
# Server'a SSH'le gir
ssh root@123.45.67.89

# System update
apt update && apt upgrade -y

# Python & dependenciesleri kur
apt install python3.11 python3-pip nginx postgresql
pip install gunicorn

# Proje kopyala
git clone https://github.com/yourname/ad-analyzer.git
cd ad-analyzer
pip install -r requirements.txt
```

### 2. Gunicorn Setup (WSGI Server)
```bash
# app.py'nin yanında wsgi.py oluştur
cat > wsgi.py << 'EOF'
from app import app
if __name__ == '__main__':
    app.run()
EOF

# Test et
gunicorn -w 4 -b 127.0.0.1:8000 wsgi:app
```

### 3. Systemd Service
```bash
# /etc/systemd/system/adanalyzer.service
[Unit]
Description=AD Analyzer
After=network.target

[Service]
User=www-data
WorkingDirectory=/var/www/ad-analyzer
ExecStart=/usr/local/bin/gunicorn -w 4 -b 127.0.0.1:8000 wsgi:app
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable adanalyzer
systemctl start adanalyzer
```

### 4. Nginx Reverse Proxy
```nginx
# /etc/nginx/sites-available/adanalyzer.io
server {
    listen 80;
    server_name adanalyzer.io www.adanalyzer.io;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # SSL (Let's Encrypt)
    listen 443 ssl;
    ssl_certificate /etc/letsencrypt/live/adanalyzer.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/adanalyzer.io/privkey.pem;
}
```

```bash
systemctl restart nginx
certbot install  # SSL otomatik kuruyor
```

---

## Database Migration

### SQLite → PostgreSQL

```bash
# PostgreSQL veritabanı oluştur
psql
CREATE DATABASE adanalyzer;
CREATE USER analyzer WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE adanalyzer TO analyzer;
\q
```

### app.py güncelle
```python
# Eski
import sqlite3
DATABASE = 'admin.db'

# Yeni
import psycopg2
DATABASE_URL = 'postgresql://analyzer:password@localhost/adanalyzer'

from sqlalchemy import create_engine
engine = create_engine(DATABASE_URL)
```

---

## ADMIN USER OLUŞTURMA

```python
# Terminal'de
python

>>> from werkzeug.security import generate_password_hash
>>> import sqlite3
>>> conn = sqlite3.connect('admin.db')
>>> c = conn.cursor()
>>> c.execute("INSERT INTO admins (username, password, email) VALUES (?, ?, ?)", 
...          ('admin', generate_password_hash('secure_pass_123'), 'admin@adanalyzer.io'))
>>> conn.commit()
>>> conn.close()

# Şimdi login et: admin / secure_pass_123
```

---

## Environment Variables (.env)

```
FLASK_ENV=production
SECRET_KEY=your-random-secret-key-here
DATABASE_URL=postgresql://user:pass@host/dbname
MAIL_SERVER=smtp.gmail.com
MAIL_USERNAME=your@email.com
MAIL_PASSWORD=app-password
DOMAIN=adanalyzer.io
DEBUG=False
```

```python
# app.py
import os
from dotenv import load_dotenv
load_dotenv()

app.secret_key = os.getenv('SECRET_KEY')
DATABASE_URL = os.getenv('DATABASE_URL')
```

---

## Monitoring & Logs

```bash
# Systemd logs
journalctl -u adanalyzer -f

# Nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# Application logs
tail -f /var/www/ad-analyzer/app.log
```

---

## SSL/HTTPS

```bash
# Let's Encrypt (FREE)
apt install certbot python3-certbot-nginx
certbot certonly --nginx -d adanalyzer.io -d www.adanalyzer.io

# Auto-renewal (systemd timer)
certbot renew --dry-run
```

---

## Heroku Deploy (En Kolay)

```bash
# Kurulum
heroku login
heroku create adanalyzer
git push heroku main

# Database
heroku addons:create heroku-postgresql:hobby-dev
```

---

## Subdomain Kurulumu (Advanced)

```
admin.adanalyzer.io → Admin panel
app.adanalyzer.io   → User dashboard
api.adanalyzer.io   → REST API
```

**DNS:**
```
admin  A  123.45.67.89
app    A  123.45.67.89
api    A  123.45.67.89
```

**Flask (Subdomain Routing):**
```python
@app.route('/', subdomain='admin')
def admin_home():
    return 'Admin Panel'

@app.route('/', subdomain='app')
def app_home():
    return 'User App'
```

---

## Şu Anki Yapı

```
Project: ad_analyzer/
├── app.py
├── templates/
│   ├── index.html (landing)
│   ├── pricing.html
│   ├── demo.html
│   ├── admin_login.html
│   ├── admin_dashboard.html
│   └── admin_subscribers.html
├── requirements.txt
├── admin.db (SQLite - local)
└── DOMAIN_SETUP.md (this file)
```

---

## Checkliste: Localhost → Production

- [ ] Domain satın al
- [ ] Hosting seç (Heroku/VPS)
- [ ] PostgreSQL veritabanı kur
- [ ] `.env` dosyası oluştur
- [ ] Admin user oluştur
- [ ] SSL sertifikası al
- [ ] DNS ayarlarını yaparlandır
- [ ] Gunicorn/Nginx kur
- [ ] Firewall kuralları ayarla
- [ ] Backups zamanla
- [ ] Monitoring kur
- [ ] Email sistemi ekle (opsiyonel)

---

## Quick Links

- Flask Docs: https://flask.palletsprojects.com
- PostgreSQL: https://www.postgresql.org
- Gunicorn: https://gunicorn.org
- Let's Encrypt: https://letsencrypt.org
- DigitalOcean: https://digitalocean.com
- Heroku: https://heroku.com

---

**Sorun olursa:** Dosyaları kontrol et, logs bak, stackoverflow'a sor!
