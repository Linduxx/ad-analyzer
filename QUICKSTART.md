# 🚀 AD Analyzer - Quick Start Guide

## 📦 Local Development (2 Dakika)

### 1. Python Virtual Environment
```bash
cd ad_analyzer
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Setup Admin User
```bash
python setup_admin.py
```

Output:
```
✅ Admin user created successfully!
📧 Username: admin
🔑 Password: admin123
```

### 4. Run App
```bash
python app.py
```

Visit: **http://localhost:5000**

---

## 🌐 Deploy to Render (5 Dakika)

### Step 1: Push to GitHub
```bash
git init
git add .
git commit -m "AD Analyzer - Final Project"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/ad-analyzer.git
git push -u origin main
```

### Step 2: Connect to Render
1. Go to **render.com**
2. Click "New Web Service"
3. Connect your GitHub repo
4. Select `main` branch
5. Click "Deploy"

**That's it!** 🎉

Your site will be live at: `https://ad-analyzer-xxxxx.onrender.com`

---

## 📱 What's Included

✅ **Landing Page** - Hero + Features showcase  
✅ **Pricing Page** - 3 pricing tiers  
✅ **Demo Reports** - 3 realistic AD audit examples  
✅ **Admin Panel** - Login + Dashboard + Subscriber list  
✅ **Email Subscribe** - Collect leads  
✅ **Responsive Design** - Mobile friendly  

---

## 🔧 Admin Panel

**Login:** http://your-domain.com/admin/login  
**Username:** admin  
**Password:** admin123  

**Change it immediately after first login!**

### Admin Pages:
- `/admin/dashboard` - Stats & metrics
- `/admin/subscribers` - View all email signups
- `/admin/logout` - Sign out

---

## 📊 Demo Reports

3 realistic Active Directory security audit reports:
- **Acme Corp** - Critical vulnerabilities
- **TechCorp** - High risk issues
- **Example.org** - Medium compliance gaps

View at: `/demo`

---

## 🎨 Customize

**Change app name:**
```html
<!-- index.html line 152 -->
<div class="logo">🔐 AD Analyzer</div>  ← Change this
```

**Change colors:**
```css
/* index.html line 17 */
color: #0066cc;  ← Change this (blue)
```

**Change pricing:**
```python
# app.py line 50-54
plans = [
    {'name': 'Starter', 'price': '$29', ...}
    ...
]
```

---

## 🚨 Before Showing Teacher

- ✅ Admin user created (`python setup_admin.py`)
- ✅ Run locally (`python app.py`)
- ✅ Test admin login (admin/admin123)
- ✅ Check demo reports
- ✅ Deploy to Render or run localhost

---

## 📝 Project Files

```
ad_analyzer/
├── app.py              # Main Flask app
├── wsgi.py             # For production servers
├── setup_admin.py      # Admin setup script
├── requirements.txt    # Dependencies
├── render.yaml         # Render.com config
├── .env.example        # Environment template
├── templates/
│   ├── index.html      # Landing page
│   ├── pricing.html    # Pricing
│   ├── demo.html       # Demo reports
│   ├── features.html   # Features
│   ├── admin_login.html
│   ├── admin_dashboard.html
│   └── admin_subscribers.html
└── DOMAIN_SETUP.md     # Detailed deploy guide
```

---

## 🆘 Troubleshooting

**Port 5000 already in use?**
```bash
python app.py --port 8000
```

**Admin can't login?**
```bash
# Delete database and recreate
rm admin.db
python setup_admin.py
python app.py
```

**Database errors?**
```bash
# Reinitialize
python -c "from app import init_db; init_db()"
```

---

## 💡 Next Steps

1. **Run locally** - Test everything works
2. **Customize** - Change colors, text, pricing
3. **Deploy** - Push to GitHub + Render
4. **Show teacher** - Impress them! 🎓

---

**Ready? Start with:**
```bash
python setup_admin.py && python app.py
```

Then visit: http://localhost:5000 ✨
