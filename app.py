#!/usr/bin/env python3
"""
AD Analyzer - Marketing Site + Admin Panel
Domain: localhost:5000 (dev) → domain.com (prod)
"""
from flask import Flask, render_template, request, session, redirect, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, secrets
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
DATABASE = 'admin.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS subscribers (
        id INTEGER PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        plan TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()

    # Create default admin if not exists
    c.execute('SELECT COUNT(*) as count FROM admins')
    if c.fetchone()['count'] == 0:
        hashed = generate_password_hash('admin123')
        c.execute("INSERT INTO admins (username, password, email) VALUES (?, ?, ?)",
                 ('admin', hashed, 'admin@adanalyzer.io'))
        conn.commit()

    conn.close()

init_db()

# ==================== MARKETİNG ROUTES ====================

@app.route('/')
def home():
    """Landing page - pazarlama sitesi"""
    return render_template('index.html')

@app.route('/pricing')
def pricing():
    """Fiyatlandırma sayfası"""
    plans = [
        {'name': 'Starter', 'price': '$29', 'period': '/month', 'features': ['10 scans', 'Basic reports', 'Email support']},
        {'name': 'Professional', 'price': '$99', 'period': '/month', 'features': ['100 scans', 'Advanced reports', 'Priority support', 'API'], 'popular': True},
        {'name': 'Enterprise', 'price': 'Custom', 'period': '', 'features': ['Unlimited', 'Custom reports', '24/7 support', 'Dedicated account']}
    ]
    return render_template('pricing.html', plans=plans)

@app.route('/features')
def features():
    """Özellikler sayfası"""
    features_list = [
        {'icon': '📊', 'title': '50-Point Assessment', 'desc': 'Comprehensive security analysis'},
        {'icon': '📈', 'title': 'Detailed Reports', 'desc': 'Professional HTML/PDF reports'},
        {'icon': '🔔', 'title': 'Real-time Alerts', 'desc': 'Instant notifications for issues'},
        {'icon': '🔐', 'title': 'Enterprise Security', 'desc': 'Bank-level encryption'},
        {'icon': '⚡', 'title': 'API Access', 'desc': 'Integrate with your tools'},
        {'icon': '👥', 'title': 'Team Collaboration', 'desc': 'Share reports easily'}
    ]
    return render_template('features.html', features=features_list)

def generate_vulnerabilities(count=550):
    """Generate detailed vulnerability list"""
    vuln_templates = [
        {'id': 'AC-{:03d}', 'title': 'Excessive Domain Administrator Accounts', 'severity': 'critical', 'desc': 'Multiple user accounts with unrestricted administrative privileges detected in Domain Admins group.', 'remediation': 'Audit and implement least privilege access. Remove unnecessary admin accounts and use Protected Users group.'},
        {'id': 'AC-{:03d}', 'title': 'Guest Account Enabled', 'severity': 'critical', 'desc': 'Built-in Guest account is in enabled state allowing anonymous access to resources.', 'remediation': 'Disable Guest account immediately via Group Policy. Remove from all security groups.'},
        {'id': 'KR-{:03d}', 'title': 'Kerberoastable Service Accounts', 'severity': 'critical', 'desc': 'Service accounts with SPNs support weak RC4 encryption enabling offline password cracking.', 'remediation': 'Enable AES256 encryption on all service accounts. Migrate to Group Managed Service Accounts (gMSAs).'},
        {'id': 'PP-{:03d}', 'title': 'Weak Password Policy Configuration', 'severity': 'high', 'desc': 'Password minimum length below recommended standards. Current: 8 characters, Recommended: 14+', 'remediation': 'Update Group Policy to enforce 14+ character passwords with complexity requirements.'},
        {'id': 'PM-{:03d}', 'title': 'Privileged Account Missing MFA', 'severity': 'high', 'desc': 'Domain Admin accounts do not require multi-factor authentication for login.', 'remediation': 'Enable MFA for all Tier 0 and Tier 1 accounts. Deploy smart cards or hardware tokens.'},
        {'id': 'SY-{:03d}', 'title': 'Legacy Protocol Support Enabled', 'severity': 'high', 'desc': 'NTLMv1 and LM authentication protocols still enabled in domain, vulnerable to relay attacks.', 'remediation': 'Disable legacy protocols. Require NTLMv2 minimum via Group Policy security settings.'},
        {'id': 'AC-{:03d}', 'title': 'Inactive User Accounts Not Removed', 'severity': 'medium', 'desc': 'User accounts with no logon activity for 90+ days still active and assigned to privileged groups.', 'remediation': 'Implement automated account lifecycle management. Disable inactive accounts after 60 days.'},
        {'id': 'PP-{:03d}', 'title': 'No Account Lockout Policy', 'severity': 'medium', 'desc': 'Account lockout policy not configured enabling unlimited password guessing attempts.', 'remediation': 'Configure 5 failed attempts lockout with 15-minute duration via Group Policy.'},
    ]

    issues = []
    for i in range(count):
        template = vuln_templates[i % len(vuln_templates)]
        issues.append({
            'id': template['id'].format(i + 1),
            'title': f"{template['title']} (Instance {i // len(vuln_templates) + 1})",
            'severity': template['severity'],
            'desc': template['desc'],
            'remediation': template['remediation']
        })
    return issues

@app.route('/report/<int:report_id>')
def report_detail(report_id):
    """Zafiyet detay sayfası"""
    all_issues = generate_vulnerabilities(550)

    vulnerabilities = {
        1: {  # Acme Corp
            'name': 'Acme Corp - Critical Security Assessment',
            'company': 'acme.com',
            'score': 15,
            'findings_count': 550,
            'severity': 'critical',
            'issues': all_issues
        },
        2: {  # TechCorp
            'name': 'TechCorp - High Risk AD Audit',
            'company': 'techcorp.net',
            'score': 42,
            'findings_count': 487,
            'severity': 'high',
            'issues': all_issues[50:487]
        },
        3: {  # Example.org
            'name': 'Example.org - Compliance Verification',
            'company': 'example.org',
            'score': 68,
            'findings_count': 95,
            'severity': 'medium',
            'issues': all_issues[400:495]
        }
    }

    if report_id not in vulnerabilities:
        return redirect('/demo')

    report = vulnerabilities[report_id]
    return render_template('report_detail.html', report=report)

@app.route('/demo')
def demo():
    """Demo raporlar"""
    reports = [
        {
            'title': 'Acme Corp - Critical Security Assessment',
            'company': 'acme.com',
            'severity': 'critical',
            'score': 15,
            'issues': 550,
            'date': '2026-05-20',
            'summary': 'Critical security vulnerabilities detected across multiple domains. Immediate remediation required.',
            'risk_distribution': {'critical': 8, 'high': 10, 'medium': 6},
            'assessment_scope': '2,847 users | 156 groups | 42 GPOs | 8 domain controllers',
            'findings': [
                'Multi-Factor Authentication (MFA) completely disabled on all user accounts',
                'Kerberos delegation misconfigured - potential privilege escalation vectors',
                'Domain Group Policy Objects (GPOs) not properly configured for security',
                '347 stale/inactive user accounts still maintaining active status',
                'No audit logging for privileged account changes and modifications',
                'Service account passwords stored in AD description fields (security risk)',
                'Domain functional level below 2016 minimum - legacy authentication enabled',
                'No account lockout policy - brute force attacks possible'
            ],
            'recommendations': [
                'Enable MFA immediately for all accounts (Azure AD, Duo Security, or similar)',
                'Audit and reconfigure all Kerberos delegation settings',
                'Review and update all 42 Group Policy Objects for security compliance',
                'Disable or remove 347 inactive user accounts within 30 days',
                'Implement comprehensive audit logging for all privileged AD changes',
                'Migrate service account passwords to secure vaults (Azure Key Vault, CyberArk)',
                'Upgrade domain functional level to 2016 or higher immediately',
                'Implement account lockout policy: 5 attempts in 30 minutes with 30-min lockout'
            ],
            'remediation_timeline': '14-21 days for critical items',
            'compliance_gaps': ['SOC2 Type II', 'HIPAA', 'PCI-DSS', 'ISO 27001']
        },
        {
            'title': 'TechCorp - High Risk AD Audit',
            'company': 'techcorp.net',
            'severity': 'high',
            'score': 42,
            'issues': 487,
            'date': '2026-05-18',
            'summary': 'Several high-risk security issues identified. Should be addressed within 30 days.',
            'risk_distribution': {'critical': 0, 'high': 8, 'medium': 10},
            'assessment_scope': '1,256 users | 89 groups | 31 GPOs | 4 domain controllers',
            'findings': [
                'Account lockout policy not configured - no protection against brute force attacks',
                'Legacy authentication protocols (NTLM, LM) still enabled on domain',
                'Domain audit logging incomplete - critical events not being captured',
                'Weak password policies (minimum 8 characters, no complexity requirements)',
                'Administrative groups contain 23 unnecessary users with elevated privileges',
                'No conditional access policies in place for risk-based authentication',
                'DNS security (DNSSEC) not implemented - vulnerable to DNS spoofing',
                'Password expiration policies inconsistent across organizational units'
            ],
            'recommendations': [
                'Implement account lockout policy: 5 attempts in 30 minutes, 30-minute lockout duration',
                'Disable NTLM and LM protocols, require Kerberos-only authentication',
                'Enable comprehensive audit logging on all 4 domain controllers',
                'Enforce strong password policy: 14+ characters, complexity, 90-day rotation',
                'Audit and remove 23 unnecessary administrative group members within 14 days',
                'Deploy conditional access rules for risk-based authentication and MFA',
                'Implement DNSSEC to prevent DNS spoofing and security attacks',
                'Standardize password expiration policies across all organizational units'
            ],
            'remediation_timeline': '30-45 days',
            'compliance_gaps': ['SOC2 Type II', 'ISO 27001', 'NIST Cybersecurity Framework']
        },
        {
            'title': 'Example.org - Compliance Verification Audit',
            'company': 'example.org',
            'severity': 'medium',
            'score': 68,
            'issues': 95,
            'date': '2026-05-15',
            'summary': 'Moderate security gaps identified. Address within 60 days to maintain compliance.',
            'risk_distribution': {'critical': 0, 'high': 2, 'medium': 6},
            'assessment_scope': '892 users | 67 groups | 22 GPOs | 3 domain controllers',
            'findings': [
                'Conditional access policies only partially implemented - coverage gaps exist',
                'Multi-factor authentication not enforced for remote access connections',
                'Privileged Identity Management (PIM) not configured or deployed',
                'Password reset frequency not enforced - no maximum password age set',
                'Inactive accounts not automatically disabled after 90 days',
                'Device compliance policies incomplete - endpoints not validated',
                'Security awareness training records incomplete or outdated',
                'Backup and disaster recovery procedures not documented for AD'
            ],
            'recommendations': [
                'Expand conditional access to cover all remote access and sensitive operations',
                'Require MFA for all VPN, RDP, and remote access connections immediately',
                'Deploy Azure AD Privileged Identity Management (PIM) for privileged accounts',
                'Set password reset requirement to every 60-90 days with enforcement',
                'Implement automatic account disabling after 90 days of inactivity',
                'Define and enforce device compliance standards for all endpoints',
                'Conduct annual security awareness training for all 892 users',
                'Document and test AD backup and disaster recovery procedures monthly'
            ],
            'remediation_timeline': '60 days',
            'compliance_gaps': ['SOC2 Type II', 'GDPR', 'HIPAA', 'ISO 27001']
        }
    ]
    return render_template('demo.html', reports=reports)

# ==================== ADMIN PANEL ROUTES ====================

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin giriş"""
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM admins WHERE username = ?', (data.get('username'),))
        admin = c.fetchone()
        conn.close()

        if admin and check_password_hash(admin['password'], data.get('password')):
            session['admin_id'] = admin['id']
            session['admin_username'] = admin['username']
            return jsonify({'status': 'success', 'redirect': '/admin/dashboard'}) if request.is_json else redirect('/admin/dashboard')

        if request.is_json:
            return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401
        return render_template('admin_login.html', error='Invalid credentials')

    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin paneli"""
    if 'admin_id' not in session:
        return redirect('/admin/login')

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT COUNT(*) as count FROM subscribers')
    total_subs = c.fetchone()['count']
    c.execute('SELECT COUNT(*) as count FROM subscribers WHERE plan IS NOT NULL')
    paid_subs = c.fetchone()['count']
    conn.close()

    stats = {
        'total_subscribers': total_subs,
        'paid_subscribers': paid_subs,
        'free_users': total_subs - paid_subs,
        'mrr': paid_subs * 50  # Approximate
    }

    return render_template('admin_dashboard.html', admin=session['admin_username'], stats=stats)

@app.route('/admin/subscribers')
def admin_subscribers():
    """Aboneleri listele"""
    if 'admin_id' not in session:
        return redirect('/admin/login')

    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM subscribers ORDER BY created_at DESC')
    subscribers = c.fetchall()
    conn.close()

    return render_template('admin_subscribers.html', subscribers=subscribers)

@app.route('/admin/logout')
def admin_logout():
    """Çıkış"""
    session.clear()
    return redirect('/')

# ==================== API ROUTES ====================

@app.route('/api/subscribe', methods=['POST'])
def api_subscribe():
    """Email subscribe"""
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'status': 'error', 'message': 'Email required'}), 400

    conn = get_db()
    c = conn.cursor()
    try:
        c.execute('INSERT INTO subscribers (email, plan) VALUES (?, ?)', (email, 'free'))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Subscribed!'})
    except sqlite3.IntegrityError:
        return jsonify({'status': 'error', 'message': 'Already subscribed'}), 400
    finally:
        conn.close()

# ==================== SETUP ====================

if __name__ == '__main__':
    init_db()
    debug_mode = os.getenv('FLASK_ENV', 'development') == 'development'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
