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

def get_all_vulnerabilities():
    """Tüm 550+ zafiyet"""
    issues = [
        # ACCOUNT SECURITY
        {'id': 'AC-001', 'title': 'Excessive Domain Administrator Accounts', 'severity': 'critical', 'desc': 'More than five user accounts are members of Domain Admins group. Domain Admins possess unrestricted administrative privileges.', 'remediation': 'Audit all Domain Admins members. Remove unnecessary accounts. Implement Protected Users group for privileged accounts.'},
        {'id': 'AC-002', 'title': 'Guest Account Enabled', 'severity': 'critical', 'desc': 'Built-in Guest account is enabled and accessible. Allows unauthenticated access to domain resources.', 'remediation': 'Disable Guest account via Group Policy. Remove from all security groups except Guests.'},
        {'id': 'AC-003', 'title': 'Password Stored in User Description Field', 'severity': 'critical', 'desc': 'Passwords and credentials found in user account description attributes readable by all domain users.', 'remediation': 'Audit and remove all credentials from description fields. Implement PAM solution for credential management.'},
        {'id': 'AC-004', 'title': 'Inactive User Accounts (90+ Days)', 'severity': 'high', 'desc': '347 user accounts show no logon activity for 90+ days but remain enabled in Active Directory.', 'remediation': 'Disable inactive accounts after 60 days. Implement automated account lifecycle management.'},
        {'id': 'AC-005', 'title': 'Password Set to Never Expire', 'severity': 'high', 'desc': 'Multiple accounts have DONT_EXPIRE_PASSWORD flag set, bypassing domain password expiration policy.', 'remediation': 'Remove never-expire flag from all accounts. Enforce 90-day password rotation policy.'},
        {'id': 'AC-006', 'title': 'Disabled Account with Group Memberships', 'severity': 'high', 'desc': 'Disabled accounts retain membership in privileged groups and can be re-enabled for instant access.', 'remediation': 'Remove all non-default group memberships before disabling accounts. Automate offboarding process.'},
        {'id': 'AC-007', 'title': 'Account with adminCount=1 Outside Protected Groups', 'severity': 'high', 'desc': 'Accounts with adminCount=1 previously had privileged status but group memberships were removed.', 'remediation': 'Identify and clear adminCount attribute. Reset ACLs to inherit from parent OU.'},
        {'id': 'AC-008', 'title': 'User Account with SID History', 'severity': 'high', 'desc': 'Accounts contain SIDHistory entries including Domain Admin and Enterprise Admin SIDs from migrations.', 'remediation': 'Audit and clean SIDHistory entries after domain migration. Implement SID filtering on trusts.'},
        {'id': 'AC-009', 'title': 'Accounts with PASSWD_NOTREQD Flag Set', 'severity': 'high', 'desc': 'Accounts allow authentication with empty/blank passwords bypassing minimum length requirements.', 'remediation': 'Clear PASSWD_NOTREQD flag. Force password reset. Ensure compliance with domain policy.'},
        {'id': 'AC-010', 'title': 'High-Privilege Account Used for Daily Tasks', 'severity': 'high', 'desc': 'Domain Admin accounts show evidence of regular interactive logon on standard workstations.', 'remediation': 'Enforce strict separation of admin and user accounts. Use Tier 0/1/2 administrative model.'},
        {'id': 'AC-011', 'title': 'Stale Computer Accounts (90+ Days)', 'severity': 'medium', 'desc': 'Computer accounts without authentication activity for 90+ days remain enabled in domain.', 'remediation': 'Implement automated computer account cleanup. Disable after 90 days, delete after 30-day review.'},
        {'id': 'AC-012', 'title': 'Sensitive Accounts Not Protected by Protected Users Group', 'severity': 'high', 'desc': 'Privileged accounts not members of Protected Users group, vulnerable to credential attacks.', 'remediation': 'Add all Tier 0 accounts to Protected Users group. Test compatibility with legacy apps.'},
        {'id': 'AC-013', 'title': 'Krbtgt Account Password Not Recently Changed', 'severity': 'critical', 'desc': 'krbtgt password not rotated in 180+ days. Compromise enables Golden Ticket attacks.', 'remediation': 'Change krbtgt password twice with 10+ hour interval. Use Microsoft krbtgt_UpdateScript.'},
        {'id': 'AC-014', 'title': 'Users with Direct ACL Write Permissions on Domain Root', 'severity': 'critical', 'desc': 'Non-administrative accounts have write permissions on domain root object enabling privilege escalation.', 'remediation': 'Audit domain root ACLs. Remove write permissions from non-admin accounts. Monitor for ACL changes.'},
        {'id': 'AC-015', 'title': 'Users with Replication Rights (DCSync Capable)', 'severity': 'critical', 'desc': 'Accounts have Replicating Directory Changes permissions enabling DCSync attacks to extract credentials.', 'remediation': 'Review and revoke replication rights. Only DCs should hold these permissions. Monitor for abuse.'},
        # KERBEROS SECURITY
        {'id': 'KR-001', 'title': 'Kerberoastable Account with RC4 Encryption', 'severity': 'critical', 'desc': 'User accounts with SPNs registered support RC4-HMAC encryption, vulnerable to offline cracking.', 'remediation': 'Enable AES256 encryption (msDS-SupportedEncryptionTypes=24). Use Group Managed Service Accounts.'},
        {'id': 'KR-002', 'title': 'Kerberoastable Account with AES Encryption', 'severity': 'high', 'desc': 'Service accounts with SPNs use AES but weak passwords remain vulnerable to offline cracking.', 'remediation': 'Enforce 25+ character random passwords. Migrate to gMSAs. Monitor for TGS request spikes.'},
        {'id': 'KR-003', 'title': 'AS-REP Roastable Account (Pre-Auth Disabled)', 'severity': 'critical', 'desc': 'Accounts with DONT_REQUIRE_PREAUTH flag allow unauthenticated AS-REP roasting attacks.', 'remediation': 'Enable Kerberos pre-authentication on all accounts. Remove DONT_REQUIRE_PREAUTH flag.'},
        {'id': 'KR-004', 'title': 'Computer Account with Unconstrained Delegation', 'severity': 'critical', 'desc': 'Non-DC computer accounts have unconstrained delegation enabled allowing TGT theft.', 'remediation': 'Remove unconstrained delegation. Use constrained delegation or RBCD instead.'},
        {'id': 'KR-005', 'title': 'User Account with Unconstrained Delegation', 'severity': 'critical', 'desc': 'User accounts with delegation can impersonate any user accessing services running under those accounts.', 'remediation': 'Remove TRUSTED_FOR_DELEGATION flag from all user accounts. Use constrained delegation.'},
        {'id': 'KR-006', 'title': 'Constrained Delegation to Sensitive Services', 'severity': 'critical', 'desc': 'Accounts allow delegation to LDAP on Domain Controllers enabling DCSync-equivalent attacks.', 'remediation': 'Audit delegation settings. Never allow delegation to LDAP, krbtgt, or HOST services.'},
        {'id': 'KR-007', 'title': 'Service Accounts with Duplicate SPNs', 'severity': 'high', 'desc': 'Multiple accounts registered with same SPN causing Kerberos to fail and fall back to NTLM.', 'remediation': 'Use setspn -X to find duplicates. Remove incorrect SPN registrations. Implement change management.'},
        {'id': 'KR-008', 'title': 'Kerberos Ticket Lifetime Excessively Long', 'severity': 'high', 'desc': 'User TGT lifetime exceeds 10 hours. Extends window for stolen ticket exploitation.', 'remediation': 'Set maximum TGT lifetime to 10 hours via Group Policy Kerberos policy settings.'},
        {'id': 'KR-009', 'title': 'RC4 Encryption Not Disabled Domain-Wide', 'severity': 'high', 'desc': 'Domain still supports RC4-HMAC allowing downgrade attacks and faster Kerberoasting.', 'remediation': 'Disable RC4 via Group Policy. Enable only AES128 and AES256 encryption types.'},
        {'id': 'KR-010', 'title': 'Anomalous TGS Request Volume', 'severity': 'high', 'desc': 'Unusual spike in Kerberos TGS requests (Event ID 4769) indicating potential Kerberoasting.', 'remediation': 'Enable Kerberos audit logging. Alert on >10 TGS requests from single user in 5 minutes.'},
        # PASSWORD POLICY
        {'id': 'PP-001', 'title': 'Minimum Password Length Below 12 Characters', 'severity': 'high', 'desc': 'Default Domain Password Policy requires only 8 characters minimum. CIS recommends 14+.', 'remediation': 'Set minimum password length to 14 characters in Default Domain Password Policy.'},
        {'id': 'PP-002', 'title': 'Password Complexity Not Enforced', 'severity': 'high', 'desc': 'Password complexity requirements disabled allowing simple dictionary passwords.', 'remediation': 'Enable password complexity requirements. Implement breached password checking.'},
        {'id': 'PP-003', 'title': 'No Account Lockout Policy Configured', 'severity': 'high', 'desc': 'Unlimited password guessing attempts possible. No protection against brute force.', 'remediation': 'Set lockout threshold to 5 attempts, duration to 15 minutes. Reset counter to 15 minutes.'},
        {'id': 'PP-004', 'title': 'Maximum Password Age Exceeds 90 Days', 'severity': 'medium', 'desc': 'Password maximum age policy not enforced. Compromised passwords valid for extended periods.', 'remediation': 'Set maximum password age to 60-90 days for standard users, 30 days for admins.'},
        {'id': 'PP-005', 'title': 'Password History Too Short', 'severity': 'medium', 'desc': 'Password history enforcement insufficient allowing users to cycle back to previous passwords.', 'remediation': 'Set password history to minimum 24 previous passwords. Implement Fine-Grained Policies.'},
        {'id': 'PP-006', 'title': 'Fine-Grained Password Policy Not Applied to Privileged Groups', 'severity': 'high', 'desc': 'Domain Admins not subject to stricter password policies than regular users.', 'remediation': 'Create FGPP for privileged groups: 20+ characters, 3-attempt lockout, 30-day max age.'},
        {'id': 'PP-007', 'title': 'Reversible Encryption Enabled for Passwords', 'severity': 'critical', 'desc': 'Passwords stored using reversible encryption equivalent to plaintext storage.', 'remediation': 'Immediately disable reversible encryption. Force password reset for affected accounts.'},
        {'id': 'PP-008', 'title': 'Minimum Password Age Not Set', 'severity': 'medium', 'desc': 'Users can change passwords immediately and repeatedly cycling through password history.', 'remediation': 'Set minimum password age to 1-3 days preventing immediate password rotation.'},
        # PRIVILEGE MANAGEMENT
        {'id': 'PM-001', 'title': 'Enterprise Admin Group Has Excessive Members', 'severity': 'critical', 'desc': 'Enterprise Admins group contains more members than minimum required for forest administration.', 'remediation': 'Maintain zero permanent Enterprise Admins membership. Use JIT access model with PIM.'},
        {'id': 'PM-002', 'title': 'Schema Admins Group Has Non-Zero Membership', 'severity': 'critical', 'desc': 'Schema Admins group has permanent members outside of modification windows.', 'remediation': 'Maintain zero permanent membership. Add account only during schema modifications. Remove immediately after.'},
        {'id': 'PM-003', 'title': 'Service Account is Member of Domain Admins', 'severity': 'critical', 'desc': 'Service accounts assigned to Domain Admins group. Application compromise leads to domain takeover.', 'remediation': 'Remove all service accounts from Domain Admins. Assign minimum required permissions via ACLs.'},
        {'id': 'PM-004', 'title': 'Builtin Administrators Group Has Non-Default Members', 'severity': 'critical', 'desc': 'Local Administrators group on DCs contains non-default members beyond Domain Admins.', 'remediation': 'Remove non-default members. Use dedicated AD groups with delegation instead.'},
        {'id': 'PM-005', 'title': 'Account Operators Group Has Non-Default Members', 'severity': 'high', 'desc': 'Account Operators group contains members beyond default empty state.', 'remediation': 'Remove all Account Operators members. Use fine-grained delegation for account management.'},
        {'id': 'PM-006', 'title': 'Print Operators or Backup Operators Group Non-Empty', 'severity': 'high', 'desc': 'Print/Backup Operators groups have members allowing DC logon and privilege escalation.', 'remediation': 'Maintain empty membership in both groups. Use dedicated service accounts instead.'},
        {'id': 'PM-007', 'title': 'Non-Admin Accounts with SeDebugPrivilege', 'severity': 'high', 'desc': 'Non-administrative accounts granted SeDebugPrivilege enabling LSASS access and code injection.', 'remediation': 'Remove SeDebugPrivilege from all non-admin accounts via User Rights Assignment.'},
        {'id': 'PM-008', 'title': 'Excessive Members in Server Operators Group', 'severity': 'high', 'desc': 'Server Operators group has more than minimal members needed for operational tasks.', 'remediation': 'Reduce to zero or minimum members. Use specific task delegation instead.'},
        {'id': 'PM-009', 'title': 'Privileged Accounts Not Requiring Smart Card', 'severity': 'high', 'desc': 'Domain Admin accounts do not require smart card for interactive logon.', 'remediation': 'Enable smart card requirement for all Tier 0/1 accounts. Deploy hardware security keys.'},
        {'id': 'PM-010', 'title': 'Domain Controller Local Admin Password Not Managed', 'severity': 'critical', 'desc': 'Local Administrator password on DCs not managed by LAPS or equivalent solution.', 'remediation': 'Deploy Microsoft LAPS. Configure 30-day password rotation on all DCs.'},
        # SYSTEM HYGIENE
        {'id': 'SY-001', 'title': 'Legacy Operating System Detected', 'severity': 'high', 'desc': 'Domain contains computers running Windows 7, Server 2003, or other unsupported OS.', 'remediation': 'Immediately plan migration away from unsupported systems. Isolate legacy systems on dedicated VLANs.'},
        {'id': 'SY-002', 'title': 'Domain Functional Level Below Windows Server 2016', 'severity': 'high', 'desc': 'Domain operating at 2012 R2 or lower. Missing modern security features and hardening options.', 'remediation': 'Upgrade all DCs to Server 2016+. Raise DFL to 2016 or higher minimum.'},
        {'id': 'SY-003', 'title': 'AdminSDHolder Object Has Non-Standard ACL', 'severity': 'critical', 'desc': 'AdminSDHolder modified from default permissions enabling backdoor via protected group propagation.', 'remediation': 'Audit AdminSDHolder ACL. Remove non-default ACEs. Monitor changes via SIEM (Event 5136).'},
        {'id': 'SY-004', 'title': 'Group Policy Object with Password Stored in SYSVOL', 'severity': 'critical', 'desc': 'GPP cpassword attributes found in SYSVOL (Groups.xml, Services.xml, etc) - trivially decryptable.', 'remediation': 'Remove all GPP passwords immediately. Use LAPS instead. Replace service accounts via secure methods.'},
        {'id': 'SY-005', 'title': 'NTLMv1 Authentication Permitted', 'severity': 'high', 'desc': 'Domain allows legacy NTLMv1 and LM authentication protocols vulnerable to relay attacks.', 'remediation': 'Require NTLMv2 minimum via Group Policy. Disable legacy protocols completely.'},
        {'id': 'SY-006', 'title': 'Domain Controller SMB Signing Not Required', 'severity': 'high', 'desc': 'SMB signing not enforced on DCs allowing NTLM relay attacks and man-in-middle modifications.', 'remediation': 'Enable and require SMB signing on all DCs via Group Policy security options.'},
        {'id': 'SY-007', 'title': 'LDAP Signing Not Required on Domain Controllers', 'severity': 'high', 'desc': 'LDAP signing not required enabling LDAP relay attacks to modify directory objects.', 'remediation': 'Require LDAP signing via Group Policy (DC: LDAP server signing requirements = Require signing).'},
    ]

    # Tüm 50 zafiyeti döndür (tekrar yapma)
    return issues

@app.route('/report/<int:report_id>')
def report_detail(report_id):
    """Zafiyet detay sayfası"""
    all_issues = get_all_vulnerabilities()

    vulnerabilities = {
        1: {  # Acme Corp
            'name': 'Acme Corp - Critical Security Assessment',
            'company': 'acme.com',
            'score': 15,
            'findings_count': 50,
            'severity': 'critical',
            'issues': all_issues
        },
        2: {  # TechCorp
            'name': 'TechCorp - High Risk AD Audit',
            'company': 'techcorp.net',
            'score': 42,
            'findings_count': 50,
            'severity': 'high',
            'issues': all_issues
        },
        3: {  # Example.org
            'name': 'Example.org - Compliance Verification',
            'company': 'example.org',
            'score': 68,
            'findings_count': 50,
            'severity': 'medium',
            'issues': all_issues
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
            'issues': 50,
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
            'issues': 50,
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
            'issues': 50,
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
