#!/usr/bin/env python3
"""
Quick admin user setup script
Usage: python setup_admin.py
"""
import sqlite3
from werkzeug.security import generate_password_hash

def setup_admin():
    conn = sqlite3.connect('admin.db')
    c = conn.cursor()

    # Create tables if they don't exist
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

    # Default admin credentials
    username = 'admin'
    password = 'admin123'
    email = 'admin@adanalyzer.io'

    # Delete existing admin if present
    c.execute("DELETE FROM admins WHERE username = ?", (username,))
    conn.commit()

    # Create fresh admin
    hashed = generate_password_hash(password)
    c.execute(
        "INSERT INTO admins (username, password, email) VALUES (?, ?, ?)",
        (username, hashed, email)
    )
    conn.commit()
    print(f"\n[OK] Admin user ready!")
    print(f"\n[*] Username: {username}")
    print(f"[*] Password: {password}")
    print(f"[*] Login URL: http://localhost:5000/admin/login")
    print(f"\n[!] CHANGE THIS PASSWORD AFTER FIRST LOGIN!\n")
    conn.close()

if __name__ == '__main__':
    setup_admin()
