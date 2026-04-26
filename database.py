import sqlite3
import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DATABASE = 'fraud_detection.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def migrate_db():
    """Add missing columns to existing database"""
    conn = get_db_connection()
    
    # Check if columns exist and add them if not
    cursor = conn.execute("PRAGMA table_info(applications)")
    columns = [row[1] for row in cursor.fetchall()]
    
    if 'age' not in columns:
        conn.execute("ALTER TABLE applications ADD COLUMN age INTEGER")
    if 'gender' not in columns:
        conn.execute("ALTER TABLE applications ADD COLUMN gender TEXT")
    if 'district' not in columns:
        conn.execute("ALTER TABLE applications ADD COLUMN district TEXT")
    if 'created_by' not in columns:
        conn.execute("ALTER TABLE applications ADD COLUMN created_by INTEGER")
    
    conn.commit()
    conn.close()

def init_db():
    conn = get_db_connection()
    
    # Create applications table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            aadhaar TEXT NOT NULL,
            phone TEXT NOT NULL,
            income REAL NOT NULL,
            address TEXT NOT NULL,
            scheme TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            classification TEXT NOT NULL,
            reasons TEXT,
            age INTEGER,
            gender TEXT,
            district TEXT,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    ''')
    
    # Create users table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT DEFAULT 'officer',
            department TEXT,
            is_active INTEGER DEFAULT 1,
            email_verified INTEGER DEFAULT 0,
            phone_verified INTEGER DEFAULT 0,
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Create login attempts table for tracking
    conn.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip_address TEXT,
            user_agent TEXT,
            attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success INTEGER DEFAULT 0,
            failure_reason TEXT
        )
    ''')
    
    # Create user sessions table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            session_token TEXT UNIQUE,
            ip_address TEXT,
            user_agent TEXT,
            device_info TEXT,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            logout_time TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create OTP table for verification
    conn.execute('''
        CREATE TABLE IF NOT EXISTS otp_verification (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            otp_code TEXT,
            otp_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            verified INTEGER DEFAULT 0,
            attempts INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create fraud_predictions table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS fraud_predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER,
            predicted_risk_score INTEGER,
            prediction_confidence REAL,
            prediction_factors TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (application_id) REFERENCES applications (id)
        )
    ''')
    
    # Create network_links table for fraud ring detection
    conn.execute('''
        CREATE TABLE IF NOT EXISTS network_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT NOT NULL,
            entity_value TEXT NOT NULL,
            application_id INTEGER,
            link_strength INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (application_id) REFERENCES applications (id)
        )
    ''')
    
    # Create document_verifications table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS document_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER,
            document_type TEXT,
            document_hash TEXT,
            ocr_confidence REAL,
            forgery_score REAL,
            verification_status TEXT DEFAULT 'pending',
            extracted_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (application_id) REFERENCES applications (id)
        )
    ''')
    
    # Create behavior_patterns table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS behavior_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            ip_address TEXT,
            mouse_movements INTEGER DEFAULT 0,
            typing_speed REAL,
            time_on_page INTEGER,
            form_interactions INTEGER DEFAULT 0,
            bot_probability REAL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create geo_locations table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS geo_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER,
            ip_address TEXT,
            latitude REAL,
            longitude REAL,
            city TEXT,
            region TEXT,
            country TEXT,
            geo_fenced INTEGER DEFAULT 0,
            distance_from_address REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (application_id) REFERENCES applications (id)
        )
    ''')
    
    # Create financial_transactions table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS financial_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER,
            bank_account TEXT,
            account_holder TEXT,
            transaction_pattern TEXT,
            reuse_count INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'low',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (application_id) REFERENCES applications (id)
        )
    ''')
    
    # Create verification_requests table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS verification_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER,
            verification_type TEXT,
            verification_entity TEXT,
            request_sent TIMESTAMP,
            response_received TIMESTAMP,
            verification_status TEXT DEFAULT 'pending',
            verification_result TEXT,
            confidence_score REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (application_id) REFERENCES applications (id)
        )
    ''')
    
    # Create trust_scores table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS trust_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            aadhaar TEXT UNIQUE,
            phone TEXT,
            trust_score INTEGER DEFAULT 50,
            verification_level INTEGER DEFAULT 1,
            history_factor REAL DEFAULT 0,
            consistency_factor REAL DEFAULT 0,
            community_factor REAL DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create citizen_reports table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS citizen_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_name TEXT,
            reporter_contact TEXT,
            reported_aadhaar TEXT,
            reported_phone TEXT,
            fraud_type TEXT,
            description TEXT,
            evidence_files TEXT,
            report_status TEXT DEFAULT 'pending',
            admin_notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create audit_logs table (blockchain-style)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_type TEXT,
            entity_type TEXT,
            entity_id INTEGER,
            user_id INTEGER,
            old_values TEXT,
            new_values TEXT,
            ip_address TEXT,
            session_token TEXT,
            previous_hash TEXT,
            current_hash TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create device_fingerprints table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS device_fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint_hash TEXT UNIQUE,
            user_agent TEXT,
            screen_resolution TEXT,
            timezone TEXT,
            language TEXT,
            platform TEXT,
            fonts TEXT,
            canvas_hash TEXT,
            webgl_hash TEXT,
            account_count INTEGER DEFAULT 0,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create api_access_logs table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS api_access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint TEXT,
            method TEXT,
            ip_address TEXT,
            api_key TEXT,
            request_count INTEGER DEFAULT 1,
            rate_limit_hit INTEGER DEFAULT 0,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create blacklist_whitelist table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS blacklist_whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT NOT NULL,
            entity_value TEXT NOT NULL,
            list_type TEXT NOT NULL,
            reason TEXT,
            added_by INTEGER,
            auto_added INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (added_by) REFERENCES users (id)
        )
    ''')
    
    # Create face_verifications table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS face_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER,
            face_hash TEXT,
            liveness_score REAL,
            deepfake_probability REAL,
            spoof_detected INTEGER DEFAULT 0,
            verification_status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (application_id) REFERENCES applications (id)
        )
    ''')
    
    # Create benefit_tracking table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS benefit_tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            aadhaar TEXT NOT NULL,
            scheme TEXT NOT NULL,
            application_id INTEGER,
            benefit_amount REAL,
            benefit_date TIMESTAMP,
            abuse_flag INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (application_id) REFERENCES applications (id)
        )
    ''')
    
    # Create nlp_analysis table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS nlp_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER,
            text_field TEXT,
            similarity_score REAL,
            pattern_detected TEXT,
            spam_score REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (application_id) REFERENCES applications (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    
    # Create default admin user if not exists
    create_default_admin()

def create_default_admin():
    """Create default admin user if no users exist from JSON config"""
    import json
    import os
    
    conn = get_db_connection()
    user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    conn.close()
    
    if user_count == 0:
        # Load users from JSON file
        config_path = os.path.join(os.path.dirname(__file__), 'config', 'users.json')
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                for user in config.get('users', []):
                    create_user(
                        username=user['username'],
                        email=user['email'],
                        password=user['password'],
                        full_name=user['full_name'],
                        role=user['role'],
                        department=user['department']
                    )
                    # Update email_verified status
                    conn = get_db_connection()
                    conn.execute('UPDATE users SET email_verified = ? WHERE username = ?',
                               (1 if user.get('email_verified', False) else 0, user['username']))
                    conn.commit()
                    conn.close()
        except FileNotFoundError:
            # Fallback to hardcoded defaults if JSON file not found
            create_user('admin', 'admin@gov.in', 'admin123', 'System Administrator', 'admin', 'IT')
            create_user('officer1', 'officer1@gov.in', 'officer123', 'Officer One', 'officer', 'Welfare')
            create_user('officer2', 'officer2@gov.in', 'officer123', 'Officer Two', 'officer', 'Revenue')

def create_user(username, email, password, full_name, role='officer', department=''):
    """Create a new user"""
    conn = get_db_connection()
    try:
        password_hash = generate_password_hash(password)
        conn.execute('''
            INSERT INTO users (username, email, password_hash, full_name, role, department)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, email, password_hash, full_name, role, department))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def get_user_by_username(username):
    """Get user by username"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    """Get user by ID"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return user

def verify_user(username, password):
    """Verify user credentials"""
    user = get_user_by_username(username)
    if user and check_password_hash(user['password_hash'], password):
        if user['is_active']:
            update_last_login(user['id'])
            return user
    return None

def update_last_login(user_id):
    """Update last login timestamp"""
    conn = get_db_connection()
    conn.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

def get_all_users():
    """Get all users (admin only)"""
    conn = get_db_connection()
    users = conn.execute('''
        SELECT id, username, email, full_name, role, department, is_active, created_at, last_login 
        FROM users ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    return users

def insert_application(name, aadhaar, phone, income, address, scheme, risk_score, classification, reasons, created_by=None, age=None, gender=None, district=None):
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO applications (name, aadhaar, phone, income, address, scheme, risk_score, classification, reasons, created_by, age, gender, district)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (name, aadhaar, phone, income, address, scheme, risk_score, classification, json.dumps(reasons), created_by, age, gender, district))
    conn.commit()
    conn.close()

def get_all_applications():
    conn = get_db_connection()
    applications = conn.execute('SELECT * FROM applications ORDER BY created_at DESC').fetchall()
    conn.close()
    return applications

def get_application_by_id(app_id):
    conn = get_db_connection()
    application = conn.execute('SELECT * FROM applications WHERE id = ?', (app_id,)).fetchone()
    conn.close()
    return application

def get_statistics():
    conn = get_db_connection()
    total = conn.execute('SELECT COUNT(*) FROM applications').fetchone()[0]
    approved = conn.execute("SELECT COUNT(*) FROM applications WHERE classification = 'APPROVE'").fetchone()[0]
    review = conn.execute("SELECT COUNT(*) FROM applications WHERE classification = 'REVIEW'").fetchone()[0]
    rejected = conn.execute("SELECT COUNT(*) FROM applications WHERE classification = 'REJECT'").fetchone()[0]
    
    # Get daily stats for last 7 days
    daily_stats = conn.execute('''
        SELECT DATE(created_at) as date, COUNT(*) as count, 
               SUM(CASE WHEN classification = 'REJECT' THEN 1 ELSE 0 END) as fraud_count
        FROM applications 
        WHERE created_at >= DATE('now', '-7 days')
        GROUP BY DATE(created_at)
        ORDER BY date
    ''').fetchall()
    
    # Get scheme-wise statistics
    scheme_stats = conn.execute('''
        SELECT scheme, COUNT(*) as count 
        FROM applications 
        GROUP BY scheme 
        ORDER BY count DESC
    ''').fetchall()
    
    # Get risk score distribution
    risk_distribution = conn.execute('''
        SELECT 
            SUM(CASE WHEN risk_score <= 20 THEN 1 ELSE 0 END) as safe,
            SUM(CASE WHEN risk_score > 20 AND risk_score <= 40 THEN 1 ELSE 0 END) as low,
            SUM(CASE WHEN risk_score > 40 AND risk_score <= 60 THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN risk_score > 60 AND risk_score <= 80 THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN risk_score > 80 THEN 1 ELSE 0 END) as critical
        FROM applications
    ''').fetchone()
    
    # Get hourly activity (last 24 hours)
    hourly_activity = conn.execute('''
        SELECT strftime('%H', created_at) as hour, COUNT(*) as count
        FROM applications
        WHERE created_at >= datetime('now', '-24 hours')
        GROUP BY hour
        ORDER BY hour
    ''').fetchall()
    
    # Fill in missing hours with 0
    hourly_dict = {row['hour']: row['count'] for row in hourly_activity}
    full_hourly = []
    for i in range(24):
        hour_str = f"{i:02d}"
        full_hourly.append({'hour': hour_str, 'count': hourly_dict.get(hour_str, 0)})
    
    # Get monthly statistics
    monthly_stats = conn.execute('''
        SELECT strftime('%Y-%m', created_at) as month, 
               COUNT(*) as total,
               SUM(CASE WHEN classification = 'REJECT' THEN 1 ELSE 0 END) as fraud
        FROM applications
        GROUP BY month
        ORDER BY month DESC
        LIMIT 6
    ''').fetchall()
    
    # Get fraud indicators (from reasons JSON)
    # This is a simplified version - in production you'd parse JSON properly
    fraud_indicators = [
        {'type': 'Duplicate Aadhaar', 'count': conn.execute("SELECT COUNT(*) FROM applications WHERE reasons LIKE '%Duplicate Aadhaar%'").fetchone()[0]},
        {'type': 'Phone Mismatch', 'count': conn.execute("SELECT COUNT(*) FROM applications WHERE reasons LIKE '%phone number used with different%'").fetchone()[0]},
        {'type': 'Income Exceeded', 'count': conn.execute("SELECT COUNT(*) FROM applications WHERE reasons LIKE '%Income%'").fetchone()[0]},
        {'type': 'Address Issues', 'count': conn.execute("SELECT COUNT(*) FROM applications WHERE reasons LIKE '%address%'").fetchone()[0]},
        {'type': 'Age Validation', 'count': conn.execute("SELECT COUNT(*) FROM applications WHERE reasons LIKE '%Age%'").fetchone()[0]},
        {'type': 'ML Anomaly', 'count': conn.execute("SELECT COUNT(*) FROM applications WHERE reasons LIKE '%ML anomaly%'").fetchone()[0]},
    ]
    fraud_indicators = [f for f in fraud_indicators if f['count'] > 0]
    
    # Get district statistics
    district_stats = conn.execute('''
        SELECT district, COUNT(*) as count 
        FROM applications 
        WHERE district IS NOT NULL
        GROUP BY district 
        ORDER BY count DESC
        LIMIT 10
    ''').fetchall()
    
    conn.close()
    
    return {
        'total': total,
        'approved': approved,
        'review': review,
        'rejected': rejected,
        'daily_stats': [dict(row) for row in daily_stats],
        'scheme_stats': [dict(row) for row in scheme_stats],
        'risk_distribution': dict(risk_distribution) if risk_distribution else {'safe': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
        'hourly_activity': full_hourly,
        'monthly_stats': [dict(row) for row in monthly_stats],
        'fraud_indicators': fraud_indicators,
        'district_stats': [dict(row) for row in district_stats]
    }

def check_duplicate_aadhaar(aadhaar):
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) FROM applications WHERE aadhaar = ?', (aadhaar,)).fetchone()[0]
    conn.close()
    return count

def check_phone_name_mismatch(phone, name):
    conn = get_db_connection()
    result = conn.execute('SELECT name FROM applications WHERE phone = ? AND name != ?', (phone, name)).fetchone()
    conn.close()
    return result is not None

def get_applications_by_phone(phone):
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) FROM applications WHERE phone = ?', (phone,)).fetchone()[0]
    conn.close()
    return count

def get_similar_addresses(address):
    conn = get_db_connection()
    # Simple similarity check - count applications with similar address patterns
    applications = conn.execute('SELECT address FROM applications').fetchall()
    similar_count = 0
    for app in applications:
        # Check for common words in address
        existing_addr = app['address'].lower()
        new_addr = address.lower()
        # Simple similarity - if they share significant common parts
        if len(existing_addr) > 10 and len(new_addr) > 10:
            # Check for common substrings
            common_words = set(existing_addr.split()) & set(new_addr.split())
            if len(common_words) >= 3:
                similar_count += 1
    conn.close()
    return similar_count

def get_applications_count_by_phone(phone):
    """Get total count of applications by phone number"""
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) FROM applications WHERE phone = ?', (phone,)).fetchone()[0]
    conn.close()
    return count

def get_recent_applications_by_phone(phone, hours=24):
    """Get count of applications from same phone within last N hours"""
    conn = get_db_connection()
    count = conn.execute('''
        SELECT COUNT(*) FROM applications 
        WHERE phone = ? 
        AND created_at >= datetime('now', '-{} hours')
    '''.format(hours), (phone,)).fetchone()[0]
    conn.close()
    return count

# Login attempt tracking functions
def log_login_attempt(username, ip_address, user_agent, success=False, failure_reason=None):
    """Log a login attempt for security tracking"""
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO login_attempts (username, ip_address, user_agent, success, failure_reason)
        VALUES (?, ?, ?, ?, ?)
    ''', (username, ip_address, user_agent, 1 if success else 0, failure_reason))
    conn.commit()
    conn.close()

def get_recent_login_attempts(username, minutes=30):
    """Get count of recent failed login attempts"""
    conn = get_db_connection()
    count = conn.execute('''
        SELECT COUNT(*) FROM login_attempts 
        WHERE username = ? AND success = 0 
        AND attempt_time >= datetime('now', '-{} minutes')
    '''.format(minutes), (username,)).fetchone()[0]
    conn.close()
    return count

def get_login_attempts_by_ip(ip_address, minutes=60):
    """Get login attempts from a specific IP"""
    conn = get_db_connection()
    attempts = conn.execute('''
        SELECT username, attempt_time, success 
        FROM login_attempts 
        WHERE ip_address = ? 
        AND attempt_time >= datetime('now', '-{} minutes')
        ORDER BY attempt_time DESC
    '''.format(minutes), (ip_address,)).fetchall()
    conn.close()
    return attempts

# Session management functions
def create_session(user_id, session_token, ip_address, user_agent, device_info=None):
    """Create a new user session"""
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, device_info)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, session_token, ip_address, user_agent, device_info))
    conn.commit()
    conn.close()

def update_session_activity(session_token):
    """Update last activity time for a session"""
    conn = get_db_connection()
    conn.execute('''
        UPDATE user_sessions SET last_activity = CURRENT_TIMESTAMP 
        WHERE session_token = ?
    ''', (session_token,))
    conn.commit()
    conn.close()

def deactivate_session(session_token):
    """Deactivate a session (logout)"""
    conn = get_db_connection()
    conn.execute('''
        UPDATE user_sessions 
        SET is_active = 0, logout_time = CURRENT_TIMESTAMP 
        WHERE session_token = ?
    ''', (session_token,))
    conn.commit()
    conn.close()

def get_active_sessions(user_id):
    """Get all active sessions for a user"""
    conn = get_db_connection()
    sessions = conn.execute('''
        SELECT * FROM user_sessions 
        WHERE user_id = ? AND is_active = 1
        ORDER BY last_activity DESC
    ''', (user_id,)).fetchall()
    conn.close()
    return sessions

# OTP functions
def create_otp(user_id, otp_code, otp_type='email', expiry_minutes=10):
    """Create an OTP for verification"""
    conn = get_db_connection()
    # Invalidate old OTPs
    conn.execute('''
        UPDATE otp_verification SET verified = -1 
        WHERE user_id = ? AND otp_type = ? AND verified = 0
    ''', (user_id, otp_type))
    
    # Create new OTP
    conn.execute('''
        INSERT INTO otp_verification (user_id, otp_code, otp_type, expires_at)
        VALUES (?, ?, ?, datetime('now', '+{} minutes'))
    '''.format(expiry_minutes), (user_id, otp_code, otp_type))
    conn.commit()
    conn.close()

def verify_otp(user_id, otp_code, otp_type='email'):
    """Verify an OTP"""
    conn = get_db_connection()
    otp_record = conn.execute('''
        SELECT * FROM otp_verification 
        WHERE user_id = ? AND otp_code = ? AND otp_type = ? 
        AND verified = 0 AND expires_at > CURRENT_TIMESTAMP
    ''', (user_id, otp_code, otp_type)).fetchone()
    
    if otp_record:
        conn.execute('''
            UPDATE otp_verification SET verified = 1 
            WHERE id = ?
        ''', (otp_record['id'],))
        conn.commit()
        conn.close()
        return True
    
    # Increment attempts if OTP exists but wrong
    conn.execute('''
        UPDATE otp_verification SET attempts = attempts + 1 
        WHERE user_id = ? AND otp_type = ? AND verified = 0
    ''', (user_id, otp_type))
    conn.commit()
    conn.close()
    return False

def update_user_verification(user_id, email_verified=None, phone_verified=None):
    """Update user verification status"""
    conn = get_db_connection()
    if email_verified is not None:
        conn.execute('UPDATE users SET email_verified = ? WHERE id = ?', 
                    (1 if email_verified else 0, user_id))
    if phone_verified is not None:
        conn.execute('UPDATE users SET phone_verified = ? WHERE id = ?', 
                    (1 if phone_verified else 0, user_id))
    conn.commit()
    conn.close()
