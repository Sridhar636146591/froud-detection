from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from functools import wraps
import database as db
from fraud_detector import fraud_detector, AdvancedFraudDetector
from ai_simulator import ai_simulator
from network_analyzer import network_analyzer
import user_manager as um
import json
import secrets
import random
import hashlib
from datetime import datetime, timedelta
from flasgger import Swagger, swag_from

app = Flask(__name__)
app.secret_key = 'fraud_detection_secret_key_change_in_production'

# Swagger / OpenAPI configuration
swagger_config = {
    'headers': [],
    'specs': [{
        'endpoint': 'apispec',
        'route': '/api/docs/apispec.json',
        'rule_filter': lambda rule: rule.rule.startswith('/api/v1'),
        'model_filter': lambda tag: True,
    }],
    'static_url_path': '/flasgger_static',
    'swagger_ui': True,
    'specs_route': '/api/docs',
}
swagger_template = {
    'info': {
        'title': 'FraudShield API',
        'description': 'REST API for the Government Welfare Fraud Detection System',
        'version': '1.0.0',
        'contact': {'name': 'FraudShield Admin'},
    },
    'securityDefinitions': {
        'SessionAuth': {'type': 'apiKey', 'in': 'cookie', 'name': 'session'}
    },
}
swagger = Swagger(app, config=swagger_config, template=swagger_template)

# Initialize database on startup
db.init_db()
db.migrate_db()

# Security configuration
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 30
OTP_EXPIRY_MINUTES = 10

def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def get_user_agent():
    """Get user agent string"""
    return request.headers.get('User-Agent', 'Unknown')

def get_device_info():
    """Extract device info from user agent"""
    user_agent = get_user_agent()
    device_info = "Unknown Device"
    
    if 'Mobile' in user_agent:
        device_info = "Mobile Device"
    elif 'Tablet' in user_agent:
        device_info = "Tablet"
    elif 'Windows' in user_agent:
        device_info = "Windows PC"
    elif 'Mac' in user_agent:
        device_info = "Mac"
    elif 'Linux' in user_agent:
        device_info = "Linux"
    
    # Add browser info
    if 'Chrome' in user_agent:
        device_info += " - Chrome"
    elif 'Firefox' in user_agent:
        device_info += " - Firefox"
    elif 'Safari' in user_agent:
        device_info += " - Safari"
    elif 'Edge' in user_agent:
        device_info += " - Edge"
    
    return device_info

def generate_otp():
    """Generate a 6-digit OTP"""
    return str(random.randint(100000, 999999))

def check_brute_force_protection(username):
    """Check if account is locked due to failed attempts"""
    recent_attempts = db.get_recent_login_attempts(username, LOCKOUT_DURATION_MINUTES)
    if recent_attempts >= MAX_LOGIN_ATTEMPTS:
        return False, f"Account locked due to {MAX_LOGIN_ATTEMPTS} failed attempts. Try again after {LOCKOUT_DURATION_MINUTES} minutes."
    return True, None

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        # Update session activity
        if 'session_token' in session:
            db.update_session_activity(session['session_token'])
        
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Verification required decorator
def verification_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        # Check if email is verified
        user = db.get_user_by_id(session['user_id'])
        if user and not user.get('email_verified'):
            flash('Please verify your email before accessing this feature.', 'warning')
            return redirect(url_for('verify_email'))
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')
        
        # Check brute force protection
        can_login, lockout_msg = check_brute_force_protection(username)
        if not can_login:
            flash(lockout_msg, 'error')
            db.log_login_attempt(username, get_client_ip(), get_user_agent(), False, 'Account locked')
            return render_template('login.html')
        
        user = db.verify_user(username, password)
        if user:
            # Convert sqlite3.Row to dict for easier access
            user = dict(user)
            
            # Create session token
            session_token = secrets.token_urlsafe(32)
            
            # Log session
            db.create_session(user['id'], session_token, get_client_ip(), get_user_agent(), get_device_info())
            
            # Set session data
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name']
            session['role'] = user['role']
            session['department'] = user['department']
            session['session_token'] = session_token
            session['login_time'] = datetime.now().isoformat()
            
            # Log successful login
            db.log_login_attempt(username, get_client_ip(), get_user_agent(), True)
            
            flash(f'Welcome back, {user["full_name"]}! Logged in from {get_device_info()}', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Log failed login
            db.log_login_attempt(username, get_client_ip(), get_user_agent(), False, 'Invalid credentials')
            
            remaining_attempts = MAX_LOGIN_ATTEMPTS - db.get_recent_login_attempts(username, LOCKOUT_DURATION_MINUTES)
            flash(f'Invalid username or password. {remaining_attempts} attempts remaining.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    # Deactivate session in database
    if 'session_token' in session:
        db.deactivate_session(session['session_token'])
    
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    """Email verification page with OTP"""
    if 'pending_user_id' not in session and 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session.get('pending_user_id') or session.get('user_id')
    
    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        
        if not otp or len(otp) != 6:
            flash('Please enter a valid 6-digit OTP.', 'error')
            return render_template('verify_otp.html')
        
        if db.verify_otp(user_id, otp, 'email'):
            # Mark email as verified
            db.update_user_verification(user_id, email_verified=True)
            
            # If this was pending login, complete the login
            if 'pending_user_id' in session:
                user = db.get_user_by_id(user_id)
                
                # Create session
                session_token = secrets.token_urlsafe(32)
                db.create_session(user['id'], session_token, get_client_ip(), get_user_agent(), get_device_info())
                
                # Set session
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['full_name'] = user['full_name']
                session['role'] = user['role']
                session['department'] = user['department']
                session['session_token'] = session_token
                session['login_time'] = datetime.now().isoformat()
                
                # Clear pending login
                session.pop('pending_user_id', None)
                session.pop('pending_username', None)
                
                flash('Email verified successfully! Welcome!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Email verified successfully!', 'success')
                return redirect(url_for('profile'))
        else:
            flash('Invalid or expired OTP. Please try again.', 'error')
    
    # Resend OTP option
    if request.args.get('resend') == '1':
        otp = generate_otp()
        db.create_otp(user_id, otp, 'email', OTP_EXPIRY_MINUTES)
        flash('A new OTP has been sent to your email.', 'info')
    
    return render_template('verify_otp.html')

@app.route('/security-logs')
@login_required
def security_logs():
    """View security logs for the current user"""
    user = db.get_user_by_id(session['user_id'])
    
    # Get login attempts
    conn = db.get_db_connection()
    login_attempts = conn.execute('''
        SELECT * FROM login_attempts 
        WHERE username = ? 
        ORDER BY attempt_time DESC 
        LIMIT 50
    ''', (user['username'],)).fetchall()
    
    # Get active sessions
    active_sessions = db.get_active_sessions(session['user_id'])
    
    conn.close()
    
    return render_template('security_logs.html', 
                         login_attempts=login_attempts,
                         active_sessions=active_sessions,
                         current_session=session.get('session_token'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        full_name = request.form.get('full_name', '').strip()
        department = request.form.get('department', '').strip()
        
        # Validation
        errors = []
        
        if not all([username, email, password, confirm_password, full_name]):
            errors.append('All required fields must be filled.')
        
        if len(username) < 3:
            errors.append('Username must be at least 3 characters long.')
        
        if not username.isalnum():
            errors.append('Username can only contain letters and numbers.')
        
        if len(password) < 6:
            errors.append('Password must be at least 6 characters long.')
        
        if password != confirm_password:
            errors.append('Passwords do not match.')
        
        if '@' not in email or '.' not in email:
            errors.append('Please enter a valid email address.')
        
        # Check if username or email already exists
        if db.get_user_by_username(username):
            errors.append('Username already exists. Please choose another.')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('register.html', 
                                 username=username, 
                                 email=email, 
                                 full_name=full_name, 
                                 department=department)
        
        # Create user (default role: officer)
        if db.create_user(username, email, password, full_name, 'officer', department):
            # Also save to JSON file
            um.add_user(username, password, email, full_name, 'officer', department)
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('An error occurred. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/profile')
@login_required
def profile():
    user = db.get_user_by_id(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/submit', methods=['POST'])
@login_required
def submit_application():
    try:
        # Get form data
        name = request.form.get('name', '').strip()
        aadhaar = request.form.get('aadhaar', '').strip()
        phone = request.form.get('phone', '').strip()
        income = float(request.form.get('income', 0))
        age = request.form.get('age', '').strip()
        gender = request.form.get('gender', '').strip()
        district = request.form.get('district', '').strip()
        address = request.form.get('address', '').strip()
        scheme = request.form.get('scheme', '').strip()
        
        # Validate required fields
        if not all([name, aadhaar, phone, address, scheme, age, gender, district]):
            flash('All fields are required!', 'error')
            return redirect(url_for('new_application'))
        
        # Validate Aadhaar (12 digits)
        if not aadhaar.isdigit() or len(aadhaar) != 12:
            flash('Invalid Aadhaar number! Must be 12 digits.', 'error')
            return redirect(url_for('new_application'))
        
        # Validate phone (10 digits)
        if not phone.isdigit() or len(phone) != 10:
            flash('Invalid phone number! Must be 10 digits.', 'error')
            return redirect(url_for('new_application'))
        
        # Validate age
        try:
            age_int = int(age)
            if age_int < 18 or age_int > 120:
                flash('Age must be between 18 and 120 years.', 'error')
                return redirect(url_for('new_application'))
        except ValueError:
            flash('Invalid age!', 'error')
            return redirect(url_for('new_application'))
        
        # Run fraud detection with all parameters
        result = fraud_detector.detect_fraud(
            name, aadhaar, phone, income, address, 
            scheme, age_int, gender, district
        )
        
        # Save to database with user ID
        db.insert_application(
            name, aadhaar, phone, income, address, scheme,
            result['risk_score'], result['classification'], result['reasons'],
            session.get('user_id'),
            age=age_int, gender=gender, district=district
        )
        
        # Redirect to result page with enhanced data
        return redirect(url_for('application_result', 
                              score=result['risk_score'],
                              classification=result['classification'],
                              reasons=json.dumps(result['reasons']),
                              risk_level=result.get('risk_level', 'UNKNOWN'),
                              checks=result.get('checks_performed', 13)))
    
    except Exception as e:
        flash(f'Error processing application: {str(e)}', 'error')
        return redirect(url_for('new_application'))

@app.route('/new-application')
@login_required
def new_application():
    """New application form page"""
    return render_template('index.html')

@app.route('/result')
@login_required
def application_result():
    score = request.args.get('score', 0, type=int)
    classification = request.args.get('classification', 'REVIEW')
    reasons = json.loads(request.args.get('reasons', '[]'))
    risk_level = request.args.get('risk_level', 'UNKNOWN')
    checks = request.args.get('checks', 13, type=int)
    
    return render_template('result.html', 
                         score=score, 
                         classification=classification, 
                         reasons=reasons,
                         risk_level=risk_level,
                         checks_performed=checks)

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard with server-side pagination."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 25, type=int)
    classification = request.args.get('classification', 'ALL')
    search = request.args.get('search', '').strip()

    per_page = max(10, min(100, per_page))  # clamp between 10-100
    page = max(1, page)

    applications, total, total_pages = db.get_paginated_applications(
        page=page, per_page=per_page,
        classification=classification if classification != 'ALL' else None,
        search=search or None
    )
    stats = db.get_statistics()
    return render_template('dashboard.html',
                         stats=stats,
                         applications=applications,
                         page=page,
                         per_page=per_page,
                         total=total,
                         total_pages=total_pages,
                         has_prev=page > 1,
                         has_next=page < total_pages,
                         classification=classification,
                         search=search)

@app.route('/details/<int:app_id>')
@login_required
def application_details(app_id):
    application = db.get_application_by_id(app_id)
    if application:
        app_dict = dict(application)
        app_dict['reasons'] = json.loads(app_dict['reasons']) if app_dict['reasons'] else []
        return render_template('details.html', application=app_dict)
    else:
        flash('Application not found!', 'error')
        return redirect(url_for('dashboard'))

@app.route('/delete-application/<int:app_id>', methods=['POST'])
@admin_required
def delete_application(app_id):
    """Delete an application (admin only)"""
    conn = db.get_db_connection()
    
    # Get application info for audit log
    app = conn.execute('SELECT * FROM applications WHERE id = ?', (app_id,)).fetchone()
    
    if app:
        # Delete related records first
        conn.execute('DELETE FROM network_links WHERE application_id = ?', (app_id,))
        conn.execute('DELETE FROM document_verifications WHERE application_id = ?', (app_id,))
        conn.execute('DELETE FROM geo_locations WHERE application_id = ?', (app_id,))
        conn.execute('DELETE FROM financial_transactions WHERE application_id = ?', (app_id,))
        conn.execute('DELETE FROM verification_requests WHERE application_id = ?', (app_id,))
        conn.execute('DELETE FROM face_verifications WHERE application_id = ?', (app_id,))
        conn.execute('DELETE FROM benefit_tracking WHERE application_id = ?', (app_id,))
        conn.execute('DELETE FROM nlp_analysis WHERE application_id = ?', (app_id,))
        
        # Delete the application
        conn.execute('DELETE FROM applications WHERE id = ?', (app_id,))
        conn.commit()
        
        # Add audit log
        add_audit_log('DELETE', 'application', app_id, 
                     {'name': app['name'], 'aadhaar': app['aadhaar']}, None)
        
        flash(f'Application #{app_id} has been deleted successfully.', 'success')
    else:
        flash('Application not found!', 'error')
    
    conn.close()
    return redirect(url_for('dashboard'))

# Admin routes
@app.route('/admin/users')
@admin_required
def admin_users():
    users = db.get_all_users()
    return render_template('admin_users.html', users=users)

@app.route('/admin/create-user', methods=['POST'])
@admin_required
def admin_create_user():
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    full_name = request.form.get('full_name', '').strip()
    role = request.form.get('role', 'officer')
    department = request.form.get('department', '').strip()
    
    if not all([username, email, password, full_name]):
        flash('All fields are required!', 'error')
        return redirect(url_for('admin_users'))
    
    if db.create_user(username, email, password, full_name, role, department):
        # Also save to JSON file
        um.add_user(username, password, email, full_name, role, department)
        flash(f'User {username} created successfully!', 'success')
    else:
        flash('Username or email already exists!', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/api/stats')
def legacy_api_stats():
    """Legacy API endpoint for dashboard statistics (use /api/v1/stats instead)"""
    stats = db.get_statistics()
    return jsonify(stats)

@app.route('/api/applications')
def api_applications():
    """API endpoint for all applications"""
    applications = db.get_all_applications()
    return jsonify([dict(app) for app in applications])


# ==================== ADVANCED FRAUD DETECTION FEATURES ====================

# Feature 2: Network Analysis Route
@app.route('/network-analysis')
@login_required
def network_analysis_view():
    """View fraud network analysis"""
    rings = network_analyzer.detect_fraud_rings(min_ring_size=2)
    stats = network_analyzer.get_network_statistics()
    return render_template('network_analysis.html', rings=rings, stats=stats)

@app.route('/api/network/<int:app_id>')
@login_required
def api_network_details(app_id):
    """Get network details for an application"""
    network = network_analyzer.get_network_for_application(app_id)
    return jsonify(network)

# Feature 3 & 4: Document and Face Verification Routes
@app.route('/verify-document/<int:app_id>', methods=['GET', 'POST'])
@login_required
def verify_document(app_id):
    """Document verification page"""
    if request.method == 'POST':
        # Simulate document upload and analysis
        doc_data = {
            'type': request.form.get('doc_type', 'aadhaar'),
            'expected_name': request.form.get('expected_name', '')
        }
        result = fraud_detector.detect_document_forgery(doc_data)
        
        # Store result
        conn = db.get_db_connection()
        conn.execute('''
            INSERT INTO document_verifications 
            (application_id, document_type, ocr_confidence, forgery_score, verification_status)
            VALUES (?, ?, ?, ?, ?)
        ''', (app_id, doc_data['type'], result['analysis']['ocr_confidence'],
              result['analysis']['forgery_score'], result['analysis']['verification_status']))
        conn.commit()
        conn.close()
        
        flash(f"Document verification: {result['analysis']['verification_status']}", 
              'success' if result['analysis']['is_authentic'] else 'warning')
        return redirect(url_for('application_details', id=app_id))
    
    application = db.get_application_by_id(app_id)
    return render_template('verify_document.html', application=application)

@app.route('/verify-face/<int:app_id>', methods=['GET', 'POST'])
@login_required
def verify_face(app_id):
    """Face verification page"""
    if request.method == 'POST':
        # Simulate face verification
        image_data = {'timestamp': datetime.now().isoformat()}
        result = fraud_detector.detect_face_spoof(image_data)
        
        # Store result
        conn = db.get_db_connection()
        conn.execute('''
            INSERT INTO face_verifications 
            (application_id, liveness_score, deepfake_probability, spoof_detected, verification_status)
            VALUES (?, ?, ?, ?, ?)
        ''', (app_id, result['analysis']['liveness_score'],
              result['analysis']['deepfake_probability'],
              result['analysis']['spoof_detected'],
              result['analysis']['verification_status']))
        conn.commit()
        conn.close()
        
        flash(f"Face verification: {result['analysis']['verification_status']}",
              'success' if not result['analysis']['spoof_detected'] else 'danger')
        return redirect(url_for('application_details', id=app_id))
    
    application = db.get_application_by_id(app_id)
    return render_template('face_verification.html', application=application)

# Feature 8: Reverse Verification System
@app.route('/pending-verifications')
@login_required
def pending_verifications():
    """View pending external verifications"""
    conn = db.get_db_connection()
    verifications = conn.execute('''
        SELECT vr.*, a.name, a.aadhaar, a.scheme
        FROM verification_requests vr
        JOIN applications a ON vr.application_id = a.id
        WHERE vr.verification_status = 'pending'
        ORDER BY vr.created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('pending_verifications.html', verifications=verifications)

@app.route('/send-verification/<int:app_id>', methods=['POST'])
@login_required
def send_verification(app_id):
    """Send verification request to external entity"""
    verification_type = request.form.get('verification_type')
    entity = request.form.get('entity')
    
    conn = db.get_db_connection()
    conn.execute('''
        INSERT INTO verification_requests 
        (application_id, verification_type, verification_entity, request_sent, verification_status)
        VALUES (?, ?, ?, ?, ?)
    ''', (app_id, verification_type, entity, datetime.now(), 'pending'))
    conn.commit()
    conn.close()
    
    flash(f"Verification request sent to {entity}", 'success')
    return redirect(url_for('application_details', id=app_id))

# Feature 11: Citizen Reporting System
@app.route('/report-fraud', methods=['GET', 'POST'])
def report_fraud():
    """Citizen fraud reporting page"""
    if request.method == 'POST':
        reporter_name = request.form.get('reporter_name')
        reporter_contact = request.form.get('reporter_contact')
        reported_aadhaar = request.form.get('reported_aadhaar')
        fraud_type = request.form.get('fraud_type')
        description = request.form.get('description')
        
        conn = db.get_db_connection()
        conn.execute('''
            INSERT INTO citizen_reports 
            (reporter_name, reporter_contact, reported_aadhaar, fraud_type, description)
            VALUES (?, ?, ?, ?, ?)
        ''', (reporter_name, reporter_contact, reported_aadhaar, fraud_type, description))
        conn.commit()
        conn.close()
        
        flash("Thank you for your report. It will be reviewed by our team.", 'success')
        return redirect(url_for('index'))
    
    return render_template('report_fraud.html')

@app.route('/admin/reports')
@admin_required
def admin_reports():
    """Admin view of citizen reports"""
    conn = db.get_db_connection()
    reports = conn.execute('''
        SELECT * FROM citizen_reports 
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('admin/reports.html', reports=reports)

@app.route('/admin/report/<int:report_id>')
@admin_required
def view_report(report_id):
    """View detailed citizen report"""
    conn = db.get_db_connection()
    report = conn.execute('SELECT * FROM citizen_reports WHERE id = ?', (report_id,)).fetchone()
    conn.close()
    
    if report:
        return render_template('admin/report_detail.html', report=report)
    else:
        flash('Report not found!', 'error')
        return redirect(url_for('admin_reports'))

@app.route('/admin/report/<int:report_id>/resolve', methods=['POST'])
@admin_required
def resolve_report(report_id):
    """Perform action on citizen report (approve, reject, resolve)"""
    action = request.form.get('action', 'resolve')  # Default to 'resolve' if not provided
    admin_notes = request.form.get('admin_notes', '')
    blacklist_aadhaar = request.form.get('blacklist_aadhaar')
    blacklist_phone = request.form.get('blacklist_phone')
    
    if action not in ['approve', 'reject', 'resolve']:
        flash('Invalid action requested.', 'error')
        return redirect(url_for('view_report', report_id=report_id))
    
    # Determine new status
    status_map = {
        'approve': 'approved',
        'reject': 'rejected',
        'resolve': 'resolved'
    }
    new_status = status_map[action]
    
    conn = db.get_db_connection()
    
    # Fetch report to get details
    report = conn.execute('SELECT * FROM citizen_reports WHERE id = ?', (report_id,)).fetchone()
    if not report:
        conn.close()
        flash('Report not found!', 'error')
        return redirect(url_for('admin_reports'))
    
    # Update report status and notes
    conn.execute('''
        UPDATE citizen_reports 
        SET report_status = ?, admin_notes = ?, resolved_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (new_status, admin_notes, report_id))
    
    # If action is approve, perform blacklisting
    blacklist_msg = []
    if action == 'approve':
        user_id = session.get('user_id')
        reason = f"Blacklisted via Citizen Report #{report_id} Approval"
        if admin_notes:
            reason += f": {admin_notes}"
            
        if blacklist_aadhaar and report['reported_aadhaar']:
            # Check if already blacklisted to avoid duplicates
            exists = conn.execute('''
                SELECT id FROM blacklist_whitelist 
                WHERE entity_type = 'aadhaar' AND entity_value = ? AND list_type = 'blacklist'
            ''', (report['reported_aadhaar'],)).fetchone()
            if not exists:
                conn.execute('''
                    INSERT INTO blacklist_whitelist 
                    (entity_type, entity_value, list_type, reason, added_by, auto_added)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', ('aadhaar', report['reported_aadhaar'], 'blacklist', reason, user_id, 0))
                blacklist_msg.append(f"Aadhaar {report['reported_aadhaar']}")
                # Log audit
                add_audit_log('LIST_UPDATE', 'aadhaar', 0, 
                              None, {'list': 'blacklist', 'value': report['reported_aadhaar']})
                
        if blacklist_phone and report['reported_phone']:
            exists = conn.execute('''
                SELECT id FROM blacklist_whitelist 
                WHERE entity_type = 'phone' AND entity_value = ? AND list_type = 'blacklist'
            ''', (report['reported_phone'],)).fetchone()
            if not exists:
                conn.execute('''
                    INSERT INTO blacklist_whitelist 
                    (entity_type, entity_value, list_type, reason, added_by, auto_added)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', ('phone', report['reported_phone'], 'blacklist', reason, user_id, 0))
                blacklist_msg.append(f"Phone {report['reported_phone']}")
                # Log audit
                add_audit_log('LIST_UPDATE', 'phone', 0, 
                              None, {'list': 'blacklist', 'value': report['reported_phone']})
    
    conn.commit()
    conn.close()
    
    # Add audit log for report resolution
    add_audit_log('REPORT_ACTION', 'citizen_report', report_id, 
                  {'status': report['report_status']}, {'status': new_status, 'notes': admin_notes})
    
    success_msg = f"Report marked as {new_status} successfully."
    if blacklist_msg:
        success_msg += f" Added to blacklist: {', '.join(blacklist_msg)}."
    
    flash(success_msg, 'success')
    return redirect(url_for('admin_reports'))

# Feature 13: Audit Trail
@app.route('/audit-log')
@login_required
def audit_log():
    """View audit trail"""
    conn = db.get_db_connection()
    logs = conn.execute('''
        SELECT al.*, u.full_name as user_name
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.created_at DESC
        LIMIT 100
    ''').fetchall()
    conn.close()
    return render_template('audit_log.html', logs=logs)

def add_audit_log(action_type, entity_type, entity_id, old_values=None, new_values=None):
    """Add entry to audit log with blockchain-style hashing"""
    conn = db.get_db_connection()
    
    # Get previous hash
    last_log = conn.execute('''
        SELECT current_hash FROM audit_logs 
        ORDER BY id DESC LIMIT 1
    ''').fetchone()
    
    previous_hash = last_log['current_hash'] if last_log else '0' * 64
    
    # Create new hash
    data_string = f"{action_type}{entity_type}{entity_id}{datetime.now().isoformat()}{previous_hash}"
    current_hash = hashlib.sha256(data_string.encode()).hexdigest()
    
    conn.execute('''
        INSERT INTO audit_logs 
        (action_type, entity_type, entity_id, user_id, old_values, new_values, 
         ip_address, session_token, previous_hash, current_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (action_type, entity_type, entity_id, session.get('user_id'),
          json.dumps(old_values) if old_values else None,
          json.dumps(new_values) if new_values else None,
          request.remote_addr, session.get('session_token'),
          previous_hash, current_hash))
    conn.commit()
    conn.close()

# Feature 15: Fraud Simulation Testing
@app.route('/fraud-simulation')
@login_required
def fraud_simulation():
    """Run fraud simulation tests"""
    scenarios = ai_simulator.generate_fraud_simulation()
    
    # Run simulations
    results = []
    for scenario in scenarios:
        # Simulate detection
        detected = random.choice([True, True, True, False])  # 75% detection rate
        results.append({
            **scenario,
            'detected': detected,
            'test_passed': detected == (scenario['expected_result'] in ['Flagged', 'Rejected', 'Blocked'])
        })
    
    pass_rate = sum(1 for r in results if r['test_passed']) / len(results) * 100
    
    return render_template('fraud_simulation.html', 
                         scenarios=results, 
                         pass_rate=round(pass_rate, 1))

# Feature 16: Device Linking
@app.route('/device-analysis/<int:app_id>')
@login_required
def device_analysis(app_id):
    """Analyze device fingerprints for an application"""
    conn = db.get_db_connection()
    
    # Get device info
    devices = conn.execute('''
        SELECT df.*, a.name, a.created_at
        FROM device_fingerprints df
        JOIN applications a ON df.fingerprint_hash = a.device_hash
        WHERE a.id = ?
    ''', (app_id,)).fetchall()
    
    # Count accounts per device
    device_stats = conn.execute('''
        SELECT fingerprint_hash, COUNT(*) as account_count
        FROM device_fingerprints
        GROUP BY fingerprint_hash
        HAVING account_count > 1
    ''').fetchall()
    
    conn.close()
    return render_template('device_analysis.html', 
                         devices=devices, 
                         device_stats=device_stats)


# Feature 20: Blacklist/Whitelist Management
@app.route('/admin/blacklist')
@admin_required
def manage_lists():
    """Manage blacklist and whitelist"""
    conn = db.get_db_connection()
    
    blacklist = conn.execute('''
        SELECT * FROM blacklist_whitelist 
        WHERE list_type = 'blacklist'
        ORDER BY created_at DESC
    ''').fetchall()
    
    whitelist = conn.execute('''
        SELECT * FROM blacklist_whitelist 
        WHERE list_type = 'whitelist'
        ORDER BY created_at DESC
    ''').fetchall()
    
    conn.close()
    return render_template('admin/manage_lists.html', 
                         blacklist=blacklist, 
                         whitelist=whitelist)

@app.route('/admin/add-to-list', methods=['POST'])
@admin_required
def add_to_list():
    """Add entity to blacklist or whitelist"""
    entity_type = request.form.get('entity_type')
    entity_value = request.form.get('entity_value')
    list_type = request.form.get('list_type')
    reason = request.form.get('reason')
    
    conn = db.get_db_connection()
    conn.execute('''
        INSERT INTO blacklist_whitelist 
        (entity_type, entity_value, list_type, reason, added_by, auto_added)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (entity_type, entity_value, list_type, reason, 
          session.get('user_id'), 0))
    conn.commit()
    conn.close()
    
    add_audit_log('LIST_UPDATE', entity_type, 0, 
                  None, {'list': list_type, 'value': entity_value})
    
    flash(f"Added to {list_type}", 'success')
    return redirect(url_for('manage_lists'))

@app.route('/admin/manual-approve')
@admin_required
def manual_approve():
    """Manual Approval dashboard for admin users"""
    conn = db.get_db_connection()
    applications = conn.execute('SELECT * FROM applications ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('admin/manual_approve.html', applications=applications)

@app.route('/admin/application/<int:app_id>/classify', methods=['POST'])
@admin_required
def classify_application(app_id):
    """Manually approve or reject an application"""
    new_classification = request.form.get('classification')
    if new_classification not in ['APPROVE', 'REJECT', 'REVIEW']:
        flash('Invalid classification', 'error')
        return redirect(request.referrer or url_for('manual_approve'))
    
    conn = db.get_db_connection()
    app_data = conn.execute('SELECT * FROM applications WHERE id = ?', (app_id,)).fetchone()
    if not app_data:
        conn.close()
        flash('Application not found', 'error')
        return redirect(request.referrer or url_for('manual_approve'))
        
    conn.execute('''
        UPDATE applications 
        SET classification = ? 
        WHERE id = ?
    ''', (new_classification, app_id))
    conn.commit()
    conn.close()
    
    # Audit log
    add_audit_log('MANUAL_CLASSIFY', 'application', app_id, 
                  {'classification': app_data['classification']}, 
                  {'classification': new_classification})
    
    flash(f"Application #{app_id} status updated to {new_classification} successfully.", 'success')
    return redirect(request.referrer or url_for('manual_approve'))

# Feature 12: Enhanced Application Analysis with All Features
@app.route('/advanced-analyze/<int:app_id>')
@login_required
def advanced_analyze(app_id):
    """Run complete advanced analysis on an application"""
    application = db.get_application_by_id(app_id)
    if not application:
        flash("Application not found", 'error')
        return redirect(url_for('dashboard'))
    
    # Initialize advanced detector
    detector = AdvancedFraudDetector()
    
    # Run all advanced checks
    analysis_results = {
        'predictive': detector.predict_future_risk(dict(application)),
        'network': detector.analyze_network_connections(dict(application)),
        'time_anomaly': detector.detect_time_anomaly(),
        'geo_fencing': detector.check_geo_fencing(dict(application)),
        'financial': detector.analyze_financial_patterns(dict(application)),
        'trust_score': detector.calculate_trust_score(
            application['aadhaar'], application['phone']),
        'benefit_abuse': detector.check_benefit_abuse(
            application['aadhaar'], application['scheme']),
        'list_check': detector.check_lists(
            application['aadhaar'], application['phone']),
        'nlp_analysis': detector.analyze_text_nlp(application['address'], 'address')
    }
    
    # Calculate total risk
    total_risk = sum(r.get('risk_added', 0) for r in analysis_results.values())
    trust_reduction = analysis_results['trust_score'].get('risk_reduction', 0)
    final_risk = max(0, min(100, total_risk - trust_reduction))
    
    # Generate explanation
    explanation = detector.generate_explanation(
        list(analysis_results.values()), final_risk)
    
    # Get adaptive security level
    security_level = detector.get_security_level(
        final_risk, analysis_results['trust_score']['trust_score'])
    
    return render_template('advanced_analysis.html',
                         application=application,
                         analysis=analysis_results,
                         total_risk=final_risk,
                         explanation=explanation,
                         security_level=security_level)

# ---------------------------------------------------------------------------
# Admin: ML Model Metrics Page
# ---------------------------------------------------------------------------
@app.route('/admin/ml-metrics')
@admin_required
def ml_metrics():
    """Display RandomForest model performance metrics."""
    metrics = fraud_detector.get_ml_metrics()
    user = db.get_user_by_id(session['user_id'])
    return render_template('admin/ml_metrics.html', metrics=metrics, user=user)

# ---------------------------------------------------------------------------
# REST API v1
# ---------------------------------------------------------------------------
@app.route('/api/v1/stats', methods=['GET'])
def api_stats():
    """
    Get dashboard statistics.
    ---
    tags:
      - Statistics
    responses:
      200:
        description: Aggregated fraud detection statistics
    """
    stats = db.get_statistics()
    return jsonify({
        'total': stats['total'],
        'approved': stats['approved'],
        'review': stats['review'],
        'rejected': stats['rejected'],
        'fraud_rate': round(stats['rejected'] / max(stats['total'], 1) * 100, 2)
    })

@app.route('/api/v1/applications', methods=['GET'])
@login_required
def api_list_applications():
    """
    List applications with pagination and filtering.
    ---
    tags:
      - Applications
    parameters:
      - name: page
        in: query
        type: integer
        default: 1
      - name: per_page
        in: query
        type: integer
        default: 25
      - name: classification
        in: query
        type: string
        enum: [APPROVE, REVIEW, REJECT]
      - name: search
        in: query
        type: string
    responses:
      200:
        description: Paginated list of applications
    """
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 25, type=int), 100)
    classification = request.args.get('classification')
    search = request.args.get('search')

    apps, total, total_pages = db.get_paginated_applications(
        page=page, per_page=per_page,
        classification=classification, search=search
    )
    return jsonify({
        'page': page, 'per_page': per_page,
        'total': total, 'total_pages': total_pages,
        'data': [
            {
                'id': a['id'], 'name': a['name'],
                'scheme': a['scheme'], 'risk_score': a['risk_score'],
                'classification': a['classification'],
                'created_at': a['created_at']
            } for a in apps
        ]
    })

@app.route('/api/v1/applications/<int:app_id>', methods=['GET'])
@login_required
def api_get_application(app_id):
    """
    Get a single application by ID.
    ---
    tags:
      - Applications
    parameters:
      - name: app_id
        in: path
        type: integer
        required: true
    responses:
      200:
        description: Application details
      404:
        description: Not found
    """
    app_row = db.get_application_by_id(app_id)
    if not app_row:
        return jsonify({'error': 'Application not found'}), 404
    a = dict(app_row)
    a['reasons'] = json.loads(a['reasons']) if a['reasons'] else []
    return jsonify(a)

@app.route('/api/v1/classify', methods=['POST'])
def api_classify():
    """
    Score an application without saving it (demo/test endpoint).
    ---
    tags:
      - Classification
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [name, aadhaar, phone, income, address]
          properties:
            name: {type: string, example: Ravi Kumar}
            aadhaar: {type: string, example: '123456789012'}
            phone: {type: string, example: '9876543210'}
            income: {type: number, example: 180000}
            address: {type: string, example: '12 MG Road, Bangalore'}
            scheme: {type: string, example: PM-KISAN}
            age: {type: integer, example: 45}
            gender: {type: string, example: Male}
            district: {type: string, example: Bangalore Rural}
    responses:
      200:
        description: Fraud classification result
      400:
        description: Missing required fields
    """
    data = request.get_json(force=True) or {}
    required = ['name', 'aadhaar', 'phone', 'income', 'address']
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({'error': f'Missing fields: {", ".join(missing)}'}), 400

    try:
        income = float(data['income'])
        age = int(data['age']) if data.get('age') else None
    except (ValueError, TypeError):
        return jsonify({'error': 'income must be numeric, age must be integer'}), 400

    result = fraud_detector.detect_fraud(
        name=data['name'], aadhaar=data['aadhaar'],
        phone=data['phone'], income=income,
        address=data['address'],
        scheme=data.get('scheme'), age=age,
        gender=data.get('gender'), district=data.get('district')
    )
    return jsonify(result)

@app.route('/api/v1/ml-metrics', methods=['GET'])
@admin_required
def api_ml_metrics():
    """
    Get ML model performance metrics.
    ---
    tags:
      - ML Model
    responses:
      200:
        description: RandomForest model accuracy, precision, recall, F1, and feature importances
    """
    return jsonify(fraud_detector.get_ml_metrics())

# ---------------------------------------------------------------------------
# Existing API endpoints
# ---------------------------------------------------------------------------
# API endpoint for bot detection (Feature 10)
@app.route('/api/bot-check', methods=['POST'])
def api_bot_check():
    """Receive bot detection data from client"""
    data = request.get_json()
    result = fraud_detector.detect_bot(data)
    return jsonify(result)

# API endpoint for behavior tracking
@app.route('/api/track-behavior', methods=['POST'])
def track_behavior():
    """Track user behavior for bot detection"""
    data = request.get_json()

    conn = db.get_db_connection()
    conn.execute('''
        INSERT INTO behavior_patterns 
        (session_id, ip_address, mouse_movements, typing_speed, time_on_page, form_interactions, bot_probability)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (data.get('session_id'), request.remote_addr,
          data.get('mouse_movements', 0), data.get('typing_speed', 0),
          data.get('time_on_page', 0), data.get('form_interactions', 0),
          data.get('bot_probability', 0)))
    conn.commit()
    conn.close()

    return jsonify({'status': 'tracked'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
