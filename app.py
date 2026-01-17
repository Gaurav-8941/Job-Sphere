from flask import Flask, render_template, request, jsonify, redirect, url_for, abort, session, send_file, send_from_directory
from flask_sock import Sock
import os
from werkzeug.utils import secure_filename
from datetime import datetime
import json
import mysql.connector
from mysql.connector import pooling
import threading
import time
import emailsent
import towstepverification
import notificationvideo  
import windowsnotification
import secrets

# Flask paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

if not os.path.isdir(TEMPLATES_DIR):
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '.'))
    TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
    STATIC_DIR = os.path.join(BASE_DIR, 'static')

app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
app.config['SECRET_KEY'] = 'your-very-secret-key-that-should-be-random'

# Websockets
sock = Sock(app)
hr_sockets = {}
user_sockets = {}
pending_offers = {}
pending_answers = {}
pending_ice = {}
pending_ice_hr = {}  

# Uploads
app.config['UPLOAD_FOLDER'] = os.path.join(STATIC_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'pdf'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# MySQL Connection Pool (mysql-connector)
db_config = {
    "user": "root",
    "password": "root",
    "host": "127.0.0.1",
    "database": "hr_portal",
    "raise_on_warnings": True,
    "autocommit": True
}
try:
    pool = mysql.connector.pooling.MySQLConnectionPool(
        pool_name="job_sphere_pool",
        pool_size=5,
        **db_config
    )
except Exception as e:
    print("MySQL pool creation error:", e)
    pool = None

def get_connection():
    if pool:
        return pool.get_connection()
    else:
        return mysql.connector.connect(**db_config)

def fetch_one(query, params=()):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(query, params)
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row

def fetch_all(query, params=()):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(query, params)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows

def execute(query, params=()):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(query, params)
    conn.commit()
    last_id = cursor.lastrowid
    cursor.close()
    conn.close()
    return last_id

#mock data incase of empty db
jobs = [
    {'id': 1, 'title': 'Senior Software Engineer', 'department': 'IT', 'location': 'Remote',
     'experience': '5+ years', 'skills': ['Python', 'Flask'],
     'description': 'Develop scalable systems.'},
]
#helper for route guards
def require_admin():
    if not session.get('is_admin'):
        return redirect('/admin/login')
def require_hr():
    if not session.get('is_hr'):
        print('[DEBUG] require_hr: session[is_hr] not set, redirecting to login_page')
        return redirect(url_for('login_page'))
    return True
def require_user():
    if 'email' not in session or session.get('is_hr') or session.get('is_admin'):
        return redirect('/login')
    
# Routes
@app.route('/')
def index():
    return render_template('index.html')


# Registration type selection page
@app.route('/register-type')
def register_type():
    return render_template('register_type.html')
# Admin registration page 
@app.route('/admin_register', methods=['GET'])
def admin_register_page():
    return render_template('admin_register.html')
#route for jobs page
@app.route('/jobs')
def jobs_page():
    company_id = session.get('company_id')
    if session.get('is_admin') and company_id:
        job_rows = fetch_all("SELECT * FROM jobs WHERE company_id=%s", (company_id,))
    else:
        job_rows = fetch_all("SELECT * FROM jobs")
    return render_template('jobs.html', jobs=job_rows)

#route for job fill page using job id
@app.route('/jobs/<int:job_id>')
def job_detail(job_id):
    company_id = session.get('company_id')
    if company_id:
        job = fetch_one("SELECT * FROM jobs WHERE id = %s AND company_id = %s", (job_id, company_id))
    else:
        job = fetch_one("SELECT * FROM jobs WHERE id = %s", (job_id,))
    if not job:
        abort(404)
    return render_template('job-detail.html', job=job)

#login page route
@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

#login route
@app.route('/api/login', methods=['POST'])

def login():
    data = request.get_json(silent=True) or request.form

    identifier = (data.get('email') or "").strip()   # email OR username
    password = (data.get('password') or "").strip()

    if not identifier or not password:
        return jsonify({"error": "Email/Username and password required"}), 400


    # HR LOGIN (email OR username)
    hr_row = fetch_one("""
        SELECT * FROM hr
        WHERE (email = %s OR username = %s) AND password = %s
    """, (identifier, identifier, password))

    # USER LOGIN
    user_row = fetch_one("""
        SELECT * FROM users
        WHERE (email = %s OR username = %s) AND password = %s
    """, (identifier, identifier, password))


    # ADMIN LOGIN (email only)
    admin_row = fetch_one("""
        SELECT * FROM admin
        WHERE email = %s AND password = %s
    """, (identifier, password))

    # Only HR and USER require OTP (not admin)
    if hr_row or user_row:
        # Store login attempt in session
        session['pending_login'] = {
            'type': 'hr' if hr_row else 'user',
            'id': hr_row['id'] if hr_row else user_row['id'],
            'email': hr_row['email'] if hr_row else user_row['email'],
            'username': hr_row['username'] if hr_row else user_row['username']
        }
        # Generate and send OTP
        otp = towstepverification.generate_otp()
        print(f"[DEBUG] OTP for {identifier}: {otp}")
        emailsent.send_otp_email(identifier, otp)
        session['otp_sent_time'] = int(time.time())
        return jsonify({"otp_required": True, "message": "OTP sent to your email."})


    if admin_row:
        # Admin login (no OTP)
        session['is_admin'] = True
        session['is_hr'] = False
        session['admin_email'] = admin_row["email"]
        session['company_id'] = admin_row["company_id"]
        return jsonify({"redirect": url_for('admin_dashboard')})

    return jsonify({"error": "Invalid credentials"}), 401


# OTP verification route
@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json(silent=True) or request.form
    otp = (data.get('otp') or '').strip()
    pending = session.get('pending_login')
    sent_time = session.get('otp_sent_time')
    if not pending or not sent_time:
        return jsonify({"error": "No OTP session found. Please login again."}), 400
    if int(time.time()) - int(sent_time) > 30:
        return jsonify({"error": "OTP expired. Please login again."}), 400
    if not towstepverification.verify_otp(otp):
        return jsonify({"error": "Invalid OTP. Please try again."}), 401

    # OTP valid, complete login
    if pending['type'] == 'hr':
        # Fetch HR row to get company_id
        hr_row = fetch_one("SELECT * FROM hr WHERE id=%s", (pending['id'],))
        session['is_hr'] = True
        session['is_admin'] = False
        session['email'] = pending['email']
        session['username'] = pending['username']
        session['hr_id'] = pending['id']
        # If HR has no company_id, assign the first available company
        company_id = hr_row['company_id'] if hr_row and hr_row['company_id'] else None
        if not company_id:
            company = fetch_one("SELECT company_id FROM company LIMIT 1")
            if company:
                company_id = company['company_id']
                execute("UPDATE hr SET company_id=%s WHERE id=%s", (company_id, pending['id']))
        session['company_id'] = company_id
        session.pop('pending_login', None)
        session.pop('otp_sent_time', None)
        return jsonify({"redirect": url_for('dashboard_hr')})
    elif pending['type'] == 'user':
        session['is_hr'] = False
        session['is_admin'] = False
        session['email'] = pending['email']
        session['username'] = pending['username']
        session['user_id'] = pending['id']
        session['user_table'] = f"user_{pending['id']}_activity"
        session.pop('pending_login', None)
        session.pop('otp_sent_time', None)
        return jsonify({"redirect": url_for('dashboard_user')})
    else:
        return jsonify({"error": "Unknown login type."}), 400

# === Add this new route to app.py ===
@app.route('/api/get-ice-servers')
def get_ice_servers():
    """Securely provide STUN/TURN server credentials."""
    # Optional: Protect the endpoint. Basic example:
    # if not session.get('user_id') and not session.get('hr_id'):
    #     return jsonify({'error': 'Unauthorized'}), 403

    ice_servers = [
        # Public STUN servers - Good for testing
        {"urls": "stun:stun.l.google.com:19302"},
        {"urls": "stun:stun1.l.google.com:19302"},
        # TODO: Add your production TURN servers here
        # {
        #     "urls": "turn:your.turn.server:3478",
        #     "username": "username_from_env_var",
        #     "credential": "password_from_env_var"
        # },
    ]
    return jsonify(ice_servers)

@app.route('/apply', methods=['POST'])
def apply_job():
    # 1. FIRST CHECK: Is user logged in?
    if not session.get('user_id'):
        return jsonify({'error': 'You must be logged in to apply'}), 401
    
    try:
        # 2. Get form data
        job_id = request.form.get('job_id')
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        cover_letter = request.form.get('cover_letter')
    
        # 3. Verify form email matches logged-in user
        logged_in_email = session.get('email')
        if email != logged_in_email:
            return jsonify({'error': 'Email does not match your account'}), 400
        
        # Resume upload
        if 'resume' not in request.files:
            return jsonify({'error': 'No resume uploaded'}), 400

        file = request.files['resume']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Only PDF allowed.'}), 400

        filename = secure_filename(file.filename)
        unique_name = f"{int(datetime.now().timestamp())}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
        file.save(file_path)

        # Fetch job → includes hr_id
        job_row = fetch_one("SELECT hr_id FROM jobs WHERE id=%s", (job_id,))
        if not job_row:
            return jsonify({'error': 'Job not found'}), 400
        
        hr_id = job_row["hr_id"]
        user_id = session['user_id']  

        # Insert into global applications table WITH user_id
        global_app_id = execute("""
            INSERT INTO applications (job_id, hr_id, user_id, applicant_name, email, phone, cover_letter, resume_file, date_applied, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), 'Pending')
        """, (job_id, hr_id, user_id, name, email, phone, cover_letter, unique_name))
        
        # Insert into user's private table USING SESSION USER_ID (NOT EMAIL LOOKUP)
        user_table = f"user_{user_id}_activity"
        
        execute(f"""
            INSERT INTO {user_table} (job_id, global_app_id, status, resume_file, date_applied)
            VALUES (%s, %s, %s, %s, NOW())
        """, (job_id, global_app_id, "Pending", unique_name))
        
        return jsonify({'message': 'Application submitted successfully!'})
        
    except Exception as e:
        print("Error in apply_job:", e)
        return jsonify({'error': str(e)}), 500


#HR dashboard
@app.route('/dashboard/hr')
def dashboard_hr():
    if require_hr() is not True:
        return require_hr()
    print('[DEBUG] dashboard_hr: session =', dict(session))
    hr_email = session.get('email')
    company_id = session.get('company_id')
    # Get HR information
    hr_row = fetch_one(
        "SELECT id, username, name, department FROM hr WHERE email=%s AND company_id=%s",
        (hr_email, company_id)
    )
    if not hr_row:
        return redirect(url_for('login_page'))
    hr_id = hr_row['id']
    hr_department = hr_row['department']
    session['hr_id'] = hr_id
    # Count only jobs in this HR's department and company
    total_jobs = fetch_one(
        "SELECT COUNT(*) AS cnt FROM jobs WHERE department = %s AND company_id=%s",
        (hr_department, company_id)
    )['cnt']
    total_applications = fetch_one("""
        SELECT COUNT(*) AS cnt
        FROM applications a
        JOIN jobs j ON a.job_id = j.id
        WHERE j.department = %s AND j.company_id=%s
    """, (hr_department, company_id))['cnt']
    interviews = fetch_one("""
        SELECT COUNT(*) AS cnt
        FROM applications a
        JOIN jobs j ON a.job_id = j.id
        WHERE j.department = %s AND j.company_id=%s AND a.status='Interview Scheduled'
    """, (hr_department, company_id))['cnt']
    hired = fetch_one("""
        SELECT COUNT(*) AS cnt
        FROM applications a
        JOIN jobs j ON a.job_id = j.id
        WHERE j.department = %s AND j.company_id=%s AND a.status='Hired'
    """, (hr_department, company_id))['cnt']
    # Fetch latest applications for this HR's department and company
    applications = fetch_all("""
        SELECT a.id,
           a.applicant_name,
           j.title,
           j.department,
           a.status,
           a.date_applied,
           a.resume_file
    FROM applications a
    JOIN jobs j ON a.job_id = j.id
    WHERE j.department = %s AND j.company_id=%s
    ORDER BY a.date_applied DESC
    LIMIT 10
""", (hr_department, company_id))
    dashboard_data = {
        'total_openings': total_jobs,
        'total_applications': total_applications,
        'interviews': interviews,
        'hired_candidates': hired
    }
    return render_template(
        'dashboard_hr.html',
        data=dashboard_data,
        applications=applications,
        user_email=hr_email
    )

# Admin routes

# Admin registration API
import re
import secrets
from urllib.parse import urlparse

def extract_domain(email):
    return email.split('@')[-1].lower()

def extract_website_domain(website):
    try:
        parsed = urlparse(website)
        return parsed.netloc.lower().replace('www.', '')
    except Exception:
        return ''


@app.route('/api/admin/register', methods=['POST'])
def admin_register():
    data = request.form
    admin_name = data.get('admin_name', '').strip()
    admin_email = data.get('admin_email', '').strip().lower()
    password = data.get('password', '').strip()
    company_name = data.get('company_name', '').strip()
    company_email = data.get('company_email', '').strip().lower()
    company_website = data.get('company_website', '').strip().lower()
    company_address = data.get('company_address', '').strip()
    company_phone = data.get('company_phone', '').strip()
    industry = data.get('industry', '').strip()
    company_size = data.get('company_size', '').strip()


    # Only block throwaway/temporary email domains, not gmail.com
    FREE_EMAIL_DOMAINS = {
        'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com',
        'mail.com', 'gmx.com', 'protonmail.com', 'zoho.com', 'yandex.com', 'rediffmail.com',
        'msn.com', 'live.com', 'inbox.com', 'fastmail.com', 'hushmail.com', 'rocketmail.com',
        'mail.ru', 'qq.com', 'naver.com', '163.com', '126.com', 'sina.com', 'yeah.net',
        'bk.ru', 'list.ru', 'mailinator.com', 'tempmail.com', 'guerrillamail.com', '10minutemail.com'
    }

    # Check for throwaway/temporary email domain
    company_email_domain = company_email.split('@')[-1].lower()
    if company_email_domain in FREE_EMAIL_DOMAINS:
        return jsonify({'error': 'Please use your official company email address, not a temporary email provider.', 'redirect': url_for('index')}), 400


    # Store pending registration in a dedicated table
    try:
        pending_id = execute('''
            INSERT INTO pending_admin_registrations (
                admin_name, admin_email, password, company_name, company_email, company_website, company_address, company_phone, industry, company_size, submitted_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        ''', (admin_name, admin_email, password, company_name, company_email, company_website, company_address, company_phone, industry, company_size))
        review_body = f"A new admin registration is pending manual verification.\n\nCompany Name: {company_name}\nAdmin Email: {admin_email}\nCompany Email: {company_email}\nWebsite: {company_website}\n\nPlease verify and approve/reject this registration."
        emailsent.send_otp_email("gauravchavan28123@gmail.com", review_body)
    except Exception as e:
        print(f"Failed to store pending registration or send notification: {e}")
        return jsonify({'error': 'Failed to submit registration. Please try again later.'}), 500
    return jsonify({'success': True, 'message': 'Registration submitted and pending manual verification by the platform admin.'})

    # Basic validation
    if not (admin_name and admin_email and password and company_name and company_email and company_website):
        return jsonify({'error': 'All required fields must be filled.'}), 400

    # Check if admin or company already exists
    exists = fetch_one("SELECT admin_id FROM admin WHERE email=%s", (admin_email,))
    if exists:
        return jsonify({'error': 'Admin email already registered.'}), 400
    exists_company = fetch_one("SELECT company_id FROM company WHERE company_email=%s", (company_email,))
    if exists_company:
        return jsonify({'error': 'Company email already registered.'}), 400

    # Company email domain check (basic)
    email_domain = extract_domain(company_email)
    website_domain = extract_website_domain(company_website)
    domain_warning = False
    if website_domain and email_domain not in website_domain:
        domain_warning = True

    # Generate verification token
    verify_token = secrets.token_urlsafe(32)

    # Insert company (pending manual review)
    company_id = execute("""
        INSERT INTO company (company_name, company_email, company_website, company_address, company_phone, industry, company_size, verified, verify_token, pending_review)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (company_name, company_email, company_website, company_address, company_phone, industry, company_size, False, verify_token, True))

    # Insert admin (pending verification)
    admin_id = execute("""
        INSERT INTO admin (name, email, password, company_id, verified)
        VALUES (%s, %s, %s, %s, %s)
    """, (admin_name, admin_email, password, company_id, False))

    # Send verification email to company official email
    verify_link = url_for('verify_company_email', token=verify_token, _external=True)
    subject = f"Verify your company for Job Sphere"
    body = f"Hello,\n\nPlease verify your company registration for Job Sphere by clicking the link below:\n{verify_link}\n\nIf you did not request this, please ignore."
    try:
        emailsent.send_otp_email(company_email, body)  # Reuse for now, or create a new send_email function
    except Exception as e:
        return jsonify({'error': f'Failed to send verification email: {e}'}), 500

    # Notify platform admin for manual review (after all variables are set)
    try:
        review_subject = f"Manual Review Needed: New Company Registration ({company_name})"
        review_body = f"A new company has registered and is pending manual review.\n\nCompany Name: {company_name}\nAdmin Email: {admin_email}\nCompany Email: {company_email}\nWebsite: {company_website}\n\nPlease review and approve/reject in the admin dashboard or database."
        emailsent.send_otp_email("gauravchavan@gmail.com", review_body)
    except Exception as e:
        print(f"Failed to send manual review notification: {e}")

    if domain_warning:
        return jsonify({'success': True, 'message': 'Registration submitted and pending manual review because your company email does not match your website domain. Please verify via the company official email.'})
    return jsonify({'success': True, 'message': 'Registration submitted. Please verify via the company official email.'})


    # Send verification email to company official email
    verify_link = url_for('verify_company_email', token=verify_token, _external=True)
    subject = f"Verify your company for Job Sphere"
    body = f"Hello,\n\nPlease verify your company registration for Job Sphere by clicking the link below:\n{verify_link}\n\nIf you did not request this, please ignore."
    try:
        emailsent.send_otp_email(company_email, body)  # Reuse for now, or create a new send_email function
    except Exception as e:
        return jsonify({'error': f'Failed to send verification email: {e}'}), 500

    # Notify platform admin for manual review (after all variables are set)
    try:
        review_subject = f"Manual Review Needed: New Company Registration ({company_name})"
        review_body = f"A new company has registered and is pending manual review.\n\nCompany Name: {company_name}\nAdmin Email: {admin_email}\nCompany Email: {company_email}\nWebsite: {company_website}\n\nPlease review and approve/reject in the admin dashboard or database."
        emailsent.send_otp_email("gauravchavan@gmail.com", review_body)
    except Exception as e:
        print(f"Failed to send manual review notification: {e}")

    if domain_warning:
        return jsonify({'success': True, 'message': 'Registration submitted and pending manual review because your company email does not match your website domain. Please verify via the company official email.'})
    return jsonify({'success': True, 'message': 'Registration submitted. Please verify via the company official email.'})

# Company email verification endpoint
@app.route('/verify-company-email/<token>')
def verify_company_email(token):
    # Find company by token
    company = fetch_one("SELECT company_id FROM company WHERE verify_token=%s", (token,))
    if not company:
        return "Invalid or expired verification link.", 400
    # Check if company is approved by admin (manual review)
    pending_review = fetch_one("SELECT pending_review FROM company WHERE company_id=%s", (company['company_id'],))
    if pending_review and pending_review['pending_review']:
        return "Your company registration is pending manual review by the platform admin. You will be notified once approved.", 200
    # Mark company as verified
    execute("UPDATE company SET verified=1, verify_token=NULL WHERE company_id=%s", (company['company_id'],))
    # Mark all admins for this company as verified
    execute("UPDATE admin SET verified=1 WHERE company_id=%s", (company['company_id'],))
    return "Company email verified! You may now log in as admin.", 200

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    #Search & filters 
    search = request.args.get("search", "").strip()
    department = request.args.get("department", "").strip()
    page = int(request.args.get("page", 1))
    per_page = 5
    offset = (page - 1) * per_page

    filters = []
    params = []

    if search:
        filters.append("(name LIKE %s OR email LIKE %s)")
        params += [f"%{search}%", f"%{search}%"]

    if department:
        filters.append("department = %s")
        params.append(department)

    where_clause = "WHERE " + " AND ".join(filters) if filters else ""


    # Always filter HRs by company_id
    if where_clause:
        where_clause = f"WHERE company_id=%s AND " + where_clause[6:]
        params = [session['company_id']] + params
    else:
        where_clause = "WHERE company_id=%s"
        params = [session['company_id']]
    hr_list = fetch_all(
        f"SELECT id, name, department, email FROM hr {where_clause} LIMIT %s OFFSET %s",
        params + [per_page, offset]
    )
    next_count = fetch_all(
        f"SELECT COUNT(*) AS c FROM hr {where_clause}",
        params
    )[0]['c']
    has_next = next_count > page * per_page

    # Hired & pending stats
    hired_rows = fetch_all("SELECT hr_id, COUNT(*) AS hired_count FROM applications WHERE status='Hired' GROUP BY hr_id")
    pending_rows = fetch_all("SELECT hr_id, COUNT(*) AS pending_count FROM applications WHERE status='Interview Scheduled' GROUP BY hr_id")

    hired_data = {r['hr_id']: r['hired_count'] for r in hired_rows}
    pending_data = {r['hr_id']: r['pending_count'] for r in pending_rows}

    return render_template(
        "dashboard_admin.html",
        hr_list=hr_list,
        hired=hired_data,
        pending=pending_data,
        search=search,
        department=department,
        page=page,
        has_next=has_next
    )


#Add HR 
@app.route('/admin/hr/add', methods=['POST'])
def admin_add_hr():
    name = request.form['name']
    dept = request.form['department']
    email = request.form['email']
    password = request.form['password']
    # Check user table & admin table also
    user_exists = fetch_one("SELECT id FROM users WHERE email=%s", (email,))
    admin_exists = fetch_one("SELECT admin_id FROM admin WHERE email=%s", (email,))

    if user_exists or admin_exists:
        return redirect(url_for('admin_dashboard', error="Email already used by another account"))

    username = request.form['username']

# Check unique email
    exists_email = fetch_one("SELECT id FROM hr WHERE email=%s", (email,))
    if exists_email:
        return redirect(url_for('admin_dashboard', error="Email already exists"))

    # Check unique username
    exists_user = fetch_one("SELECT id FROM hr WHERE username=%s", (username,))
    if exists_user:
        return redirect(url_for('admin_dashboard', error="Username already exists"))


    execute("""
        INSERT INTO hr (username, name, department, email, password, company_id)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (username, name, dept, email, password, session['company_id']))


    return redirect(url_for('admin_dashboard', success="HR added successfully"))

# Edit HR 
@app.route('/admin/hr/edit/<int:hr_id>', methods=['POST'])
def admin_edit_hr(hr_id):
    username = request.form['username']
    name = request.form['name']
    dept = request.form['department']
    email = request.form['email']
    password = request.form['password']

    # Check username duplicate
    exists_user = fetch_one("SELECT id FROM hr WHERE username=%s AND id!=%s", (username, hr_id))
    if exists_user:
        return redirect(url_for('admin_dashboard', error="Username already in use"))

    # Check email duplicate
    exists_email = fetch_one("SELECT id FROM hr WHERE email=%s AND id!=%s", (email, hr_id))
    if exists_email:
        return redirect(url_for('admin_dashboard', error="Email already in use"))

    # Password optional during edit
    if password.strip():
        execute("""
            UPDATE hr SET username=%s, name=%s, department=%s, email=%s, password=%s
            WHERE id=%s
        """, (username, name, dept, email, password, hr_id))
    else:
        execute("""
            UPDATE hr SET username=%s, name=%s, department=%s, email=%s
            WHERE id=%s
        """, (username, name, dept, email, hr_id))

    return redirect(url_for('admin_dashboard', success="HR updated successfully"))

#Delete hr
@app.route('/admin/hr/delete/<int:hr_id>')
def admin_delete_hr(hr_id):
    execute("DELETE FROM hr WHERE id = %s", (hr_id,))
    return redirect(url_for('admin_dashboard'))
#Route for the page
@app.route('/hr/jobs/add')
def hr_add_job():
    if not session.get('is_hr'):
        return redirect(url_for('login_page'))
    return render_template('hr_add_job.html')

#Route for the adding jobs
@app.route('/hr/jobs/add', methods=['POST'])
def hr_add_job_post():
    if not session.get('is_hr'):
        return redirect(url_for('login_page'))
    hr_email = session.get('email')
    hr_row = fetch_one("SELECT id FROM hr WHERE email=%s", (hr_email,))
    hr_id = hr_row['id']
    title = request.form['title']
    hr_info = fetch_one("SELECT id, department FROM hr WHERE email=%s", (hr_email,))
    hr_id = hr_info['id']
    department = hr_info['department']  # Force HR's own department
    location = request.form['location']
    experience = request.form['experience']
    skills = request.form['skills']
    description = request.form['description']
    start_date = request.form['start_date']
    end_date = request.form['end_date']

    execute("""
        INSERT INTO jobs (hr_id, title, department, location, experience, skills, description, hiring_start, hiring_end)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (hr_id,title, department, location, experience, skills, description, start_date, end_date))
    return redirect(url_for('hr_jobs_manage'))


# MANAGE JOBS (LIST + DELETE BUTTON)
@app.route('/hr/jobs/manage')
def hr_jobs_manage():
    if not session.get('is_hr'):
        return redirect(url_for('login_page'))

    hr_email = session.get('email')
    hr_row = fetch_one("SELECT id, department FROM hr WHERE email=%s", (hr_email,))
    hr_id = hr_row['id']

    job_rows = fetch_all("SELECT * FROM jobs WHERE hr_id=%s ORDER BY id DESC", (hr_id,))

    return render_template('hr_jobs_manage.html', jobs=job_rows)


# EDIT JOB PAGE
@app.route('/hr/jobs/edit/<int:job_id>')
def hr_edit_job(job_id):
    if not session.get('is_hr'):
        return redirect(url_for('login_page'))
    
    # Get HR ID from session
    hr_id = session.get('hr_id')
    if not hr_id:
        # Fallback: query from database
        hr_email = session.get('email')
        hr_row = fetch_one("SELECT id FROM hr WHERE email=%s", (hr_email,))
        hr_id = hr_row['id'] if hr_row else None
    
    job = fetch_one("SELECT * FROM jobs WHERE id = %s AND hr_id=%s", (job_id, hr_id))
    if not job:
        abort(404)
    return render_template('hr_edit_job.html', job=job)


# EDIT JOB POST
@app.route('/hr/jobs/edit/<int:job_id>', methods=['POST'])
def hr_edit_job_post(job_id):
    if not session.get('is_hr'):
        return redirect(url_for('login_page'))
    
    # Get HR info
    hr_email = session.get('email')
    hr_info = fetch_one("SELECT id, department FROM hr WHERE email=%s", (hr_email,))
    
    if not hr_info:
        return redirect(url_for('login_page'))
    
    hr_id = hr_info['id']
    department = hr_info['department']
    
    # Get form data
    title = request.form['title']
    location = request.form['location']
    experience = request.form['experience']
    skills = request.form['skills']
    description = request.form['description']
    start_date = request.form['start_date']
    end_date = request.form['end_date']
    
    execute("""
        UPDATE jobs SET 
            title=%s, department=%s, location=%s, experience=%s,
            skills=%s, description=%s, hiring_start=%s, hiring_end=%s
        WHERE id=%s AND hr_id=%s
    """, (title, department, location, experience, skills, description, start_date, end_date, job_id, hr_id))
    
    return redirect(url_for('hr_jobs_manage'))


# DELETE JOB
@app.route('/hr/jobs/delete/<int:job_id>')
def hr_delete_job(job_id):
    if not session.get('is_hr'):
        return redirect(url_for('login_page'))
    
    # Get HR ID from session
    hr_id = session.get('hr_id')
    if not hr_id:
        hr_email = session.get('email')
        hr_row = fetch_one("SELECT id FROM hr WHERE email=%s", (hr_email,))
        hr_id = hr_row['id'] if hr_row else None
    
    execute("DELETE FROM jobs WHERE id=%s AND hr_id=%s", (job_id, hr_id))
    return redirect(url_for('hr_jobs_manage'))

@app.route('/resume/<path:filename>')
def view_resume(filename):
    """
    Opens the resume directly in browser (inline preview).
    """
    resume_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return send_file(resume_path, mimetype='application/pdf')

@app.route('/resume/download/<path:filename>')
def download_resume(filename):
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        filename,
        as_attachment=True
    )

@app.route('/update_status/<int:app_id>', methods=['POST'])
def update_status(app_id):
    if not session.get('is_hr'):
        return redirect(url_for('login_page'))

    new_status = request.form.get('status')

    hr_email = session.get('email')
    hr_row = fetch_one("SELECT id FROM hr WHERE email=%s", (hr_email,))
    hr_id = hr_row['id'] if hr_row else None

    # Get current status
    app_row = fetch_one("SELECT status, user_id FROM applications WHERE id=%s", (app_id,))
    if not app_row:
        return redirect(url_for('dashboard_hr'))
    current_status = app_row['status']

    # Only allow 'Hired' if current status is 'Interview Scheduled' or 'Hired'
    if new_status == 'Hired' and current_status not in ['Interview Scheduled', 'Hired']:
        # Optionally flash a message or return an error
        return redirect(url_for('dashboard_hr'))

    # 1. Update the applications table
    execute("UPDATE applications SET status=%s, hr_id=%s WHERE id=%s",
            (new_status, hr_id, app_id))

    # 2. Find which user table to update
    if app_row['user_id']:
        user_id = app_row['user_id']
        user_table = f"user_{user_id}_activity"
        # 3. Update the user's private table
        execute(f"""
            UPDATE {user_table} 
            SET status = %s 
            WHERE global_app_id = %s
        """, (new_status, app_id))

    return redirect(url_for('dashboard_hr'))
#Admin analytics
@app.route('/admin/analytics/data')
def admin_analytics_data():
    if not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403

    rows = fetch_all("""
        SELECT hr_id,
               SUM(CASE WHEN status='Hired' THEN 1 ELSE 0 END) AS hired,
               SUM(CASE WHEN status='Interview Scheduled' THEN 1 ELSE 0 END) AS pending
        FROM applications
        GROUP BY hr_id
    """)

    return jsonify(rows)


#Register

@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')

@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.get_json(silent=True) or request.form

    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    # Check if email exists in users OR hr OR admin
    exists_user = fetch_one("SELECT id FROM users WHERE email=%s", (email,))
    exists_hr = fetch_one("SELECT id FROM hr WHERE email=%s", (email,))
    exists_admin = fetch_one("SELECT admin_id FROM admin WHERE email=%s", (email,))

    if exists_user or exists_hr or exists_admin:
        return jsonify({"error": "Email already in use"}), 400

    if not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    exists = fetch_one("SELECT id FROM users WHERE email=%s", (email,))
    if exists:
        return jsonify({"error": "Email already exists"}), 400

    # Insert into main users table
    user_id = execute("""
        INSERT INTO users (username, email, password)
        VALUES (%s, %s, %s)
    """, (username, email, password))

    # Create private table for the user
    table_name = f"user_{user_id}_activity"

    execute(f"""
        CREATE TABLE {table_name} (
            id INT AUTO_INCREMENT PRIMARY KEY,
            job_id INT,
            status VARCHAR(50),
            resume_file VARCHAR(255),
            date_applied DATETIME
        );
    """)

    return jsonify({"message": "Account created successfully!", "redirect": "/login"})


#User Dashboard
@app.route('/dashboard/user')
def dashboard_user():
    require_user()

    user_email = session['email']
    table_name = session['user_table']

    user_apps = fetch_all("""
        SELECT a.id as app_id,
            a.status,
            a.resume_file,
            j.title,
            j.department
        FROM applications a
        JOIN jobs j ON a.job_id = j.id
        WHERE a.user_id = %s
        ORDER BY a.date_applied DESC
    """, (session['user_id'],))
    print(f"DEBUG: User table: {table_name}")
    print(f"DEBUG: User apps data: {user_apps}")
    return render_template("dashboard_user.html", applications=user_apps, user_email=user_email)

#Video call stuff
@app.route("/video/<int:app_id>")
def video_call(app_id):
    # Get user email for notification
    app_data = fetch_one("SELECT email FROM applications WHERE id=%s", (app_id,))
    if app_data:
        user_email = app_data['email']
        # Send email notification to user
        try:
            notificationvideo.send_video_email(user_email)
            print(f"Video call notification sent to {user_email}")
            windowsnotification.notify_video_call("Video Call", f"A video call has been initiated. Check your profile page.")
            print("Desktop notification sent.")
        except Exception as e:
            print(f"Failed to send notification email: {e}")
    
    return render_template("video_call.html", app_id=app_id)


@app.route("/video/user/<int:app_id>")
def video_call_user(app_id):
    app_data=fetch_one("SELECT a.email, a.hr_id, h.email as hr_email FROM applications a JOIN hr h ON a.hr_id=h.id WHERE a.id=%s",(app_id,))
    if app_data:
        hr_email=app_data['hr_email']
        try:
            notificationvideo.send_video_email(hr_email)
            print(f"Video call notification sent to HR: {hr_email}")
            windowsnotification.notify_video_call_hr("Video Call", f"Candidate has joined the video call. Check your dashboard.")
            print("Desktop notification sent to HR.")
        except Exception as e:
            print(f"Failed to send notification email to HR: {e}")
    return render_template("video_call_user.html", app_id=app_id)

# --- WebSocket Keepalive Helper ---
def ws_keepalive(ws, interval=20):
    """Send ping messages to keep ngrok/host WebSocket alive."""
    try:
        while True:
            ws.send(json.dumps({"type": "ping"}))
            time.sleep(interval)
    except Exception:
        pass

# HR WebSocket (caller)
@sock.route('/ws/hr/<int:app_id>')
def ws_hr(ws, app_id):
    print(f" HR WebSocket connected for app_id: {app_id}")
    hr_sockets[app_id] = ws
    print(f"DEBUG: Stored HR socket for app_id {app_id}. Total HR sockets: {list(hr_sockets.keys())}")

    # Start keepalive thread
    threading.Thread(target=ws_keepalive, args=(ws,), daemon=True).start()

    # Notify candidate HR is online
    if app_id in user_sockets:
        try:
            user_sockets[app_id].send(json.dumps({"type": "hr_online"}))
            print(f" Notified user {app_id} that HR is online")
        except Exception as e:
            print(f" Error notifying user: {e}")
    else:
        print(f" User not connected yet for app_id: {app_id}")

    # Always send all buffered ICE from user to HR
    if app_id in pending_ice_hr:
        print(f" Sending {len(pending_ice_hr[app_id])} buffered ICE candidates to HR {app_id}")
        for c in pending_ice_hr[app_id]:
            try:
                ws.send(json.dumps({"type": "ice", "ice": c}))
            except Exception as e:
                print(f"Error sending buffered ICE to HR: {e}")

    try:
        while True:
            msg = ws.receive()
            if not msg:
                print(f" HR WebSocket closed for app_id: {app_id}")
                break
            
            print(f" HR received message for app_id {app_id}: {msg[:100]}...")
            data = json.loads(msg)
            
            # HR SENDS OFFER
            if data["type"] == "offer":
                print(f" HR sending offer to user for app_id: {app_id}")
                if app_id in user_sockets:
                    user_sockets[app_id].send(json.dumps({
                        "type": "offer",
                        "offer": data["offer"]
                    }))
                    print(f" Offer forwarded to user {app_id}")
                else:
                    pending_offers[app_id] = data["offer"]
                    print(f" Offer stored pending user connection for app_id: {app_id}")
            
            # HR ICE
            elif data["type"] == "ice":
                # Always buffer ICE
                pending_ice.setdefault(app_id, []).append(data["ice"])
                # Relay ICE to user if connected
                if app_id in user_sockets:
                    try:
                        user_sockets[app_id].send(json.dumps({
                            "type": "ice",
                            "ice": data["ice"]
                        }))
                    except Exception as e:
                        print(f"Error sending ICE to user: {e}")
            # Optionally handle pings/pongs
            elif data["type"] == "ping":
                continue
    except Exception as e:
        print(f" HR WebSocket error for app_id {app_id}: {e}")
    finally:
        hr_sockets.pop(app_id, None)
        print(f" HR WebSocket cleaned up for app_id: {app_id}")


# USER WebSocket (receiver)
@sock.route('/ws/user/<int:app_id>')
def ws_user(ws, app_id):
    print(f" USER WebSocket connected for app_id: {app_id}")
    user_sockets[app_id] = ws
    print(f"DEBUG: Stored USER socket for app_id {app_id}. Total USER sockets: {list(user_sockets.keys())}")

    # Start keepalive thread
    threading.Thread(target=ws_keepalive, args=(ws,), daemon=True).start()

    # Send pending events if user came late
    if app_id in pending_offers:
        try:
            ws.send(json.dumps({"type": "offer", "offer": pending_offers[app_id]}))
        except Exception as e:
            print(f"Error sending pending offer: {e}")
        del pending_offers[app_id]
    if app_id in pending_ice:
        print(f" Sending {len(pending_ice[app_id])} buffered ICE candidates to user {app_id}")
        for c in pending_ice[app_id]:
            try:
                ws.send(json.dumps({"type": "ice", "ice": c}))
            except Exception as e:
                print(f"Error sending buffered ICE: {e}")

    # Notify HR that user joined
    if app_id in hr_sockets:
        try:
            hr_sockets[app_id].send(json.dumps({"type": "user_online"}))
        except Exception as e:
            print(f"Error notifying HR: {e}")

    try:
        while True:
            msg = ws.receive()
            if not msg:
                print(f" USER WebSocket closed for app_id: {app_id}")
                break
            
            print(f" USER received message for app_id {app_id}: {msg[:100]}...")
            data = json.loads(msg)
            
            # USER SENDS ANSWER
            if data["type"] == "answer":
                print(f" User sending answer to HR for app_id: {app_id}")
                if app_id in hr_sockets:
                    hr_sockets[app_id].send(json.dumps({
                        "type": "answer",
                        "answer": data["answer"]
                    }))
                    print(f" Answer forwarded to HR {app_id}")
                else:
                    pending_answers[app_id] = data["answer"]
                    print(f" Answer stored pending HR connection for app_id: {app_id}")
            
            # USER ICE
            elif data["type"] == "ice":
                # Always buffer ICE
                pending_ice_hr.setdefault(app_id, []).append(data["ice"])
                # Relay ICE to HR if connected
                if app_id in hr_sockets:
                    try:
                        hr_sockets[app_id].send(json.dumps({
                            "type": "ice",
                            "ice": data["ice"]
                        }))
                    except Exception as e:
                        print(f"Error sending ICE to HR: {e}")
            elif data["type"] == "ping":
                continue
    except Exception as e:
        print(f" USER WebSocket error for app_id {app_id}: {e}")
    finally:
        user_sockets.pop(app_id, None)
        print(f"USER WebSocket cleaned up for app_id: {app_id}")


# Manual verifier login and OTP

@app.route('/manual-verification', methods=['GET', 'POST'])
def manual_verifier_login():
    if request.method == 'GET':
        return render_template('manual_verification.html')
    # POST: handle login (email + password)
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '').strip()
    allowed_email = 'fycopractice@gmail.com'
    allowed_password = '7066company'
    if email != allowed_email:
        return render_template('manual_verification.html', error='Invalid email for manual verification.')
    if password != allowed_password:
        return render_template('manual_verification.html', error='Incorrect password.')
    # Generate OTP and send
    otp = secrets.randbelow(900000) + 100000
    session['manual_verifier_otp'] = str(otp)
    session['manual_verifier_email'] = email
    try:
        emailsent.send_otp_email(email, f"Your OTP for manual verification login is: {otp}")
    except Exception as e:
        print(f"Failed to send OTP: {e}")
        return render_template('manual_verification.html', error='Failed to send OTP email.')
    return render_template('manual_verification.html', otp_sent=True, email=email)

@app.route('/manual-verification/otp', methods=['GET', 'POST'])
def manual_verifier_otp():
    otp = (request.form.get('otp') or request.args.get('otp') or '').strip()
    email = session.get('manual_verifier_email')
    if not email or not otp:
        return render_template('manual_verification.html', error='Session expired or invalid OTP.')
    if otp != session.get('manual_verifier_otp'):
        return render_template('manual_verification.html', otp_sent=True, email=email, error='Invalid OTP.')
    session['is_manual_verifier'] = True
    return redirect(url_for('manual_verifier_dashboard'))

@app.route('/manual-verification/dashboard')
def manual_verifier_dashboard():
    if not session.get('is_manual_verifier'):
        return redirect(url_for('manual_verifier_login'))
    pending = fetch_all("SELECT * FROM pending_admin_registrations ORDER BY submitted_at DESC")
    return render_template('manual_verification_dashboard.html', pending=pending)

@app.route('/manual-verification/approve/<int:pending_id>', methods=['POST'])
def manual_verifier_approve(pending_id):
    if not session.get('is_manual_verifier'):
        return redirect(url_for('manual_verifier_login'))
    reg = fetch_one("SELECT * FROM pending_admin_registrations WHERE id=%s", (pending_id,))
    if not reg:
        return redirect(url_for('manual_verifier_dashboard', error='Registration not found'))
    company_id = execute("""
        INSERT INTO company (company_name, company_email, company_website, company_address, company_phone, industry, company_size, verified, pending_review)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (reg['company_name'], reg['company_email'], reg['company_website'], reg['company_address'], reg['company_phone'], reg['industry'], reg['company_size'], True, False))
    admin_id = execute("""
        INSERT INTO admin (name, email, password, company_id, verified)
        VALUES (%s, %s, %s, %s, %s)
    """, (reg['admin_name'], reg['admin_email'], reg['password'], company_id, True))
    try:
        emailsent.send_otp_email(reg['admin_email'], f"Your admin registration for {reg['company_name']} has been approved. You may now log in.")
    except Exception as e:
        print(f"Failed to send approval email: {e}")
    execute("DELETE FROM pending_admin_registrations WHERE id=%s", (pending_id,))
    return redirect(url_for('manual_verifier_dashboard', success='Registration approved.'))

@app.route('/manual-verification/reject/<int:pending_id>', methods=['POST'])
def manual_verifier_reject(pending_id):
    if not session.get('is_manual_verifier'):
        return redirect(url_for('manual_verifier_login'))
    reg = fetch_one("SELECT * FROM pending_admin_registrations WHERE id=%s", (pending_id,))
    if not reg:
        return redirect(url_for('manual_verifier_dashboard', error='Registration not found'))
    try:
        emailsent.send_otp_email(reg['admin_email'], f"Your admin registration for {reg['company_name']} was rejected. Please contact support for more information.")
    except Exception as e:
        print(f"Failed to send rejection email: {e}")
    execute("DELETE FROM pending_admin_registrations WHERE id=%s", (pending_id,))
    return redirect(url_for('manual_verifier_dashboard', success='Registration rejected.'))


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)