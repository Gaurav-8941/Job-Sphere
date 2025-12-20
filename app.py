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
pending_ice_hr = {}   # <-- add this line

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
        return redirect('/login')
def require_user():
    if 'email' not in session or session.get('is_hr') or session.get('is_admin'):
        return redirect('/login')
    
# Routes
@app.route('/')
def index():
    return render_template('index.html')

#route for jobs page
@app.route('/jobs')
def jobs_page():
    job_rows = fetch_all("SELECT * FROM jobs")
    return render_template('jobs.html', jobs=job_rows)

#route for job fill page using job id
@app.route('/jobs/<int:job_id>')
def job_detail(job_id):
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

    if hr_row:
        session['is_hr'] = True
        session['is_admin'] = False
        session['email'] = hr_row["email"]
        session['username'] = hr_row["username"]

        return jsonify({"redirect": url_for('dashboard_hr')})

    # USER LOGIN
    user_row = fetch_one("""
        SELECT * FROM users
        WHERE (email = %s OR username = %s) AND password = %s
    """, (identifier, identifier, password))

    if user_row:
        session['is_hr'] = False
        session['is_admin'] = False
        session['email'] = user_row["email"]
        session['username'] = user_row["username"]
        session['user_id'] = user_row["id"]
        session['user_table'] = f"user_{user_row['id']}_activity"

        return jsonify({"redirect": url_for('dashboard_user')})

    # ADMIN LOGIN (email only)
    admin_row = fetch_one("""
        SELECT * FROM admin
        WHERE email = %s AND password = %s
    """, (identifier, password))

    if admin_row:
        session['is_admin'] = True
        session['is_hr'] = False
        session['admin_email'] = admin_row["email"]
        return jsonify({"redirect": url_for('admin_dashboard')})

    return jsonify({"error": "Invalid credentials"}), 401


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
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), 'Pending')
        """, (job_id, hr_id, user_id, name, email, phone, cover_letter, unique_name))
        
        # Insert into global applications table AND GET THE GLOBAL ID
        global_app_id = execute("""
            INSERT INTO applications (job_id, hr_id, applicant_name, email, phone, cover_letter, resume_file, date_applied, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), 'Pending')
        """, (job_id, hr_id, name, email, phone, cover_letter, unique_name))
        
        # Insert into user's private table USING SESSION USER_ID (NOT EMAIL LOOKUP)
        user_id = session['user_id']  # From authenticated session
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
    require_hr()

    hr_email = session.get('email')
    
    # Get HR information
    hr_row = fetch_one(
        "SELECT id, username, name, department FROM hr WHERE email=%s",
        (hr_email,)
    )
    
    if not hr_row:
        return redirect(url_for('login_page'))
    
    hr_id = hr_row['id']
    hr_department = hr_row['department']
    
    # Store hr_id in session for later use
    session['hr_id'] = hr_id
    
    # Count only jobs in this HR's department
    total_jobs = fetch_one(
        "SELECT COUNT(*) AS cnt FROM jobs WHERE department = %s",
        (hr_department,)
    )['cnt']

    total_applications = fetch_one("""
        SELECT COUNT(*) AS cnt
        FROM applications a
        JOIN jobs j ON a.job_id = j.id
        WHERE j.department = %s
    """, (hr_department,))['cnt']

    interviews = fetch_one("""
        SELECT COUNT(*) AS cnt
        FROM applications a
        JOIN jobs j ON a.job_id = j.id
        WHERE j.department = %s AND a.status='Interview Scheduled'
    """, (hr_department,))['cnt']

    hired = fetch_one("""
        SELECT COUNT(*) AS cnt
        FROM applications a
        JOIN jobs j ON a.job_id = j.id
        WHERE j.department = %s AND a.status='Hired'
    """, (hr_department,))['cnt']

    # Fetch latest applications for this HR's department
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
    WHERE j.department = %s
    ORDER BY a.date_applied DESC
    LIMIT 10
""", (hr_department,))

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
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        admin = fetch_one("SELECT admin_id, name, email FROM admin WHERE email = %s AND password = %s", (email, password))
        if admin:
            session['is_admin'] = True
            session['admin_id'] = admin['admin_id']
            session['admin_email'] = admin['email']
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin_login.html', error="Invalid credentials")
    return render_template('admin_login.html')

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

    #paginated query
    hr_list = fetch_all(
        f"SELECT id, name, department, email FROM hr {where_clause} LIMIT %s OFFSET %s",
        params + [per_page, offset]
    )

    # Next page availability
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
        INSERT INTO hr (username, name, department, email, password)
        VALUES (%s, %s, %s, %s, %s)
    """, (username, name, dept, email, password))


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

    # 1. Update the applications table
    execute("UPDATE applications SET status=%s, hr_id=%s WHERE id=%s",
            (new_status, hr_id, app_id))
    
    # 2. Find which user table to update
    # Get the user_id from applications table (we need to store this)
    app_data = fetch_one("SELECT user_id, email FROM applications WHERE id=%s", (app_id,))
    
    if app_data and app_data['user_id']:
        user_id = app_data['user_id']
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
    return render_template("video_call.html", app_id=app_id)


# ------------------------
# USER joins video call page
# ------------------------
@app.route("/video/user/<int:app_id>")
def video_call_user(app_id):
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

    # Deliver pending ICE from user to HR
    if app_id in pending_ice_hr:
        print(f" Sending {len(pending_ice_hr[app_id])} pending ICE candidates to HR {app_id}")
        for c in pending_ice_hr[app_id]:
            try:
                ws.send(json.dumps({"type": "ice", "ice": c}))
            except Exception as e:
                print(f"Error sending pending ICE to HR: {e}")
        del pending_ice_hr[app_id]

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
                # Relay ICE to user or store pending
                if app_id in user_sockets:
                    try:
                        user_sockets[app_id].send(json.dumps({
                            "type": "ice",
                            "ice": data["ice"]
                        }))
                    except Exception as e:
                        print(f"Error sending ICE to user: {e}")
                else:
                    pending_ice.setdefault(app_id, []).append(data["ice"])
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
        print(f" Sending {len(pending_ice[app_id])} pending ICE candidates to user {app_id}")
        for c in pending_ice[app_id]:
            try:
                ws.send(json.dumps({"type": "ice", "ice": c}))
            except Exception as e:
                print(f"Error sending pending ICE: {e}")
        del pending_ice[app_id]

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
                if app_id in hr_sockets:
                    try:
                        hr_sockets[app_id].send(json.dumps({
                            "type": "ice",
                            "ice": data["ice"]
                        }))
                    except Exception as e:
                        print(f"Error sending ICE to HR: {e}")
                else:
                    pending_ice_hr.setdefault(app_id, []).append(data["ice"])
            elif data["type"] == "ping":
                continue
    except Exception as e:
        print(f" USER WebSocket error for app_id {app_id}: {e}")
    finally:
        user_sockets.pop(app_id, None)
        print(f"USER WebSocket cleaned up for app_id: {app_id}")



@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)