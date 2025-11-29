from flask import Flask, render_template, request, jsonify, redirect, url_for, abort, session
import os
from werkzeug.utils import secure_filename
from datetime import datetime
import json
import mysql.connector
from mysql.connector import pooling

# -------------------------------
# Paths (keeps your requested pattern but safe fallback)
# -------------------------------
# Preferred (keeps your original pattern)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

# If the preferred path doesn't contain templates (common when app.py is inside backend/),
# fall back to current directory so Flask can actually find templates/static.
if not os.path.isdir(TEMPLATES_DIR):
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '.'))
    TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
    STATIC_DIR = os.path.join(BASE_DIR, 'static')

app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
app.config['SECRET_KEY'] = 'your-very-secret-key-that-should-be-random'

# -------------------------------
# File upload config (unchanged)
# -------------------------------
app.config['UPLOAD_FOLDER'] = os.path.join(STATIC_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'pdf'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# -------------------------------
# MySQL Connection Pool
# -------------------------------
# Install dependency: pip install mysql-connector-python
#
# Edit the db_config dict below to match your local MySQL credentials.
db_config = {
    "user": "root",
    "password": "root",
    "host": "127.0.0.1",
    "database": "hr_portal",
    "raise_on_warnings": True,
    "autocommit": True
}

# Create a small connection pool
try:
    pool = mysql.connector.pooling.MySQLConnectionPool(pool_name="job_sphere_pool",
                                                       pool_size=5,
                                                       **db_config)
except Exception as e:
    # If pool creation fails, print error (server will still run but DB calls will fail)
    print("MySQL pool creation error:", e)
    pool = None

def get_connection():
    if pool:
        return pool.get_connection()
    else:
        # fallback single connection (less ideal)
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

# -------------------------------
# Mock data (kept for placeholders; DB will be used for auth)
# -------------------------------
jobs = [
    {'id': 1, 'title': 'Senior Software Engineer', 'department': 'IT', 'location': 'Remote',
     'experience': '5+ years', 'skills': ['Python', 'Flask'],
     'description': 'Develop scalable systems.'},
    {'id': 2, 'title': 'Marketing Manager', 'department': 'Marketing', 'location': 'NY',
     'experience': '3+ years', 'skills': ['SEO'],
     'description': 'Lead marketing campaigns.'}
]

# If you want to seed applications from DB later, replace with DB queries.
applications = [
    {'id': 101, 'job_title': 'Senior Software Engineer', 'applicant_name': 'Alice Johnson',
     'department': 'IT', 'status': 'Interview Scheduled', 'date_applied': 'Oct 15, 2025',
     'resume_file': 'alice_resume.pdf'},
    {'id': 102, 'job_title': 'Marketing Manager', 'applicant_name': 'Bob Williams',
     'department': 'Marketing', 'status': 'Under Review', 'date_applied': 'Oct 14, 2025',
     'resume_file': 'bob_resume.pdf'}
]

# -------------------------------
# Routes
# -------------------------------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/jobs')
def jobs_page():
    job_rows = fetch_all("SELECT * FROM jobs")
    return render_template('jobs.html', jobs=job_rows)

@app.route('/jobs/<int:job_id>')
def job_detail(job_id):
    job = fetch_one("SELECT * FROM jobs WHERE id = %s", (job_id,))
    if not job:
        abort(404)
    return render_template('job-detail.html', job=job)

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

# This is the login API used by the login.html client-side script.
# It accepts JSON (fetch from login.html) or regular form post for flexibility.

@app.route('/api/login', methods=['POST'])
def login():
    # Accept JSON (fetch) or form-encoded
    data = request.get_json(silent=True) or request.form
    email = (data.get('email') or '').strip()
    password = (data.get('password') or '').strip()

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    # 1) Check HR table
    hr_row = None
    try:
        hr_row = fetch_one("SELECT * FROM hr WHERE email = %s AND password = %s", (email, password))
    except Exception as e:
        print("DB error during HR lookup:", e)
        return jsonify({'error': 'DB error during auth'}), 500

    if hr_row:
        session['is_hr'] = True
        session['email'] = email
        return jsonify({'redirect': url_for('dashboard_hr')})

    # 2) Check users table (regular user)
    user_row = None
    try:
        user_row = fetch_one("SELECT * FROM users WHERE email = %s AND password = %s", (email, password))
    except Exception as e:
        print("DB error during user lookup:", e)
        return jsonify({'error': 'DB error during auth'}), 500

    if user_row:
        session['is_hr'] = False
        session['email'] = email
        return jsonify({'redirect': url_for('dashboard_user')})

    # No match
    return jsonify({'error': 'Invalid credentials'}), 401

# Backwards-compatible route name used in job-detail.html form action
@app.route('/apply', methods=['POST'])
@app.route('/api/apply', methods=['POST'])
def apply_job():
    try:
        job_id = request.form.get('job_id')
        if not job_id:
            return jsonify({'error': 'Job ID not specified'}), 400

        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        cover_letter = request.form.get('cover_letter')

        if 'resume' not in request.files:
            return jsonify({'error': 'No resume uploaded'}), 400

        file = request.files['resume']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Only PDF allowed.'}), 400

        filename = secure_filename(file.filename)
        unique_name = f"{int(datetime.now().timestamp())}_{filename}"
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
        file.save(save_path)

        # In production, save application data to DB. For now we print and return success.
        print("Application saved:", {
            "job_id": job_id, "name": name, "email": email, "phone": phone,
            "cover_letter": cover_letter, "resume_file": unique_name
        })

        return jsonify({'message': 'Application submitted successfully!'}), 200

    except Exception as e:
        print("Error in apply_job:", e)
        return jsonify({'error': str(e)}), 500


@app.route('/dashboard/hr')
def dashboard_hr():
    # Require HR session
    if not session.get('is_hr'):
        return redirect(url_for('login_page'))

    # Create dashboard data (you can replace with DB-driven counts)
    dashboard_data = {
        'total_openings': len(jobs),
        'total_applications': len(applications),
        'interviews': 45,
        'hired': 8
    }

    return render_template('dashboard_hr.html',
                           data=dashboard_data,
                           applications=applications,
                           user_email=session.get('email'))


# -------------------------------
# HR JOB ROUTES (FIXED & CLEAN)
# -------------------------------

@app.route('/hr/jobs/add')
def hr_add_job():
    if not session.get('is_hr'):
        return redirect(url_for('login_page'))
    return render_template('hr_add_job.html')


@app.route('/hr/jobs/add', methods=['POST'])
def hr_add_job_post():
    if not session.get('is_hr'):
        return redirect(url_for('login_page'))

    title = request.form['title']
    department = request.form['department']
    location = request.form['location']
    experience = request.form['experience']
    skills = request.form['skills']
    description = request.form['description']
    start_date = request.form['start_date']
    end_date = request.form['end_date']

    execute("""
        INSERT INTO jobs (title, department, location, experience, skills, description, hiring_start, hiring_end)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (title, department, location, experience, skills, description, start_date, end_date))

    return redirect(url_for('hr_jobs_manage'))


# MANAGE JOBS (LIST + DELETE BUTTON)
@app.route('/hr/jobs/manage')
def hr_jobs_manage():
    if not session.get('is_hr'):
        return redirect(url_for('login_page'))

    job_rows = fetch_all("SELECT * FROM jobs ORDER BY id DESC")
    return render_template('hr_jobs_manage.html', jobs=job_rows)


# EDIT JOB PAGE
@app.route('/hr/jobs/edit/<int:job_id>')
def hr_edit_job(job_id):
    if not session.get('is_hr'):
        return redirect(url_for('login_page'))

    job = fetch_one("SELECT * FROM jobs WHERE id = %s", (job_id,))
    return render_template('hr_edit_job.html', job=job)


# EDIT JOB POST
@app.route('/hr/jobs/edit/<int:job_id>', methods=['POST'])
def hr_edit_job_post(job_id):
    if not session.get('is_hr'):
        return redirect(url_for('login_page'))

    title = request.form['title']
    department = request.form['department']
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
        WHERE id=%s
    """, (title, department, location, experience, skills, description, start_date, end_date, job_id))

    return redirect(url_for('hr_jobs_manage'))


# DELETE JOB
@app.route('/hr/jobs/delete/<int:job_id>')
def hr_delete_job(job_id):
    if not session.get('is_hr'):
        return redirect(url_for('login_page'))

    execute("DELETE FROM jobs WHERE id = %s", (job_id,))
    return redirect(url_for('hr_jobs_manage'))


@app.route('/dashboard/user')
def dashboard_user():
    # Simple user dashboard placeholder - requires logged in user (non-HR)
    if 'email' not in session:
        return redirect(url_for('login_page'))
    return render_template('dashboard_dept.html', user_email=session.get('email'))

@app.route('/dashboard/dept')
def dashboard_dept():
    return render_template('dashboard_dept.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Custom 404
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

# Run
if __name__ == '__main__':
    app.run(debug=True)
