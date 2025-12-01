from flask import Flask, render_template, request, jsonify, redirect, url_for, abort, session, send_file,send_from_directory
from flask_sock import Sock
import os
from werkzeug.utils import secure_filename
from datetime import datetime
import json
import mysql.connector
from mysql.connector import pooling

#Video call stuff
app= Flask(__name__)
sock = Sock(app)
user_sockets = {}
hr_sockets = {}
pending_calls = {}


#Flask path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

# If the preferred path doesn't contain templates/static,
# fall back to current directory so Flask can actually find templates/static.
if not os.path.isdir(TEMPLATES_DIR):
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '.'))
    TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
    STATIC_DIR = os.path.join(BASE_DIR, 'static')

app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
app.config['SECRET_KEY'] = 'your-very-secret-key-that-should-be-random'

#upload files
app.config['UPLOAD_FOLDER'] = os.path.join(STATIC_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'pdf'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#MYSQL Connection Pool
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

@app.route('/apply', methods=['POST'])
@app.route('/api/apply', methods=['POST'])
def apply_job():
    try:
        job_id = request.form.get('job_id')
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        cover_letter = request.form.get('cover_letter')

        # Upload resume
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

        # INSERT INTO DATABASE
        execute("""
            INSERT INTO applications (job_id, applicant_name, email, phone, cover_letter, resume_file)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (job_id, name, email, phone, cover_letter, unique_name))

        return jsonify({'message': 'Application submitted successfully!'})

    except Exception as e:
        print("Error in apply_job:", e)
        return jsonify({'error': str(e)}), 500

@app.route('/dashboard/hr')
def dashboard_hr():
    if not session.get('is_hr'):
        return redirect(url_for('login_page'))

    # Fetch job count and application count
    job_rows = fetch_all("SELECT COUNT(*) AS total FROM jobs")
    application_rows = fetch_all("SELECT COUNT(*) AS total FROM applications")

    dashboard_data = {
        'total_openings': job_rows[0]['total'],
        'total_applications': application_rows[0]['total'],
        'interviews': 45,
        'hired': 8
    }

    # Fetch latest applications from DB
    applications = fetch_all("""
        SELECT a.*, j.title AS job_title, j.department
        FROM applications a
        JOIN jobs j ON a.job_id = j.id
        ORDER BY a.date_applied DESC
        LIMIT 10
    """)

    return render_template('dashboard_hr.html',
                           data=dashboard_data,
                           applications=applications,
                           user_email=session.get('email'))

#Hr jobs route

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

    execute("UPDATE applications SET status = %s WHERE id = %s", (new_status, app_id))

    return redirect(url_for('dashboard_hr'))


#User Dashboard
@app.route('/dashboard/user')
def dashboard_user():
    if 'email' not in session or session.get('is_hr'):
        return redirect(url_for('login_page'))

    user_email = session['email']

    user_apps = fetch_all("""
        SELECT applications.id AS app_id,
               applications.status,
               applications.resume_file,
               jobs.title,
               jobs.department
        FROM applications
        JOIN jobs ON applications.job_id = jobs.id
        WHERE applications.email = %s
        ORDER BY applications.id DESC
    """, (user_email,))

    return render_template("dashboard_user.html",
                           applications=user_apps,
                           user_email=user_email)

#Video call stuff
@app.route('/video/<int:app_id>')
def video_call(app_id):
    if not session.get('is_hr'):
        return redirect(url_for('login_page'))

    app_data = fetch_one("SELECT * FROM applications WHERE id = %s", (app_id,))
    if not app_data:
        return "Application not found", 404

    return render_template('video_call.html', app=app_data)

@sock.route('/ws/hr/<int:app_id>')
def hr_socket(ws, app_id):
    hr_sockets[app_id] = ws

    # inform user that HR started the call
    if app_id in user_sockets:
        try:
            user_sockets[app_id].send(json.dumps({"type": "call_start"}))
        except:
            pass

    while True:
        data = ws.receive()
        if not data:
            break

        # Forward HR's OFFER or ICE to user
        if app_id in user_sockets:
            try:
                user_sockets[app_id].send(data)
            except:
                pass

@sock.route('/ws/user/<int:app_id>')
def user_socket(ws, app_id):
    user_sockets[app_id] = ws

    while True:
        data = ws.receive()
        if not data:
            break

        # Forward user's ANSWER or ICE to HR
        if app_id in hr_sockets:
            try:
                hr_sockets[app_id].send(data)
            except:
                pass

#Video call join
@app.route("/interview/<int:application_id>")
def interview_page(application_id):
    return render_template("video_join.html", application_id=application_id)

@app.route('/video/user/<int:app_id>')
def video_user(app_id):
    return render_template("video_call_user.html", app_id=app_id)

@app.route('/video-call/start/<int:app_id>')
def start_video_call(app_id):
    return render_template("video_call.html", app_id=app_id)





@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))


# Run
if __name__ == '__main__':
    app.run(debug=True)
