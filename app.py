from flask import Flask, request, render_template, redirect, url_for, flash, session
from functools import wraps
import os
import re
from werkzeug.utils import secure_filename
from supabase import Client

# --- CUSTOM MODULE IMPORTS ---
from ocr import run_ocr
from security_filter import check_file_extension
from backend_scanner import scan_logic 
from database import log_scan, create_user_profile, get_user_profile # <--- Imported new functions

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# --- SUPABASE CONFIG ---
SUPABASE_URL = "https://sutccxmhqstoatpublqp.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN1dGNjeG1ocXN0b2F0cHVibHFwIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2ODQ5MTgxNywiZXhwIjoyMDg0MDY3ODE3fQ.4iei3BHbae-kdHPV1sUoZY7NKzniZj4H8OrJeYoeg7E"
supabase = Client(SUPABASE_URL, SUPABASE_KEY)

# --- UPLOAD CONFIG ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- AUTH DECORATOR ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- AUTH ROUTES ---

@app.route('/')
def root():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            # 1. Authenticate against auth.users
            response = supabase.auth.sign_in_with_password({"email": email, "password": password})
            user_id = response.user.id
            
            # 2. Fetch details from 'profiles' table
            profile = get_user_profile(user_id)
            display_name = profile.get('display_name', email.split('@')[0]) # Fallback to email prefix

            # 3. Store in Session
            session['user'] = {
                'id': user_id,
                'email': response.user.email,
                'name': display_name
            }
            
            flash(f"Welcome back, {display_name}!", "success")
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f"Login failed: {str(e)}", "danger")
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        # Get extra profile fields
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        display_name = request.form.get('display_name')

        try:
            # 1. Create Auth User
            response = supabase.auth.sign_up({"email": email, "password": password})
            
            if response.user:
                # 2. Create Profile Entry
                # We use the ID from the new auth user to link the profile
                create_user_profile(response.user.id, first_name, last_name, display_name)
                
                flash("Account created successfully! Please log in.", "success")
                return redirect(url_for('login'))
                
        except Exception as e:
            flash(f"Signup failed: {str(e)}", "danger")
            
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

# --- DASHBOARD & SCAN ROUTES ---

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=session['user'])

@app.route('/scan/text', methods=['POST'])
@login_required
def scan_text():
    text = request.form.get('text_content', '').strip()
    if not text:
        flash("Please enter text.", "warning"); return redirect(url_for('dashboard'))

    result = scan_logic(body=text, sender="Unknown")
    log_scan("text", result, sender="Unknown", content=text, user_id=session['user']['id'])
    
    result['content_snippet'] = text[:100] + "..."
    return render_template('dashboard.html', result=result, mode='text', user=session['user'])

@app.route('/scan/url', methods=['POST'])
@login_required
def scan_url():
    url = request.form.get('url_content', '').strip()
    if not url:
        flash("Please enter a URL.", "warning"); return redirect(url_for('dashboard'))

    result = scan_logic(body=url, sender=url)
    log_scan("url", result, sender=url, content=url, user_id=session['user']['id'])

    result['content_snippet'] = url
    return render_template('dashboard.html', result=result, mode='url', user=session['user'])

@app.route('/scan/image', methods=['POST'])
@login_required
def scan_image():
    if 'file_upload' not in request.files: return redirect(url_for('dashboard'))
    file = request.files['file_upload']
    if file.filename == '': return redirect(url_for('dashboard'))

    if check_file_extension(file.filename) == "High Risk":
        flash("File blocked.", "danger"); return redirect(url_for('dashboard'))

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    extracted_text = run_ocr(filepath)
    if extracted_text and extracted_text.strip():
        match = re.search(r'(?:From|Sender):?\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', extracted_text, re.IGNORECASE)
        detected_sender = match.group(1) if match else "Image_OCR"

        result = scan_logic(body=extracted_text, sender=detected_sender)
        log_scan("image", result, sender=detected_sender, content=extracted_text, user_id=session['user']['id'])
        
        return render_template('dashboard.html', result=result, extracted_text=extracted_text, mode='image', user=session['user'])
    else:
        flash("No text detected.", "warning")
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)