from flask import Flask, request, render_template, redirect, url_for, flash
import os
import re
from werkzeug.utils import secure_filename

# --- IMPORTS ---
from ocr import run_ocr
from security_filter import check_file_extension
# Import the backend scanner logic
from backend_scanner import scan_logic 

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- ROUTES ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan/text', methods=['POST'])
def scan_text():
    text = request.form.get('text_content', '').strip()
    
    if not text:
        flash("Please enter some text to analyze.", "warning")
        return redirect(url_for('home'))

    # Text paste usually has no verified sender, so we default to Unknown
    # This forces the AI to check the content strictly.
    result = scan_logic(body=text, sender="Unknown")
    
    result['content_snippet'] = text[:100] + "..." if len(text) > 100 else text
    return render_template('index.html', result=result, mode='text')

@app.route('/scan/url', methods=['POST'])
def scan_url():
    url = request.form.get('url_content', '').strip()
    
    if not url:
        flash("Please enter a URL to analyze.", "warning")
        return redirect(url_for('home'))

    # FIX: We treat the URL as the "Sender" identity for whitelisting
    result = scan_logic(body=url, sender=url)
    
    result['content_snippet'] = url
    return render_template('index.html', result=result, mode='url')

@app.route('/scan/image', methods=['POST'])
def scan_image():
    if 'file_upload' not in request.files:
        flash("No file part", "danger")
        return redirect(url_for('home'))
        
    file = request.files['file_upload']
    
    if file.filename == '':
        flash("No selected file", "warning")
        return redirect(url_for('home'))

    # 1. Security Filter (Check extension before saving)
    security_status = check_file_extension(file.filename)
    if security_status == "High Risk":
        flash(f"SECURITY ALERT: The file '{file.filename}' was blocked.", "danger")
        return redirect(url_for('home'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # 2. Run OCR
        extracted_text = None
        try:
            extracted_text = run_ocr(filepath)
        except Exception as e:
            print(f"OCR Failed: {e}")

        # 3. Analyze Extracted Info
        if extracted_text and extracted_text.strip():
            
            # --- INTELLIGENT SENDER EXTRACTION ---
            detected_sender = "Image_OCR" # Default
            
            match = re.search(r'(?:From|Sender|Source|Via):?\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', extracted_text, re.IGNORECASE)
            
            if match:
                detected_sender = match.group(1)
                print(f"OCR successfully detected sender: {detected_sender}")
            else:
                print("OCR could not find a 'From:' address. Using default analysis.")

            # 4. Pass DETECTED sender to the scanner logic
            # If the regex found 'support@google.com', the whitelist will now Pass!
            result = scan_logic(body=extracted_text, sender=detected_sender)
            
            return render_template('index.html', result=result, extracted_text=extracted_text, mode='image')
        else:
            flash("Could not detect any text in the image.", "warning")
            return redirect(url_for('home'))
            
    flash("Invalid file type.", "danger")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)