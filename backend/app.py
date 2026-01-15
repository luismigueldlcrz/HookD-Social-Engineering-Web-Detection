from flask import Flask, request, render_template, redirect, url_for, flash
import joblib
import os
from werkzeug.utils import secure_filename

# --- NEW IMPORTS ---
from ocr import run_ocr
from security_filter import check_file_extension

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'phishing_detector.pkl')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- SERVICE LAYER ---

def load_model():
    """Safely loads the ML model."""
    try:
        model = joblib.load(MODEL_PATH)
        print("Model loaded successfully.")
        return model
    except Exception as e:
        print(f"CRITICAL ERROR: Could not load model. {e}")
        return None

# Load model once at startup
model = load_model()

def allowed_file(filename):
    """
    Standard allowlist check: ensure file is an allowed image format.
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_prediction(content):
    """
    Central logic for ML predictions.
    """
    if not model:
        return {'label': 'System Error', 'confidence': 0, 'css': 'secondary', 'message': 'Model not active.'}

    try:
        prediction = model.predict([content])[0]
        probs = model.predict_proba([content])[0]
        confidence = round(max(probs) * 100, 2)
        
        css_class = "danger" if prediction == "Phishing" else "success"
        
        return {
            'label': prediction,
            'confidence': confidence,
            'css': css_class,
            'content_snippet': content[:100] + "..." if len(content) > 100 else content
        }
    except Exception as e:
        return {'label': 'Error', 'confidence': 0, 'css': 'warning', 'message': f"Prediction failed: {str(e)}"}

# OCR Logic
def process_ocr(filepath):
    try:
        # This calls the function in ocr.py, which handles 
        # preprocessing (gray/threshold/denoise) and extraction.
        text = run_ocr(filepath)
        return text.strip()
    except Exception as e:
        print(f"OCR Error: {e}")
        return None

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

    result = get_prediction(text)
    return render_template('index.html', result=result, mode='text')

@app.route('/scan/url', methods=['POST'])
def scan_url():
    url = request.form.get('url_content', '').strip()
    
    if not url:
        flash("Please enter a URL to analyze.", "warning")
        return redirect(url_for('home'))

    result = get_prediction(url)
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

    # --- INTEGRATION: Security Filter ---
    # Check the file extension
    security_status = check_file_extension(file.filename)
    
    if security_status == "High Risk":
        # Block the request immediately if it matches dangerous extensions
        flash(f"SECURITY ALERT: The file '{file.filename}' is flagged as High Risk and was blocked.", "danger")
        return redirect(url_for('home'))

    if file and allowed_file(file.filename):
        # 1. Secure Save
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # 2. Extract Text (OCR)
        extracted_text = process_ocr(filepath)

        # 3. Analyze
        if extracted_text:
            result = get_prediction(extracted_text)
            return render_template('index.html', result=result, extracted_text=extracted_text, mode='image')
        else:
            flash("Could not detect any text in the image. Try a clearer image.", "warning")
            return redirect(url_for('home'))
            
    flash("Invalid file type. Please upload PNG, JPG, or JPEG.", "danger")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)