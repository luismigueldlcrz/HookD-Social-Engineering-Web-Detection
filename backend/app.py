from flask import Flask, request, render_template
import joblib
import pytesseract
from PIL import Image
import os

app = Flask(__name__)

# --- CONFIGURATION ---
UPLOAD_FOLDER = 'static/uploads'
MODEL_PATH = 'models/phishing_detector.pkl'

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- WINDOWS USERS ONLY: UNCOMMENT THIS LINE IF TESSERACT FAILS ---
# pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# --- LOAD THE BRAIN ---
model = None
try:
    model = joblib.load(MODEL_PATH)
    print("Model loaded successfully.")
except Exception as e:
    print(f"Error loading model: {e}")
    print("Did you run 'train_model.py' first?")

# --- HELPER FUNCTION ---
def analyze_content(text):
    """Takes text, returns a dictionary with prediction results."""
    if not model:
        return {'label': 'Error', 'confidence': 0, 'css': 'secondary', 'message': 'Model not loaded'}
    
    # 1. Predict
    prediction = model.predict([text])[0]
    
    # 2. Get Confidence Score
    probs = model.predict_proba([text])[0]
    confidence = max(probs) * 100
    
    # 3. Determine Color (Red for Phishing, Green for Safe)
    css_class = "danger" if prediction == "Phishing" else "success"
    
    return {
        'label': prediction,
        'confidence': round(confidence, 2),
        'css': css_class
    }

# --- ROUTES ---
@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    extracted_text = None
    
    if request.method == 'POST':
        
        # SCENARIO 1: TEXT ANALYSIS
        if 'text_content' in request.form and request.form['text_content'].strip():
            text = request.form['text_content']
            result = analyze_content(text)

        # SCENARIO 2: URL ANALYSIS
        elif 'url_content' in request.form and request.form['url_content'].strip():
            url = request.form['url_content']
            # We treat the URL as text for analysis
            result = analyze_content(url)

        # SCENARIO 3: IMAGE ANALYSIS (OCR)
        elif 'file_upload' in request.files:
            file = request.files['file_upload']
            if file.filename != '':
                # Save temp file
                filepath = os.path.join(UPLOAD_FOLDER, file.filename)
                file.save(filepath)
                
                try:
                    # Run OCR
                    extracted_text = pytesseract.image_to_string(Image.open(filepath))
                    
                    if extracted_text.strip():
                        result = analyze_content(extracted_text)
                    else:
                        result = {'label': 'Error', 'confidence': 0, 'css': 'warning', 'message': "No text found in image."}
                        
                except Exception as e:
                    result = {'label': 'Error', 'confidence': 0, 'css': 'danger', 'message': str(e)}

    return render_template('index.html', result=result, extracted_text=extracted_text) # To be replaced by the bootstrap frontend

if __name__ == '__main__':
    app.run(debug=True)