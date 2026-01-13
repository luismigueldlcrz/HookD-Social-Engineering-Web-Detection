# OCR Vision Module (Tasks 1–4)

## Scope
This module handles:
- Environment setup
- Image preprocessing
- OCR text extraction
- Attachment security filtering

Text normalization and NLP processing are handled by a downstream module.

---

## Requirements
- Python 3.x
- Tesseract OCR installed and accessible in PATH

Install Python dependencies:
pip install -r requirements.txt

---

## Files

### security_filter.py
Provides file-extension–based risk filtering.

Function:
check_file_extension(filename) -> "Safe" | "High Risk"

---

### preprocess.py
Preprocesses images for OCR using OpenCV:
- Grayscale
- Thresholding (OTSU)
- Noise removal

Function:
preprocess_image(image_path) -> processed image

---

### ocr.py
Extracts raw text from preprocessed images using Tesseract.

Function:
run_ocr(image_path) -> raw OCR text

---

## Output Contract
- OCR output is raw text
- Text may include OCR noise or symbols
- Downstream modules are responsible for normalization and NLP preprocessing
