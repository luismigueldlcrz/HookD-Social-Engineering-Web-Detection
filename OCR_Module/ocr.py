import pytesseract
from preprocess import preprocess_image


def extract_text(image):
    text = pytesseract.image_to_string(
        image,
        config="--psm 6"
    )
    return text


def run_ocr(image_path):
    processed_image = preprocess_image(image_path)
    text = extract_text(processed_image)
    return text
