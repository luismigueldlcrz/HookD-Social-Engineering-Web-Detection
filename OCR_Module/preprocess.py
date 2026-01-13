import cv2


def load_image(path):
    """
    Step 1: Load the image from disk
    """
    image = cv2.imread(path)

    if image is None:
        raise ValueError("Image not found or path is incorrect")

    return image


def to_grayscale(image):
    """
    Step 2: Convert image to grayscale
    """
    return cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)


def apply_threshold(gray_image):
    """
    Step 3: Apply thresholding to increase contrast
    Uses OTSU's method to automatically choose threshold
    """
    _, thresh = cv2.threshold(
        gray_image,
        0,
        255,
        cv2.THRESH_BINARY + cv2.THRESH_OTSU
    )
    return thresh


def remove_noise(thresh_image):
    """
    Step 4: Remove noise using morphological operations
    """
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (1, 1))
    cleaned = cv2.morphologyEx(
        thresh_image,
        cv2.MORPH_OPEN,
        kernel
    )
    return cleaned


def preprocess_image(image_path):
    """
    Full preprocessing pipeline
    """
    image = load_image(image_path)
    gray = to_grayscale(image)
    thresh = apply_threshold(gray)
    clean = remove_noise(thresh)
    return clean


