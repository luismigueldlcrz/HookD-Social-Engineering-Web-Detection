import os

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".scr",
    ".js",
    ".vbs",
    ".ps1",
    ".msi"
}


def check_file_extension(filename):
    """
    Checks if a file extension is considered dangerous
    """
    _, ext = os.path.splitext(filename.lower())

    if ext in DANGEROUS_EXTENSIONS:
        return "High Risk"

    return "Safe"

