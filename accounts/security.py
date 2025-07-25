# Simple security utilities for RMS
import re
import html
from django.contrib.auth.hashers import make_password, check_password

def sanitize_input(text):
    """Basic input sanitization"""
    if not text:
        return text
    
    # Remove HTML tags and escape special characters
    text = html.escape(text.strip())
    
    # Remove potentially dangerous characters
    dangerous_chars = ['<', '>', '"', "'", '&', ';']
    for char in dangerous_chars:
        text = text.replace(char, '')
    
    return text

def validate_email(email):
    """Simple email validation"""
    if not email:
        return False
    
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

def validate_username(username):
    """Simple username validation"""
    if not username:
        return False
    
    # Only allow letters, numbers, dots, and underscores
    username_regex = r'^[a-zA-Z0-9._]+$'
    return re.match(username_regex, username) is not None

def validate_matric_number(matric_number):
    """Simple matric number validation for format like 22A/UE/BICT/10016"""
    if not matric_number:
        return False

    # Format: YYA/UE/DEPT/NNNNN (e.g., 22A/UE/BICT/10016)
    matric_regex = r'^[0-9]{2}[A-Z]/[A-Z]{2}/[A-Z]{3,5}/[0-9]{4,6}$'
    return re.match(matric_regex, matric_number) is not None

def validate_name(name):
    """Simple name validation"""
    if not name:
        return False
    
    # Only allow letters, spaces, apostrophes, and hyphens
    name_regex = r"^[a-zA-Z\s'-]+$"
    return re.match(name_regex, name) is not None

def secure_password_hash(password):
    """Ensure password is properly hashed"""
    # Django's create_user already handles this, but this is for extra security
    return make_password(password)

def verify_password(password, hashed_password):
    """Verify password against hash"""
    return check_password(password, hashed_password)

# Basic security headers
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
}

class BasicSecurityMiddleware:
    """Simple security middleware for basic protection"""
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Add basic security headers
        for header, value in SECURITY_HEADERS.items():
            response[header] = value
        
        return response
