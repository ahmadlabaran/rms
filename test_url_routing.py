#!/usr/bin/env python
"""
Test script for URL routing and authentication redirects
"""
import os
import sys

# Ensure we're in the correct directory
project_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(project_dir)

# Add the project directory to the Python path
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'RMS.settings')

# Import Django and setup
import django
django.setup()

# Fix ALLOWED_HOSTS for testing
from django.conf import settings
if 'testserver' not in settings.ALLOWED_HOSTS:
    settings.ALLOWED_HOSTS.extend(['127.0.0.1', 'localhost', 'testserver'])

from django.test import Client
from django.contrib.auth.models import User
from accounts.models import UserRole

def test_url_routing():
    """Test URL routing and authentication redirects"""
    print("=== TESTING URL ROUTING AND AUTHENTICATION ===")
    
    # Create test client
    client = Client()
    
    # Test 1: Access protected page without login
    print("\n--- Test 1: Access protected page without login ---")
    response = client.get('/api/lecturer/enter-results/?course_id=1&session_id=6')
    print(f"Status: {response.status_code}")
    
    if response.status_code == 302:  # Redirect
        print(f"✓ Redirected to: {response.url}")
        if '/api/login/' in response.url:
            print("✓ Correct login URL redirect")
        else:
            print(f"✗ Incorrect login URL redirect: {response.url}")
    else:
        print(f"✗ Expected redirect (302), got {response.status_code}")
    
    # Test 2: Check login page accessibility
    print("\n--- Test 2: Check login page accessibility ---")
    login_response = client.get('/api/login/')
    print(f"Login page status: {login_response.status_code}")
    
    if login_response.status_code == 200:
        print("✓ Login page accessible")
    else:
        print(f"✗ Login page not accessible: {login_response.status_code}")
    
    # Test 3: Test with authenticated user
    print("\n--- Test 3: Test with authenticated user ---")
    try:
        lecturer_user = User.objects.get(username='MrP')
        client.force_login(lecturer_user)
        
        auth_response = client.get('/api/lecturer/enter-results/?course_id=1&session_id=6')
        print(f"Authenticated access status: {auth_response.status_code}")
        
        if auth_response.status_code == 200:
            print("✓ Authenticated user can access protected page")
        else:
            print(f"✗ Authenticated user cannot access page: {auth_response.status_code}")
            
    except User.DoesNotExist:
        print("✗ Test user 'MrP' not found")
    
    # Test 4: Check Django settings
    print("\n--- Test 4: Check Django settings ---")
    print(f"LOGIN_URL: {getattr(settings, 'LOGIN_URL', 'Not set')}")
    print(f"LOGIN_REDIRECT_URL: {getattr(settings, 'LOGIN_REDIRECT_URL', 'Not set')}")
    print(f"LOGOUT_REDIRECT_URL: {getattr(settings, 'LOGOUT_REDIRECT_URL', 'Not set')}")
    
    # Test 5: Check URL patterns
    print("\n--- Test 5: Check URL patterns ---")
    from django.urls import reverse
    try:
        login_url = reverse('web_login')
        print(f"✓ Login URL resolved: {login_url}")
    except:
        print("✗ Could not resolve login URL")
    
    try:
        lecturer_url = reverse('lecturer_enter_results')
        print(f"✓ Lecturer results URL resolved: {lecturer_url}")
    except:
        print("✗ Could not resolve lecturer results URL")

if __name__ == '__main__':
    test_url_routing()
