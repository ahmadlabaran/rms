#!/usr/bin/env python
"""
Test script for exam officer dashboard
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
from accounts.models import UserRole, Level

def test_exam_officer_dashboard():
    """Test the exam officer dashboard functionality"""
    print("=== TESTING EXAM OFFICER DASHBOARD ===")
    
    # Create test client
    client = Client()
    
    # Check if we have any exam officers
    exam_officers = UserRole.objects.filter(role='EXAM_OFFICER')
    print(f"Found {exam_officers.count()} exam officers in the system")
    
    if not exam_officers.exists():
        print("✗ No exam officers found in the system")
        return
    
    # Get the first exam officer
    exam_officer_role = exam_officers.first()
    exam_officer_user = exam_officer_role.user
    
    print(f"Testing with exam officer: {exam_officer_user.username} - {exam_officer_user.get_full_name()}")
    print(f"Faculty: {exam_officer_role.faculty.name if exam_officer_role.faculty else 'None'}")
    
    # Login as exam officer
    client.force_login(exam_officer_user)
    
    # Test 1: Access exam officer dashboard
    print("\n--- Test 1: Access exam officer dashboard ---")
    response = client.get('/api/exam-officer/')
    print(f"Status: {response.status_code}")
    
    if response.status_code == 200:
        print("✓ Exam officer dashboard accessible")
    elif response.status_code == 302:
        print(f"✓ Redirected to: {response.url}")
    else:
        print(f"✗ Dashboard access failed: {response.status_code}")
        if hasattr(response, 'content'):
            print(f"Error content: {response.content.decode()[:200]}")
        return
    
    # Test 2: Access dashboard with different level parameters
    print("\n--- Test 2: Test level parameter handling ---")
    test_levels = ['100', '200', '300', '400', '999']  # Include invalid level
    
    for level_param in test_levels:
        response = client.get(f'/api/exam-officer/?level={level_param}')
        print(f"Level {level_param}: Status {response.status_code}")
        
        if response.status_code != 200:
            print(f"  ✗ Failed to load dashboard with level {level_param}")
        else:
            print(f"  ✓ Successfully loaded dashboard with level {level_param}")
    
    # Test 3: Verify Level objects are working correctly
    print("\n--- Test 3: Verify Level objects ---")
    levels = Level.objects.all().order_by('numeric_value')
    print(f"Total levels in system: {levels.count()}")
    
    for level in levels:
        print(f"  - {level.name} (numeric_value: {level.numeric_value})")
    
    # Test the specific query that was failing
    try:
        level_100 = Level.objects.filter(numeric_value=100).first()
        if level_100:
            print(f"✓ Level 100 query works: {level_100.name}")
        else:
            print("✗ No Level with numeric_value=100 found")
    except Exception as e:
        print(f"✗ Level 100 query failed: {e}")

if __name__ == '__main__':
    test_exam_officer_dashboard()
