#!/usr/bin/env python
import os
import sys
import django
from django.conf import settings

# Add the project directory to the Python path
sys.path.append('C:\\Users\\Public\\Documents\\RMS')

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'RMS.settings')
django.setup()

from django.test import RequestFactory, Client
from django.contrib.auth.models import User
from accounts.models import UserRole, Course, AcademicSession, CourseEnrollment, CourseAssignment
from accounts.views import lecturer_enter_results

def test_result_submission():
    print("=== Testing Result Submission System ===")
    
    # Create a test client
    client = Client()
    
    # Try to get the lecturer user
    try:
        lecturer_user = User.objects.get(username='MrP')
        print(f"Found lecturer: {lecturer_user.username} - {lecturer_user.get_full_name()}")
        
        # Check if user has lecturer role
        lecturer_role = UserRole.objects.filter(user=lecturer_user, role='LECTURER').first()
        if lecturer_role:
            print(f"User has LECTURER role in faculty: {lecturer_role.faculty.name if lecturer_role.faculty else 'None'}")
        else:
            print("User does not have LECTURER role")
            return
        
        # Login as the lecturer
        login_success = client.login(username='MrP', password='password')  # Try common password
        if not login_success:
            # Try without password (if user has no password set)
            client.force_login(lecturer_user)
            print("Force logged in as lecturer")
        else:
            print("Successfully logged in as lecturer")
        
        # Test GET request first
        print("\n--- Testing GET request ---")
        get_response = client.get('/api/lecturer/enter-results/?course_id=1&session_id=6')
        print(f"GET response status: {get_response.status_code}")
        
        if get_response.status_code == 200:
            print("GET request successful")
            
            # Test POST request with sample data
            print("\n--- Testing POST request ---")
            post_data = {
                'course_id': '1',
                'session_id': '6',
                'ca_score_1': '25',
                'exam_score_1': '65',
            }
            
            post_response = client.post('/api/lecturer/enter-results/?course_id=1&session_id=6', post_data)
            print(f"POST response status: {post_response.status_code}")
            
            if post_response.status_code == 302:  # Redirect
                print(f"POST request redirected to: {post_response.url}")
            elif post_response.status_code == 200:
                print("POST request successful")
                # Check if there are any messages
                if hasattr(post_response, 'context') and post_response.context:
                    messages = list(post_response.context.get('messages', []))
                    if messages:
                        for message in messages:
                            print(f"Message: {message}")
            else:
                print(f"POST request failed with status: {post_response.status_code}")
                print(f"Response content: {post_response.content.decode()[:500]}")
        
        else:
            print(f"GET request failed with status: {get_response.status_code}")
            print(f"Response content: {get_response.content.decode()[:500]}")
            
    except User.DoesNotExist:
        print("Lecturer user 'MrP' does not exist")
        
        # List all users
        users = User.objects.all()
        print(f"Available users: {[u.username for u in users]}")
        
        # List all lecturer roles
        lecturer_roles = UserRole.objects.filter(role='LECTURER')
        print(f"Users with LECTURER role: {[lr.user.username for lr in lecturer_roles]}")

if __name__ == '__main__':
    test_result_submission()
