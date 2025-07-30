#!/usr/bin/env python
"""
Test script for lecturer result submission system
"""
import os
import sys
import django
from django.conf import settings

# Add the project directory to the Python path
sys.path.append('C:\\Users\\Public\\Documents\\RMS')

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'rms.settings')
django.setup()

from django.test import Client
from django.contrib.auth.models import User
from accounts.models import UserRole, Course, AcademicSession, CourseEnrollment, CourseAssignment, Result

def test_lecturer_result_submission():
    """Test the lecturer result submission functionality"""
    print("=== TESTING LECTURER RESULT SUBMISSION ===")
    
    # Create test client
    client = Client()
    
    try:
        # Get the lecturer user
        lecturer_user = User.objects.get(username='MrP')
        print(f"✓ Found lecturer: {lecturer_user.username}")
        
        # Force login (bypass password)
        client.force_login(lecturer_user)
        print("✓ Logged in as lecturer")
        
        # Get course and session
        course = Course.objects.get(id=1)
        session = AcademicSession.objects.get(id=6)
        print(f"✓ Course: {course.code} - {course.title}")
        print(f"✓ Session: {session.name}")
        
        # Check enrollment
        enrollment = CourseEnrollment.objects.filter(course=course, session=session).first()
        if enrollment:
            print(f"✓ Found enrollment: {enrollment.student.matric_number}")
        else:
            print("✗ No enrollment found")
            return
        
        # Test GET request
        print("\n--- Testing GET Request ---")
        get_url = f'/api/lecturer/enter-results/?course_id={course.id}&session_id={session.id}'
        get_response = client.get(get_url)
        print(f"GET {get_url}")
        print(f"Status: {get_response.status_code}")
        
        if get_response.status_code != 200:
            print(f"✗ GET request failed: {get_response.status_code}")
            if hasattr(get_response, 'content'):
                print(f"Content: {get_response.content.decode()[:200]}")
            return
        
        # Test POST request with valid data
        print("\n--- Testing POST Request ---")
        post_data = {
            'course_id': str(course.id),
            'session_id': str(session.id),
            f'ca_score_{enrollment.id}': '25',
            f'exam_score_{enrollment.id}': '65',
        }
        
        print(f"POST data: {post_data}")
        post_response = client.post(get_url, post_data)
        print(f"Status: {post_response.status_code}")
        
        if post_response.status_code == 302:  # Redirect
            print(f"✓ Redirected to: {post_response.url}")
            
            # Check if result was created
            result = Result.objects.filter(enrollment=enrollment).first()
            if result:
                print(f"✓ Result created: CA={result.ca_score}, Exam={result.exam_score}, Total={result.total_score}, Grade={result.grade}")
                print(f"✓ Status: {result.status}")
            else:
                print("✗ No result was created")
                
        elif post_response.status_code == 200:
            print("✓ POST request successful (200)")
            # Check response content for messages
            content = post_response.content.decode()
            if 'error' in content.lower():
                print(f"✗ Error in response: {content[:200]}")
            else:
                print("✓ No errors in response")
        else:
            print(f"✗ POST request failed: {post_response.status_code}")
            if hasattr(post_response, 'content'):
                print(f"Content: {post_response.content.decode()[:200]}")
        
        # Test draft saving
        print("\n--- Testing Draft Saving ---")
        draft_data = post_data.copy()
        draft_data['save_as_draft'] = 'true'
        
        draft_response = client.post(get_url, draft_data)
        print(f"Draft Status: {draft_response.status_code}")
        
        if draft_response.status_code == 200:
            try:
                import json
                response_data = json.loads(draft_response.content.decode())
                print(f"Draft Response: {response_data}")
                if response_data.get('success'):
                    print("✓ Draft saved successfully")
                else:
                    print(f"✗ Draft save failed: {response_data.get('error')}")
            except:
                print("✗ Could not parse draft response as JSON")
        
    except User.DoesNotExist:
        print("✗ Lecturer user 'MrP' not found")
        users = User.objects.all()
        print(f"Available users: {[u.username for u in users]}")
    except Course.DoesNotExist:
        print("✗ Course ID 1 not found")
    except AcademicSession.DoesNotExist:
        print("✗ Session ID 6 not found")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_lecturer_result_submission()
