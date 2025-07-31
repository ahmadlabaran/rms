#!/usr/bin/env python
"""
Test script to verify exam officer can see submitted results
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
from accounts.models import UserRole, Result, CourseEnrollment, Course, AcademicSession

def test_exam_officer_results():
    """Test that exam officer can see submitted results"""
    print("=== TESTING EXAM OFFICER RESULT VISIBILITY ===")
    
    # Create test client
    client = Client()
    
    # Check for exam officers
    exam_officers = UserRole.objects.filter(role='EXAM_OFFICER')
    print(f"Found {exam_officers.count()} exam officers")
    
    if not exam_officers.exists():
        print("✗ No exam officers found")
        return
    
    # Get first exam officer
    exam_officer_role = exam_officers.first()
    exam_officer_user = exam_officer_role.user
    faculty = exam_officer_role.faculty
    
    print(f"Testing with: {exam_officer_user.username} - {exam_officer_user.get_full_name()}")
    print(f"Faculty: {faculty.name if faculty else 'None'}")
    
    # Check for submitted results in this faculty
    submitted_results = Result.objects.filter(
        status='SUBMITTED_TO_EXAM_OFFICER',
        enrollment__course__departments__faculty=faculty
    )
    
    print(f"\n--- Result Status Check ---")
    print(f"Results with status 'SUBMITTED_TO_EXAM_OFFICER' in faculty: {submitted_results.count()}")
    
    for result in submitted_results:
        print(f"  - Student: {result.enrollment.student.matric_number}")
        print(f"    Course: {result.enrollment.course.code}")
        print(f"    CA: {result.ca_score}, Exam: {result.exam_score}, Total: {result.total_score}")
        print(f"    Status: {result.status}")
        print(f"    Created by: {result.created_by.username if result.created_by else 'Unknown'}")
    
    # Check all results regardless of status
    all_results = Result.objects.filter(
        enrollment__course__departments__faculty=faculty
    )
    print(f"\nAll results in faculty: {all_results.count()}")
    
    status_counts = {}
    for result in all_results:
        status = result.status
        if status in status_counts:
            status_counts[status] += 1
        else:
            status_counts[status] = 1
    
    print("Result status breakdown:")
    for status, count in status_counts.items():
        print(f"  - {status}: {count}")
    
    # Login as exam officer and test dashboard
    print(f"\n--- Testing Exam Officer Dashboard ---")
    client.force_login(exam_officer_user)
    
    # Test dashboard access
    response = client.get('/api/exam-officer/')
    print(f"Dashboard status: {response.status_code}")
    
    if response.status_code == 200:
        print("✓ Dashboard accessible")
        
        # Test pending results page
        pending_response = client.get('/api/exam-officer/pending-results/')
        print(f"Pending results page status: {pending_response.status_code}")
        
        if pending_response.status_code == 200:
            print("✓ Pending results page accessible")
        else:
            print(f"✗ Pending results page failed: {pending_response.status_code}")
    else:
        print(f"✗ Dashboard failed: {response.status_code}")
    
    # Check if we need to create test data
    if submitted_results.count() == 0:
        print(f"\n--- Creating Test Result ---")
        
        # Find a course enrollment in this faculty
        enrollments = CourseEnrollment.objects.filter(
            course__departments__faculty=faculty
        )
        
        if enrollments.exists():
            enrollment = enrollments.first()
            print(f"Creating test result for: {enrollment.student.matric_number} in {enrollment.course.code}")
            
            # Create a test result
            test_result = Result.objects.create(
                enrollment=enrollment,
                ca_score=25.0,
                exam_score=65.0,
                total_score=90.0,
                grade='A',
                status='SUBMITTED_TO_EXAM_OFFICER',
                created_by=User.objects.filter(username='MrP').first()  # Lecturer who submitted
            )
            
            print(f"✓ Test result created with ID: {test_result.id}")
            print("Now the exam officer should see this result in pending results")
        else:
            print("✗ No course enrollments found in this faculty")

if __name__ == '__main__':
    test_exam_officer_results()
