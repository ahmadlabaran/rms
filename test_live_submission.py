#!/usr/bin/env python
"""
Test live form submission to see what's happening
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

from accounts.models import CourseEnrollment, Course, AcademicSession, Result

def test_live_submission():
    print("=== TESTING LIVE FORM SUBMISSION ===")
    
    # Get current state
    course = Course.objects.first()
    session = AcademicSession.objects.filter(is_active=True).first()
    
    if not course or not session:
        print("❌ No course or session found")
        return
    
    print(f"Course: {course.code} - {course.title}")
    print(f"Session: {session.name}")
    
    # Get enrollments
    enrollments = CourseEnrollment.objects.filter(course=course, session=session)
    print(f"Enrollments: {enrollments.count()}")
    
    for enrollment in enrollments:
        print(f"  ID: {enrollment.id}, Student: {enrollment.student.matric_number}")
        
        # Check if result exists
        try:
            result = Result.objects.get(enrollment=enrollment)
            print(f"    Has result: YES - CA: {result.ca_score}, Exam: {result.exam_score}, Status: {result.status}")
        except Result.DoesNotExist:
            print(f"    Has result: NO")
    
    print("\n=== FORM FIELD NAMES EXPECTED ===")
    for enrollment in enrollments:
        print(f"ca_score_{enrollment.id}")
        print(f"exam_score_{enrollment.id}")
    
    print("\n=== INSTRUCTIONS FOR MANUAL TEST ===")
    print("1. Go to the lecturer result entry page")
    print("2. Enter scores for at least one student")
    print("3. Click Submit")
    print("4. Check the server console for debug output")
    print("5. If you see 'NO SCORE FIELDS FOUND', there's a form issue")
    print("6. If you see the scores being processed, the backend is working")
    
    print(f"\nDirect URL: http://127.0.0.1:8000/api/lecturer/enter-results/?course_id={course.id}&session_id={session.id}")

if __name__ == '__main__':
    test_live_submission()
