#!/usr/bin/env python
"""
Fix duplicate Level objects in the database
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

from accounts.models import Level, Student, Course

def fix_duplicate_levels():
    """Fix duplicate Level objects"""
    print("=== FIXING DUPLICATE LEVEL OBJECTS ===")
    
    # Find duplicate Level objects with numeric_value=100
    levels_100 = Level.objects.filter(numeric_value=100).order_by('id')
    
    if levels_100.count() <= 1:
        print("No duplicate Level objects found.")
        return
    
    print(f"Found {levels_100.count()} Level objects with numeric_value=100:")
    for level in levels_100:
        print(f"  - ID: {level.id}, Name: '{level.name}'")
    
    # Keep the first one (ID: 1, Name: "100L") and remove the duplicate
    primary_level = levels_100.first()  # ID: 1, Name: "100L"
    duplicate_levels = levels_100[1:]   # ID: 8, Name: "100 Level"
    
    print(f"\nKeeping primary level: ID {primary_level.id}, Name '{primary_level.name}'")
    
    for duplicate in duplicate_levels:
        print(f"Removing duplicate level: ID {duplicate.id}, Name '{duplicate.name}'")
        
        # Check if any students are using this duplicate level
        students_using_duplicate = Student.objects.filter(current_level=duplicate)
        if students_using_duplicate.exists():
            print(f"  - Found {students_using_duplicate.count()} students using duplicate level")
            print(f"  - Updating students to use primary level (ID {primary_level.id})")
            students_using_duplicate.update(current_level=primary_level)
        
        # Check if any courses are using this duplicate level
        courses_using_duplicate = Course.objects.filter(level=duplicate)
        if courses_using_duplicate.exists():
            print(f"  - Found {courses_using_duplicate.count()} courses using duplicate level")
            print(f"  - Updating courses to use primary level (ID {primary_level.id})")
            courses_using_duplicate.update(level=primary_level)
        
        # Delete the duplicate level
        duplicate.delete()
        print(f"  - Deleted duplicate level ID {duplicate.id}")
    
    print("\n=== VERIFICATION ===")
    remaining_levels_100 = Level.objects.filter(numeric_value=100)
    print(f"Remaining Level objects with numeric_value=100: {remaining_levels_100.count()}")
    for level in remaining_levels_100:
        print(f"  - ID: {level.id}, Name: '{level.name}'")
    
    # Test the query that was failing
    try:
        test_level = Level.objects.get(numeric_value=100)
        print(f"✓ Level.objects.get(numeric_value=100) now works: {test_level}")
    except Exception as e:
        print(f"✗ Level.objects.get(numeric_value=100) still fails: {e}")

if __name__ == '__main__':
    fix_duplicate_levels()
