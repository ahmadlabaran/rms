#!/usr/bin/env python
"""
Debug script to investigate Level objects causing MultipleObjectsReturned error
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

from accounts.models import Level

def debug_level_objects():
    """Debug Level objects to identify duplicates"""
    print("=== DEBUGGING LEVEL OBJECTS ===")
    
    # Get all Level objects
    levels = Level.objects.all()
    print(f"Total Level objects: {levels.count()}")
    
    print("\n--- All Level Objects ---")
    for level in levels:
        print(f"ID: {level.id}, Name: {level.name}, Numeric Value: {level.numeric_value}")
    
    # Check for duplicate numeric values
    print("\n--- Checking for Duplicate Numeric Values ---")
    numeric_values = {}
    for level in levels:
        if level.numeric_value in numeric_values:
            numeric_values[level.numeric_value].append(level)
        else:
            numeric_values[level.numeric_value] = [level]
    
    duplicates_found = False
    for numeric_value, level_list in numeric_values.items():
        if len(level_list) > 1:
            duplicates_found = True
            print(f"DUPLICATE: Numeric value {numeric_value} has {len(level_list)} objects:")
            for level in level_list:
                print(f"  - ID: {level.id}, Name: {level.name}")
    
    if not duplicates_found:
        print("No duplicate numeric values found.")
    
    # Test the problematic query
    print("\n--- Testing Problematic Query ---")
    try:
        level_100 = Level.objects.get(numeric_value=100)
        print(f"✓ Level.objects.get(numeric_value=100) succeeded: {level_100}")
    except Level.MultipleObjectsReturned as e:
        print(f"✗ Level.objects.get(numeric_value=100) failed: {e}")
        # Show all objects with numeric_value=100
        levels_100 = Level.objects.filter(numeric_value=100)
        print(f"Found {levels_100.count()} Level objects with numeric_value=100:")
        for level in levels_100:
            print(f"  - ID: {level.id}, Name: {level.name}, Numeric Value: {level.numeric_value}")
    except Level.DoesNotExist:
        print("✗ No Level object with numeric_value=100 found")
    
    # Test other common level values
    for test_value in [200, 300, 400]:
        try:
            level = Level.objects.get(numeric_value=test_value)
            print(f"✓ Level.objects.get(numeric_value={test_value}) succeeded: {level}")
        except Level.MultipleObjectsReturned as e:
            print(f"✗ Level.objects.get(numeric_value={test_value}) failed: {e}")
            levels_test = Level.objects.filter(numeric_value=test_value)
            print(f"Found {levels_test.count()} Level objects with numeric_value={test_value}:")
            for level in levels_test:
                print(f"  - ID: {level.id}, Name: {level.name}")
        except Level.DoesNotExist:
            print(f"No Level object with numeric_value={test_value} found")

if __name__ == '__main__':
    debug_level_objects()
