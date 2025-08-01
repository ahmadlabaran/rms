#!/usr/bin/env python
"""
Script to populate the Level table with standard academic levels
"""
import os
import sys
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'RMS.settings')
django.setup()

from accounts.models import Level

def populate_levels():
    """Create standard academic levels"""
    levels_data = [
        {'name': '100L', 'numeric_value': 100},
        {'name': '200L', 'numeric_value': 200},
        {'name': '300L', 'numeric_value': 300},
        {'name': '400L', 'numeric_value': 400},
        {'name': '500L', 'numeric_value': 500},
        {'name': '600L', 'numeric_value': 600},
        {'name': '700L', 'numeric_value': 700},
    ]
    
    for level_data in levels_data:
        level, created = Level.objects.get_or_create(
            numeric_value=level_data['numeric_value'],
            defaults={'name': level_data['name']}
        )
        if created:
            print(f"Created level: {level.name}")
        else:
            print(f"Level already exists: {level.name}")

if __name__ == '__main__':
    populate_levels()
    print("Level population completed!")
