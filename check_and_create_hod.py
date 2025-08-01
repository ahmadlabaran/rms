#!/usr/bin/env python
import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'RMS.settings')
django.setup()

from django.contrib.auth.models import User
from accounts.models import UserRole, Faculty, Department

def check_database():
    print("=== CHECKING DATABASE ===")
    
    # Check users
    print("\n1. USERS:")
    users = User.objects.all()
    if users.exists():
        for user in users:
            print(f"   - ID: {user.id}, Username: {user.username}, Email: {user.email}")
            print(f"     Staff: {user.is_staff}, Superuser: {user.is_superuser}")
    else:
        print("   No users found!")
    
    # Check user roles
    print("\n2. USER ROLES:")
    roles = UserRole.objects.all()
    if roles.exists():
        for role in roles:
            print(f"   - User: {role.user.username}, Role: {role.role}")
            print(f"     Faculty: {role.faculty}, Department: {role.department}")
    else:
        print("   No user roles found!")
    
    # Check faculties
    print("\n3. FACULTIES:")
    faculties = Faculty.objects.all()
    if faculties.exists():
        for faculty in faculties:
            print(f"   - ID: {faculty.id}, Name: {faculty.name}")
    else:
        print("   No faculties found!")
    
    # Check departments
    print("\n4. DEPARTMENTS:")
    departments = Department.objects.all()
    if departments.exists():
        for dept in departments:
            print(f"   - ID: {dept.id}, Name: {dept.name}, Faculty: {dept.faculty}")
    else:
        print("   No departments found!")
    
    return users, roles, faculties, departments

def create_test_data():
    print("\n=== CREATING TEST DATA ===")
    
    # Get or create a user (assuming you're the first user)
    user = User.objects.first()
    if not user:
        print("No users found. Creating admin user...")
        user = User.objects.create_user(
            username='admin',
            email='admin@university.edu',
            password='admin123',
            is_staff=True,
            is_superuser=True
        )
        print(f"Created user: {user.username}")
    else:
        print(f"Using existing user: {user.username}")
    
    # Create faculty if none exists
    faculty = Faculty.objects.first()
    if not faculty:
        print("Creating test faculty...")
        faculty = Faculty.objects.create(
            name='Faculty of Science',
            created_by=user
        )
        print(f"Created faculty: {faculty.name}")
    else:
        print(f"Using existing faculty: {faculty.name}")
    
    # Create department if none exists
    department = Department.objects.first()
    if not department:
        print("Creating test department...")
        department = Department.objects.create(
            name='Computer Science',
            faculty=faculty,
            created_by=user
        )
        print(f"Created department: {department.name}")
    else:
        print(f"Using existing department: {department.name}")
    
    # Check if user already has HOD role
    hod_role = UserRole.objects.filter(user=user, role='HOD').first()
    if hod_role:
        print(f"User {user.username} already has HOD role for {hod_role.department}")
    else:
        print("Creating HOD role...")
        hod_role = UserRole.objects.create(
            user=user,
            role='HOD',
            faculty=faculty,
            department=department,
            is_primary=True,
            created_by=user
        )
        print(f"Created HOD role for {user.username} in {department.name}")
    
    return user, faculty, department, hod_role

if __name__ == "__main__":
    print("Django RMS - Database Check and HOD Role Creation")
    print("=" * 50)
    
    # Check current state
    users, roles, faculties, departments = check_database()
    
    # Create missing data
    user, faculty, department, hod_role = create_test_data()
    
    print("\n=== FINAL STATE ===")
    check_database()
    
    print(f"\n✅ HOD role created successfully!")
    print(f"   User: {user.username}")
    print(f"   Role: HOD")
    print(f"   Faculty: {faculty.name}")
    print(f"   Department: {department.name}")
    print(f"\nYou can now access the HOD dashboard at: http://127.0.0.1:8000/api/hod/")
