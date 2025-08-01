#!/usr/bin/env python
import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'RMS.settings')
django.setup()

from django.contrib.auth.models import User
from accounts.models import *

def check_database():
    print("=== CURRENT DATABASE STATE ===")
    print(f"Total Users: {User.objects.count()}")
    print(f"Users with roles: {User.objects.filter(rms_roles__isnull=False).distinct().count()}")
    print(f"Users without roles: {User.objects.filter(rms_roles__isnull=True).count()}")
    print(f"Total Faculties: {Faculty.objects.count()}")
    print(f"Total Departments: {Department.objects.count()}")
    print(f"Total UserRoles: {UserRole.objects.count()}")
    
    print("\n=== USERS DETAILS ===")
    for user in User.objects.all():
        roles = [r.role for r in user.rms_roles.all()]
        print(f"User: {user.username} ({user.get_full_name()}) - Roles: {roles}")
    
    print("\n=== FACULTIES ===")
    for faculty in Faculty.objects.all():
        print(f"Faculty: {faculty.name} ({faculty.code})")
        
    print("\n=== DEPARTMENTS ===")
    for dept in Department.objects.all():
        print(f"Department: {dept.name} - Faculty: {dept.faculty.name}")

def create_test_data():
    print("\n=== CREATING TEST DATA ===")

    # Get or create a superuser
    superuser = None
    if not User.objects.filter(is_superuser=True).exists():
        print("Creating superuser...")
        superuser = User.objects.create_superuser(
            username='admin',
            email='admin@rms.edu',
            password='admin123',
            first_name='Super',
            last_name='Admin'
        )
        print("✅ Superuser created: admin/admin123")
    else:
        superuser = User.objects.filter(is_superuser=True).first()
        print(f"✅ Using existing superuser: {superuser.username}")

    # Give superuser the SUPER_ADMIN role if not exists
    if not UserRole.objects.filter(user=superuser, role='SUPER_ADMIN').exists():
        UserRole.objects.create(
            user=superuser,
            role='SUPER_ADMIN',
            created_by=superuser
        )
        print("✅ Assigned SUPER_ADMIN role")
    
    # Create Computer Science Faculty if it doesn't exist
    cs_faculty, created = Faculty.objects.get_or_create(
        code='CS',
        defaults={
            'name': 'Faculty of Computer Science',
            'description': 'Computer Science and Information Technology'
        }
    )
    if created:
        print("✅ Created Computer Science Faculty")
    
    # Create Computer Science Department
    cs_dept, created = Department.objects.get_or_create(
        code='CSC',
        faculty=cs_faculty,
        defaults={
            'name': 'Computer Science Department'
        }
    )
    if created:
        print("✅ Created Computer Science Department")
    
    # Create Engineering Faculty
    eng_faculty, created = Faculty.objects.get_or_create(
        code='ENG',
        defaults={
            'name': 'Faculty of Engineering',
            'description': 'Engineering and Technology'
        }
    )
    if created:
        print("✅ Created Engineering Faculty")
    
    # Create Electrical Engineering Department
    ee_dept, created = Department.objects.get_or_create(
        code='EEE',
        faculty=eng_faculty,
        defaults={
            'name': 'Electrical Engineering Department'
        }
    )
    if created:
        print("✅ Created Electrical Engineering Department")
    
    # Create test users with different roles
    test_users = [
        {
            'username': 'dr_smith',
            'email': 'smith@rms.edu',
            'first_name': 'John',
            'last_name': 'Smith',
            'role': 'EXAM_OFFICER',
            'faculty': cs_faculty,
            'department': cs_dept
        },
        {
            'username': 'dr_johnson',
            'email': 'johnson@rms.edu',
            'first_name': 'Sarah',
            'last_name': 'Johnson',
            'role': 'LECTURER',
            'faculty': cs_faculty,
            'department': cs_dept
        },
        {
            'username': 'prof_williams',
            'email': 'williams@rms.edu',
            'first_name': 'Michael',
            'last_name': 'Williams',
            'role': 'HOD',
            'faculty': cs_faculty,
            'department': cs_dept
        },
        {
            'username': 'dean_brown',
            'email': 'brown@rms.edu',
            'first_name': 'Emily',
            'last_name': 'Brown',
            'role': 'FACULTY_DEAN',
            'faculty': cs_faculty,
            'department': None
        },
        {
            'username': 'dr_davis',
            'email': 'davis@rms.edu',
            'first_name': 'Robert',
            'last_name': 'Davis',
            'role': 'EXAM_OFFICER',
            'faculty': eng_faculty,
            'department': ee_dept
        },
        {
            'username': 'jane_doe',
            'email': 'jane@rms.edu',
            'first_name': 'Jane',
            'last_name': 'Doe',
            'role': None,  # User without role
            'faculty': None,
            'department': None
        }
    ]
    
    for user_data in test_users:
        user, created = User.objects.get_or_create(
            username=user_data['username'],
            defaults={
                'email': user_data['email'],
                'first_name': user_data['first_name'],
                'last_name': user_data['last_name'],
                'password': 'pbkdf2_sha256$600000$test$test'  # password: 'test123'
            }
        )
        
        if created:
            user.set_password('test123')
            user.save()
            print(f"✅ Created user: {user.username}")
            
            # Create role if specified
            if user_data['role']:
                UserRole.objects.create(
                    user=user,
                    role=user_data['role'],
                    faculty=user_data['faculty'],
                    department=user_data['department'],
                    created_by=superuser
                )
                print(f"   ✅ Assigned role: {user_data['role']}")

if __name__ == '__main__':
    check_database()
    create_test_data()
    print("\n" + "="*50)
    check_database()
    print("\n🎉 Test data creation complete!")
    print("\nYou can now:")
    print("1. Login as admin/admin123 (Super Admin)")
    print("2. Go to 'Manage Users' to see all users")
    print("3. Click 'Delegate' button next to any user")
    print("4. Go to 'Permission Management' to see delegations")
