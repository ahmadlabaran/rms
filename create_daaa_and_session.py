#!/usr/bin/env python
import os
import sys
import django
from datetime import datetime, date

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'RMS.settings')
django.setup()

from django.contrib.auth.models import User
from accounts.models import UserRole, AcademicSession, AuditLog

def create_daaa_user():
    print("=== CREATING DAAA USER ===")
    
    # Check if DAAA user already exists
    daaa_user = User.objects.filter(username='DAAA').first()
    if daaa_user:
        print(f"DAAA user already exists: {daaa_user.username}")
    else:
        print("Creating DAAA user...")
        daaa_user = User.objects.create_user(
            username='DAAA',
            email='daaa@university.edu',
            password='daaa123',
            first_name='DAAA',
            last_name='Office',
            is_staff=True
        )
        print(f"Created DAAA user: {daaa_user.username}")
    
    # Check if DAAA role exists
    daaa_role = UserRole.objects.filter(user=daaa_user, role='DAAA').first()
    if daaa_role:
        print(f"DAAA role already exists for {daaa_user.username}")
    else:
        print("Creating DAAA role...")
        # Get super admin user for created_by
        super_admin = User.objects.filter(is_superuser=True).first()
        if not super_admin:
            super_admin = daaa_user  # Use self if no super admin exists
            
        daaa_role = UserRole.objects.create(
            user=daaa_user,
            role='DAAA',
            faculty=None,  # DAAA is university-wide
            department=None,  # DAAA is university-wide
            is_primary=True,
            created_by=super_admin
        )
        print(f"Created DAAA role for {daaa_user.username}")
    
    return daaa_user

def create_academic_session():
    print("\n=== CREATING ACADEMIC SESSION ===")
    
    # Get current academic year
    now = datetime.now()
    current_year = now.year
    current_month = now.month
    
    # If it's before September, use previous year as start
    academic_start_year = current_year - 1 if current_month < 9 else current_year
    academic_end_year = academic_start_year + 1
    
    session_name = f"{academic_start_year}/{academic_end_year}"
    
    # Check if session already exists
    existing_session = AcademicSession.objects.filter(name=session_name).first()
    if existing_session:
        print(f"Academic session already exists: {existing_session.name}")
        print(f"Status: {'Active' if existing_session.is_active else 'Inactive'}, {'Locked' if existing_session.is_locked else 'Unlocked'}")
        return existing_session
    
    # Create new session
    print(f"Creating academic session: {session_name}")
    
    # Get DAAA user for created_by
    daaa_user = User.objects.filter(username='DAAA').first()
    if not daaa_user:
        daaa_user = User.objects.filter(is_superuser=True).first()
    
    session = AcademicSession.objects.create(
        name=session_name,
        start_date=date(academic_start_year, 9, 1),  # September 1st
        end_date=date(academic_end_year, 8, 31),     # August 31st next year
        is_active=True,  # Make it active immediately
        is_locked=False,
        created_by=daaa_user
    )
    
    print(f"Created academic session: {session.name}")
    print(f"Period: {session.start_date} to {session.end_date}")
    print(f"Status: Active and Unlocked")
    
    # Log the action
    AuditLog.objects.create(
        user=daaa_user,
        action='CREATE_SESSION',
        description=f'Created and activated academic session: {session.name}',
        level='INFO'
    )
    
    return session

def update_super_admin_permissions():
    print("\n=== UPDATING SUPER ADMIN PERMISSIONS ===")
    
    # Give Super Admin users DAAA role as well for session management
    super_admins = User.objects.filter(is_superuser=True)
    
    for admin in super_admins:
        # Check if they already have DAAA role
        daaa_role = UserRole.objects.filter(user=admin, role='DAAA').first()
        if not daaa_role:
            print(f"Adding DAAA role to Super Admin: {admin.username}")
            UserRole.objects.create(
                user=admin,
                role='DAAA',
                faculty=None,
                department=None,
                is_primary=False,  # Secondary role
                created_by=admin
            )
        else:
            print(f"Super Admin {admin.username} already has DAAA role")

def check_final_state():
    print("\n=== FINAL STATE CHECK ===")
    
    # Check active session
    active_session = AcademicSession.objects.filter(is_active=True).first()
    if active_session:
        print(f"✅ Active Academic Session: {active_session.name}")
        print(f"   Period: {active_session.start_date} to {active_session.end_date}")
        print(f"   Status: {'Locked' if active_session.is_locked else 'Unlocked'}")
    else:
        print("❌ No active academic session found!")
    
    # Check DAAA users
    daaa_roles = UserRole.objects.filter(role='DAAA')
    print(f"\n✅ DAAA Users ({daaa_roles.count()}):")
    for role in daaa_roles:
        print(f"   - {role.user.username} ({role.user.get_full_name()})")
    
    # Check all sessions
    all_sessions = AcademicSession.objects.all().order_by('-created_at')
    print(f"\n📅 All Academic Sessions ({all_sessions.count()}):")
    for session in all_sessions:
        status = []
        if session.is_active:
            status.append("ACTIVE")
        if session.is_locked:
            status.append("LOCKED")
        if not status:
            status.append("INACTIVE")
        
        print(f"   - {session.name} ({', '.join(status)})")

if __name__ == "__main__":
    print("Django RMS - DAAA User and Academic Session Setup")
    print("=" * 55)
    
    try:
        # Create DAAA user and role
        daaa_user = create_daaa_user()
        
        # Create academic session
        session = create_academic_session()
        
        # Update super admin permissions
        update_super_admin_permissions()
        
        # Check final state
        check_final_state()
        
        print(f"\nSETUP COMPLETE!")
        print(f"DAAA user created/verified")
        print(f"Academic session created/verified: {session.name}")
        print(f"Super Admin users have DAAA permissions")
        print(f"\nAccess URLs:")
        print(f"   DAAA Dashboard: http://127.0.0.1:8000/api/daaa/")
        print(f"   Session Management: http://127.0.0.1:8000/api/daaa/manage-sessions/")
        print(f"   Create Session: http://127.0.0.1:8000/api/daaa/create-session/")
        print(f"   HOD Dashboard: http://127.0.0.1:8000/api/hod/")
        
        print(f"\n👤 Login Credentials:")
        print(f"   DAAA User: username='DAAA', password='daaa123'")
        print(f"   Or use your existing Super Admin account")
        
    except Exception as e:
        print(f"\n❌ Error during setup: {str(e)}")
        import traceback
        traceback.print_exc()
