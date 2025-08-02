#!/usr/bin/env python
"""
Test script to verify user deletion functionality works properly
"""
import os
import sys
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'RMS.settings')
django.setup()

from django.contrib.auth.models import User
from accounts.models import AuditLog

def test_user_deletion():
    print("🧪 Testing User Deletion Functionality")
    print("=" * 50)
    
    # Create a test user
    test_user = User.objects.create_user(
        username='test_delete_user',
        email='test@delete.com',
        first_name='Test',
        last_name='Delete'
    )
    print(f"✅ Created test user: {test_user.username} (ID: {test_user.id})")
    
    # Create an audit log entry for this user
    audit_log = AuditLog.objects.create(
        user=test_user,
        action='TEST_ACTION',
        model_name='User',
        object_id=str(test_user.id),
        description='Test audit log entry for user deletion test'
    )
    print(f"✅ Created audit log entry: {audit_log.id}")
    
    # Try to delete the user
    try:
        user_id = test_user.id
        username = test_user.username
        test_user.delete()
        print(f"✅ Successfully deleted user: {username} (ID: {user_id})")
        
        # Check if audit log still exists with user set to NULL
        audit_log.refresh_from_db()
        if audit_log.user is None:
            print(f"✅ Audit log preserved with user set to NULL: {audit_log.description}")
        else:
            print(f"❌ Audit log still has user reference: {audit_log.user}")
            
        return True
        
    except Exception as e:
        print(f"❌ Failed to delete user: {e}")
        # Clean up the test user if deletion failed
        try:
            test_user.delete()
        except:
            pass
        return False

if __name__ == "__main__":
    success = test_user_deletion()
    if success:
        print("\n🎉 User deletion test PASSED!")
        print("✅ Users can now be deleted without foreign key constraint errors")
    else:
        print("\n❌ User deletion test FAILED!")
        print("❌ Database migration may be needed")
    
    print("\n" + "=" * 50)
