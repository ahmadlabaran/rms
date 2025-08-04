from django.core.management.base import BaseCommand
from accounts.models import PermissionDelegation, UserRole, User
from django.db import transaction

class Command(BaseCommand):
    help = 'Fix broken delegations by creating missing temporary roles or cleaning up orphaned delegations'

    def add_arguments(self, parser):
        parser.add_argument(
            '--fix',
            action='store_true',
            help='Actually fix the issues (default is dry run)',
        )

    def handle(self, *args, **options):
        fix_mode = options['fix']
        
        if fix_mode:
            self.stdout.write(self.style.WARNING("FIXING MODE: Will make changes to the database"))
        else:
            self.stdout.write(self.style.SUCCESS("DRY RUN MODE: No changes will be made"))
        
        self.stdout.write("\n=== CHECKING DELEGATION INTEGRITY ===")
        
        # Check for delegations without corresponding temporary roles
        active_delegations = PermissionDelegation.objects.filter(status='ACTIVE')
        
        issues_found = 0
        
        for delegation in active_delegations:
            self.stdout.write(f"\nChecking Delegation ID: {delegation.id}")
            self.stdout.write(f"Delegate: {delegation.delegate.get_full_name()}")
            self.stdout.write(f"Role: {delegation.delegated_role.get_role_display()}")
            
            # Check if temporary role exists
            temp_role = UserRole.objects.filter(
                user=delegation.delegate,
                role=delegation.delegated_role.role,
                is_temporary=True,
                delegation=delegation
            ).first()
            
            if not temp_role:
                issues_found += 1
                self.stdout.write(self.style.ERROR(f"  ISSUE: No temporary role found for delegation {delegation.id}"))
                
                if fix_mode:
                    try:
                        with transaction.atomic():
                            # Create the missing temporary role
                            temp_role = UserRole.objects.create(
                                user=delegation.delegate,
                                role=delegation.delegated_role.role,
                                faculty=delegation.delegated_role.faculty,
                                department=delegation.delegated_role.department,
                                is_primary=False,
                                is_temporary=True,
                                delegation=delegation,
                                created_by=delegation.created_by
                            )
                            self.stdout.write(self.style.SUCCESS(f"  FIXED: Created temporary role {temp_role.id}"))
                    except Exception as e:
                        self.stdout.write(self.style.ERROR(f"  ERROR: Failed to create temporary role: {e}"))
                else:
                    self.stdout.write(self.style.WARNING(f"  WOULD FIX: Create temporary role for delegation {delegation.id}"))
            else:
                self.stdout.write(self.style.SUCCESS(f"  OK: Temporary role {temp_role.id} exists"))
        
        # Check for orphaned temporary roles
        self.stdout.write("\n=== CHECKING FOR ORPHANED TEMPORARY ROLES ===")
        
        temp_roles = UserRole.objects.filter(is_temporary=True)
        
        for temp_role in temp_roles:
            self.stdout.write(f"\nChecking Temp Role ID: {temp_role.id}")
            self.stdout.write(f"User: {temp_role.user.get_full_name()}")
            self.stdout.write(f"Role: {temp_role.get_role_display()}")
            
            if not temp_role.delegation:
                issues_found += 1
                self.stdout.write(self.style.ERROR(f"  ISSUE: Temporary role {temp_role.id} has no delegation"))
                
                if fix_mode:
                    try:
                        temp_role.delete()
                        self.stdout.write(self.style.SUCCESS(f"  FIXED: Deleted orphaned temporary role {temp_role.id}"))
                    except Exception as e:
                        self.stdout.write(self.style.ERROR(f"  ERROR: Failed to delete temporary role: {e}"))
                else:
                    self.stdout.write(self.style.WARNING(f"  WOULD FIX: Delete orphaned temporary role {temp_role.id}"))
            elif temp_role.delegation.status != 'ACTIVE':
                issues_found += 1
                self.stdout.write(self.style.ERROR(f"  ISSUE: Temporary role {temp_role.id} linked to inactive delegation"))
                
                if fix_mode:
                    try:
                        temp_role.delete()
                        self.stdout.write(self.style.SUCCESS(f"  FIXED: Deleted temporary role {temp_role.id} for inactive delegation"))
                    except Exception as e:
                        self.stdout.write(self.style.ERROR(f"  ERROR: Failed to delete temporary role: {e}"))
                else:
                    self.stdout.write(self.style.WARNING(f"  WOULD FIX: Delete temporary role {temp_role.id} for inactive delegation"))
            else:
                self.stdout.write(self.style.SUCCESS(f"  OK: Temporary role {temp_role.id} is properly linked"))
        
        self.stdout.write(f"\n=== SUMMARY ===")
        self.stdout.write(f"Issues found: {issues_found}")
        
        if issues_found > 0 and not fix_mode:
            self.stdout.write(self.style.WARNING("Run with --fix to actually fix these issues"))
        elif issues_found == 0:
            self.stdout.write(self.style.SUCCESS("No issues found!"))
        else:
            self.stdout.write(self.style.SUCCESS("All issues have been fixed!"))
