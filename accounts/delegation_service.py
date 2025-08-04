"""
Service for handling delegation operations
"""

from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone
from .models import UserRole, PermissionDelegation, AuditLog, Student
from .notification_service import NotificationService
import logging

logger = logging.getLogger(__name__)


class DelegationService:
    """Handles delegation operations"""
    
    @staticmethod
    def create_new_delegation(delegator_role_id, delegate_user_id, created_by, reason,
                             start_date=None, end_date=None):
        """
        Creates a new delegation
        """
        try:
            # Get the role and user objects
            delegator_role = UserRole.objects.get(id=delegator_role_id)
            delegate_user = User.objects.get(id=delegate_user_id)

            # Check if delegation is allowed
            is_delegation_valid, error_list = PermissionDelegation.check_if_delegation_is_allowed(
                delegator_role, delegate_user, created_by
            )

            if not is_delegation_valid:
                return False, error_list, []
            
            # Check dates if provided
            if start_date and end_date:
                if end_date <= start_date:
                    return False, ["End date must be after start date"], []

                if start_date < timezone.now():
                    return False, ["Start date cannot be in the past"], []
            
            # Create the delegation
            with transaction.atomic():
                # Create delegation record
                delegation = PermissionDelegation.objects.create(
                    delegator=delegator_role.user,
                    delegate=delegate_user,
                    delegated_role=delegator_role,
                    created_by=created_by,
                    reason=reason,
                    start_date=start_date,
                    end_date=end_date,
                    status='ACTIVE'
                )

                # Create temporary role for delegate
                temp_role = UserRole.objects.create(
                    user=delegate_user,
                    role=delegator_role.role,
                    faculty=delegator_role.faculty,
                    department=delegator_role.department,
                    is_primary=False,
                    is_temporary=True,
                    delegation=delegation,
                    created_by=created_by
                )
                
                # Log what happened
                AuditLog.objects.create(
                    user=created_by,
                    action='CREATE_DELEGATION',
                    description=f'Created delegation: {delegator_role.get_role_display()} '
                               f'from {delegator_role.user.get_full_name()} '
                               f'to {delegate_user.get_full_name()}',
                    level='INFO'
                )

                # Send notifications
                try:
                    NotificationService.notify_delegation_created(delegation)
                except Exception as e:
                    logger.error(f'Error sending delegation notifications: {str(e)}')

                # Create success message
                success_message = (
                    f"Delegation created successfully. {delegate_user.get_full_name()} "
                    f"now has temporary {delegator_role.get_role_display()} permissions."
                )

                return True, delegation, [success_message]
                
        except UserRole.DoesNotExist:
            return False, ["Invalid delegator role selected"], []
        except User.DoesNotExist:
            return False, ["Invalid delegate user selected"], []
        except Exception as e:
            logger.error(f'Error creating delegation: {str(e)}')
            return False, [f"Error creating delegation: {str(e)}"], []
    
    @staticmethod
    def revoke_delegation(delegation_id, revoked_by, reason=""):
        """
        Revokes a delegation
        """
        try:
            # Find the delegation
            delegation = PermissionDelegation.objects.get(
                id=delegation_id,
                status='ACTIVE'
            )

            # Check if user can revoke delegations
            if not PermissionDelegation.check_if_super_admin(revoked_by):
                return False, ["Only Super Admin can revoke delegations"]

            # Send notifications first
            try:
                NotificationService.notify_delegation_revoked(delegation, revoked_by, reason)
            except Exception as e:
                logger.error(f'Error sending revocation notifications: {str(e)}')

            # Actually revoke the delegation
            delegation.revoke(revoked_by, reason)

            # Create success message
            success_message = f"Successfully revoked delegation for {delegation.delegate.get_full_name()}"
            return True, [success_message]
            
        except PermissionDelegation.DoesNotExist:
            return False, ["Delegation not found or already revoked"]
        except Exception as e:
            logger.error(f'Error revoking delegation: {str(e)}')
            return False, [f"Error revoking delegation: {str(e)}"]
    
    @staticmethod
    def get_user_delegation_info(user):
        """
        Gets delegation info for a user
        """
        # Check if user has active delegations
        user_active_delegation = PermissionDelegation.objects.filter(
            delegate=user,
            status='ACTIVE'
        ).first()

        # Check if user's roles are delegated to others
        user_delegated_roles = PermissionDelegation.objects.filter(
            delegator=user,
            status='ACTIVE'
        )
        
        return {
            'has_delegated_role': user_active_delegation is not None,
            'delegated_role': user_active_delegation.delegated_role.get_role_display() if user_active_delegation else None,
            'delegated_from': user_active_delegation.delegator.get_full_name() if user_active_delegation else None,
            'delegation_expires': user_active_delegation.end_date if user_active_delegation else None,
            'roles_being_delegated': [
                {
                    'role': d.delegated_role.get_role_display(),
                    'delegate': d.delegate.get_full_name(),
                    'expires': d.end_date
                }
                for d in user_delegated_roles
            ],
            'can_receive_delegation': DelegationService.check_if_user_can_receive_delegation(user),
            'delegation_limit_reached': user_active_delegation is not None
        }
    
    @staticmethod
    def check_if_user_can_receive_delegation(user):
        """Check if user can receive delegation"""
        # Students can't receive delegations
        is_student = Student.objects.filter(user=user).exists()
        if is_student:
            return False

        # Users with active delegations can't receive another
        has_active_delegation = PermissionDelegation.objects.filter(delegate=user, status='ACTIVE').exists()
        if has_active_delegation:
            return False

        return True
    
    @staticmethod
    def get_faculty_delegation_summary(faculty):
        """
        Gets delegation summary for faculty
        """
        # Get all roles in this faculty
        faculty_role_list = UserRole.objects.filter(faculty=faculty, is_temporary=False)
        # Get all users in this faculty
        faculty_user_list = User.objects.filter(rms_roles__in=faculty_role_list).distinct()

        # Get active delegations for this faculty
        active_delegation_list = PermissionDelegation.objects.filter(
            delegated_role__faculty=faculty,
            status='ACTIVE'
        )
        
        return {
            'faculty_name': faculty.name,
            'total_roles': faculty_role_list.count(),
            'total_users': faculty_user_list.count(),
            'active_delegations': active_delegation_list.count(),
            'delegated_roles': [
                {
                    'role': d.delegated_role.get_role_display(),
                    'delegator': d.delegator.get_full_name(),
                    'delegate': d.delegate.get_full_name(),
                    'created': d.created_at,
                    'expires': d.end_date
                }
                for d in active_delegation_list
            ]
        }
    
    @staticmethod
    def check_cross_faculty_delegation(delegator_role, delegate_user, created_by):
        """
        Checks if cross-faculty delegation is allowed
        """
        # Super Admin can delegate across faculties
        is_super_admin = PermissionDelegation.check_if_super_admin(created_by)
        if is_super_admin:
            return True, "Super Admin can delegate across faculties"

        # Check if same faculty
        is_same_faculty = PermissionDelegation.check_same_faculty(delegator_role, delegate_user)
        if is_same_faculty:
            return True, "Same faculty delegation allowed"

        return False, "Cross-faculty delegation only allowed for Super Admin"
    
    @staticmethod
    def find_delegation_conflicts(delegate_user, role):
        """
        Finds conflicts that would prevent delegation
        """
        conflict_list = []

        # Check if user is student
        is_student = Student.objects.filter(user=delegate_user).exists()
        if is_student:
            conflict_list.append("Cannot delegate roles to students")

        # Check if user already has this role
        already_has_role = UserRole.objects.filter(user=delegate_user, role=role).exists()
        if already_has_role:
            conflict_list.append(f"User already has {role} role")

        # Check if user has active delegation
        existing_delegation = PermissionDelegation.objects.filter(
            delegate=delegate_user,
            status='ACTIVE'
        ).first()

        if existing_delegation:
            conflict_list.append(
                f"User already has active delegation: {existing_delegation.delegated_role.get_role_display()}"
            )
        
        # Check role hierarchy conflicts
        user_role_list = UserRole.objects.filter(user=delegate_user).values_list('role', flat=True)

        # Define role hierarchy - higher roles include lower role permissions
        role_hierarchy_map = {
            'SUPER_ADMIN': ['SENATE', 'DAAA', 'FACULTY_DEAN', 'HOD', 'EXAM_OFFICER', 'LECTURER'],
            'SENATE': ['DAAA', 'FACULTY_DEAN', 'HOD', 'EXAM_OFFICER', 'LECTURER'],
            'DAAA': ['FACULTY_DEAN', 'HOD', 'EXAM_OFFICER', 'LECTURER'],
            'FACULTY_DEAN': ['HOD', 'EXAM_OFFICER', 'LECTURER'],
            'HOD': ['EXAM_OFFICER', 'LECTURER'],
        }

        # Check if user has higher role that includes this role's permissions
        for user_role in user_role_list:
            if user_role in role_hierarchy_map and role in role_hierarchy_map[user_role]:
                conflict_list.append(
                    f"User has {user_role} role which includes {role} permissions"
                )

        return conflict_list
