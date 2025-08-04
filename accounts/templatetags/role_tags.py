from django import template
from django.db.models import Q
from accounts.models import UserRole, PermissionDelegation
from accounts.permissions import get_user_roles_with_details, get_active_delegations_for_user

register = template.Library()


@register.simple_tag
def get_user_roles_with_delegation(user):
    """Get all user roles including delegation context"""
    return get_user_roles_with_details(user)


@register.simple_tag
def get_user_active_delegations(user):
    """Get active delegations for a user"""
    return get_active_delegations_for_user(user)


@register.simple_tag
def user_has_role(user, role):
    """Check if user has a specific role (including delegated)"""
    from accounts.permissions import user_has_role as check_role
    return check_role(user, role)


@register.simple_tag
def user_has_any_role(user, roles):
    """Check if user has any of the specified roles"""
    from accounts.permissions import user_has_any_role as check_any_role
    if isinstance(roles, str):
        roles = [roles]
    return check_any_role(user, roles)


@register.simple_tag
def get_delegation_badge_class(role):
    """Get CSS class for delegation badge based on role"""
    role_classes = {
        'HOD': 'badge-hod',
        'FACULTY_DEAN': 'badge-dean',
        'DAAA': 'badge-daaa',
        'SENATE': 'badge-senate',
        'SUPER_ADMIN': 'badge-admin',
        'EXAM_OFFICER': 'badge-exam',
        'LECTURER': 'badge-lecturer',
        'ADMISSION_OFFICER': 'badge-admission',
        'STUDENT': 'badge-student'
    }
    return role_classes.get(role, 'badge-default')


@register.simple_tag
def get_role_display_name(role):
    """Get human-readable role name"""
    role_names = {
        'HOD': 'Head of Department',
        'FACULTY_DEAN': 'Faculty Dean',
        'DAAA': 'DAAA',
        'SENATE': 'Senate',
        'SUPER_ADMIN': 'Super Admin',
        'EXAM_OFFICER': 'Exam Officer',
        'LECTURER': 'Lecturer',
        'ADMISSION_OFFICER': 'Admission Officer',
        'STUDENT': 'Student'
    }
    return role_names.get(role, role)


@register.inclusion_tag('role_delegation_badges.html')
def show_delegation_badges(user):
    """Show delegation badges for a user"""
    roles_info = get_user_roles_with_details(user)
    delegated_roles = [role for role in roles_info if role['is_delegated']]
    return {'delegated_roles': delegated_roles, 'user': user}


@register.inclusion_tag('role_navigation_menu.html')
def show_role_navigation(user):
    """Show navigation menu based on user roles including delegated ones"""
    roles_info = get_user_roles_with_details(user)
    all_roles = [role['role'] for role in roles_info]
    return {'user_roles': all_roles, 'roles_info': roles_info, 'user': user}


@register.filter
def has_delegated_role(user, role):
    """Template filter to check if user has a delegated role"""
    delegated_roles = UserRole.objects.filter(
        user=user,
        role=role,
        is_temporary=True,
        delegation__status='ACTIVE'
    )
    return delegated_roles.exists()


@register.filter
def has_direct_role(user, role):
    """Template filter to check if user has a direct (non-delegated) role"""
    direct_roles = UserRole.objects.filter(
        user=user,
        role=role,
        is_temporary=False
    )
    return direct_roles.exists()


@register.simple_tag
def get_delegation_info(user, role):
    """Get delegation information for a specific role"""
    try:
        user_role = UserRole.objects.get(
            user=user,
            role=role,
            is_temporary=True,
            delegation__status='ACTIVE'
        )
        return {
            'delegation': user_role.delegation,
            'delegated_from': user_role.delegation.delegator,
            'created_at': user_role.delegation.created_at,
            'reason': user_role.delegation.reason
        }
    except UserRole.DoesNotExist:
        return None


@register.simple_tag
def count_active_delegations(user):
    """Count active delegations for a user"""
    return PermissionDelegation.objects.filter(
        delegate=user,
        status='ACTIVE'
    ).count()


@register.simple_tag
def count_delegations_by_user(user):
    """Count delegations created by a user"""
    return PermissionDelegation.objects.filter(
        delegator=user,
        status='ACTIVE'
    ).count()
