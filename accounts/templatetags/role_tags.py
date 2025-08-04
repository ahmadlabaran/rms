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
    """Show clean navigation menu with unique roles only"""
    # I think this approach will prevent duplicate navigation links
    roles_info = get_user_roles_with_details(user)

    # Create unique role list - no duplicates even if user has multiple contexts
    unique_roles = set()
    for role_info in roles_info:
        unique_roles.add(role_info['role'])

    # Convert back to list for template
    all_roles = list(unique_roles)

    return {
        'user_roles': all_roles,
        'roles_info': roles_info,
        'user': user
    }


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


@register.filter
def get_delegation_context(user, role_name):
    """Get delegation context for a specific role"""
    # I think this should help show delegation details in templates
    delegation_role = UserRole.objects.filter(
        user=user,
        role=role_name,
        is_temporary=True,
        delegation__status='ACTIVE'
    ).select_related('delegation', 'delegation__delegated_role', 'faculty', 'department').first()

    if delegation_role and delegation_role.delegation:
        return {
            'is_delegated': True,
            'delegated_from': delegation_role.delegation.delegator,
            'department': delegation_role.department,
            'faculty': delegation_role.faculty,
            'end_date': delegation_role.delegation.end_date
        }
    return {'is_delegated': False}
