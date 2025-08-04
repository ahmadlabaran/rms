"""
Context processors for the accounts app.
Provides user role information to all templates.
"""
from .permissions import get_user_roles_with_delegation, get_user_roles_with_details

def user_roles(request):
    """
    Add user role information to template context.
    Includes both direct and delegated roles.
    """
    context = {
        'user_roles': [],
        'is_super_admin': False,
        'is_faculty_dean': False,
        'is_hod': False,
        'is_lecturer': False,
        'is_student': False,
        'is_exam_officer': False,
        'is_daaa': False,
        'is_senate': False,
        'is_admission_officer': False,
    }

    if request.user.is_authenticated:
        # Get all user roles including delegated ones
        role_names = get_user_roles_with_delegation(request.user)

        context['user_roles'] = role_names
        context['is_super_admin'] = 'SUPER_ADMIN' in role_names
        context['is_faculty_dean'] = 'FACULTY_DEAN' in role_names
        context['is_hod'] = 'HOD' in role_names
        context['is_lecturer'] = 'LECTURER' in role_names
        context['is_student'] = 'STUDENT' in role_names
        context['is_exam_officer'] = 'EXAM_OFFICER' in role_names
        context['is_daaa'] = 'DAAA' in role_names
        context['is_senate'] = 'SENATE' in role_names
        context['is_admission_officer'] = 'ADMISSION_OFFICER' in role_names

        # Get primary role (only from direct roles, not delegated)
        direct_user_roles = request.user.rms_roles.filter(is_temporary=False)
        primary_role = direct_user_roles.filter(is_primary=True).first()
        if primary_role:
            context['primary_role'] = primary_role.role
            context['primary_faculty'] = primary_role.faculty
            context['primary_department'] = primary_role.department
        else:
            context['primary_role'] = None
            context['primary_faculty'] = None
            context['primary_department'] = None

        # Add delegation context for templates
        roles_with_details = get_user_roles_with_details(request.user)
        context['roles_with_details'] = roles_with_details
        context['has_delegated_roles'] = any(role['is_delegated'] for role in roles_with_details)

    return context
