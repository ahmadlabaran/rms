"""
Context processors for the accounts app.
Provides user role information to all templates.
"""

def user_roles(request):
    """
    Add user role information to template context.
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
    }
    
    if request.user.is_authenticated:
        # Get all user roles
        user_roles = request.user.rms_roles.all()
        role_names = [role.role for role in user_roles]
        
        context['user_roles'] = role_names
        context['is_super_admin'] = 'SUPER_ADMIN' in role_names
        context['is_faculty_dean'] = 'FACULTY_DEAN' in role_names
        context['is_hod'] = 'HOD' in role_names
        context['is_lecturer'] = 'LECTURER' in role_names
        context['is_student'] = 'STUDENT' in role_names
        context['is_exam_officer'] = 'EXAM_OFFICER' in role_names
        context['is_daaa'] = 'DAAA' in role_names
        context['is_senate'] = 'SENATE' in role_names
        
        # Get primary role
        primary_role = user_roles.filter(is_primary=True).first()
        if primary_role:
            context['primary_role'] = primary_role.role
            context['primary_faculty'] = primary_role.faculty
            context['primary_department'] = primary_role.department
        else:
            context['primary_role'] = None
            context['primary_faculty'] = None
            context['primary_department'] = None
    
    return context
