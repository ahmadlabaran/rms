from rest_framework import permissions
from .models import UserRole, PermissionDelegation
from django.db.models import Q


class BaseRolePermission(permissions.BasePermission):
    """Base permission class for role checking with delegation support"""

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        return True

    def get_all_user_roles(self, user):
        """Gets all roles for user including delegated ones"""
        # Get direct roles
        direct_role_list = UserRole.objects.filter(user=user).values_list('role', flat=True)

        # Get delegated roles (temporary roles from active delegations)
        delegated_role_list = UserRole.objects.filter(
            user=user,
            is_temporary=True,
            delegation__status='ACTIVE'
        ).values_list('role', flat=True)

        # Combine and remove duplicates
        all_role_list = list(direct_role_list) + list(delegated_role_list)
        return list(set(all_role_list))

    def get_user_roles_with_details(self, user):
        """Gets all roles for user with delegation details"""
        role_info_list = []

        # Get direct roles
        direct_role_list = UserRole.objects.filter(user=user).select_related('faculty', 'department')
        for role in direct_role_list:
            role_info_list.append({
                'role': role.role,
                'is_delegated': False,
                'is_temporary': role.is_temporary,
                'faculty': role.faculty,
                'department': role.department,
                'delegation': None
            })

        # Get delegated roles
        delegated_role_list = UserRole.objects.filter(
            user=user,
            is_temporary=True,
            delegation__status='ACTIVE'
        ).select_related('faculty', 'department', 'delegation__delegator')

        for role in delegated_role_list:
            role_info_list.append({
                'role': role.role,
                'is_delegated': True,
                'is_temporary': True,
                'faculty': role.faculty,
                'department': role.department,
                'delegation': role.delegation,
                'delegated_from': role.delegation.delegator if role.delegation else None
            })

        return role_info_list

    def check_if_user_has_role(self, user, role):
        """Check if user has specific role (including delegated)"""
        return role in self.get_all_user_roles(user)

    def check_if_user_has_direct_role(self, user, role):
        """Check if user has role directly (not delegated)"""
        direct_role_list = UserRole.objects.filter(user=user, is_temporary=False).values_list('role', flat=True)
        return role in direct_role_list

    def check_if_user_has_delegated_role(self, user, role):
        """Check if user has role through delegation"""
        delegated_role_list = UserRole.objects.filter(
            user=user,
            is_temporary=True,
            delegation__status='ACTIVE'
        ).values_list('role', flat=True)
        return role in delegated_role_list


class IsStudent(BaseRolePermission):
    """Permission for students only"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.check_if_user_has_role(request.user, 'STUDENT')


class IsLecturer(BaseRolePermission):
    """Permission for lecturers only"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.check_if_user_has_role(request.user, 'LECTURER')


class IsAdmissionOfficer(BaseRolePermission):
    """Permission for admission officers only"""
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.check_if_user_has_role(request.user, 'ADMISSION_OFFICER')


class IsExamOfficer(BaseRolePermission):
    """Permission for exam officers only"""
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.check_if_user_has_role(request.user, 'EXAM_OFFICER')


class IsHOD(BaseRolePermission):
    """Permission for HODs only"""
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.check_if_user_has_role(request.user, 'HOD')


class IsFacultyDean(BaseRolePermission):
    """Permission for faculty deans only"""
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.check_if_user_has_role(request.user, 'FACULTY_DEAN')


class IsDAAA(BaseRolePermission):
    """Permission for DAAA only"""
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.check_if_user_has_role(request.user, 'DAAA')


class IsSenate(BaseRolePermission):
    """Permission for senate only"""
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.check_if_user_has_role(request.user, 'SENATE')


class IsSuperAdmin(BaseRolePermission):
    """Permission for super admin only"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.check_if_user_has_role(request.user, 'SUPER_ADMIN')


class IsLecturerOrAbove(BaseRolePermission):
    """Permission for lecturer and above roles"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        allowed_roles = ['LECTURER', 'EXAM_OFFICER', 'HOD', 'FACULTY_DEAN', 'DAAA', 'SENATE', 'SUPER_ADMIN']
        user_roles = self.get_all_user_roles(request.user)
        return any(role in allowed_roles for role in user_roles)


class IsExamOfficerOrAbove(BaseRolePermission):
    """Permission for exam officer and above roles"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        allowed_roles = ['EXAM_OFFICER', 'HOD', 'FACULTY_DEAN', 'DAAA', 'SENATE', 'SUPER_ADMIN']
        user_roles = self.get_all_user_roles(request.user)
        return any(role in allowed_roles for role in user_roles)


class IsAdmissionOfficerOrAbove(BaseRolePermission):
    """Permission for admission officer and above roles (for student management)"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        allowed_roles = ['ADMISSION_OFFICER', 'EXAM_OFFICER', 'FACULTY_DEAN', 'SENATE', 'SUPER_ADMIN']
        user_roles = self.get_all_user_roles(request.user)
        return any(role in allowed_roles for role in user_roles)


class IsHODOrAbove(BaseRolePermission):
    """Permission for HOD and above roles"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        allowed_roles = ['HOD', 'FACULTY_DEAN', 'DAAA', 'SENATE', 'SUPER_ADMIN']
        user_roles = self.get_all_user_roles(request.user)
        return any(role in allowed_roles for role in user_roles)


class IsFacultyDeanOrAbove(BaseRolePermission):
    """Permission for faculty dean and above roles"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        allowed_roles = ['FACULTY_DEAN', 'DAAA', 'SENATE', 'SUPER_ADMIN']
        user_roles = self.get_all_user_roles(request.user)
        return any(role in allowed_roles for role in user_roles)


class IsDAAAAOrAbove(BaseRolePermission):
    """Permission for DAAA and above roles"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        allowed_roles = ['DAAA', 'SENATE', 'SUPER_ADMIN']
        user_roles = self.get_all_user_roles(request.user)
        return any(role in allowed_roles for role in user_roles)


class CanManageResults(BaseRolePermission):
    """Permission for users who can manage results"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        # All roles except students can manage results in some capacity
        allowed_roles = ['LECTURER', 'EXAM_OFFICER', 'HOD', 'FACULTY_DEAN', 'DAAA', 'SENATE', 'SUPER_ADMIN']
        user_roles = self.get_all_user_roles(request.user)
        return any(role in allowed_roles for role in user_roles)


class CanViewTranscripts(BaseRolePermission):
    """Permission for users who can view/generate transcripts"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        # Only DAAA, Senate, and Faculty Deans can view transcripts
        allowed_roles = ['FACULTY_DEAN', 'DAAA', 'SENATE', 'SUPER_ADMIN']
        user_roles = self.get_all_user_roles(request.user)
        return any(role in allowed_roles for role in user_roles)


class CanCreateAlternativeLogins(BaseRolePermission):
    """Permission for users who can create alternative login credentials"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        # Only super admin can create alternative logins
        return self.check_if_user_has_role(request.user, 'SUPER_ADMIN')


# Utility functions for role checking in views
def get_user_roles_with_delegation(user):
    """
    Gets all user roles including delegated ones
    """
    permission_checker = BaseRolePermission()
    return permission_checker.get_all_user_roles(user)


def get_user_roles_with_details(user):
    """
    Gets detailed role information with delegation context
    """
    permission_checker = BaseRolePermission()
    return permission_checker.get_user_roles_with_details(user)


def user_has_role(user, role):
    """
    Checks if user has specific role (including delegated)
    """
    permission_checker = BaseRolePermission()
    return permission_checker.check_if_user_has_role(user, role)


def user_has_any_role(user, role_list):
    """
    Checks if user has any of the specified roles
    """
    user_role_list = get_user_roles_with_delegation(user)
    return any(role in user_role_list for role in role_list)


def get_active_delegations_for_user(user):
    """
    Gets all active delegations where user is the delegate
    """
    delegation_list = PermissionDelegation.objects.filter(
        delegate=user,
        status='ACTIVE'
    ).select_related('delegator', 'delegated_role__user', 'delegated_role__faculty', 'delegated_role__department')
    return delegation_list


def get_delegations_by_user(user):
    """
    Gets all delegations created by the user
    """
    delegation_list = PermissionDelegation.objects.filter(
        delegator=user,
        status='ACTIVE'
    ).select_related('delegate', 'delegated_role__user', 'delegated_role__faculty', 'delegated_role__department')
    return delegation_list
