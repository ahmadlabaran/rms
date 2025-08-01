from rest_framework import permissions
from .models import UserRole


class BaseRolePermission(permissions.BasePermission):
    """Base permission class for role-based access control"""

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        return True

    def get_user_roles(self, user):
        """Get all roles for a user"""
        return UserRole.objects.filter(user=user).values_list('role', flat=True)

    def has_role(self, user, role):
        """Check if user has a specific role"""
        return role in self.get_user_roles(user)


class IsStudent(BaseRolePermission):
    """Permission for students only"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.has_role(request.user, 'STUDENT')


class IsLecturer(BaseRolePermission):
    """Permission for lecturers only"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.has_role(request.user, 'LECTURER')


class IsAdmissionOfficer(BaseRolePermission):
    """Permission for admission officers only"""
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.has_role(request.user, 'ADMISSION_OFFICER')


class IsExamOfficer(BaseRolePermission):
    """Permission for exam officers only"""
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.has_role(request.user, 'EXAM_OFFICER')


class IsHOD(BaseRolePermission):
    """Permission for HODs only"""
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.has_role(request.user, 'HOD')


class IsFacultyDean(BaseRolePermission):
    """Permission for faculty deans only"""
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.has_role(request.user, 'FACULTY_DEAN')


class IsDAAA(BaseRolePermission):
    """Permission for DAAA only"""
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.has_role(request.user, 'DAAA')


class IsSenate(BaseRolePermission):
    """Permission for senate only"""
    
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.has_role(request.user, 'SENATE')


class IsSuperAdmin(BaseRolePermission):
    """Permission for super admin only"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return self.has_role(request.user, 'SUPER_ADMIN')


class IsLecturerOrAbove(BaseRolePermission):
    """Permission for lecturer and above roles"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        allowed_roles = ['LECTURER', 'EXAM_OFFICER', 'HOD', 'FACULTY_DEAN', 'DAAA', 'SENATE', 'SUPER_ADMIN']
        user_roles = self.get_user_roles(request.user)
        return any(role in allowed_roles for role in user_roles)


class IsExamOfficerOrAbove(BaseRolePermission):
    """Permission for exam officer and above roles"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        allowed_roles = ['EXAM_OFFICER', 'HOD', 'FACULTY_DEAN', 'DAAA', 'SENATE', 'SUPER_ADMIN']
        user_roles = self.get_user_roles(request.user)
        return any(role in allowed_roles for role in user_roles)


class IsAdmissionOfficerOrAbove(BaseRolePermission):
    """Permission for admission officer and above roles (for student management)"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        allowed_roles = ['ADMISSION_OFFICER', 'EXAM_OFFICER', 'FACULTY_DEAN', 'SENATE', 'SUPER_ADMIN']
        user_roles = self.get_user_roles(request.user)
        return any(role in allowed_roles for role in user_roles)


class IsHODOrAbove(BaseRolePermission):
    """Permission for HOD and above roles"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        allowed_roles = ['HOD', 'FACULTY_DEAN', 'DAAA', 'SENATE', 'SUPER_ADMIN']
        user_roles = self.get_user_roles(request.user)
        return any(role in allowed_roles for role in user_roles)


class IsFacultyDeanOrAbove(BaseRolePermission):
    """Permission for faculty dean and above roles"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        allowed_roles = ['FACULTY_DEAN', 'DAAA', 'SENATE', 'SUPER_ADMIN']
        user_roles = self.get_user_roles(request.user)
        return any(role in allowed_roles for role in user_roles)


class IsDAAAAOrAbove(BaseRolePermission):
    """Permission for DAAA and above roles"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        allowed_roles = ['DAAA', 'SENATE', 'SUPER_ADMIN']
        user_roles = self.get_user_roles(request.user)
        return any(role in allowed_roles for role in user_roles)


class CanManageResults(BaseRolePermission):
    """Permission for users who can manage results"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        # All roles except students can manage results in some capacity
        allowed_roles = ['LECTURER', 'EXAM_OFFICER', 'HOD', 'FACULTY_DEAN', 'DAAA', 'SENATE', 'SUPER_ADMIN']
        user_roles = self.get_user_roles(request.user)
        return any(role in allowed_roles for role in user_roles)


class CanViewTranscripts(BaseRolePermission):
    """Permission for users who can view/generate transcripts"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        # Only DAAA, Senate, and Faculty Deans can view transcripts
        allowed_roles = ['FACULTY_DEAN', 'DAAA', 'SENATE', 'SUPER_ADMIN']
        user_roles = self.get_user_roles(request.user)
        return any(role in allowed_roles for role in user_roles)


class CanCreateAlternativeLogins(BaseRolePermission):
    """Permission for users who can create alternative login credentials"""

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False

        # Only super admin can create alternative logins
        return self.has_role(request.user, 'SUPER_ADMIN')
