import json
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Count
from rest_framework import status, generics, viewsets, serializers
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.models import Token
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.models import User
from django.db.models import Q
from django.utils import timezone
from django.db import transaction
from django.views.decorators.http import require_http_methods
import json
from .security import sanitize_input, validate_email, validate_username, validate_matric_number, validate_name

from .models import (
    AcademicSession, Faculty, Department, Level, Course, CourseAssignment,
    Student, UserRole, AlternativeLogin, Notification, AuditLog, CourseEnrollment,
    Result, ResultApproval, CarryOverList, GradingScale, GradeRange, CarryOverCriteria,
    StudentComplaint, PermissionDelegation, LevelProgression
)
from .serializers import (
    UserSerializer, LoginSerializer, AlternativeLoginSerializer,
    AcademicSessionSerializer, FacultySerializer, DepartmentSerializer,
    LevelSerializer, CourseSerializer, StudentSerializer, CourseEnrollmentSerializer,
    ResultSerializer, ResultApprovalSerializer
)
from .permissions import (
    IsSuperAdmin, IsDAAA, IsFacultyDean, IsHOD, IsAdmissionOfficer,
    IsLecturer, IsStudent, IsDAAAAOrAbove, IsFacultyDeanOrAbove, IsHODOrAbove,
    IsAdmissionOfficerOrAbove, IsLecturerOrAbove, IsHODOrAbove, IsFacultyDeanOrAbove
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def check_if_user_has_access(user, required_role_list):
    """
    Checks if user has required roles or is Super Admin
    Also checks delegated roles and returns proper context
    """
    # Super Admin always has access
    if user.is_superuser:
        # Get first available department/faculty for Super Admin
        first_department = Department.objects.first()
        first_faculty = Faculty.objects.first()
        return True, 'SUPER_ADMIN', first_department, first_faculty

    # Check for specific roles (including SUPER_ADMIN role and delegated roles)
    all_required_role_list = required_role_list + ['SUPER_ADMIN']

    # Check both direct roles and delegated roles
    user_role_list = UserRole.objects.filter(
        user=user,
        role__in=all_required_role_list
    ).filter(
        Q(is_temporary=False) |  # Direct roles
        Q(is_temporary=True, delegation__status='ACTIVE')  # Active delegated roles
    )

    if not user_role_list.exists():
        return False, None, None, None

    # Get the first matching role
    first_user_role = user_role_list.first()

    if first_user_role.role == 'SUPER_ADMIN':
        # Super Admin can access any department/faculty
        first_department = Department.objects.first()
        first_faculty = Faculty.objects.first()
    else:
        # Regular role user
        first_department = first_user_role.department
        first_faculty = first_user_role.faculty

    return True, first_user_role.role, first_department, first_faculty

# ============================================================================
# AUTHENTICATION VIEWS
# ============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    """Standard login for existing website users"""
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']

        # Create or get token
        token, created = Token.objects.get_or_create(user=user)

        # Log the login
        AuditLog.objects.create(
            user=user,
            action='LOGIN',
            model_name='User',
            object_id=str(user.id),
            description=f'User {user.username} logged in via standard login',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return Response({
            'status': 'success',
            'message': 'Login successful',
            'data': {
                'token': token.key,
                'user': UserSerializer(user).data
            }
        }, status=status.HTTP_200_OK)

    return Response({
        'status': 'error',
        'message': 'Invalid credentials',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def alternative_login_view(request):
    """Alternative login using super admin created credentials"""
    serializer = AlternativeLoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        role = serializer.validated_data['role']
        faculty = serializer.validated_data.get('faculty')
        department = serializer.validated_data.get('department')

        # Create or get token
        token, created = Token.objects.get_or_create(user=user)

        # Log the login
        AuditLog.objects.create(
            user=user,
            action='LOGIN',
            model_name='AlternativeLogin',
            object_id=str(user.id),
            description=f'User {user.username} logged in via alternative login as {role}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return Response({
            'status': 'success',
            'message': 'Alternative login successful',
            'data': {
                'token': token.key,
                'user': UserSerializer(user).data,
                'active_role': {
                    'role': role,
                    'faculty': faculty.name if faculty else None,
                    'department': department.name if department else None
                }
            }
        }, status=status.HTTP_200_OK)

    return Response({
        'status': 'error',
        'message': 'Invalid credentials',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """Logout user and delete token"""
    try:
        # Delete the user's token
        request.user.auth_token.delete()

        # Log the logout
        AuditLog.objects.create(
            user=request.user,
            action='LOGOUT',
            model_name='User',
            object_id=str(request.user.id),
            description=f'User {request.user.username} logged out',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return Response({
            'status': 'success',
            'message': 'Logout successful'
        }, status=status.HTTP_200_OK)
    except:
        return Response({
            'status': 'error',
            'message': 'Error during logout'
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def current_user_view(request):
    """Get current user information with roles"""
    return Response({
        'status': 'success',
        'data': UserSerializer(request.user).data
    }, status=status.HTTP_200_OK)


# ============================================================================
# ACADEMIC STRUCTURE VIEWS
# ============================================================================

class AcademicSessionViewSet(viewsets.ModelViewSet):
    """ViewSet for Academic Sessions - DAAA and Super Admin"""
    queryset = AcademicSession.objects.all().order_by('-created_at')
    serializer_class = AcademicSessionSerializer

    def get_permissions(self):
        """Allow DAAA and Super Admin to manage sessions"""
        permission_classes = [IsDAAAAOrAbove]  # This includes DAAA, Senate, and Super Admin
        return [permission() for permission in permission_classes]

    def perform_create(self, serializer):
        # Ensure only one active session
        if serializer.validated_data.get('is_active', False):
            AcademicSession.objects.filter(is_active=True).update(is_active=False)

        serializer.save(created_by=self.request.user)

        # Log the action
        AuditLog.objects.create(
            user=self.request.user,
            action='CREATE',
            model_name='AcademicSession',
            object_id=str(serializer.instance.id),
            description=f'Created academic session: {serializer.instance.name}',
            ip_address=self.request.META.get('REMOTE_ADDR')
        )

    @action(detail=True, methods=['patch'])
    def toggle_lock(self, request, pk=None):
        """Lock or unlock a session"""
        session = self.get_object()
        session.is_locked = not session.is_locked
        session.save()

        action_desc = 'locked' if session.is_locked else 'unlocked'
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            model_name='AcademicSession',
            object_id=str(session.id),
            description=f'Session {session.name} {action_desc}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return Response({
            'status': 'success',
            'message': f'Session {action_desc} successfully',
            'data': self.get_serializer(session).data
        })

    @action(detail=False, methods=['get'])
    def active(self, request):
        """Get the currently active session"""
        try:
            active_session = AcademicSession.objects.get(is_active=True)
            return Response({
                'status': 'success',
                'data': self.get_serializer(active_session).data
            })
        except AcademicSession.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'No active session found'
            }, status=status.HTTP_404_NOT_FOUND)


class FacultyViewSet(viewsets.ModelViewSet):
    """ViewSet for Faculties"""
    queryset = Faculty.objects.all().order_by('name')
    serializer_class = FacultySerializer

    def get_permissions(self):
        """Different permissions for different actions"""
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            permission_classes = [IsSuperAdmin]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def perform_create(self, serializer):
        serializer.save()

        AuditLog.objects.create(
            user=self.request.user,
            action='CREATE',
            model_name='Faculty',
            object_id=str(serializer.instance.id),
            description=f'Created faculty: {serializer.instance.name}',
            ip_address=self.request.META.get('REMOTE_ADDR')
        )

    @action(detail=True, methods=['get'])
    def departments(self, request, pk=None):
        """Get departments in this faculty"""
        faculty = self.get_object()
        departments = Department.objects.filter(faculty=faculty)
        serializer = DepartmentSerializer(departments, many=True)
        return Response({
            'status': 'success',
            'data': serializer.data
        })


class DepartmentViewSet(viewsets.ModelViewSet):
    """ViewSet for Departments"""
    serializer_class = DepartmentSerializer

    def get_queryset(self):
        """Filter departments based on user role"""
        user_roles = UserRole.objects.filter(user=self.request.user)

        # Super admin sees all
        if user_roles.filter(role='SUPER_ADMIN').exists():
            return Department.objects.all().order_by('name')

        # Faculty dean sees their faculty's departments
        faculty_dean_roles = user_roles.filter(role='FACULTY_DEAN')
        if faculty_dean_roles.exists():
            faculties = [role.faculty for role in faculty_dean_roles if role.faculty]
            return Department.objects.filter(faculty__in=faculties).order_by('name')

        # HOD sees their department
        hod_roles = user_roles.filter(role='HOD')
        if hod_roles.exists():
            departments = [role.department for role in hod_roles if role.department]
            return Department.objects.filter(id__in=[d.id for d in departments]).order_by('name')

        # Others see departments in their faculty
        faculties = [role.faculty for role in user_roles if role.faculty]
        return Department.objects.filter(faculty__in=faculties).order_by('name')

    def get_permissions(self):
        """Different permissions for different actions"""
        if self.action in ['create']:
            permission_classes = [IsFacultyDeanOrAbove]  # Includes Faculty Dean, DAAA, Senate, Super Admin
        elif self.action in ['update', 'partial_update']:
            permission_classes = [IsHODOrAbove]  # Includes HOD, Faculty Dean, DAAA, Senate, Super Admin
        elif self.action in ['destroy']:
            permission_classes = [IsSuperAdmin]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def perform_create(self, serializer):
        serializer.save()

        AuditLog.objects.create(
            user=self.request.user,
            action='CREATE',
            model_name='Department',
            object_id=str(serializer.instance.id),
            description=f'Created department: {serializer.instance.name}',
            ip_address=self.request.META.get('REMOTE_ADDR')
        )


class LevelViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for Academic Levels - Read only"""
    queryset = Level.objects.all().order_by('numeric_value')
    serializer_class = LevelSerializer
    permission_classes = [IsAuthenticated]


class CourseViewSet(viewsets.ModelViewSet):
    """ViewSet for Courses"""
    serializer_class = CourseSerializer

    def get_queryset(self):
        """Filter courses based on user role and search parameters"""
        user_roles = UserRole.objects.filter(user=self.request.user)

        # Base queryset
        queryset = Course.objects.all()

        # Apply role-based filtering
        if user_roles.filter(role='SUPER_ADMIN').exists():
            # Super admin sees all courses
            pass
        elif user_roles.filter(role='DAAA').exists():
            # DAAA sees all courses
            pass
        elif user_roles.filter(role='FACULTY_DEAN').exists():
            # Faculty dean sees courses in their faculty
            faculties = [role.faculty for role in user_roles.filter(role='FACULTY_DEAN') if role.faculty]
            queryset = queryset.filter(departments__faculty__in=faculties)
        elif user_roles.filter(role='HOD').exists():
            # HOD sees courses in their department
            departments = [role.department for role in user_roles.filter(role='HOD') if role.department]
            queryset = queryset.filter(departments__in=departments)
        elif user_roles.filter(role='LECTURER').exists():
            # Lecturer sees only assigned courses
            lecturer_courses = CourseAssignment.objects.filter(
                lecturer=self.request.user
            ).values_list('course', flat=True)
            queryset = queryset.filter(id__in=lecturer_courses)
        else:
            # Students and others see courses in their faculty
            faculties = [role.faculty for role in user_roles if role.faculty]
            queryset = queryset.filter(departments__faculty__in=faculties)

        # Apply search filters
        search = self.request.query_params.get('search', '')
        if search:
            queryset = queryset.filter(
                Q(title__icontains=search) |
                Q(code__icontains=search)
            )

        # Filter by level
        level = self.request.query_params.get('level', '')
        if level:
            queryset = queryset.filter(level__name=level)

        # Filter by department
        department = self.request.query_params.get('department', '')
        if department:
            queryset = queryset.filter(departments__name__icontains=department)

        return queryset.distinct().order_by('code')

    def get_permissions(self):
        """Different permissions for different actions"""
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            permission_classes = [IsHODOrAbove]  # Includes HOD, Faculty Dean, DAAA, Senate, Super Admin
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def perform_create(self, serializer):
        # Set the current active session
        try:
            active_session = AcademicSession.objects.get(is_active=True)
            serializer.save(created_by=self.request.user, session=active_session)
        except AcademicSession.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'No active session found. Cannot create course.'
            }, status=status.HTTP_400_BAD_REQUEST)

        AuditLog.objects.create(
            user=self.request.user,
            action='CREATE',
            model_name='Course',
            object_id=str(serializer.instance.id),
            description=f'Created course: {serializer.instance.code} - {serializer.instance.title}',
            ip_address=self.request.META.get('REMOTE_ADDR')
        )

    @action(detail=True, methods=['post'])
    def assign_lecturer(self, request, pk=None):
        """Assign lecturer to course - Faculty Dean only"""
        if not UserRole.objects.filter(user=request.user, role='FACULTY_DEAN').exists():
            return Response({
                'status': 'error',
                'message': 'Only Faculty Deans can assign lecturers'
            }, status=status.HTTP_403_FORBIDDEN)

        course = self.get_object()
        lecturer_id = request.data.get('lecturer_id')

        try:
            lecturer = User.objects.get(id=lecturer_id)

            # Check if lecturer role exists
            if not UserRole.objects.filter(user=lecturer, role='LECTURER').exists():
                return Response({
                    'status': 'error',
                    'message': 'User is not a lecturer'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Create assignment
            assignment, created = CourseAssignment.objects.get_or_create(
                course=course,
                lecturer=lecturer,
                defaults={'assigned_by': request.user}
            )

            if created:
                AuditLog.objects.create(
                    user=request.user,
                    action='CREATE',
                    model_name='CourseAssignment',
                    object_id=str(assignment.id),
                    description=f'Assigned {lecturer.get_full_name()} to course {course.code}',
                    ip_address=request.META.get('REMOTE_ADDR')
                )

                return Response({
                    'status': 'success',
                    'message': 'Lecturer assigned successfully'
                })
            else:
                return Response({
                    'status': 'error',
                    'message': 'Lecturer already assigned to this course'
                }, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'Lecturer not found'
            }, status=status.HTTP_404_NOT_FOUND)


# ============================================================================
# STUDENT MANAGEMENT VIEWS
# ============================================================================

class StudentViewSet(viewsets.ModelViewSet):
    """ViewSet for Students"""
    serializer_class = StudentSerializer

    def get_queryset(self):
        """Filter students based on user role and search parameters"""
        user_roles = UserRole.objects.filter(user=self.request.user)

        # Base queryset - empty by default (search required)
        queryset = Student.objects.none()

        # Only show results if search parameters are provided
        search = self.request.query_params.get('search', '')
        faculty_filter = self.request.query_params.get('faculty', '')
        department_filter = self.request.query_params.get('department', '')
        level_filter = self.request.query_params.get('level', '')

        if search or faculty_filter or department_filter or level_filter:
            # Start with all students
            queryset = Student.objects.all()

            # Apply role-based filtering
            if user_roles.filter(role='SUPER_ADMIN').exists():
                # Super admin sees all students
                pass
            elif user_roles.filter(role='DAAA').exists():
                # DAAA sees all students
                pass
            elif user_roles.filter(role='FACULTY_DEAN').exists():
                # Faculty dean sees students in their faculty
                faculties = [role.faculty for role in user_roles.filter(role='FACULTY_DEAN') if role.faculty]
                queryset = queryset.filter(faculty__in=faculties)
            elif user_roles.filter(role='HOD').exists():
                # HOD sees students in their department
                departments = [role.department for role in user_roles.filter(role='HOD') if role.department]
                queryset = queryset.filter(department__in=departments)
            elif user_roles.filter(role='LECTURER').exists():
                # Lecturer sees students enrolled in their courses
                lecturer_courses = CourseAssignment.objects.filter(
                    lecturer=self.request.user
                ).values_list('course', flat=True)
                enrolled_students = CourseEnrollment.objects.filter(
                    course__in=lecturer_courses
                ).values_list('student', flat=True)
                queryset = queryset.filter(id__in=enrolled_students)
            else:
                # Others see students in their faculty
                faculties = [role.faculty for role in user_roles if role.faculty]
                queryset = queryset.filter(faculty__in=faculties)

            # Apply search filters
            if search:
                queryset = queryset.filter(
                    Q(matric_number__icontains=search) |
                    Q(user__first_name__icontains=search) |
                    Q(user__last_name__icontains=search) |
                    Q(user__email__icontains=search)
                )

            if faculty_filter:
                queryset = queryset.filter(faculty__name__icontains=faculty_filter)

            if department_filter:
                queryset = queryset.filter(department__name__icontains=department_filter)

            if level_filter:
                queryset = queryset.filter(current_level__name=level_filter)

        return queryset.distinct().order_by('matric_number')

    def get_permissions(self):
        """Different permissions for different actions"""
        if self.action in ['create']:
            permission_classes = [IsAdmissionOfficerOrAbove]  # Admission Officer, Exam Officer, Faculty Dean, Senate, Super Admin
        elif self.action in ['update', 'partial_update']:
            permission_classes = [IsAdmissionOfficerOrAbove]  # Same roles for updates
        elif self.action in ['destroy']:
            permission_classes = [IsSuperAdmin]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

        AuditLog.objects.create(
            user=self.request.user,
            action='CREATE',
            model_name='Student',
            object_id=str(serializer.instance.id),
            description=f'Created student: {serializer.instance.matric_number}',
            ip_address=self.request.META.get('REMOTE_ADDR')
        )


# ============================================================================
# USER ROLE MANAGEMENT VIEWS (Super Admin)
# ============================================================================

@api_view(['GET'])
@permission_classes([IsSuperAdmin])
def list_users(request):
    """List all users for role management"""
    search = request.GET.get('search', '')

    if search:
        users = User.objects.filter(
            Q(username__icontains=search) |
            Q(first_name__icontains=search) |
            Q(last_name__icontains=search) |
            Q(email__icontains=search)
        ).order_by('username')
    else:
        users = User.objects.none()  # Empty by default

    serializer = UserSerializer(users, many=True)
    return Response({
        'status': 'success',
        'data': serializer.data
    })


@api_view(['POST'])
@permission_classes([IsSuperAdmin])
def assign_role(request, user_id):
    """Assign role to user"""
    try:
        user = User.objects.get(id=user_id)
        role = request.data.get('role')
        faculty_id = request.data.get('faculty_id')
        department_id = request.data.get('department_id')
        is_primary = request.data.get('is_primary', False)

        # Validate role
        valid_roles = [choice[0] for choice in UserRole.ROLE_CHOICES]
        if role not in valid_roles:
            return Response({
                'status': 'error',
                'message': 'Invalid role'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get faculty and department if provided
        faculty = None
        department = None
        if faculty_id:
            try:
                faculty = Faculty.objects.get(id=faculty_id)
            except Faculty.DoesNotExist:
                return Response({
                    'status': 'error',
                    'message': 'Faculty not found'
                }, status=status.HTTP_404_NOT_FOUND)

        if department_id:
            try:
                department = Department.objects.get(id=department_id)
            except Department.DoesNotExist:
                return Response({
                    'status': 'error',
                    'message': 'Department not found'
                }, status=status.HTTP_404_NOT_FOUND)

        # Create role assignment
        user_role, created = UserRole.objects.get_or_create(
            user=user,
            role=role,
            faculty=faculty,
            department=department,
            defaults={
                'is_primary': is_primary,
                'created_by': request.user
            }
        )

        if created:
            AuditLog.objects.create(
                user=request.user,
                action='ROLE_ASSIGN',
                model_name='UserRole',
                object_id=str(user_role.id),
                description=f'Assigned role {role} to {user.username}',
                ip_address=request.META.get('REMOTE_ADDR')
            )

            return Response({
                'status': 'success',
                'message': 'Role assigned successfully'
            })
        else:
            return Response({
                'status': 'error',
                'message': 'User already has this role'
            }, status=status.HTTP_400_BAD_REQUEST)

    except User.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'User not found'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['DELETE'])
@permission_classes([IsSuperAdmin])
def remove_role(request, user_id, role_id):
    """Remove role from user"""
    try:
        user_role = UserRole.objects.get(id=role_id, user_id=user_id)

        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            model_name='UserRole',
            object_id=str(user_role.id),
            description=f'Removed role {user_role.role} from {user_role.user.username}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        user_role.delete()

        return Response({
            'status': 'success',
            'message': 'Role removed successfully'
        })

    except UserRole.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'Role assignment not found'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([IsSuperAdmin])
def create_alternative_login(request, user_id):
    """Create alternative login credentials for user"""
    try:
        user = User.objects.get(id=user_id)
        username = request.data.get('username')
        password = request.data.get('password')
        role = request.data.get('role')
        faculty_id = request.data.get('faculty_id')
        department_id = request.data.get('department_id')

        # Validate required fields
        if not all([username, password, role]):
            return Response({
                'status': 'error',
                'message': 'Username, password, and role are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if username already exists
        if AlternativeLogin.objects.filter(username=username).exists():
            return Response({
                'status': 'error',
                'message': 'Username already exists'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get faculty and department if provided
        faculty = None
        department = None
        if faculty_id:
            faculty = Faculty.objects.get(id=faculty_id)
        if department_id:
            department = Department.objects.get(id=department_id)

        # Create alternative login
        alt_login = AlternativeLogin.objects.create(
            user=user,
            username=username,
            password=password,  # In production, hash this password
            role=role,
            faculty=faculty,
            department=department,
            created_by=request.user
        )

        AuditLog.objects.create(
            user=request.user,
            action='CREATE',
            model_name='AlternativeLogin',
            object_id=str(alt_login.id),
            description=f'Created alternative login {username} for {user.username}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return Response({
            'status': 'success',
            'message': 'Alternative login created successfully'
        })

    except User.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'User not found'
        }, status=status.HTTP_404_NOT_FOUND)
    except Faculty.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'Faculty not found'
        }, status=status.HTTP_404_NOT_FOUND)
    except Department.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'Department not found'
        }, status=status.HTTP_404_NOT_FOUND)


# ============================================================================
# UNIVERSAL EXTERNAL INTEGRATION VIEWS
# ============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
def external_authenticate(request):
    """
    Universal authentication endpoint for ANY external website/application.

    Usage:
    POST /api/external/authenticate/
    {
        "username": "user123",
        "password": "password123"
    }

    Response:
    {
        "status": "success",
        "data": {
            "token": "abc123...",
            "user": {...},
            "expires_in": 86400
        }
    }
    """
    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return Response({
            'status': 'error',
            'message': 'Username and password are required',
            'errors': {
                'username': 'This field is required' if not username else None,
                'password': 'This field is required' if not password else None
            }
        }, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(username=username, password=password)
    if user and user.is_active:
        # Create or get API token
        token, created = Token.objects.get_or_create(user=user)

        # Log the external authentication
        AuditLog.objects.create(
            user=user,
            action='LOGIN',
            model_name='ExternalAuth',
            object_id=str(user.id),
            description=f'User {user.username} authenticated via external API',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return Response({
            'status': 'success',
            'message': 'Authentication successful',
            'data': {
                'token': token.key,
                'user': UserSerializer(user).data,
                'expires_in': 86400,  # 24 hours
                'api_base_url': request.build_absolute_uri('/api/'),
                'usage': {
                    'authorization_header': f'Token {token.key}',
                    'example_request': 'Authorization: Token ' + token.key
                }
            }
        })

    return Response({
        'status': 'error',
        'message': 'Invalid username or password'
    }, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def validate_token(request):
    """
    Validate if an API token is still valid.

    Usage:
    GET /api/external/validate/
    Authorization: Token abc123...

    Response:
    {
        "status": "success",
        "data": {
            "valid": true,
            "user": {...}
        }
    }
    """
    return Response({
        'status': 'success',
        'message': 'Token is valid',
        'data': {
            'valid': True,
            'user': UserSerializer(request.user).data,
            'token_info': {
                'created': request.auth.created if hasattr(request.auth, 'created') else None,
                'last_used': timezone.now().isoformat()
            }
        }
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def revoke_token(request):
    """
    Revoke/logout the current API token.

    Usage:
    POST /api/external/revoke/
    Authorization: Token abc123...

    Response:
    {
        "status": "success",
        "message": "Token revoked successfully"
    }
    """
    try:
        # Delete the current token
        request.auth.delete()

        # Log the logout
        AuditLog.objects.create(
            user=request.user,
            action='LOGOUT',
            model_name='ExternalAuth',
            object_id=str(request.user.id),
            description=f'User {request.user.username} revoked API token',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return Response({
            'status': 'success',
            'message': 'Token revoked successfully'
        })
    except Exception as e:
        return Response({
            'status': 'error',
            'message': 'Failed to revoke token'
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([AllowAny])
def api_documentation(request):
    """
    API documentation endpoint for external integrators.

    Usage:
    GET /api/external/docs/

    Returns comprehensive API documentation.
    """
    base_url = request.build_absolute_uri('/api/')

    return Response({
        'status': 'success',
        'data': {
            'api_name': 'RMS (Result Management System) API',
            'version': '1.0',
            'base_url': base_url,
            'authentication': {
                'type': 'Token Authentication',
                'header': 'Authorization: Token <your_token>',
                'obtain_token': f'{base_url}external/authenticate/',
                'validate_token': f'{base_url}external/validate/',
                'revoke_token': f'{base_url}external/revoke/'
            },
            'endpoints': {
                'authentication': {
                    'login': f'{base_url}auth/login/',
                    'logout': f'{base_url}auth/logout/',
                    'current_user': f'{base_url}auth/user/',
                    'external_auth': f'{base_url}external/authenticate/'
                },
                'academic_structure': {
                    'sessions': f'{base_url}sessions/',
                    'faculties': f'{base_url}faculties/',
                    'departments': f'{base_url}departments/',
                    'levels': f'{base_url}levels/',
                    'courses': f'{base_url}courses/'
                },
                'user_management': {
                    'students': f'{base_url}students/',
                    'users': f'{base_url}users/'
                }
            },
            'response_format': {
                'success': {
                    'status': 'success',
                    'data': '...',
                    'message': 'Optional success message'
                },
                'error': {
                    'status': 'error',
                    'message': 'Error description',
                    'errors': 'Optional detailed errors'
                }
            },
            'rate_limits': {
                'anonymous': '100 requests per hour',
                'authenticated': '1000 requests per hour'
            }
        }
    })


# ============================================================================
# COURSE ENROLLMENT AND RESULTS MANAGEMENT VIEWS
# ============================================================================

class CourseEnrollmentViewSet(viewsets.ModelViewSet):
    """ViewSet for Course Enrollments"""
    serializer_class = CourseEnrollmentSerializer

    def get_queryset(self):
        """Filter enrollments based on user role"""
        user_roles = UserRole.objects.filter(user=self.request.user)

        # Base queryset
        queryset = CourseEnrollment.objects.all()

        # Apply role-based filtering
        if user_roles.filter(role='SUPER_ADMIN').exists():
            # Super admin sees all enrollments
            pass
        elif user_roles.filter(role='LECTURER').exists():
            # Lecturer sees enrollments for their courses
            lecturer_courses = CourseAssignment.objects.filter(
                lecturer=self.request.user
            ).values_list('course', flat=True)
            queryset = queryset.filter(course__in=lecturer_courses)
        elif user_roles.filter(role='HOD').exists():
            # HOD sees enrollments in their department
            departments = [role.department for role in user_roles.filter(role='HOD') if role.department]
            queryset = queryset.filter(course__departments__in=departments)
        elif user_roles.filter(role='FACULTY_DEAN').exists():
            # Faculty dean sees enrollments in their faculty
            faculties = [role.faculty for role in user_roles.filter(role='FACULTY_DEAN') if role.faculty]
            queryset = queryset.filter(course__departments__faculty__in=faculties)
        else:
            # Others see limited enrollments
            queryset = CourseEnrollment.objects.none()

        return queryset.distinct().order_by('-enrolled_at')

    def get_permissions(self):
        """Different permissions for different actions"""
        if self.action in ['create']:
            permission_classes = [IsLecturerOrAbove]  # Lecturer and above can enroll students
        elif self.action in ['destroy']:
            permission_classes = [IsHODOrAbove]  # HOD and above can remove enrollments
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def perform_create(self, serializer):
        # Set current active session if not provided
        if not serializer.validated_data.get('session'):
            try:
                active_session = AcademicSession.objects.get(is_active=True)
                serializer.save(enrolled_by=self.request.user, session=active_session)
            except AcademicSession.DoesNotExist:
                raise serializers.ValidationError("No active session found")
        else:
            serializer.save(enrolled_by=self.request.user)

        AuditLog.objects.create(
            user=self.request.user,
            action='CREATE',
            model_name='CourseEnrollment',
            object_id=str(serializer.instance.id),
            description=f'Enrolled {serializer.instance.student.matric_number} in {serializer.instance.course.code}',
            ip_address=self.request.META.get('REMOTE_ADDR')
        )


class ResultViewSet(viewsets.ModelViewSet):
    """ViewSet for Results Management"""
    serializer_class = ResultSerializer

    def get_queryset(self):
        """Filter results based on user role"""
        user_roles = UserRole.objects.filter(user=self.request.user)

        # Base queryset
        queryset = Result.objects.all()

        # Apply role-based filtering
        if user_roles.filter(role='SUPER_ADMIN').exists():
            # Super admin sees all results
            pass
        elif user_roles.filter(role='DAAA').exists():
            # DAAA sees all results
            pass
        elif user_roles.filter(role='LECTURER').exists():
            # Lecturer sees results for their courses only
            lecturer_courses = CourseAssignment.objects.filter(
                lecturer=self.request.user
            ).values_list('course', flat=True)
            queryset = queryset.filter(enrollment__course__in=lecturer_courses)
        elif user_roles.filter(role='HOD').exists():
            # HOD sees results in their department
            departments = [role.department for role in user_roles.filter(role='HOD') if role.department]
            queryset = queryset.filter(enrollment__course__departments__in=departments)
        elif user_roles.filter(role='FACULTY_DEAN').exists():
            # Faculty dean sees results in their faculty
            faculties = [role.faculty for role in user_roles.filter(role='FACULTY_DEAN') if role.faculty]
            queryset = queryset.filter(enrollment__course__departments__faculty__in=faculties)
        else:
            # Others see limited results
            queryset = Result.objects.none()

        return queryset.distinct().order_by('-created_at')

    def get_permissions(self):
        """Different permissions for different actions"""
        if self.action in ['create', 'update', 'partial_update']:
            permission_classes = [IsLecturerOrAbove]  # Lecturer and above can enter/edit results
        elif self.action in ['destroy']:
            permission_classes = [IsSuperAdmin]  # Only Super Admin can delete results
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def perform_create(self, serializer):
        # Results are linked to enrollments, so no need to set session separately
        serializer.save(
            created_by=self.request.user,
            last_modified_by=self.request.user
        )

        AuditLog.objects.create(
            user=self.request.user,
            action='CREATE',
            model_name='Result',
            object_id=str(serializer.instance.id),
            description=f'Entered result for {serializer.instance.enrollment.student.matric_number} in {serializer.instance.enrollment.course.code}',
            ip_address=self.request.META.get('REMOTE_ADDR')
        )

    @action(detail=True, methods=['post'])
    def submit_to_exam_officer(self, request, pk=None):
        """Submit result to Exam Officer - Lecturer only"""
        result = self.get_object()

        if result.status != 'DRAFT':
            return Response({
                'status': 'error',
                'message': 'Result must be in DRAFT status to submit to Exam Officer'
            }, status=status.HTTP_400_BAD_REQUEST)

        result.status = 'SUBMITTED_TO_EXAM_OFFICER'
        result.last_modified_by = request.user
        result.save()

        return Response({
            'status': 'success',
            'message': 'Result submitted to Exam Officer successfully',
            'data': self.get_serializer(result).data
        })

    @action(detail=True, methods=['post'])
    def submit_to_hod(self, request, pk=None):
        """Submit result to HOD - Exam Officer only"""
        result = self.get_object()

        if result.status != 'APPROVED_BY_EXAM_OFFICER':
            return Response({
                'status': 'error',
                'message': 'Result must be approved by Exam Officer first'
            }, status=status.HTTP_400_BAD_REQUEST)

        result.status = 'SUBMITTED_TO_HOD'
        result.last_modified_by = request.user
        result.save()

        return Response({
            'status': 'success',
            'message': 'Result submitted to HOD successfully',
            'data': self.get_serializer(result).data
        })

    @action(detail=True, methods=['post'])
    def submit_to_dean(self, request, pk=None):
        """Submit result to Faculty Dean - HOD only"""
        result = self.get_object()

        if result.status != 'APPROVED_BY_HOD':
            return Response({
                'status': 'error',
                'message': 'Result must be approved by HOD first'
            }, status=status.HTTP_400_BAD_REQUEST)

        result.status = 'SUBMITTED_TO_DEAN'
        result.last_modified_by = request.user
        result.save()

        return Response({
            'status': 'success',
            'message': 'Result submitted to Faculty Dean successfully',
            'data': self.get_serializer(result).data
        })

    @action(detail=True, methods=['post'])
    def submit_to_daaa(self, request, pk=None):
        """Submit result to DAAA - Faculty Dean only"""
        result = self.get_object()

        if result.status != 'APPROVED_BY_DEAN':
            return Response({
                'status': 'error',
                'message': 'Result must be approved by Faculty Dean first'
            }, status=status.HTTP_400_BAD_REQUEST)

        result.status = 'SUBMITTED_TO_DAAA'
        result.last_modified_by = request.user
        result.save()

        return Response({
            'status': 'success',
            'message': 'Result submitted to DAAA successfully',
            'data': self.get_serializer(result).data
        })

    @action(detail=True, methods=['post'])
    def submit_to_senate(self, request, pk=None):
        """Submit result to Senate - DAAA only"""
        result = self.get_object()

        if result.status != 'APPROVED_BY_DAAA':
            return Response({
                'status': 'error',
                'message': 'Result must be approved by DAAA first'
            }, status=status.HTTP_400_BAD_REQUEST)

        result.status = 'SUBMITTED_TO_SENATE'
        result.last_modified_by = request.user
        result.save()

        return Response({
            'status': 'success',
            'message': 'Result submitted to Senate successfully',
            'data': self.get_serializer(result).data
        })

    @action(detail=True, methods=['post'])
    def publish(self, request, pk=None):
        """Publish result - Senate only"""
        result = self.get_object()

        if result.status != 'SUBMITTED_TO_SENATE':
            return Response({
                'status': 'error',
                'message': 'Result must be submitted to Senate first'
            }, status=status.HTTP_400_BAD_REQUEST)

        result.status = 'PUBLISHED'
        result.last_modified_by = request.user
        result.save()

        return Response({
            'status': 'success',
            'message': 'Result published successfully',
            'data': self.get_serializer(result).data
        })


class ResultApprovalViewSet(viewsets.ModelViewSet):
    """ViewSet for Result Approval Workflow"""
    serializer_class = ResultApprovalSerializer

    def get_queryset(self):
        """Filter approvals based on user role"""
        user_roles = UserRole.objects.filter(user=self.request.user)

        # Base queryset
        queryset = ResultApproval.objects.all()

        # Apply role-based filtering
        if user_roles.filter(role='SUPER_ADMIN').exists():
            # Super admin sees all approvals
            pass
        elif user_roles.filter(role='DAAA').exists():
            # DAAA sees all approvals
            pass
        elif user_roles.filter(role='SENATE').exists():
            # Senate sees all approvals
            pass
        elif user_roles.filter(role='FACULTY_DEAN').exists():
            # Faculty dean sees approvals in their faculty
            faculties = [role.faculty for role in user_roles.filter(role='FACULTY_DEAN') if role.faculty]
            queryset = queryset.filter(result__enrollment__course__departments__faculty__in=faculties)
        elif user_roles.filter(role='HOD').exists():
            # HOD sees approvals in their department
            departments = [role.department for role in user_roles.filter(role='HOD') if role.department]
            queryset = queryset.filter(result__enrollment__course__departments__in=departments)
        elif user_roles.filter(role='EXAM_OFFICER').exists():
            # Exam Officer sees approvals in their faculty/department
            faculties = [role.faculty for role in user_roles.filter(role='EXAM_OFFICER') if role.faculty]
            departments = [role.department for role in user_roles.filter(role='EXAM_OFFICER') if role.department]
            if faculties:
                queryset = queryset.filter(result__enrollment__course__departments__faculty__in=faculties)
            elif departments:
                queryset = queryset.filter(result__enrollment__course__departments__in=departments)
        else:
            # Others see limited approvals
            queryset = ResultApproval.objects.none()

        return queryset.distinct().order_by('-timestamp')

    def get_permissions(self):
        """Different permissions for different actions"""
        if self.action in ['create']:
            # Anyone involved in the approval process can create approvals
            permission_classes = [IsLecturerOrAbove]
        elif self.action in ['update', 'partial_update']:
            # Only the person who created the approval can modify it
            permission_classes = [IsAuthenticated]
        elif self.action in ['destroy']:
            permission_classes = [IsSuperAdmin]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def perform_create(self, serializer):
        # Determine the role based on the current user's roles
        user_roles = UserRole.objects.filter(user=self.request.user)

        # Set the role based on what role the user is acting as
        role = 'LECTURER'  # Default
        if user_roles.filter(role='EXAM_OFFICER').exists():
            role = 'EXAM_OFFICER'
        elif user_roles.filter(role='HOD').exists():
            role = 'HOD'
        elif user_roles.filter(role='FACULTY_DEAN').exists():
            role = 'FACULTY_DEAN'
        elif user_roles.filter(role='DAAA').exists():
            role = 'DAAA'
        elif user_roles.filter(role='SENATE').exists():
            role = 'SENATE'

        serializer.save(user=self.request.user, role=role)

        # Update the result status based on the approval action
        result = serializer.instance.result
        action = serializer.instance.action

        if action == 'APPROVED':
            # Move to next stage based on current status
            if result.status == 'SUBMITTED_TO_EXAM_OFFICER':
                result.status = 'APPROVED_BY_EXAM_OFFICER'
            elif result.status == 'SUBMITTED_TO_HOD':
                result.status = 'APPROVED_BY_HOD'
            elif result.status == 'SUBMITTED_TO_DEAN':
                result.status = 'APPROVED_BY_DEAN'
            elif result.status == 'SUBMITTED_TO_DAAA':
                result.status = 'APPROVED_BY_DAAA'
            elif result.status == 'SUBMITTED_TO_SENATE':
                result.status = 'PUBLISHED'
        elif action == 'REJECTED':
            result.status = 'REJECTED'

        result.last_modified_by = self.request.user
        result.save()

        AuditLog.objects.create(
            user=self.request.user,
            action='APPROVAL',
            model_name='ResultApproval',
            object_id=str(serializer.instance.id),
            description=f'{action} result for {result.enrollment.student.matric_number} in {result.enrollment.course.code}',
            ip_address=self.request.META.get('REMOTE_ADDR')
        )


# ============================================================================
# WEB INTERFACE VIEWS (iOS Aesthetic)
# ============================================================================

@login_required
def dashboard_view(request):
    """Main dashboard that shows different content based on user role"""
    # Get all user roles including delegated ones
    user_role_list = UserRole.objects.filter(user=request.user).filter(
        Q(is_temporary=False) |  # Direct roles
        Q(is_temporary=True, delegation__status='ACTIVE')  # Active delegated roles
    ).select_related('faculty', 'department', 'delegation')

    # Redirect to role-specific dashboards if user has specific roles
    if user_role_list.filter(role='FACULTY_DEAN').exists():
        return redirect('faculty_dean_dashboard')
    elif user_role_list.filter(role='LECTURER').exists():
        return redirect('lecturer_dashboard')
    elif user_role_list.filter(role='EXAM_OFFICER').exists():
        return redirect('exam_officer_dashboard')
    elif user_role_list.filter(role='HOD').exists():
        return redirect('hod_dashboard')
    elif user_role_list.filter(role='DAAA').exists():
        return redirect('daaa_dashboard')
    elif user_role_list.filter(role='SENATE').exists():
        return redirect('senate_dashboard')
    elif user_role_list.filter(role='STUDENT').exists():
        return redirect('student_dashboard')
    elif user_role_list.filter(role='ADMISSION_OFFICER').exists():
        return redirect('admission_officer_dashboard')
    elif user_role_list.filter(role='SUPER_ADMIN').exists():
        return redirect('super_admin_dashboard')

    # Get current active session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Calculate stats based on user roles
    stats = {}
    if user_role_list.filter(role__in=['SUPER_ADMIN', 'DAAA']).exists():
        # Full system stats for admins
        stats = {
            'total_students': Student.objects.count(),
            'total_courses': Course.objects.count(),
            'pending_results': Result.objects.exclude(status='PUBLISHED').count(),
            'published_results': Result.objects.filter(status='PUBLISHED').count(),
        }
    elif user_role_list.filter(role='FACULTY_DEAN').exists():
        # Faculty-specific stats
        faculty_list = [role.faculty for role in user_role_list.filter(role='FACULTY_DEAN') if role.faculty]
        stats = {
            'total_students': Student.objects.filter(faculty__in=faculty_list).count(),
            'total_courses': Course.objects.filter(departments__faculty__in=faculty_list).count(),
            'pending_results': Result.objects.filter(
                enrollment__course__departments__faculty__in=faculty_list
            ).exclude(status='PUBLISHED').count(),
            'published_results': Result.objects.filter(
                enrollment__course__departments__faculty__in=faculty_list,
                status='PUBLISHED'
            ).count(),
        }
    elif user_role_list.filter(role='HOD').exists():
        # Department-specific stats
        department_list = [role.department for role in user_role_list.filter(role='HOD') if role.department]
        stats = {
            'total_students': Student.objects.filter(department__in=department_list).count(),
            'total_courses': Course.objects.filter(departments__in=department_list).count(),
            'pending_results': Result.objects.filter(
                enrollment__course__departments__in=department_list
            ).exclude(status='PUBLISHED').count(),
            'published_results': Result.objects.filter(
                enrollment__course__departments__in=department_list,
                status='PUBLISHED'
            ).count(),
        }

    # Get recent activities
    recent_activities = AuditLog.objects.filter(user=request.user).order_by('-timestamp')[:5]

    # Get delegation context
    from .permissions import get_user_roles_with_details, get_active_delegations_for_user
    roles_with_context = get_user_roles_with_details(request.user)
    active_delegations = get_active_delegations_for_user(request.user)

    context = {
        'user_roles': user_role_list,
        'current_session': current_session,
        'stats': stats,
        'recent_activities': recent_activities,
        'roles_with_context': roles_with_context,
        'active_delegations': active_delegations,
        'has_delegated_roles': any(role['is_delegated'] for role in roles_with_context),
    }

    return render(request, 'dashboard.html', context)


@login_required
def students_view(request):
    """Shows students management page"""
    user_role_list = UserRole.objects.filter(user=request.user)

    # Filter students based on user role
    student_list = Student.objects.all()
    # Check if user is admin
    is_admin = user_role_list.filter(role__in=['SUPER_ADMIN', 'DAAA']).exists()
    if not is_admin:
        # Check if user is faculty dean
        is_faculty_dean = user_role_list.filter(role='FACULTY_DEAN').exists()
        if is_faculty_dean:
            faculty_list = [role.faculty for role in user_role_list.filter(role='FACULTY_DEAN') if role.faculty]
            student_list = student_list.filter(faculty__in=faculty_list)
        # Check if user is HOD
        elif user_role_list.filter(role='HOD').exists():
            department_list = [role.department for role in user_role_list.filter(role='HOD') if role.department]
            student_list = student_list.filter(department__in=department_list)

    student_list = student_list.select_related('faculty', 'department', 'current_level', 'admission_session')

    context = {
        'students': student_list,
        'user_roles': user_role_list,
    }

    return render(request, 'students.html', context)


@login_required
def courses_view(request):
    """Courses management page"""
    user_roles = UserRole.objects.filter(user=request.user)

    # Filter courses based on user role
    courses = Course.objects.all()
    if not user_roles.filter(role__in=['SUPER_ADMIN', 'DAAA']).exists():
        if user_roles.filter(role='FACULTY_DEAN').exists():
            faculties = [role.faculty for role in user_roles.filter(role='FACULTY_DEAN') if role.faculty]
            courses = courses.filter(departments__faculty__in=faculties)
        elif user_roles.filter(role='HOD').exists():
            departments = [role.department for role in user_roles.filter(role='HOD') if role.department]
            courses = courses.filter(departments__in=departments)
        elif user_roles.filter(role='LECTURER').exists():
            lecturer_courses = CourseAssignment.objects.filter(
                lecturer=request.user
            ).values_list('course', flat=True)
            courses = courses.filter(id__in=lecturer_courses)

    courses = courses.select_related('level', 'session').prefetch_related('department_set')

    context = {
        'courses': courses,
        'user_roles': user_roles,
    }

    return render(request, 'courses.html', context)


@login_required
def results_view(request):
    """Results management page"""
    user_roles = UserRole.objects.filter(user=request.user)

    # Filter results based on user role
    results = Result.objects.all()
    if not user_roles.filter(role__in=['SUPER_ADMIN', 'DAAA']).exists():
        if user_roles.filter(role='LECTURER').exists():
            lecturer_courses = CourseAssignment.objects.filter(
                lecturer=request.user
            ).values_list('course', flat=True)
            results = results.filter(enrollment__course__in=lecturer_courses)
        elif user_roles.filter(role='HOD').exists():
            departments = [role.department for role in user_roles.filter(role='HOD') if role.department]
            results = results.filter(enrollment__course__departments__in=departments)
        elif user_roles.filter(role='FACULTY_DEAN').exists():
            faculties = [role.faculty for role in user_roles.filter(role='FACULTY_DEAN') if role.faculty]
            results = results.filter(enrollment__course__departments__faculty__in=faculties)

    results = results.select_related('enrollment__student', 'enrollment__course', 'created_by')

    context = {
        'results': results,
        'user_roles': user_roles,
    }

    return render(request, 'results.html', context)


# Placeholder views for dashboard links
@login_required
def manage_users_view(request):
    return render(request, 'placeholder.html', {'page_title': 'Manage Users', 'message': 'User management interface coming soon!'})

@login_required
def manage_faculties_view(request):
    return render(request, 'placeholder.html', {'page_title': 'Manage Faculties', 'message': 'Faculty management interface coming soon!'})

@login_required
def manage_departments_view(request):
    return render(request, 'placeholder.html', {'page_title': 'Manage Departments', 'message': 'Department management interface coming soon!'})

@login_required
def system_settings_view(request):
    return render(request, 'placeholder.html', {'page_title': 'System Settings', 'message': 'System settings interface coming soon!'})

@login_required
def manage_sessions_view(request):
    return render(request, 'placeholder.html', {'page_title': 'Manage Sessions', 'message': 'Session management interface coming soon!'})

@login_required
def approve_results_view(request):
    return render(request, 'placeholder.html', {'page_title': 'Approve Results', 'message': 'Result approval interface coming soon!'})

@login_required
def publish_results_view(request):
    return render(request, 'placeholder.html', {'page_title': 'Publish Results', 'message': 'Result publication interface coming soon!'})

@login_required
def contact_admin_view(request):
    """Contact Administrator"""
    if request.method == 'POST':
        subject = request.POST.get('subject', '').strip()
        message = request.POST.get('message', '').strip()

        if subject and message:
            # Here you would typically send an email or create a support ticket
            # For now, we'll just show a success message
            messages.success(request, 'Your message has been sent to the administrator. You will receive a response soon.')
            return redirect('contact_admin')
        else:
            messages.error(request, 'Please fill in all fields.')

    return render(request, 'contact_admin.html')


def web_login_view(request):
    """Web-based login view"""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            # Redirect to dashboard without welcome message for cleaner experience
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid username or password. Please try again.')

    return render(request, 'login.html')


def web_logout_view(request):
    """Web-based logout view"""
    logout(request)
    # Clear all messages to prevent welcome message from showing on login page
    storage = messages.get_messages(request)
    storage.used = True
    return redirect('web_login')


# ============================================================================
# LECTURER VIEWS - Professional Interface
# ============================================================================

@login_required
def lecturer_dashboard(request):
    """Professional Lecturer Dashboard"""
    # Check if user has Lecturer role
    lecturer_roles = UserRole.objects.filter(user=request.user, role='LECTURER')
    if not lecturer_roles.exists():
        messages.error(request, 'Access denied. Lecturer role required.')
        return redirect('dashboard')

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Get assigned courses for this lecturer
    assigned_courses = CourseAssignment.objects.filter(
        lecturer=request.user
    ).select_related('course', 'course__level').annotate(
        enrolled_count=Count('course__courseenrollment')
    )

    # Calculate lecturer statistics
    lecturer_course_ids = assigned_courses.values_list('course', flat=True)

    stats = {
        'assigned_courses': assigned_courses.count(),
        'total_students': CourseEnrollment.objects.filter(
            course__in=lecturer_course_ids,
            is_active=True
        ).count(),
        'draft_results': Result.objects.filter(
            enrollment__course__in=lecturer_course_ids,
            status='DRAFT'
        ).count(),
        'submitted_results': Result.objects.filter(
            enrollment__course__in=lecturer_course_ids,
            status__in=['SUBMITTED_TO_EXAM_OFFICER', 'APPROVED_BY_EXAM_OFFICER', 'SUBMITTED_TO_HOD']
        ).count(),
        'published_results': Result.objects.filter(
            enrollment__course__in=lecturer_course_ids,
            status='PUBLISHED'
        ).count(),
    }

    # Get correction requests (rejected results)
    correction_requests = ResultApproval.objects.filter(
        result__enrollment__course__in=lecturer_course_ids,
        action='REJECTED',
        sent_to=request.user
    ).select_related('result__enrollment__student', 'result__enrollment__course')

    # Get draft results count for notifications
    draft_results_count = stats['draft_results']

    context = {
        'current_session': current_session,
        'assigned_courses': assigned_courses,
        'stats': stats,
        'correction_requests': correction_requests,
        'draft_results_count': draft_results_count,
    }

    return render(request, 'lecturer_dashboard.html', context)


# ============================================================================
# EXAM OFFICER VIEWS - Professional Interface
# ============================================================================

@login_required
def exam_officer_dashboard(request):
    """Professional Exam Officer Dashboard with Level Management"""
    # Check if user has Exam Officer role
    exam_officer_roles = UserRole.objects.filter(user=request.user, role='EXAM_OFFICER')
    if not exam_officer_roles.exists():
        messages.error(request, 'Access denied. Exam Officer role required.')
        return redirect('dashboard')

    # Get the faculty for this exam officer
    exam_officer_role = exam_officer_roles.first()
    faculty = exam_officer_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Exam Officer role.')
        return redirect('dashboard')

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Get all levels
    levels = Level.objects.all().order_by('numeric_value')

    # Get current level from query parameter or default to 100L
    level_param = request.GET.get('level', '100')
    try:
        current_level = Level.objects.get(numeric_value=int(level_param))
    except (Level.DoesNotExist, ValueError):
        current_level = levels.first()

    # Get departments in this faculty
    departments = Department.objects.filter(faculty=faculty)

    # Calculate statistics for current level
    level_students = Student.objects.filter(
        faculty=faculty,
        current_level=current_level
    )

    pending_results = Result.objects.filter(
        enrollment__course__departments__faculty=faculty,
        enrollment__student__current_level=current_level,
        status='SUBMITTED_TO_EXAM_OFFICER'
    )

    approved_results = Result.objects.filter(
        enrollment__course__departments__faculty=faculty,
        enrollment__student__current_level=current_level,
        status__in=['APPROVED_BY_EXAM_OFFICER', 'SUBMITTED_TO_HOD']
    )

    carryover_students = CarryOverList.objects.filter(
        faculty=faculty,
        result__enrollment__student__current_level=current_level,
        session=current_session
    ).values('result__enrollment__student').distinct()

    stats = {
        'total_students': level_students.count(),
        'pending_results': pending_results.count(),
        'approved_results': approved_results.count(),
        'carryover_students': carryover_students.count(),
    }

    # Get recent pending results for display
    recent_pending = pending_results.select_related(
        'enrollment__student',
        'enrollment__course'
    ).order_by('-updated_at')[:10]

    context = {
        'faculty': faculty,
        'current_session': current_session,
        'levels': levels,
        'current_level': current_level,
        'departments': departments,
        'stats': stats,
        'pending_results': recent_pending,
    }

    return render(request, 'exam_officer_dashboard.html', context)


# ============================================================================
# DAAA VIEWS - Professional Interface
# ============================================================================

@login_required
def daaa_dashboard(request):
    """Professional DAAA Dashboard"""
    # Check if user has DAAA role or is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['DAAA'])
    if not has_access:
        messages.error(request, 'Access denied. DAAA or Super Admin role required.')
        return redirect('dashboard')

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Get all faculties with statistics
    faculties = Faculty.objects.annotate(
        departments_count=Count('department'),
        students_count=Count('department__student'),
        pending_results=Count(
            'department__student__courseenrollment__result',
            filter=Q(department__student__courseenrollment__result__status='SUBMITTED_TO_DAAA')
        )
    )

    # Calculate university-wide statistics
    stats = {
        'total_faculties': faculties.count(),
        'total_students': Student.objects.count(),
        'pending_results': Result.objects.filter(status='SUBMITTED_TO_DAAA').count(),
        'approved_results': Result.objects.filter(status='APPROVED_BY_DAAA').count(),
        'published_results': Result.objects.filter(status='PUBLISHED').count(),
    }

    # Get recent results awaiting DAAA approval
    pending_results = Result.objects.filter(
        status='SUBMITTED_TO_DAAA'
    ).select_related(
        'enrollment__student',
        'enrollment__course',
        'enrollment__student__faculty'
    ).order_by('-updated_at')[:10]

    context = {
        'current_session': current_session,
        'faculties': faculties,
        'stats': stats,
        'pending_results': pending_results,
    }

    return render(request, 'daaa_dashboard.html', context)


# ============================================================================
# SENATE VIEWS - Professional Interface
# ============================================================================

@login_required
def senate_dashboard(request):
    """Professional Senate Dashboard"""
    # Check if user has Senate role
    senate_roles = UserRole.objects.filter(user=request.user, role='SENATE')
    if not senate_roles.exists():
        messages.error(request, 'Access denied. Senate role required.')
        return redirect('dashboard')

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Get all faculties with statistics
    faculties = Faculty.objects.annotate(
        departments_count=Count('department'),
        pending_results=Count(
            'department__student__courseenrollment__result',
            filter=Q(department__student__courseenrollment__result__status='SUBMITTED_TO_SENATE')
        )
    )

    # Calculate university-wide statistics
    stats = {
        'total_faculties': faculties.count(),
        'pending_results': Result.objects.filter(status='SUBMITTED_TO_SENATE').count(),
        'approved_results': Result.objects.filter(status='APPROVED_BY_SENATE').count(),
        'total_students': Student.objects.count(),
        'sealed_sessions': AcademicSession.objects.filter(is_locked=True).count(),
    }

    # Get recent results awaiting Senate approval
    pending_results = Result.objects.filter(
        status='SUBMITTED_TO_SENATE'
    ).select_related(
        'enrollment__student',
        'enrollment__course',
        'enrollment__student__faculty'
    ).order_by('-updated_at')[:10]

    # Get recent Senate approvals (mock data for now)
    recent_approvals = ResultApproval.objects.filter(
        approved_by=request.user,
        action__in=['APPROVED', 'REJECTED']
    ).order_by('-created_at')[:5]

    context = {
        'current_session': current_session,
        'faculties': faculties,
        'stats': stats,
        'pending_results': pending_results,
        'recent_approvals': recent_approvals,
    }

    return render(request, 'senate_dashboard.html', context)


# ============================================================================
# STUDENT VIEWS - Professional Interface
# ============================================================================

@login_required
def student_dashboard(request):
    """Professional Student Dashboard"""
    # Check if user has Student role
    student_roles = UserRole.objects.filter(user=request.user, role='STUDENT')
    if not student_roles.exists():
        messages.error(request, 'Access denied. Student role required.')
        return redirect('dashboard')

    # Get student record
    try:
        student = Student.objects.get(user=request.user)
    except Student.DoesNotExist:
        messages.error(request, 'Student record not found.')
        return redirect('dashboard')

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Get student's published results
    published_results = Result.objects.filter(
        enrollment__student=student,
        status='PUBLISHED'
    ).select_related('enrollment__course')

    # Calculate student statistics
    total_grade_points = sum(
        result.grade_point * result.enrollment.course.credit_units
        for result in published_results if result.grade_point
    )
    total_credit_units = sum(
        result.enrollment.course.credit_units
        for result in published_results
    )
    current_cgpa = total_grade_points / total_credit_units if total_credit_units > 0 else 0.0

    stats = {
        'current_cgpa': current_cgpa,
        'published_results': published_results.count(),
        'total_courses': published_results.count(),
        'carryovers': published_results.filter(is_carry_over=True).count(),
    }

    # Get recent results
    recent_results = published_results.order_by('-updated_at')[:10]

    # Get student complaints
    student_complaints = StudentComplaint.objects.filter(student=student)
    pending_complaints_count = student_complaints.filter(
        status__in=['SUBMITTED', 'UNDER_REVIEW']
    ).count()

    # Mock new results count (would be based on notifications)
    new_results_count = 0

    context = {
        'student': student,
        'current_session': current_session,
        'stats': stats,
        'recent_results': recent_results,
        'new_results_count': new_results_count,
        'pending_complaints_count': pending_complaints_count,
    }

    return render(request, 'student_dashboard.html', context)


# ============================================================================
# ADMISSION OFFICER VIEWS - Professional Interface
# ============================================================================

@login_required
def admission_officer_dashboard(request):
    """Professional Admission Officer Dashboard"""
    # Check if user has Admission Officer role
    admission_roles = UserRole.objects.filter(user=request.user, role='ADMISSION_OFFICER')
    if not admission_roles.exists():
        messages.error(request, 'Access denied. Admission Officer role required.')
        return redirect('dashboard')

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Calculate statistics
    from datetime import datetime, timedelta
    today = datetime.now().date()
    week_ago = today - timedelta(days=7)

    stats = {
        'total_students': Student.objects.count(),
        'new_students_today': Student.objects.filter(created_at__date=today).count(),
        'new_students_this_week': Student.objects.filter(created_at__date__gte=week_ago).count(),
        'pending_registrations': 0,  # Mock data - would be based on actual pending registrations
        'total_faculties': Faculty.objects.count(),
    }

    # Get recent student registrations
    recent_students = Student.objects.select_related(
        'user', 'faculty', 'department', 'current_level'
    ).order_by('-created_at')[:20]

    # Get faculty distribution with level breakdown
    faculty_distribution = []
    for faculty in Faculty.objects.all():
        faculty_students = Student.objects.filter(faculty=faculty)
        level_distribution = []

        for level in Level.objects.all().order_by('numeric_value'):
            level_count = faculty_students.filter(current_level=level).count()
            if level_count > 0:
                level_distribution.append({
                    'level_name': level.name,
                    'count': level_count
                })

        if faculty_students.exists():
            faculty_distribution.append({
                'id': faculty.id,
                'name': faculty.name,
                'students_count': faculty_students.count(),
                'level_distribution': level_distribution
            })

    context = {
        'current_session': current_session,
        'stats': stats,
        'recent_students': recent_students,
        'faculty_distribution': faculty_distribution,
    }

    return render(request, 'admission_officer_dashboard.html', context)


# ============================================================================
# SUPER ADMIN VIEWS - Professional Interface
# ============================================================================

@login_required
def super_admin_dashboard(request):
    """Professional Super Admin Dashboard"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Calculate system statistics
    all_users = User.objects.all().prefetch_related('rms_roles')

    # Separate users with and without roles
    users_with_roles = []
    users_without_roles = []

    for user in all_users:
        user_roles = user.rms_roles.all()
        if user_roles.exists():
            users_with_roles.append(user)
        else:
            users_without_roles.append(user)

    stats = {
        'total_users': all_users.count(),
        'total_faculties': Faculty.objects.count(),
        'total_departments': Department.objects.count(),
        'total_students': Student.objects.count(),
        'total_courses': Course.objects.count(),
        'active_users': all_users.filter(is_active=True).count(),
        'users_with_roles_count': len(users_with_roles),
        'users_without_roles_count': len(users_without_roles),
        'total_sessions': AcademicSession.objects.count(),
        'total_results': Result.objects.count(),
        'total_notifications': Notification.objects.count(),
    }

    # Get faculties with statistics
    faculties = Faculty.objects.annotate(
        departments_count=Count('department'),
        students_count=Count('department__student')
    ).order_by('name')

    # Add dean information to faculties
    for faculty in faculties:
        try:
            dean_role = UserRole.objects.filter(role='FACULTY_DEAN', faculty=faculty).first()
            faculty.dean = dean_role.user if dean_role else None
        except Exception:
            faculty.dean = None

    # Get recent audit log activities
    recent_activities = AuditLog.objects.select_related('user').order_by('-timestamp')[:10]

    context = {
        'current_session': current_session,
        'stats': stats,
        'faculties': faculties,
        'recent_activities': recent_activities,
    }

    return render(request, 'super_admin_dashboard.html', context)


@login_required
def super_admin_create_faculty(request):
    """Create new faculty"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        code = request.POST.get('code', '').strip().upper()
        description = request.POST.get('description', '').strip()

        errors = {}
        form_data = {'name': name, 'code': code, 'description': description}

        # Validation
        if not name:
            errors['name'] = 'Faculty name is required'
        elif Faculty.objects.filter(name__iexact=name).exists():
            errors['name'] = 'Faculty with this name already exists'

        if not code:
            errors['code'] = 'Faculty code is required'
        elif Faculty.objects.filter(code__iexact=code).exists():
            errors['code'] = 'Faculty with this code already exists'

        if not errors:
            try:
                faculty = Faculty.objects.create(
                    name=name,
                    code=code,
                    description=description
                )

                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='CREATE_FACULTY',
                    description=f'Created faculty: {faculty.name} ({faculty.code})',
                    level='INFO'
                )

                messages.success(request, f'Faculty "{faculty.name}" created successfully!')
                return redirect('super_admin_dashboard')

            except Exception as e:
                messages.error(request, f'Error creating faculty: {str(e)}')

        context = {
            'errors': errors,
            'form_data': form_data,
            'faculties': Faculty.objects.annotate(
                departments_count=Count('department'),
                students_count=Count('department__student')
            ).order_by('name')
        }

        # Add dean information
        for faculty in context['faculties']:
            try:
                dean_role = UserRole.objects.filter(role='FACULTY_DEAN', faculty=faculty).first()
                faculty.dean = dean_role.user if dean_role else None
            except Exception:
                faculty.dean = None

        return render(request, 'super_admin_create_faculty.html', context)

    # GET request
    context = {
        'faculties': Faculty.objects.annotate(
            departments_count=Count('department'),
            students_count=Count('department__student')
        ).order_by('name')
    }

    # Add dean information
    for faculty in context['faculties']:
        try:
            dean_role = UserRole.objects.filter(role='FACULTY_DEAN', faculty=faculty).first()
            faculty.dean = dean_role.user if dean_role else None
        except Exception:
            faculty.dean = None

    return render(request, 'super_admin_create_faculty.html', context)


@login_required
def super_admin_create_faculty_with_dean(request):
    """Create faculty and assign dean in one operation"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    if request.method == 'POST':
        # Faculty data
        faculty_name = request.POST.get('faculty_name', '').strip()
        faculty_code = request.POST.get('faculty_code', '').strip().upper()
        faculty_description = request.POST.get('faculty_description', '').strip()

        # Dean user data
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        email = request.POST.get('email', '').strip()
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')

        errors = []

        # Validate faculty data
        if not faculty_name:
            errors.append('Faculty name is required')
        elif Faculty.objects.filter(name__iexact=faculty_name).exists():
            errors.append('Faculty with this name already exists')

        if not faculty_code:
            errors.append('Faculty code is required')
        elif Faculty.objects.filter(code__iexact=faculty_code).exists():
            errors.append('Faculty with this code already exists')

        # Validate dean user data
        if not first_name:
            errors.append('Dean first name is required')
        if not last_name:
            errors.append('Dean last name is required')
        if not email:
            errors.append('Dean email is required')
        elif User.objects.filter(email=email).exists():
            errors.append('User with this email already exists')
        if not username:
            errors.append('Dean username is required')
        elif User.objects.filter(username=username).exists():
            errors.append('User with this username already exists')
        if not password:
            errors.append('Password is required')
        elif len(password) < 8:
            errors.append('Password must be at least 8 characters long')
        if password != confirm_password:
            errors.append('Passwords do not match')

        if not errors:
            try:
                from django.db import transaction

                with transaction.atomic():
                    # Create faculty
                    faculty = Faculty.objects.create(
                        name=faculty_name,
                        code=faculty_code,
                        description=faculty_description
                    )

                    # Create dean user
                    dean_user = User.objects.create_user(
                        username=username,
                        email=email,
                        first_name=first_name,
                        last_name=last_name,
                        password=password
                    )

                    # Assign Faculty Dean role
                    UserRole.objects.create(
                        user=dean_user,
                        role='FACULTY_DEAN',
                        faculty=faculty,
                        created_by=request.user
                    )

                    # Log the action
                    AuditLog.objects.create(
                        user=request.user,
                        action='CREATE_FACULTY_WITH_DEAN',
                        description=f'Created faculty "{faculty.name}" and assigned {dean_user.get_full_name()} as Faculty Dean',
                        level='INFO',
                        faculty=faculty
                    )

                    messages.success(request, f'Faculty "{faculty.name}" created successfully with {dean_user.get_full_name()} as Faculty Dean!')
                    return redirect('super_admin_dashboard')

            except Exception as e:
                messages.error(request, f'Error creating faculty and dean: {str(e)}')
        else:
            for error in errors:
                messages.error(request, error)

    return redirect('super_admin_create_faculty')


# Additional Super Admin Views (Placeholders)
@login_required
def super_admin_manage_faculties(request):
    """Manage all faculties with full CRUD operations"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    # Get all faculties with their deans and department counts
    faculties = Faculty.objects.select_related('dean').prefetch_related('department_set').order_by('name')

    context = {
        'faculties': faculties,
        'total_faculties': faculties.count(),
    }

    return render(request, 'super_admin_manage_faculties.html', context)


@login_required
def super_admin_faculty_details(request, faculty_id):
    """View detailed information about a specific faculty"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    try:
        faculty = Faculty.objects.get(id=faculty_id)
        departments = faculty.department_set.select_related('hod').order_by('name')

        context = {
            'faculty': faculty,
            'departments': departments,
        }

        return render(request, 'super_admin_faculty_details.html', context)
    except Faculty.DoesNotExist:
        messages.error(request, 'Faculty not found.')
        return redirect('super_admin_manage_faculties')


@login_required
def super_admin_edit_faculty(request, faculty_id):
    """Edit faculty information"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    try:
        faculty = Faculty.objects.get(id=faculty_id)
    except Faculty.DoesNotExist:
        messages.error(request, 'Faculty not found.')
        return redirect('super_admin_manage_faculties')

    if request.method == 'POST':
        # Update faculty information
        faculty.name = request.POST.get('name', '').strip()
        dean_id = request.POST.get('dean_id')

        if dean_id:
            try:
                dean = User.objects.get(id=dean_id)
                faculty.dean = dean
            except User.DoesNotExist:
                messages.error(request, 'Selected dean not found.')
                return redirect('super_admin_edit_faculty', faculty_id=faculty.id)
        else:
            faculty.dean = None

        try:
            faculty.save()
            messages.success(request, f'Faculty {faculty.name} updated successfully.')
            return redirect('super_admin_faculty_details', faculty_id=faculty.id)
        except Exception as e:
            messages.error(request, f'Error updating faculty: {str(e)}')

    # Get potential deans (users with FACULTY_DEAN role)
    potential_deans = User.objects.filter(rms_roles__role='FACULTY_DEAN').distinct()

    context = {
        'faculty': faculty,
        'potential_deans': potential_deans,
    }

    return render(request, 'super_admin_edit_faculty.html', context)


@login_required
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def super_admin_delete_faculty(request, faculty_id):
    """Delete a faculty (for testing purposes)"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        return Response({
            'status': 'error',
            'message': 'Access denied. Super Admin role required.'
        }, status=status.HTTP_403_FORBIDDEN)

    try:
        faculty = Faculty.objects.get(id=faculty_id)

        # Check if faculty has departments
        departments_count = faculty.department_set.count()
        students_count = Student.objects.filter(faculty=faculty).count()

        # Log the action before deletion
        AuditLog.objects.create(
            user=request.user,
            action='DELETE_FACULTY',
            description=f'Deleted faculty: {faculty.name} (had {departments_count} departments, {students_count} students)',
            level='WARNING'
        )

        faculty_name = faculty.name
        faculty.delete()

        return Response({
            'status': 'success',
            'message': f'Faculty {faculty_name} deleted successfully.'
        })

    except Faculty.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'Faculty not found.'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'status': 'error',
            'message': f'Error deleting faculty: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@login_required
def super_admin_assign_dean(request):
    return render(request, 'placeholder.html', {'page_title': 'Assign Faculty Dean', 'message': 'Assign faculty deans to faculties'})

@login_required
def super_admin_faculty_reports(request):
    return render(request, 'placeholder.html', {'page_title': 'Faculty Reports', 'message': 'Generate faculty reports'})

@login_required
def super_admin_create_department(request):
    """Create a new department"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    if request.method == 'POST':
        try:
            # Get form data
            name = request.POST.get('name', '').strip()
            code = request.POST.get('code', '').strip().upper()
            description = request.POST.get('description', '').strip()
            faculty_id = request.POST.get('faculty_id')

            # Validate required fields
            if not name or not code or not faculty_id:
                messages.error(request, 'Name, code, and faculty are required.')
                return redirect('super_admin_create_department')

            # Check if department code already exists
            if Department.objects.filter(code=code).exists():
                messages.error(request, f'Department code "{code}" already exists.')
                return redirect('super_admin_create_department')

            # Get faculty
            try:
                faculty = Faculty.objects.get(id=faculty_id)
            except Faculty.DoesNotExist:
                messages.error(request, 'Selected faculty does not exist.')
                return redirect('super_admin_create_department')

            # Create the department
            department = Department.objects.create(
                name=name,
                code=code,
                faculty=faculty
            )

            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='CREATE_DEPARTMENT',
                description=f'Created department: {name} ({code}) in {faculty.name}',
                level='INFO'
            )

            messages.success(request, f'Department "{name}" created successfully!')
            return redirect('super_admin_manage_departments')

        except Exception as e:
            messages.error(request, f'Error creating department: {str(e)}')
            return redirect('super_admin_create_department')

    # GET request - show form
    faculties = Faculty.objects.all().order_by('name')

    context = {
        'faculties': faculties,
    }

    return render(request, 'super_admin_create_department.html', context)

@login_required
def super_admin_manage_departments(request):
    """Manage all departments with full CRUD operations"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    # Get all departments with their faculties and HODs
    departments = Department.objects.select_related('faculty', 'hod').order_by('faculty__name', 'name')

    context = {
        'departments': departments,
        'total_departments': departments.count(),
    }

    return render(request, 'super_admin_manage_departments.html', context)

@login_required
def super_admin_assign_hod(request):
    """Super Admin HOD Assignment Interface"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    if request.method == 'POST':
        department_id = request.POST.get('department_id')
        user_id = request.POST.get('user_id')

        if not department_id or not user_id:
            messages.error(request, 'Please select both department and user.')
        else:
            try:
                department = Department.objects.get(id=department_id)
                user = User.objects.get(id=user_id)

                # Remove existing HOD role for this department if exists
                existing_hod_role = UserRole.objects.filter(role='HOD', department=department).first()
                if existing_hod_role:
                    existing_hod_role.delete()
                    # Update department HOD field
                    department.hod = None
                    department.save()

                # Create new HOD role
                UserRole.objects.create(
                    user=user,
                    role='HOD',
                    faculty=department.faculty,
                    department=department,
                    created_by=request.user,
                    is_primary=False
                )

                # Update department HOD field
                department.hod = user
                department.save()

                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='ASSIGN_HOD',
                    description=f'Assigned {user.get_full_name()} as HOD of {department.name}',
                    level='INFO'
                )

                messages.success(request, f'{user.get_full_name()} has been assigned as HOD of {department.name}!')
                return redirect('super_admin_assign_hod')

            except Department.DoesNotExist:
                messages.error(request, 'Department not found.')
            except User.DoesNotExist:
                messages.error(request, 'User not found.')
            except Exception as e:
                messages.error(request, f'Error assigning HOD: {str(e)}')

    # Get all departments with their current HODs
    departments = Department.objects.all().select_related('faculty', 'hod').order_by('faculty__name', 'name')

    # Get all users who can be assigned as HOD (excluding students)
    eligible_users = User.objects.filter(
        rms_roles__role__in=['LECTURER', 'FACULTY_DEAN', 'SUPER_ADMIN']
    ).distinct().order_by('first_name', 'last_name')

    context = {
        'departments': departments,
        'eligible_users': eligible_users,
    }

    return render(request, 'super_admin_assign_hod.html', context)

@login_required
def super_admin_department_reports(request):
    return render(request, 'placeholder.html', {'page_title': 'Department Reports', 'message': 'Generate department reports'})

def get_departments_by_faculty(departments):
    """Helper function to organize departments by faculty for JSON serialization"""
    departments_by_faculty = {}
    for dept in departments:
        faculty_id = dept.faculty.id
        if faculty_id not in departments_by_faculty:
            departments_by_faculty[faculty_id] = []
        departments_by_faculty[faculty_id].append({
            'id': dept.id,
            'name': dept.name
        })
    return departments_by_faculty


@login_required
def super_admin_create_user(request):
    """Create new system user with role assignment"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    if request.method == 'POST':
        # Get form data
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        email = request.POST.get('email', '').strip()
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        role = request.POST.get('role', '')
        faculty_id = request.POST.get('faculty_id', '')
        department_id = request.POST.get('department_id', '')

        errors = []

        # Validate user data
        if not first_name:
            errors.append('First name is required')
        if not last_name:
            errors.append('Last name is required')
        if not email:
            errors.append('Email is required')
        elif User.objects.filter(email__iexact=email).exists():
            errors.append('User with this email already exists')
        if not username:
            errors.append('Username is required')
        elif len(username) < 3:
            errors.append('Username must be at least 3 characters long')
        elif not username.replace('_', '').replace('-', '').isalnum():
            errors.append('Username can only contain letters, numbers, underscores, and hyphens')
        elif User.objects.filter(username__iexact=username).exists():
            errors.append('User with this username already exists')
        if not password:
            errors.append('Password is required')
        elif len(password) < 8:
            errors.append('Password must be at least 8 characters long')
        if password != confirm_password:
            errors.append('Passwords do not match')
        if not role:
            errors.append('Please select a role')

        # Validate role-specific requirements
        if role in ['HOD', 'FACULTY_DEAN', 'LECTURER'] and not faculty_id:
            errors.append('Faculty is required for this role')
        if role in ['HOD', 'LECTURER'] and not department_id:
            errors.append('Department is required for this role')

        if not errors:
            try:
                from django.db import transaction, IntegrityError

                with transaction.atomic():
                    # Double-check for existing username/email before creation (race condition protection)
                    if User.objects.filter(username__iexact=username).exists():
                        messages.error(request, f'Username "{username}" is already taken. Please choose a different username.')
                        return render(request, 'super_admin_create_user.html', {
                            'faculties': Faculty.objects.all().order_by('name'),
                            'departments': Department.objects.all().order_by('name'),
                            'role_choices': UserRole.ROLE_CHOICES,
                            'departments_json': json.dumps(get_departments_by_faculty(Department.objects.all().order_by('name'))),
                            'form_data': {
                                'first_name': first_name,
                                'last_name': last_name,
                                'email': email,
                                'username': username,
                                'role': role,
                                'faculty_id': faculty_id,
                                'department_id': department_id,
                            }
                        })

                    if User.objects.filter(email__iexact=email).exists():
                        messages.error(request, f'Email "{email}" is already registered. Please use a different email address.')
                        return render(request, 'super_admin_create_user.html', {
                            'faculties': Faculty.objects.all().order_by('name'),
                            'departments': Department.objects.all().order_by('name'),
                            'role_choices': UserRole.ROLE_CHOICES,
                            'departments_json': json.dumps(get_departments_by_faculty(Department.objects.all().order_by('name'))),
                            'form_data': {
                                'first_name': first_name,
                                'last_name': last_name,
                                'email': email,
                                'username': username,
                                'role': role,
                                'faculty_id': faculty_id,
                                'department_id': department_id,
                            }
                        })

                    # Create new user
                    new_user = User.objects.create_user(
                        username=username,
                        email=email,
                        first_name=first_name,
                        last_name=last_name,
                        password=password
                    )

                    # Get faculty and department if provided
                    faculty = None
                    department = None
                    if faculty_id:
                        try:
                            faculty = Faculty.objects.get(id=faculty_id)
                        except Faculty.DoesNotExist:
                            messages.error(request, 'Selected faculty does not exist.')
                            new_user.delete()  # Clean up created user
                            return render(request, 'super_admin_create_user.html', {
                                'faculties': Faculty.objects.all().order_by('name'),
                                'departments': Department.objects.all().order_by('name'),
                                'role_choices': UserRole.ROLE_CHOICES,
                                'departments_json': json.dumps(get_departments_by_faculty(Department.objects.all().order_by('name'))),
                            })
                    if department_id:
                        try:
                            department = Department.objects.get(id=department_id)
                        except Department.DoesNotExist:
                            messages.error(request, 'Selected department does not exist.')
                            new_user.delete()  # Clean up created user
                            return render(request, 'super_admin_create_user.html', {
                                'faculties': Faculty.objects.all().order_by('name'),
                                'departments': Department.objects.all().order_by('name'),
                                'role_choices': UserRole.ROLE_CHOICES,
                                'departments_json': json.dumps(get_departments_by_faculty(Department.objects.all().order_by('name'))),
                            })

                    # Create role assignment
                    UserRole.objects.create(
                        user=new_user,
                        role=role,
                        faculty=faculty,
                        department=department,
                        created_by=request.user
                    )

                    # Log the action
                    AuditLog.objects.create(
                        user=request.user,
                        action='CREATE_USER',
                        description=f'Created user {new_user.get_full_name()} with role {role}',
                        level='INFO',
                        faculty=faculty,
                        department=department
                    )

                    messages.success(request, f'User {new_user.get_full_name()} created successfully with role {role}!')
                    return redirect('super_admin_manage_users')

            except IntegrityError as e:
                error_message = str(e).lower()
                if 'username' in error_message:
                    messages.error(request, f'Username "{username}" is already taken. Please choose a different username.')
                elif 'email' in error_message:
                    messages.error(request, f'Email "{email}" is already registered. Please use a different email address.')
                else:
                    messages.error(request, 'A user with this information already exists. Please check your input and try again.')
            except Exception as e:
                messages.error(request, f'An unexpected error occurred while creating the user: {str(e)}. Please try again.')
        else:
            for error in errors:
                messages.error(request, error)

    # Get data for form
    faculties = Faculty.objects.all().order_by('name')
    departments = Department.objects.all().order_by('name')
    departments_json = json.dumps(get_departments_by_faculty(departments))

    context = {
        'faculties': faculties,
        'departments': departments,
        'role_choices': UserRole.ROLE_CHOICES,
        'departments_json': departments_json,
    }

    return render(request, 'super_admin_create_user.html', context)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def check_email_exists(request):
    """Check if email already exists"""
    import json

    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        return Response({'error': 'Access denied'}, status=status.HTTP_403_FORBIDDEN)

    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip()

        if not email:
            return Response({'exists': False})

        exists = User.objects.filter(email__iexact=email).exists()
        return Response({'exists': exists})

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def check_username_exists(request):
    """Check if username already exists"""
    import json

    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        return Response({'error': 'Access denied'}, status=status.HTTP_403_FORBIDDEN)

    try:
        data = json.loads(request.body)
        username = data.get('username', '').strip()

        if not username:
            return Response({'exists': False})

        exists = User.objects.filter(username__iexact=username).exists()
        return Response({'exists': exists})

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@login_required
def super_admin_search(request):
    """Search functionality for users, students, and results"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    query = request.GET.get('q', '').strip()
    search_type = request.GET.get('type', 'all')

    context = {
        'query': query,
        'search_type': search_type,
        'users': [],
        'students': [],
        'results': [],
        'courses': [],
        'faculties': [],
        'departments': [],
        'total_results': 0
    }

    if query:
        from django.db.models import Q

        try:
            # Search Users - COMPREHENSIVE search
            if search_type in ['all', 'users']:
                user_query = (
                    # Basic user fields - ALWAYS WORKS
                    Q(first_name__icontains=query) |
                    Q(last_name__icontains=query) |
                    Q(email__icontains=query) |
                    Q(username__icontains=query)
                )

                # Add role-based search safely
                try:
                    user_query |= Q(rms_roles__role__icontains=query)
                except:
                    pass

                # Add faculty/department search safely
                try:
                    user_query |= (
                        Q(rms_roles__faculty__name__icontains=query) |
                        Q(rms_roles__department__name__icontains=query)
                    )
                except:
                    pass

                users = User.objects.filter(user_query).distinct()[:20]
                context['users'] = users

            # Search Students - COMPREHENSIVE search
            if search_type in ['all', 'students']:
                student_query = (
                    # Basic student and user fields - ALWAYS WORKS
                    Q(user__first_name__icontains=query) |
                    Q(user__last_name__icontains=query) |
                    Q(user__email__icontains=query) |
                    Q(user__username__icontains=query) |
                    Q(matric_number__icontains=query) |

                    # Academic structure - SAFE
                    Q(department__name__icontains=query) |
                    Q(faculty__name__icontains=query) |
                    Q(current_level__name__icontains=query)
                )

                # Add course enrollment search safely
                try:
                    student_query |= (
                        Q(courseenrollment__course__code__icontains=query) |
                        Q(courseenrollment__course__title__icontains=query)
                    )
                except:
                    pass

                students = Student.objects.filter(student_query).select_related(
                    'user', 'department', 'faculty', 'current_level'
                ).distinct()[:20]
                context['students'] = students

            # Search Results - COMPREHENSIVE search
            if search_type in ['all', 'results']:
                result_query = (
                    # Student information - SAFE
                    Q(enrollment__student__user__first_name__icontains=query) |
                    Q(enrollment__student__user__last_name__icontains=query) |
                    Q(enrollment__student__matric_number__icontains=query) |

                    # Course information - SAFE
                    Q(enrollment__course__code__icontains=query) |
                    Q(enrollment__course__title__icontains=query) |

                    # Result details - SAFE
                    Q(grade__icontains=query) |
                    Q(status__icontains=query)
                )

                # Add session search safely
                try:
                    result_query |= Q(enrollment__session__name__icontains=query)
                except:
                    pass

                results = Result.objects.filter(result_query).select_related(
                    'enrollment__student__user',
                    'enrollment__course'
                ).distinct()[:20]
                context['results'] = results

            # Search Courses - COMPREHENSIVE search
            if search_type in ['all', 'courses']:
                course_query = (
                    # Basic course information - ALWAYS WORKS
                    Q(code__icontains=query) |
                    Q(title__icontains=query)
                )

                # Add department search safely
                try:
                    course_query |= Q(departments__name__icontains=query)
                except:
                    pass

                # Add level and session search safely
                try:
                    course_query |= (
                        Q(level__name__icontains=query) |
                        Q(session__name__icontains=query)
                    )
                except:
                    pass

                # Add creator search safely
                try:
                    course_query |= (
                        Q(created_by__first_name__icontains=query) |
                        Q(created_by__last_name__icontains=query)
                    )
                except:
                    pass

                courses = Course.objects.filter(course_query).distinct()[:20]
                context['courses'] = courses

            # Search Faculties - COMPREHENSIVE search
            if search_type in ['all', 'faculties']:
                faculty_query = (
                    # Basic faculty information - ALWAYS WORKS
                    Q(name__icontains=query) |
                    Q(code__icontains=query)
                )

                # Add dean search safely
                try:
                    faculty_query |= (
                        Q(dean__first_name__icontains=query) |
                        Q(dean__last_name__icontains=query)
                    )
                except:
                    pass

                faculties = Faculty.objects.filter(faculty_query).distinct()[:20]
                context['faculties'] = faculties

            # Search Departments - COMPREHENSIVE search
            if search_type in ['all', 'departments']:
                dept_query = (
                    # Basic department information - ALWAYS WORKS
                    Q(name__icontains=query) |
                    Q(code__icontains=query)
                )

                # Add faculty search safely
                try:
                    dept_query |= Q(faculty__name__icontains=query)
                except:
                    pass

                # Add HOD search safely
                try:
                    dept_query |= (
                        Q(hod__first_name__icontains=query) |
                        Q(hod__last_name__icontains=query)
                    )
                except:
                    pass

                departments = Department.objects.filter(dept_query).distinct()[:20]
                context['departments'] = departments



        except Exception as e:
            # Log the error and return empty results
            context['users'] = []
            context['students'] = []
            context['results'] = []
            context['courses'] = []
            context['faculties'] = []
            context['departments'] = []

        # Calculate total results from all categories
        context['total_results'] = (
            len(context.get('users', [])) +
            len(context.get('students', [])) +
            len(context.get('results', [])) +
            len(context.get('courses', [])) +
            len(context.get('faculties', [])) +
            len(context.get('departments', []))
        )

    # Handle AJAX requests
    if request.GET.get('ajax'):
        from django.http import JsonResponse

        try:
            # Format data for JSON response
            json_data = {
                'total_results': context['total_results'],
                'users': [],
                'students': [],
                'results': [],
                'courses': [],
                'faculties': [],
                'departments': [],
            }

            # Format users
            for user in context['users']:
                try:
                    roles = [role.get_role_display() for role in user.rms_roles.all()]
                    json_data['users'].append({
                        'id': user.id,
                        'full_name': user.get_full_name(),
                        'email': user.email,
                        'username': user.username,
                        'roles': roles
                    })
                except Exception as e:
                    print(f"Error formatting user {user.id}: {str(e)}")
                    continue

            # Format students
            for student in context['students']:
                try:
                    json_data['students'].append({
                        'id': student.id,
                        'full_name': student.user.get_full_name(),
                        'matric_number': student.matric_number,
                        'level': student.current_level.name if student.current_level else 'N/A',
                        'department': student.department.name,
                        'faculty': student.faculty.name
                    })
                except Exception as e:
                    print(f"Error formatting student {student.id}: {str(e)}")
                    continue

            # Format results
            for result in context['results']:
                try:
                    json_data['results'].append({
                        'id': result.id,
                        'course_code': result.enrollment.course.code,
                        'course_title': result.enrollment.course.title,
                        'student_name': result.enrollment.student.user.get_full_name(),
                        'matric_number': result.enrollment.student.matric_number,
                        'total_score': float(result.total_score) if result.total_score else 0,
                        'grade': result.grade or '',
                        'session': result.enrollment.session.name,
                        'is_carry_over': result.is_carry_over
                    })
                except Exception as e:
                    print(f"Error formatting result {result.id}: {str(e)}")
                    continue

            # Format courses
            for course in context['courses']:
                try:
                    json_data['courses'].append({
                        'id': course.id,
                        'code': course.code,
                        'title': course.title,
                        'credit_units': course.credit_units,
                        'department': course.department.name,
                        'faculty': course.faculty.name
                    })
                except Exception as e:
                    print(f"Error formatting course {course.id}: {str(e)}")
                    continue

            # Format faculties
            for faculty in context['faculties']:
                try:
                    json_data['faculties'].append({
                        'id': faculty.id,
                        'name': faculty.name,
                        'code': faculty.code if hasattr(faculty, 'code') else '',
                        'dean_name': faculty.dean.get_full_name() if faculty.dean else 'No Dean Assigned',
                        'departments_count': faculty.department_set.count()
                    })
                except Exception as e:
                    print(f"Error formatting faculty {faculty.id}: {str(e)}")
                    continue

            # Format departments
            for department in context['departments']:
                try:
                    json_data['departments'].append({
                        'id': department.id,
                        'name': department.name,
                        'code': department.code,
                        'faculty': department.faculty.name,
                        'hod_name': department.hod.get_full_name() if department.hod else 'No HOD Assigned'
                    })
                except Exception as e:
                    print(f"Error formatting department {department.id}: {str(e)}")
                    continue

            return JsonResponse(json_data)

        except Exception as e:
            print(f"AJAX search error: {str(e)}")
            return JsonResponse({
                'total_results': 0,
                'users': [],
                'students': [],
                'results': [],
                'error': 'Search failed'
            })

    return render(request, 'super_admin_search_results.html', context)


@login_required
def super_admin_delegate_permissions(request, user_id):
    """Redirect to manage users page for permission delegation"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    try:
        user = User.objects.get(id=user_id)
        messages.info(request, f'Use the "Delegate" button next to {user.get_full_name()} to delegate permissions.')
        return redirect('super_admin_manage_users')
    except User.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('super_admin_manage_users')


@login_required
def super_admin_permission_delegations(request):
    """View and manage all permission delegations"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    # Get all delegations with related data
    delegations = PermissionDelegation.objects.select_related(
        'delegator', 'delegate', 'delegated_role__user', 'delegated_role__faculty',
        'delegated_role__department', 'created_by', 'revoked_by'
    ).order_by('-created_at')

    # Check for expired delegations and update status
    for delegation in delegations:
        delegation.check_expiry()

    # Filter by status if requested
    status_filter = request.GET.get('status', 'all')
    if status_filter != 'all':
        delegations = delegations.filter(status=status_filter.upper())

    context = {
        'delegations': delegations,
        'status_filter': status_filter,
        'status_choices': PermissionDelegation.STATUS_CHOICES,
    }

    return render(request, 'super_admin_permission_delegations.html', context)


@login_required
def super_admin_revoke_delegation(request, delegation_id):
    """Revoke a permission delegation"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    try:
        delegation = PermissionDelegation.objects.get(id=delegation_id)
    except PermissionDelegation.DoesNotExist:
        messages.error(request, 'Delegation not found.')
        return redirect('super_admin_permission_delegations')

    if request.method == 'POST':
        reason = request.POST.get('reason', '').strip()

        if delegation.status != 'ACTIVE':
            messages.error(request, 'Only active delegations can be revoked.')
        else:
            # Revoke the delegation
            delegation.revoke(request.user, reason)

            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='REVOKE_DELEGATION',
                description=f'Revoked {delegation.delegated_role.get_role_display()} delegation from {delegation.delegator.get_full_name()} to {delegation.delegate.get_full_name()}. Reason: {reason}',
                level='INFO'
            )

            messages.success(request, f'Successfully revoked delegation from {delegation.delegator.get_full_name()} to {delegation.delegate.get_full_name()}.')

        return redirect('super_admin_permission_delegations')

    context = {
        'delegation': delegation,
    }

    return render(request, 'super_admin_revoke_delegation.html', context)

@login_required
def super_admin_manage_users(request):
    """Manage all system users with full CRUD operations"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    # Get all users with their roles
    all_users = User.objects.all().prefetch_related('rms_roles__faculty', 'rms_roles__department').order_by('first_name', 'last_name')

    # Separate users with and without roles
    users_with_roles = []
    users_without_roles = []

    for user in all_users:
        user_roles = user.rms_roles.all()
        if user_roles.exists():
            users_with_roles.append(user)
        else:
            users_without_roles.append(user)

    # Group users by faculty and handle non-faculty roles
    faculty_groups = {}
    users_with_non_faculty_roles = []

    for user in users_with_roles:
        user_roles = user.rms_roles.all()
        has_faculty_role = False

        for role in user_roles:
            if role.faculty:
                faculty_name = role.faculty.name
                if faculty_name not in faculty_groups:
                    faculty_groups[faculty_name] = {
                        'faculty': role.faculty,
                        'users': []
                    }
                if user not in faculty_groups[faculty_name]['users']:
                    faculty_groups[faculty_name]['users'].append(user)
                has_faculty_role = True

        # If user has roles but none are faculty-associated, add to non-faculty group
        if not has_faculty_role:
            users_with_non_faculty_roles.append(user)

    # Get all faculties for the create faculty form
    faculties = Faculty.objects.all().order_by('name')

    # Get statistics
    total_users = all_users.count()
    active_users = all_users.filter(is_active=True).count()
    users_with_roles_count = len(users_with_roles)
    users_without_roles_count = len(users_without_roles)

    context = {
        'all_users': all_users,
        'users_with_roles': users_with_roles,
        'users_without_roles': users_without_roles,
        'users_with_non_faculty_roles': users_with_non_faculty_roles,
        'faculty_groups': faculty_groups,
        'faculties': faculties,
        'total_users': total_users,
        'active_users': active_users,
        'users_with_roles_count': users_with_roles_count,
        'users_without_roles_count': users_without_roles_count,
        'users_with_non_faculty_roles_count': len(users_with_non_faculty_roles),
    }

    return render(request, 'super_admin_manage_users.html', context)


@login_required
def debug_user_display(request):
    """Debug endpoint to verify user display logic"""
    from django.http import JsonResponse

    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        return JsonResponse({'error': 'Access denied'}, status=403)

    # Get all users (same as manage_users view)
    all_users = User.objects.all().prefetch_related('rms_roles__faculty', 'rms_roles__department').order_by('first_name', 'last_name')

    # Separate users with and without roles
    users_with_roles = []
    users_without_roles = []

    for user in all_users:
        user_roles = user.rms_roles.all()
        if user_roles.exists():
            users_with_roles.append(user)
        else:
            users_without_roles.append(user)

    # Group users by faculty and handle non-faculty roles
    faculty_groups = {}
    users_with_non_faculty_roles = []

    for user in users_with_roles:
        user_roles = user.rms_roles.all()
        has_faculty_role = False

        for role in user_roles:
            if role.faculty:
                faculty_name = role.faculty.name
                if faculty_name not in faculty_groups:
                    faculty_groups[faculty_name] = {
                        'faculty': role.faculty,
                        'users': []
                    }
                if user not in faculty_groups[faculty_name]['users']:
                    faculty_groups[faculty_name]['users'].append(user)
                has_faculty_role = True

        if not has_faculty_role:
            users_with_non_faculty_roles.append(user)

    # Calculate totals
    total_displayed = len(users_without_roles) + len(users_with_non_faculty_roles)
    for faculty_data in faculty_groups.values():
        total_displayed += len(faculty_data['users'])

    # Prepare response data
    response_data = {
        'total_users_in_db': all_users.count(),
        'users_with_roles': len(users_with_roles),
        'users_without_roles': len(users_without_roles),
        'users_with_non_faculty_roles': len(users_with_non_faculty_roles),
        'faculty_groups_count': len(faculty_groups),
        'total_displayed': total_displayed,
        'match': total_displayed == all_users.count(),
        'users_detail': []
    }

    # Add detailed user info
    for user in all_users:
        user_roles = [{'role': role.role, 'faculty': role.faculty.name if role.faculty else None} for role in user.rms_roles.all()]
        response_data['users_detail'].append({
            'id': user.id,
            'username': user.username,
            'full_name': user.get_full_name(),
            'email': user.email,
            'is_active': user.is_active,
            'roles': user_roles,
            'roles_count': len(user_roles)
        })

    return JsonResponse(response_data, indent=2)





@api_view(['POST'])
@permission_classes([IsAuthenticated])
def super_admin_get_role_holders(request):
    """Get users who have a specific role"""
    import json

    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        return Response({'error': 'Access denied'}, status=status.HTTP_403_FORBIDDEN)

    try:
        data = json.loads(request.body)
        role = data.get('role')

        if not role:
            return Response({'error': 'Role is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Get users with this role
        user_roles = UserRole.objects.filter(role=role).select_related('user', 'faculty', 'department')

        users = []
        for user_role in user_roles:
            users.append({
                'id': user_role.user.id,
                'name': user_role.user.get_full_name(),
                'email': user_role.user.email,
                'faculty': user_role.faculty.name if user_role.faculty else None,
                'faculty_id': user_role.faculty.id if user_role.faculty else None,
                'department': user_role.department.name if user_role.department else None,
                'department_id': user_role.department.id if user_role.department else None,
            })

        return Response({'users': users})

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_departments(request):
    """Get departments for a specific faculty"""
    import json

    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        return Response({'error': 'Access denied'}, status=status.HTTP_403_FORBIDDEN)

    try:
        data = json.loads(request.body)
        faculty_id = data.get('faculty_id')

        if not faculty_id:
            return Response({'error': 'Faculty ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Get departments for this faculty
        departments = Department.objects.filter(faculty_id=faculty_id).values('id', 'name')

        return Response({'departments': list(departments)})

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@login_required
def super_admin_delegate_permission(request):
    """Create a permission delegation"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    if request.method == 'POST':
        try:
            from django.utils import timezone
            from django.db import transaction

            # Get form data
            delegate_user_id = request.POST.get('delegate_user_id')
            delegated_user_role_id = request.POST.get('delegated_user_role_id')
            reason = request.POST.get('reason', '').strip()

            # Validate required fields
            if not delegate_user_id:
                messages.error(request, 'Please select a user to delegate permissions to.')
                return redirect('super_admin_manage_users')
            if not delegated_user_role_id:
                messages.error(request, 'Please select a role holder to delegate from.')
                return redirect('super_admin_manage_users')
            if not reason:
                messages.error(request, 'Please provide a reason for the delegation.')
                return redirect('super_admin_manage_users')

            # Get the delegate user and the original role
            try:
                delegate_user = User.objects.get(id=delegate_user_id)
                original_user_role = UserRole.objects.select_related('user', 'faculty', 'department').get(id=delegated_user_role_id)
            except (User.DoesNotExist, UserRole.DoesNotExist):
                messages.error(request, 'Invalid user or role selected.')
                return redirect('super_admin_manage_users')

            # Check if delegation already exists
            existing_delegation = PermissionDelegation.objects.filter(
                delegate=delegate_user,
                delegated_role=original_user_role,
                status='ACTIVE'
            ).exists()

            if existing_delegation:
                messages.error(request, f'An active delegation already exists for this role.')
                return redirect('super_admin_manage_users')

            # Create the delegation and temporary role
            with transaction.atomic():
                # Create delegation record
                delegation = PermissionDelegation.objects.create(
                    delegator=original_user_role.user,
                    delegate=delegate_user,
                    delegated_role=original_user_role,
                    reason=reason,
                    created_by=request.user,
                    status='ACTIVE'
                )

                # Create temporary UserRole for the delegate
                temp_role = UserRole.objects.create(
                    user=delegate_user,
                    role=original_user_role.role,
                    faculty=original_user_role.faculty,
                    department=original_user_role.department,
                    is_temporary=True,
                    delegation=delegation
                )

                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='DELEGATE_PERMISSION',
                    description=f'Delegated {original_user_role.get_role_display()} permissions from {original_user_role.user.get_full_name()} to {delegate_user.get_full_name()}. Reason: {reason}',
                    level='INFO'
                )

                messages.success(request, f'Successfully delegated {original_user_role.get_role_display()} permissions to {delegate_user.get_full_name()}.')
                return redirect('super_admin_manage_users')

            # Get faculty and department if provided
            faculty = None
            department = None

            if faculty_id:
                try:
                    faculty = Faculty.objects.get(id=faculty_id)
                except Faculty.DoesNotExist:
                    messages.error(request, 'Invalid faculty selected.')
                    return redirect('super_admin_manage_users')

            if department_id:
                try:
                    department = Department.objects.get(id=department_id)
                except Department.DoesNotExist:
                    messages.error(request, 'Invalid department selected.')
                    return redirect('super_admin_manage_users')

            # Check if delegation already exists
            existing_delegation = PermissionDelegation.objects.filter(
                delegate=delegate_user,
                delegated_role=delegated_role,
                faculty=faculty,
                department=department,
                status='ACTIVE'
            ).first()

            if existing_delegation:
                messages.error(request, 'An active delegation for this role already exists for this user.')
                return redirect('super_admin_manage_users')

            # Create delegation
            delegation = PermissionDelegation.objects.create(
                delegator=delegator_user,
                delegate=delegate_user,
                delegated_role=delegated_role,
                faculty=faculty,
                department=department,
                created_by=request.user,
                start_date=start_date,
                end_date=end_date,
                reason=reason
            )

            # Create audit log
            AuditLog.objects.create(
                user=request.user,
                action='DELEGATE_PERMISSION',
                description=f'Delegated {delegated_role} permissions from {delegator_user.get_full_name()} to {delegate_user.get_full_name()}',
                level='INFO'
            )

            messages.success(request, f'Permission delegation created successfully. {delegate_user.get_full_name()} now has {delegated_role} permissions until {end_date.strftime("%Y-%m-%d %H:%M")}.')
            return redirect('super_admin_manage_users')

        except Exception as e:
            messages.error(request, f'Error creating delegation: {str(e)}')
            return redirect('super_admin_manage_users')

    return redirect('super_admin_manage_users')


@login_required
def super_admin_user_details(request, user_id):
    """View detailed information about a specific user"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    try:
        user = User.objects.get(id=user_id)
        user_roles = UserRole.objects.filter(user=user).select_related('faculty', 'department')

        context = {
            'user': user,
            'user_roles': user_roles,
        }

        return render(request, 'super_admin_user_details.html', context)
    except User.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('super_admin_manage_users')


@login_required
def super_admin_edit_user(request, user_id):
    """Edit user information and roles"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('super_admin_manage_users')

    if request.method == 'POST':
        # Update user basic information
        user.first_name = request.POST.get('first_name', '').strip()
        user.last_name = request.POST.get('last_name', '').strip()
        user.email = request.POST.get('email', '').strip()
        user.username = request.POST.get('username', '').strip()
        user.is_active = request.POST.get('is_active') == 'on'

        try:
            user.save()
            messages.success(request, f'User {user.get_full_name()} updated successfully.')
            return redirect('super_admin_user_details', user_id=user.id)
        except Exception as e:
            messages.error(request, f'Error updating user: {str(e)}')

    user_roles = UserRole.objects.filter(user=user).select_related('faculty', 'department')
    faculties = Faculty.objects.all()
    departments = Department.objects.all()
    departments_by_faculty_json = json.dumps(get_departments_by_faculty(departments))

    context = {
        'user': user,
        'user_roles': user_roles,
        'faculties': faculties,
        'departments': departments,
        'role_choices': UserRole.ROLE_CHOICES,
        'departments_by_faculty_json': departments_by_faculty_json,
    }

    return render(request, 'super_admin_edit_user.html', context)

@login_required
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def super_admin_delete_user(request, user_id):
    """Delete a user (for testing purposes)"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        return Response({
            'status': 'error',
            'message': 'Access denied. Super Admin role required.'
        }, status=status.HTTP_403_FORBIDDEN)

    try:
        user = User.objects.get(id=user_id)

        # Don't allow deleting yourself
        if user == request.user:
            return Response({
                'status': 'error',
                'message': 'You cannot delete your own account.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Log the action before deletion
        AuditLog.objects.create(
            user=request.user,
            action='DELETE_USER',
            description=f'Deleted user: {user.get_full_name()} ({user.username})',
            level='WARNING'
        )

        user_name = user.get_full_name()
        user.delete()

        return Response({
            'status': 'success',
            'message': f'User {user_name} deleted successfully.'
        })

    except User.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'User not found.'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'status': 'error',
            'message': f'Error deleting user: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@login_required
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def super_admin_delete_role(request, role_id):
    """Delete a user role"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        return Response({
            'status': 'error',
            'message': 'Access denied. Super Admin role required.'
        }, status=status.HTTP_403_FORBIDDEN)

    try:
        role = UserRole.objects.get(id=role_id)

        # Log the action before deletion
        AuditLog.objects.create(
            user=request.user,
            action='DELETE_ROLE',
            description=f'Removed {role.get_role_display()} role from {role.user.get_full_name()}',
            level='INFO'
        )

        role_name = role.get_role_display()
        user_name = role.user.get_full_name()
        role.delete()

        return Response({
            'status': 'success',
            'message': f'{role_name} role removed from {user_name}.'
        })

    except UserRole.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'Role not found.'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'status': 'error',
            'message': f'Error removing role: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@login_required
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def super_admin_add_role(request):
    """Add a role to a user"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        return Response({
            'status': 'error',
            'message': 'Access denied. Super Admin role required.'
        }, status=status.HTTP_403_FORBIDDEN)

    try:
        user_id = request.POST.get('user_id')
        role = request.POST.get('role')
        faculty_id = request.POST.get('faculty_id')
        department_id = request.POST.get('department_id')

        user = User.objects.get(id=user_id)
        faculty = Faculty.objects.get(id=faculty_id) if faculty_id else None
        department = Department.objects.get(id=department_id) if department_id else None

        # Check if role already exists
        existing_role = UserRole.objects.filter(
            user=user,
            role=role,
            faculty=faculty,
            department=department
        ).first()

        if existing_role:
            return Response({
                'status': 'error',
                'message': 'User already has this role.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Create the role
        new_role = UserRole.objects.create(
            user=user,
            role=role,
            faculty=faculty,
            department=department,
            created_by=request.user
        )

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='ADD_ROLE',
            description=f'Added {new_role.get_role_display()} role to {user.get_full_name()}',
            level='INFO',
            faculty=faculty,
            department=department
        )

        return Response({
            'status': 'success',
            'message': f'{new_role.get_role_display()} role added to {user.get_full_name()}.'
        })

    except User.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'User not found.'
        }, status=status.HTTP_404_NOT_FOUND)
    except Faculty.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'Faculty not found.'
        }, status=status.HTTP_404_NOT_FOUND)
    except Department.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'Department not found.'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'status': 'error',
            'message': f'Error adding role: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@login_required
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def super_admin_get_role_holders(request):
    """Get users who have a specific role"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        return Response({
            'status': 'error',
            'message': 'Access denied. Super Admin role required.'
        }, status=status.HTTP_403_FORBIDDEN)

    try:
        import json
        data = json.loads(request.body)
        role = data.get('role')
        faculty_id = data.get('faculty_id')
        department_id = data.get('department_id')

        if not role:
            return Response({
                'status': 'error',
                'message': 'Role is required.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Build query filters
        filters = {'role': role}
        if faculty_id:
            filters['faculty_id'] = faculty_id
        if department_id:
            filters['department_id'] = department_id

        # Get users with this role
        user_roles = UserRole.objects.filter(**filters).select_related('user', 'faculty', 'department')

        role_holders = []
        for user_role in user_roles:
            role_holders.append({
                'id': user_role.user.id,
                'name': user_role.user.get_full_name(),
                'username': user_role.user.username,
                'faculty': user_role.faculty.name if user_role.faculty else None,
                'department': user_role.department.name if user_role.department else None,
            })

        return Response({
            'status': 'success',
            'role_holders': role_holders
        })

    except json.JSONDecodeError:
        return Response({
            'status': 'error',
            'message': 'Invalid JSON data.'
        }, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({
            'status': 'error',
            'message': f'Error fetching role holders: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@login_required
def super_admin_department_details(request, department_id):
    """View detailed information about a specific department"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    try:
        department = Department.objects.select_related('faculty', 'hod').get(id=department_id)

        context = {
            'department': department,
        }

        return render(request, 'super_admin_department_details.html', context)
    except Department.DoesNotExist:
        messages.error(request, 'Department not found.')
        return redirect('super_admin_manage_departments')


@login_required
def super_admin_edit_department(request, department_id):
    """Edit department information"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    try:
        department = Department.objects.select_related('faculty', 'hod').get(id=department_id)
    except Department.DoesNotExist:
        messages.error(request, 'Department not found.')
        return redirect('super_admin_manage_departments')

    if request.method == 'POST':
        # Update department information
        department.name = request.POST.get('name', '').strip()
        department.code = request.POST.get('code', '').strip()
        hod_id = request.POST.get('hod_id')

        if hod_id:
            try:
                hod = User.objects.get(id=hod_id)
                department.hod = hod
            except User.DoesNotExist:
                messages.error(request, 'Selected HOD not found.')
                return redirect('super_admin_edit_department', department_id=department.id)

        try:
            department.save()
            messages.success(request, f'Department "{department.name}" updated successfully.')
            return redirect('super_admin_department_details', department_id=department.id)
        except Exception as e:
            messages.error(request, f'Error updating department: {str(e)}')

    # Get potential HODs (users with HOD role in this faculty)
    potential_hods = User.objects.filter(
        rms_roles__role='HOD',
        rms_roles__faculty=department.faculty
    ).distinct()

    context = {
        'department': department,
        'potential_hods': potential_hods,
    }

    return render(request, 'super_admin_edit_department.html', context)


@login_required
def super_admin_change_password(request, user_id):
    """Change password for a user"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    try:
        target_user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('super_admin_manage_users')

    if request.method == 'POST':
        new_password = request.POST.get('new_password', '').strip()
        confirm_password = request.POST.get('confirm_password', '').strip()

        errors = []

        # Validation
        if not new_password:
            errors.append('New password is required')
        elif len(new_password) < 8:
            errors.append('Password must be at least 8 characters long')

        if new_password != confirm_password:
            errors.append('Passwords do not match')

        if not errors:
            try:
                # Change the password
                target_user.set_password(new_password)
                target_user.save()

                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='CHANGE_PASSWORD',
                    description=f'Changed password for user {target_user.get_full_name()} ({target_user.username})',
                    level='INFO'
                )

                messages.success(request, f'Password changed successfully for {target_user.get_full_name()}.')
                return redirect('super_admin_edit_user', user_id=user_id)

            except Exception as e:
                messages.error(request, f'Error changing password: {str(e)}')
        else:
            for error in errors:
                messages.error(request, error)

    return redirect('super_admin_edit_user', user_id=user_id)


@login_required
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def super_admin_get_all_role_holders(request):
    """Get all users who have any role"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        return Response({
            'status': 'error',
            'message': 'Access denied. Super Admin role required.'
        }, status=status.HTTP_403_FORBIDDEN)

    try:
        # Get all user roles with related data
        user_roles = UserRole.objects.select_related('user', 'faculty', 'department').order_by('user__first_name', 'user__last_name')

        role_holders = []
        for user_role in user_roles:
            role_holders.append({
                'user_role_id': user_role.id,
                'user_id': user_role.user.id,
                'user_name': user_role.user.get_full_name(),
                'role': user_role.role,
                'role_display': user_role.get_role_display(),
                'faculty_name': user_role.faculty.name if user_role.faculty else None,
                'department_name': user_role.department.name if user_role.department else None,
            })

        return Response({
            'status': 'success',
            'role_holders': role_holders
        })

    except Exception as e:
        return Response({
            'status': 'error',
            'message': f'Error fetching role holders: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@login_required
def super_admin_permission_delegations(request):
    """View and manage active permission delegations"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    # Get all active delegations
    active_delegations = PermissionDelegation.objects.filter(
        status='ACTIVE'
    ).select_related('delegator', 'delegate', 'delegated_role', 'created_by').order_by('-created_at')

    context = {
        'active_delegations': active_delegations,
    }

    return render(request, 'super_admin_permission_delegations.html', context)


@login_required
def super_admin_revoke_delegation(request, delegation_id):
    """Revoke a permission delegation"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    try:
        reason = request.POST.get('reason', 'Revoked by Super Admin')

        # Use delegation service for revocation
        from .delegation_service import DelegationService

        success, messages_list = DelegationService.revoke_delegation(
            delegation_id=delegation_id,
            revoked_by=request.user,
            reason=reason
        )

        if success:
            for msg in messages_list:
                messages.success(request, msg)
        else:
            for error in messages_list:
                messages.error(request, error)

    except Exception as e:
        messages.error(request, f'Error revoking delegation: {str(e)}')

    return redirect('super_admin_permission_delegations')


@login_required
def super_admin_create_delegation(request):
    """Create delegation interface"""
    # Check if user is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['SUPER_ADMIN'])
    if not has_access:
        messages.error(request, "Access denied. Super Admin privileges required.")
        return redirect('dashboard')

    if request.method == 'POST':
        return handle_delegation_creation(request)

    # Get delegatable roles (only Super Admin can create delegations)
    delegatable_roles = PermissionDelegation.get_delegatable_roles(request.user)

    # Get all faculties for filtering
    faculties = Faculty.objects.all().order_by('name')

    # Get delegation statistics
    delegation_stats = {
        'total_active': PermissionDelegation.objects.filter(status='ACTIVE').count(),
        'total_users_with_delegations': PermissionDelegation.objects.filter(
            status='ACTIVE'
        ).values('delegate').distinct().count(),
        'available_roles': delegatable_roles.count(),
    }

    context = {
        'delegatable_roles': delegatable_roles,
        'faculties': faculties,
        'delegation_stats': delegation_stats,
    }

    return render(request, 'super_admin_create_delegation.html', context)


def handle_delegation_creation(request):
    """Handles delegation creation form"""
    try:
        # Get form data
        delegator_role_id = request.POST.get('delegator_user')
        delegate_user_id = request.POST.get('delegate_user')
        reason = request.POST.get('reason', '').strip()
        enable_time_based = request.POST.get('enable_time_based') == 'on'
        start_date = request.POST.get('start_date') if enable_time_based else None
        end_date = request.POST.get('end_date') if enable_time_based else None

        # Check if all required fields are filled
        if not all([delegator_role_id, delegate_user_id, reason]):
            messages.error(request, "All required fields must be filled.")
            return redirect('super_admin_create_delegation')

        # Parse dates if time-based
        parsed_start_date = None
        parsed_end_date = None
        if enable_time_based:
            try:
                from django.utils.dateparse import parse_datetime
                if start_date:
                    parsed_start_date = parse_datetime(start_date)
                if end_date:
                    parsed_end_date = parse_datetime(end_date)
            except ValueError:
                messages.error(request, "Invalid date format.")
                return redirect('super_admin_create_delegation')

        # Create delegation using service
        from .delegation_service import DelegationService

        success, result, message_list = DelegationService.create_new_delegation(
            delegator_role_id=delegator_role_id,
            delegate_user_id=delegate_user_id,
            created_by=request.user,
            reason=reason,
            start_date=parsed_start_date,
            end_date=parsed_end_date
        )

        if success:
            for msg in message_list:
                messages.success(request, msg)
            return redirect('super_admin_permission_delegations')
        else:
            for error in result:
                messages.error(request, error)
            return redirect('super_admin_create_delegation')

    except Exception as e:
        messages.error(request, f"Error creating delegation: {str(e)}")
        return redirect('super_admin_create_delegation')


@login_required
@require_http_methods(["GET"])
def get_role_holders(request):
    """AJAX endpoint to get users with a specific role"""
    # Check if user is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['SUPER_ADMIN'])
    if not has_access:
        return JsonResponse({'error': 'Access denied'}, status=403)

    role = request.GET.get('role')
    faculty_id = request.GET.get('faculty')

    if not role:
        return JsonResponse({'error': 'Role parameter required'}, status=400)

    # Get users with the specified role
    role_holders = UserRole.objects.filter(
        role=role,
        is_temporary=False  # Only direct role holders, not delegated
    ).select_related('user', 'faculty', 'department')

    # Filter by faculty if specified
    if faculty_id:
        role_holders = role_holders.filter(faculty_id=faculty_id)

    # Exclude roles that are already being delegated
    active_delegation_role_ids = PermissionDelegation.objects.filter(
        status='ACTIVE'
    ).values_list('delegated_role_id', flat=True)
    role_holders = role_holders.exclude(id__in=active_delegation_role_ids)

    users_data = []
    for role_holder in role_holders:
        users_data.append({
            'role_id': role_holder.id,
            'user_id': role_holder.user.id,
            'name': role_holder.user.get_full_name(),
            'username': role_holder.user.username,
            'faculty': role_holder.faculty.name if role_holder.faculty else None,
            'department': role_holder.department.name if role_holder.department else None,
            'can_delegate': True  # All returned roles can be delegated
        })

    return JsonResponse({'users': users_data})


@login_required
@require_http_methods(["GET"])
def get_eligible_delegates(request):
    """AJAX endpoint to get users eligible to receive a delegation"""
    # Check if user is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['SUPER_ADMIN'])
    if not has_access:
        return JsonResponse({'error': 'Access denied'}, status=403)

    delegator_role_id = request.GET.get('delegator_role')
    if not delegator_role_id:
        return JsonResponse({'error': 'Delegator role parameter required'}, status=400)

    try:
        delegator_role = UserRole.objects.get(id=delegator_role_id)

        # Get eligible delegates using the model method
        eligible_users = PermissionDelegation.get_eligible_delegates(
            delegator_role, request.user
        )

        users_data = []
        for user in eligible_users:
            # Get user's primary role info for context
            primary_role = UserRole.objects.filter(
                user=user,
                is_temporary=False,
                is_primary=True
            ).first()

            users_data.append({
                'user_id': user.id,
                'name': user.get_full_name(),
                'username': user.username,
                'email': user.email,
                'primary_role': primary_role.get_role_display() if primary_role else 'No Role',
                'faculty': primary_role.faculty.name if primary_role and primary_role.faculty else None,
                'department': primary_role.department.name if primary_role and primary_role.department else None,
            })

        return JsonResponse({
            'users': users_data,
            'total_eligible': len(users_data),
            'delegator_faculty': delegator_role.faculty.name if delegator_role.faculty else None
        })

    except UserRole.DoesNotExist:
        return JsonResponse({'error': 'Invalid delegator role'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_http_methods(["GET"])
def check_delegation_conflicts_view(request):
    """AJAX endpoint to check for delegation conflicts with enhanced validation"""
    # Check if user is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['SUPER_ADMIN'])
    if not has_access:
        return JsonResponse({'error': 'Access denied'}, status=403)

    delegate_user_id = request.GET.get('delegate')
    delegator_role_id = request.GET.get('delegator_role')

    if not all([delegate_user_id, delegator_role_id]):
        return JsonResponse({'error': 'Missing parameters'}, status=400)

    try:
        delegate_user = User.objects.get(id=delegate_user_id)
        delegator_role = UserRole.objects.get(id=delegator_role_id)

        # Use delegation service for comprehensive conflict checking
        from .delegation_service import DelegationService

        conflicts = DelegationService.get_delegation_conflicts(delegate_user, delegator_role.role)

        # Check delegation rules
        is_valid, rule_errors = PermissionDelegation.validate_delegation_rules(
            delegator_role, delegate_user, request.user
        )

        # Check cross-faculty delegation
        cross_faculty_allowed, cross_faculty_reason = DelegationService.validate_cross_faculty_delegation(
            delegator_role, delegate_user, request.user
        )

        return JsonResponse({
            'conflicts': conflicts,
            'rule_errors': rule_errors if not is_valid else [],
            'is_valid': is_valid and len(conflicts) == 0,
            'cross_faculty_allowed': cross_faculty_allowed,
            'cross_faculty_reason': cross_faculty_reason,
            'delegate_faculty': _get_user_faculty(delegate_user),
            'delegator_faculty': delegator_role.faculty.name if delegator_role.faculty else None
        })

    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    except UserRole.DoesNotExist:
        return JsonResponse({'error': 'Delegator role not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def _get_user_faculty(user):
    """Helper function to get user's faculty"""
    primary_role = UserRole.objects.filter(
        user=user,
        is_temporary=False,
        is_primary=True
    ).first()
    return primary_role.faculty.name if primary_role and primary_role.faculty else None


def check_delegation_conflicts_internal(delegate_user, role):
    """Internal function to check for delegation conflicts"""
    conflicts = []

    # Check if user already has this role
    existing_role = UserRole.objects.filter(user=delegate_user, role=role).first()
    if existing_role:
        if existing_role.is_temporary:
            conflicts.append(f"User already has delegated {role} permissions")
        else:
            conflicts.append(f"User already has direct {role} role")

    # Check for role hierarchy conflicts
    user_roles = UserRole.objects.filter(user=delegate_user).values_list('role', flat=True)

    # Define role hierarchy (higher roles include lower role permissions)
    role_hierarchy = {
        'SUPER_ADMIN': ['SENATE', 'DAAA', 'FACULTY_DEAN', 'HOD', 'EXAM_OFFICER', 'LECTURER', 'ADMISSION_OFFICER'],
        'SENATE': ['DAAA', 'FACULTY_DEAN', 'HOD', 'EXAM_OFFICER', 'LECTURER'],
        'DAAA': ['FACULTY_DEAN', 'HOD', 'EXAM_OFFICER', 'LECTURER'],
        'FACULTY_DEAN': ['HOD', 'EXAM_OFFICER', 'LECTURER'],
        'HOD': ['EXAM_OFFICER', 'LECTURER'],
    }

    # Check if user has a higher role that would make this delegation redundant
    for user_role in user_roles:
        if user_role in role_hierarchy and role in role_hierarchy[user_role]:
            conflicts.append(f"User already has {user_role} role which includes {role} permissions")

    # Check if delegating a lower role to someone with a higher role
    if role in role_hierarchy:
        for user_role in user_roles:
            if user_role in role_hierarchy[role]:
                conflicts.append(f"Delegating {role} to user with {user_role} role may create permission conflicts")

    return conflicts


@login_required
def super_admin_delegation_history(request):
    """View delegation history with filtering and pagination"""
    # Check if user is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['SUPER_ADMIN'])
    if not has_access:
        messages.error(request, "Access denied. Super Admin privileges required.")
        return redirect('dashboard')

    # Get filter parameters
    status_filter = request.GET.get('status', '')
    role_filter = request.GET.get('role', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')

    # Build queryset with filters
    delegations = PermissionDelegation.objects.all().select_related(
        'delegator', 'delegate', 'delegated_role', 'created_by',
        'delegated_role__faculty', 'delegated_role__department'
    ).order_by('-created_at')

    if status_filter:
        delegations = delegations.filter(status=status_filter)

    if role_filter:
        delegations = delegations.filter(delegated_role__role=role_filter)

    if date_from:
        from django.utils.dateparse import parse_date
        parsed_date = parse_date(date_from)
        if parsed_date:
            delegations = delegations.filter(created_at__date__gte=parsed_date)

    if date_to:
        from django.utils.dateparse import parse_date
        parsed_date = parse_date(date_to)
        if parsed_date:
            delegations = delegations.filter(created_at__date__lte=parsed_date)

    # Calculate statistics
    stats = {
        'total_delegations': PermissionDelegation.objects.count(),
        'active_delegations': PermissionDelegation.objects.filter(status='ACTIVE').count(),
        'expired_delegations': PermissionDelegation.objects.filter(status='EXPIRED').count(),
        'revoked_delegations': PermissionDelegation.objects.filter(status='REVOKED').count(),
    }

    # Pagination
    from django.core.paginator import Paginator
    paginator = Paginator(delegations, 20)  # 20 delegations per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'delegations': page_obj,
        'stats': stats,
        'total_count': delegations.count(),
        'is_paginated': page_obj.has_other_pages(),
        'page_obj': page_obj,
    }

    return render(request, 'super_admin_delegation_history.html', context)


@login_required
def super_admin_export_delegation_report(request):
    """Export delegation report as CSV"""
    # Check if user is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['SUPER_ADMIN'])
    if not has_access:
        messages.error(request, "Access denied. Super Admin privileges required.")
        return redirect('dashboard')

    import csv
    from django.utils import timezone

    # Get same filters as history view
    status_filter = request.GET.get('status', '')
    role_filter = request.GET.get('role', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')

    # Build queryset with filters
    delegations = PermissionDelegation.objects.all().select_related(
        'delegator', 'delegate', 'delegated_role', 'created_by',
        'delegated_role__faculty', 'delegated_role__department'
    ).order_by('-created_at')

    if status_filter:
        delegations = delegations.filter(status=status_filter)
    if role_filter:
        delegations = delegations.filter(delegated_role__role=role_filter)
    if date_from:
        from django.utils.dateparse import parse_date
        parsed_date = parse_date(date_from)
        if parsed_date:
            delegations = delegations.filter(created_at__date__gte=parsed_date)
    if date_to:
        from django.utils.dateparse import parse_date
        parsed_date = parse_date(date_to)
        if parsed_date:
            delegations = delegations.filter(created_at__date__lte=parsed_date)

    # Create CSV response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="delegation_report_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'

    writer = csv.writer(response)

    # Write header
    writer.writerow([
        'ID', 'Role', 'Delegator', 'Delegate', 'Created By', 'Status',
        'Created Date', 'Start Date', 'End Date', 'Faculty', 'Department', 'Reason'
    ])

    # Write data
    for delegation in delegations:
        writer.writerow([
            delegation.id,
            delegation.delegated_role.get_role_display(),
            delegation.delegator.get_full_name(),
            delegation.delegate.get_full_name(),
            delegation.created_by.get_full_name(),
            delegation.get_status_display(),
            delegation.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            delegation.start_date.strftime('%Y-%m-%d %H:%M:%S') if delegation.start_date else '',
            delegation.end_date.strftime('%Y-%m-%d %H:%M:%S') if delegation.end_date else '',
            delegation.delegated_role.faculty.name if delegation.delegated_role.faculty else '',
            delegation.delegated_role.department.name if delegation.delegated_role.department else '',
            delegation.reason[:100] + '...' if len(delegation.reason) > 100 else delegation.reason
        ])

    # Log the export
    AuditLog.objects.create(
        user=request.user,
        action='EXPORT_DELEGATION_REPORT',
        description=f'Exported delegation report with {delegations.count()} records',
        level='INFO'
    )

    return response


# ============================================================================
# CONSOLIDATED NAVIGATION VIEWS (Smart Multi-Role Access)
# ============================================================================

from .permissions import get_user_roles_with_details, get_role_display_name

@login_required
def consolidated_students_view(request):
    """
    Consolidated students view with role context switching.
    Shows students based on user's available roles with context switching buttons.
    """
    user_roles = get_user_roles_with_details(request.user)
    available_contexts = []
    processed_roles = set()  # Prevent duplicate contexts

    # I think this approach will let users switch between different role contexts
    for role_info in user_roles:
        role = role_info['role']
        if role in ['FACULTY_DEAN', 'HOD', 'ADMISSION_OFFICER', 'EXAM_OFFICER']:
            # Skip if we already processed this role type
            if role in processed_roles:
                continue

            processed_roles.add(role)

            # Correct URL mapping for students
            url_mapping = {
                'FACULTY_DEAN': 'faculty_dean_students',
                'HOD': 'hod_lecturer_list',  # HOD manages lecturers, not students directly
                'ADMISSION_OFFICER': 'admission_all_students',
                'EXAM_OFFICER': 'exam_officer_dashboard'  # Exam officers don't have direct student management
            }

            # Build context display with delegation info
            context_suffix = ""
            if role_info.get('department'):
                context_suffix = f" - {role_info['department'].name}"
            elif role_info.get('faculty'):
                context_suffix = f" - {role_info['faculty'].name}"

            context = {
                'role': role,
                'role_display': get_role_display_name(role),
                'context_suffix': context_suffix,
                'department': role_info.get('department'),
                'faculty': role_info.get('faculty'),
                'is_delegated': role_info.get('is_delegated', False),
                'url_name': url_mapping.get(role)
            }
            available_contexts.append(context)

    # Default to first available context
    selected_context = request.GET.get('context', available_contexts[0]['role'] if available_contexts else None)

    context = {
        'page_title': 'Students Management',
        'available_contexts': available_contexts,
        'selected_context': selected_context,
        'user_roles': [r['role'] for r in user_roles]
    }

    return render(request, 'consolidated/students.html', context)


@login_required
def consolidated_lecturers_view(request):
    """
    Consolidated lecturers view with role context switching and actual data filtering.
    """
    user_roles = get_user_roles_with_details(request.user)
    available_contexts = []
    processed_roles = set()  # I think this will prevent duplicate contexts

    for role_info in user_roles:
        role = role_info['role']
        if role in ['FACULTY_DEAN', 'HOD']:
            # Skip if we already processed this role type
            if role in processed_roles:
                continue

            processed_roles.add(role)

            # Build context display with delegation info
            context_suffix = ""
            if role_info.get('department'):
                context_suffix = f" - {role_info['department'].name}"
            elif role_info.get('faculty'):
                context_suffix = f" - {role_info['faculty'].name}"

            context = {
                'role': role,
                'role_display': get_role_display_name(role),
                'context_suffix': context_suffix,
                'department': role_info.get('department'),
                'faculty': role_info.get('faculty'),
                'is_delegated': role_info.get('is_delegated', False)
            }
            available_contexts.append(context)

    # Get selected context
    selected_context = request.GET.get('context', available_contexts[0]['role'] if available_contexts else None)

    # Find the selected context details
    current_context = None
    for ctx in available_contexts:
        if ctx['role'] == selected_context:
            current_context = ctx
            break

    # Get lecturers based on selected context
    lecturer_roles = []
    departments = []
    stats = {}

    if current_context:
        if current_context['role'] == 'FACULTY_DEAN':
            # Faculty Dean sees all lecturers in their faculty
            faculty = current_context['faculty']
            if faculty:
                lecturer_roles = UserRole.objects.filter(
                    role='LECTURER',
                    faculty=faculty
                ).select_related('user', 'department').order_by('user__first_name', 'user__last_name')

                departments = Department.objects.filter(faculty=faculty).order_by('name')

                stats = {
                    'total_lecturers': lecturer_roles.count(),
                    'total_hods': UserRole.objects.filter(role='HOD', faculty=faculty).count(),
                    'departments_count': departments.count(),
                    'lecturers_by_dept': {
                        dept.name: lecturer_roles.filter(department=dept).count()
                        for dept in departments
                    }
                }

        elif current_context['role'] == 'HOD':
            # HOD sees lecturers in their department
            department = current_context['department']
            if department:
                lecturer_roles = UserRole.objects.filter(
                    role='LECTURER',
                    department=department
                ).select_related('user', 'department').order_by('user__first_name', 'user__last_name')

                departments = [department]

                stats = {
                    'total_lecturers': lecturer_roles.count(),
                    'department_name': department.name,
                    'faculty_name': department.faculty.name if department.faculty else 'N/A'
                }

    context = {
        'page_title': 'Lecturers Management',
        'available_contexts': available_contexts,
        'selected_context': selected_context,
        'current_context': current_context,
        'lecturer_roles': lecturer_roles,
        'departments': departments,
        'stats': stats,
        'user_roles': [r['role'] for r in user_roles]
    }

    return render(request, 'consolidated/lecturers.html', context)


@login_required
def consolidated_courses_view(request):
    """
    Consolidated courses view with role context switching.
    """
    user_roles = get_user_roles_with_details(request.user)
    available_contexts = []
    processed_roles = set()  # Prevent duplicate contexts

    for role_info in user_roles:
        role = role_info['role']
        if role in ['FACULTY_DEAN', 'HOD']:
            # Skip if we already processed this role type
            if role in processed_roles:
                continue

            processed_roles.add(role)

            # Correct URL mapping for courses
            url_mapping = {
                'FACULTY_DEAN': 'faculty_dean_courses',
                'HOD': 'hod_manage_courses'
            }

            # Build context display with delegation info
            context_suffix = ""
            if role_info.get('department'):
                context_suffix = f" - {role_info['department'].name}"
            elif role_info.get('faculty'):
                context_suffix = f" - {role_info['faculty'].name}"

            context = {
                'role': role,
                'role_display': get_role_display_name(role),
                'context_suffix': context_suffix,
                'department': role_info.get('department'),
                'faculty': role_info.get('faculty'),
                'is_delegated': role_info.get('is_delegated', False),
                'url_name': url_mapping.get(role)
            }
            available_contexts.append(context)

    selected_context = request.GET.get('context', available_contexts[0]['role'] if available_contexts else None)

    context = {
        'page_title': 'Courses Management',
        'available_contexts': available_contexts,
        'selected_context': selected_context,
        'user_roles': [r['role'] for r in user_roles]
    }

    return render(request, 'consolidated/courses.html', context)


@login_required
def consolidated_results_view(request):
    """
    Consolidated results view with role context switching.
    """
    user_roles = get_user_roles_with_details(request.user)
    available_contexts = []

    for role_info in user_roles:
        role = role_info['role']
        if role in ['FACULTY_DEAN', 'HOD', 'EXAM_OFFICER', 'DAAA', 'SENATE']:
            # Correct URL mapping for results
            url_mapping = {
                'FACULTY_DEAN': 'faculty_dean_pending_results',
                'HOD': 'hod_pending_results',
                'EXAM_OFFICER': 'exam_officer_dashboard',
                'DAAA': 'daaa_pending_results',
                'SENATE': 'senate_pending_results'
            }
            context = {
                'role': role,
                'role_display': get_role_display_name(role),
                'department': role_info.get('department'),
                'faculty': role_info.get('faculty'),
                'is_delegated': role_info.get('is_delegated', False),
                'url_name': url_mapping.get(role)
            }
            available_contexts.append(context)

    selected_context = request.GET.get('context', available_contexts[0]['role'] if available_contexts else None)

    context = {
        'page_title': 'Results Management',
        'available_contexts': available_contexts,
        'selected_context': selected_context,
        'user_roles': [r['role'] for r in user_roles]
    }

    return render(request, 'consolidated/results.html', context)


@login_required
def consolidated_reports_view(request):
    """
    Consolidated reports view with role context switching.
    """
    user_roles = get_user_roles_with_details(request.user)
    available_contexts = []

    for role_info in user_roles:
        role = role_info['role']
        if role in ['FACULTY_DEAN', 'HOD', 'DAAA', 'SENATE']:
            # Correct URL mapping for reports
            url_mapping = {
                'FACULTY_DEAN': 'faculty_dean_reports',
                'HOD': 'hod_course_reports',
                'DAAA': 'daaa_reports',
                'SENATE': 'senate_dashboard'  # Senate doesn't have specific reports URL
            }
            context = {
                'role': role,
                'role_display': get_role_display_name(role),
                'department': role_info.get('department'),
                'faculty': role_info.get('faculty'),
                'is_delegated': role_info.get('is_delegated', False),
                'url_name': url_mapping.get(role)
            }
            available_contexts.append(context)

    selected_context = request.GET.get('context', available_contexts[0]['role'] if available_contexts else None)

    context = {
        'page_title': 'Reports & Analytics',
        'available_contexts': available_contexts,
        'selected_context': selected_context,
        'user_roles': [r['role'] for r in user_roles]
    }

    return render(request, 'consolidated/reports.html', context)


@login_required
def faculty_dean_students(request):
    """Faculty Dean Students Management"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Faculty Dean role.')
        return redirect('dashboard')

    # Get search parameters
    search_query = request.GET.get('search', '')
    department_filter = request.GET.get('department', '')
    level_filter = request.GET.get('level', '')

    # Get students in this faculty
    students = Student.objects.filter(faculty=faculty).select_related('department', 'user')

    # Apply filters
    if search_query:
        students = students.filter(
            Q(matric_number__icontains=search_query) |
            Q(user__first_name__icontains=search_query) |
            Q(user__last_name__icontains=search_query)
        )

    if department_filter:
        students = students.filter(department_id=department_filter)

    if level_filter:
        students = students.filter(current_level__name=level_filter)

    # Get departments for filter
    departments = Department.objects.filter(faculty=faculty).order_by('name')

    # Pagination
    from django.core.paginator import Paginator
    paginator = Paginator(students, 20)
    page_number = request.GET.get('page')
    students_page = paginator.get_page(page_number)

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Statistics
    total_students = Student.objects.filter(faculty=faculty).count()
    active_students = Student.objects.filter(faculty=faculty, user__is_active=True).count()
    new_students = Student.objects.filter(faculty=faculty, admission_session=current_session).count() if current_session else 0
    graduating_students = Student.objects.filter(faculty=faculty, current_level__name__contains='400').count()

    stats = {
        'total_students': total_students,
        'active_students': active_students,
        'new_students': new_students,
        'graduating_students': graduating_students,
        'by_level': {
            '100': Student.objects.filter(faculty=faculty, current_level__name__contains='100').count(),
            '200': Student.objects.filter(faculty=faculty, current_level__name__contains='200').count(),
            '300': Student.objects.filter(faculty=faculty, current_level__name__contains='300').count(),
            '400': Student.objects.filter(faculty=faculty, current_level__name__contains='400').count(),
        },
        'by_department': {dept.name: Student.objects.filter(department=dept).count() for dept in departments}
    }

    # Get academic sessions and levels for student management
    academic_sessions = AcademicSession.objects.all().order_by('-start_date')
    levels = Level.objects.all().order_by('name')

    context = {
        'faculty': faculty,
        'students': students_page,
        'departments': departments,
        'stats': stats,
        'search_query': search_query,
        'department_filter': department_filter,
        'level_filter': level_filter,
        'academic_sessions': academic_sessions,
        'levels': levels,
    }

    return render(request, 'faculty_dean_students.html', context)


@login_required
def faculty_dean_lecturers(request):
    """Faculty Dean Lecturers Management"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Faculty Dean role.')
        return redirect('dashboard')

    # Get lecturers in this faculty
    lecturer_roles = UserRole.objects.filter(
        role='LECTURER',
        faculty=faculty
    ).select_related('user', 'department')

    # Get HODs in this faculty
    hod_roles = UserRole.objects.filter(
        role='HOD',
        faculty=faculty
    ).select_related('user', 'department')

    # Get departments for context
    departments = Department.objects.filter(faculty=faculty).order_by('name')

    # Statistics
    stats = {
        'total_lecturers': lecturer_roles.count(),
        'total_hods': hod_roles.count(),
        'departments_count': departments.count(),
        'lecturers_by_dept': {
            dept.name: lecturer_roles.filter(department=dept).count()
            for dept in departments
        }
    }

    context = {
        'faculty': faculty,
        'lecturer_roles': lecturer_roles,
        'hod_roles': hod_roles,
        'departments': departments,
        'stats': stats,
    }

    return render(request, 'faculty_dean_lecturers.html', context)


@login_required
def faculty_dean_courses(request):
    """Faculty Dean Courses Management"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Faculty Dean role.')
        return redirect('dashboard')

    # Get courses in this faculty
    courses = Course.objects.filter(departments__faculty=faculty).distinct().select_related('lecturer').prefetch_related('department_set')

    # Get departments for context
    departments = Department.objects.filter(faculty=faculty).order_by('name')

    # Statistics
    stats = {
        'total_courses': courses.count(),
        'courses_by_level': {
            '100': courses.filter(code__startswith='1').count(),
            '200': courses.filter(code__startswith='2').count(),
            '300': courses.filter(code__startswith='3').count(),
            '400': courses.filter(code__startswith='4').count(),
        },
        'courses_by_dept': {
            dept.name: courses.filter(departments=dept).count()
            for dept in departments
        }
    }

    context = {
        'faculty': faculty,
        'courses': courses,
        'departments': departments,
        'stats': stats,
    }

    return render(request, 'faculty_dean_courses.html', context)


@login_required
def faculty_dean_results(request):
    """Faculty Dean Results Management"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Faculty Dean role.')
        return redirect('dashboard')

    # Get results for this faculty
    results = Result.objects.filter(
        enrollment__student__faculty=faculty
    ).select_related(
        'enrollment__student__user',
        'enrollment__course',
        'enrollment__student__department'
    ).order_by('-updated_at')

    # Filter by status if provided
    status_filter = request.GET.get('status', '')
    if status_filter:
        results = results.filter(status=status_filter)

    # Pagination
    from django.core.paginator import Paginator
    paginator = Paginator(results, 25)
    page_number = request.GET.get('page')
    results_page = paginator.get_page(page_number)

    # Statistics
    stats = {
        'total_results': Result.objects.filter(enrollment__student__faculty=faculty).count(),
        'pending_approval': Result.objects.filter(
            enrollment__student__faculty=faculty,
            status__in=['SUBMITTED_TO_DEAN', 'APPROVED_BY_HOD']
        ).count(),
        'published': Result.objects.filter(
            enrollment__student__faculty=faculty,
            status='PUBLISHED'
        ).count(),
        'draft': Result.objects.filter(
            enrollment__student__faculty=faculty,
            status='DRAFT'
        ).count(),
    }

    context = {
        'faculty': faculty,
        'results': results_page,
        'stats': stats,
        'status_filter': status_filter,
    }

    return render(request, 'faculty_dean_results.html', context)


@login_required
def faculty_dean_pending_results(request):
    """Faculty Dean Pending Results for Approval"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Faculty Dean role.')
        return redirect('dashboard')

    # Get pending results
    pending_results = Result.objects.filter(
        enrollment__student__faculty=faculty,
        status__in=['SUBMITTED_TO_DEAN', 'APPROVED_BY_HOD']
    ).select_related(
        'enrollment__student__user',
        'enrollment__course',
        'enrollment__student__department'
    ).order_by('-updated_at')

    context = {
        'faculty': faculty,
        'pending_results': pending_results,
    }

    return render(request, 'faculty_dean_pending_results.html', context)


@login_required
def faculty_dean_reports(request):
    """Faculty Dean Reports"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Faculty Dean role.')
        return redirect('dashboard')

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Get comprehensive statistics
    departments = Department.objects.filter(faculty=faculty)

    # Student statistics
    total_students = Student.objects.filter(faculty=faculty).count()
    students_by_level = {}
    students_by_department = {}

    for level in Level.objects.all():
        count = Student.objects.filter(faculty=faculty, current_level=level).count()
        if count > 0:
            students_by_level[level.name] = count

    for dept in departments:
        count = Student.objects.filter(department=dept).count()
        students_by_department[dept.name] = count

    # Staff statistics
    total_lecturers = UserRole.objects.filter(role='LECTURER', faculty=faculty).count()
    lecturers_by_department = {}

    for dept in departments:
        count = UserRole.objects.filter(role='LECTURER', department=dept).count()
        lecturers_by_department[dept.name] = count

    # Course statistics
    total_courses = Course.objects.filter(departments__faculty=faculty).distinct().count()
    courses_by_level = {}

    for level in Level.objects.all():
        count = Course.objects.filter(departments__faculty=faculty, level=level).distinct().count()
        if count > 0:
            courses_by_level[level.name] = count

    # Results statistics
    if current_session:
        total_results = Result.objects.filter(
            enrollment__student__faculty=faculty,
            enrollment__session=current_session
        ).count()

        results_by_status = {}
        for status_choice in Result.STATUS_CHOICES:
            status_code = status_choice[0]
            status_name = status_choice[1]
            count = Result.objects.filter(
                enrollment__student__faculty=faculty,
                enrollment__session=current_session,
                status=status_code
            ).count()
            if count > 0:
                results_by_status[status_name] = count
    else:
        total_results = 0
        results_by_status = {}

    # Performance statistics
    grade_distribution = {}
    if current_session:
        for grade in ['A', 'B', 'C', 'D', 'E', 'F']:
            count = Result.objects.filter(
                enrollment__student__faculty=faculty,
                enrollment__session=current_session,
                grade=grade
            ).count()
            if count > 0:
                grade_distribution[grade] = count

    context = {
        'faculty': faculty,
        'current_session': current_session,
        'stats': {
            'overview': {
                'total_departments': departments.count(),
                'total_students': total_students,
                'total_lecturers': total_lecturers,
                'total_courses': total_courses,
                'total_results': total_results,
            },
            'students_by_level': students_by_level,
            'students_by_department': students_by_department,
            'lecturers_by_department': lecturers_by_department,
            'courses_by_level': courses_by_level,
            'results_by_status': results_by_status,
            'grade_distribution': grade_distribution,
        },
        'departments': departments,
    }

    return render(request, 'faculty_dean_reports.html', context)


@login_required
def faculty_dean_statistics(request):
    """Faculty Dean Statistics"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Faculty Dean role.')
        return redirect('dashboard')

    # Get comprehensive statistics
    departments = Department.objects.filter(faculty=faculty)

    stats = {
        'overview': {
            'total_departments': departments.count(),
            'total_students': Student.objects.filter(faculty=faculty).count(),
            'total_lecturers': UserRole.objects.filter(role='LECTURER', faculty=faculty).count(),
            'total_courses': Course.objects.filter(departments__faculty=faculty).distinct().count(),
        },
        'students_by_level': {
            '100': Student.objects.filter(faculty=faculty, current_level__name='100').count(),
            '200': Student.objects.filter(faculty=faculty, current_level__name='200').count(),
            '300': Student.objects.filter(faculty=faculty, current_level__name='300').count(),
            '400': Student.objects.filter(faculty=faculty, current_level__name='400').count(),
        },
        'results_by_status': {
            'published': Result.objects.filter(enrollment__student__faculty=faculty, status='PUBLISHED').count(),
            'pending': Result.objects.filter(enrollment__student__faculty=faculty, status__in=['SUBMITTED_TO_DEAN', 'APPROVED_BY_HOD']).count(),
            'draft': Result.objects.filter(enrollment__student__faculty=faculty, status='DRAFT').count(),
        }
    }

    context = {
        'faculty': faculty,
        'stats': stats,
        'departments': departments,
    }

    return render(request, 'faculty_dean_statistics.html', context)


@login_required
def faculty_dean_settings(request):
    """Faculty Dean Settings"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Faculty Dean role.')
        return redirect('dashboard')

    context = {
        'faculty': faculty,
    }

    return render(request, 'faculty_dean_settings.html', context)





@login_required
def faculty_dean_assign_hod(request, department_id):
    """Assign HOD to a department"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        return JsonResponse({'success': False, 'message': 'Access denied. Faculty Dean role required.'})

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    try:
        department = Department.objects.get(id=department_id, faculty=faculty)
    except Department.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Department not found.'})

    if request.method == 'POST':
        try:
            lecturer_id = request.POST.get('lecturer_id')

            if not lecturer_id:
                return JsonResponse({'success': False, 'message': 'Please select a lecturer.'})

            # Get the lecturer
            try:
                lecturer_role = UserRole.objects.get(
                    id=lecturer_id,
                    role='LECTURER',
                    faculty=faculty
                )
            except UserRole.DoesNotExist:
                return JsonResponse({'success': False, 'message': 'Lecturer not found.'})

            # Check if lecturer is already HOD of another department
            existing_hod = UserRole.objects.filter(
                user=lecturer_role.user,
                role='HOD'
            ).first()

            if existing_hod:
                return JsonResponse({
                    'success': False,
                    'message': f'{lecturer_role.user.get_full_name()} is already HOD of {existing_hod.department.name}.'
                })

            # Create HOD role
            hod_role = UserRole.objects.create(
                user=lecturer_role.user,
                role='HOD',
                faculty=faculty,
                department=department,
                created_by=request.user,
                is_primary=False
            )

            # Update department HOD
            department.hod = lecturer_role.user
            department.save()

            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='ASSIGN_HOD',
                description=f'Assigned {lecturer_role.user.get_full_name()} as HOD of {department.name}',
                level='INFO'
            )

            return JsonResponse({
                'success': True,
                'message': f'{lecturer_role.user.get_full_name()} has been assigned as HOD of {department.name}.',
                'hod_name': lecturer_role.user.get_full_name()
            })

        except Exception as e:
            return JsonResponse({'success': False, 'message': f'Error assigning HOD: {str(e)}'})

    # GET request - return available lecturers
    lecturers = UserRole.objects.filter(
        role='LECTURER',
        faculty=faculty
    ).select_related('user').exclude(
        user__userrole__role='HOD'  # Exclude users who are already HODs
    )

    lecturers_data = [
        {
            'id': lecturer.id,
            'name': lecturer.user.get_full_name(),
            'email': lecturer.user.email,
            'department': lecturer.department.name if lecturer.department else 'Faculty-wide'
        }
        for lecturer in lecturers
    ]

    return JsonResponse({
        'success': True,
        'lecturers': lecturers_data,
        'department_name': department.name
    })


@login_required
def faculty_dean_course_assignments(request):
    """Manage course assignments to lecturers"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Faculty Dean role.')
        return redirect('dashboard')

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Get all courses in this faculty
    courses = Course.objects.filter(
        departments__faculty=faculty,
        session=current_session
    ).distinct().select_related('level').prefetch_related('departments')

    # Get all course assignments for this faculty
    assignments = CourseAssignment.objects.filter(
        course__departments__faculty=faculty
    ).select_related('course', 'lecturer', 'assigned_by').distinct()

    # Get unassigned courses
    assigned_course_ids = assignments.values_list('course_id', flat=True)
    unassigned_courses = courses.exclude(id__in=assigned_course_ids)

    # Get lecturers in this faculty
    lecturers = UserRole.objects.filter(
        role='LECTURER',
        faculty=faculty
    ).select_related('user', 'department')

    # Statistics
    stats = {
        'total_courses': courses.count(),
        'assigned_courses': assignments.count(),
        'unassigned_courses': unassigned_courses.count(),
        'total_lecturers': lecturers.count(),
    }

    context = {
        'faculty': faculty,
        'current_session': current_session,
        'courses': courses,
        'assignments': assignments,
        'unassigned_courses': unassigned_courses,
        'lecturers': lecturers,
        'stats': stats,
    }

    return render(request, 'faculty_dean_course_assignments.html', context)


@login_required
def faculty_dean_assign_course(request):
    """Assign a course to a lecturer"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})

    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        return JsonResponse({'success': False, 'message': 'Access denied. Faculty Dean role required.'})

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    try:
        course_id = request.POST.get('course_id')
        lecturer_id = request.POST.get('lecturer_id')

        if not course_id or not lecturer_id:
            return JsonResponse({'success': False, 'message': 'Course and lecturer are required.'})

        # Get course
        course = Course.objects.get(
            id=course_id,
            departments__faculty=faculty
        )

        # Get lecturer
        lecturer_role = UserRole.objects.get(
            id=lecturer_id,
            role='LECTURER',
            faculty=faculty
        )

        # Check if course is already assigned
        if CourseAssignment.objects.filter(course=course).exists():
            return JsonResponse({'success': False, 'message': 'Course is already assigned to another lecturer.'})

        # Create assignment
        assignment = CourseAssignment.objects.create(
            course=course,
            lecturer=lecturer_role.user,
            assigned_by=request.user
        )

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='ASSIGN_COURSE',
            description=f'Assigned course {course.code} to {lecturer_role.user.get_full_name()}',
            level='INFO'
        )

        return JsonResponse({
            'success': True,
            'message': f'Course {course.code} assigned to {lecturer_role.user.get_full_name()} successfully!'
        })

    except Course.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Course not found.'})
    except UserRole.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Lecturer not found.'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error assigning course: {str(e)}'})


@login_required
def faculty_dean_unassign_course(request, assignment_id):
    """Unassign a course from a lecturer"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})

    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        return JsonResponse({'success': False, 'message': 'Access denied. Faculty Dean role required.'})

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    try:
        assignment = CourseAssignment.objects.get(
            id=assignment_id,
            course__departments__faculty=faculty
        )

        course_code = assignment.course.code
        lecturer_name = assignment.lecturer.get_full_name()

        assignment.delete()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='UNASSIGN_COURSE',
            description=f'Unassigned course {course_code} from {lecturer_name}',
            level='INFO'
        )

        return JsonResponse({
            'success': True,
            'message': f'Course {course_code} unassigned from {lecturer_name} successfully!'
        })

    except CourseAssignment.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Assignment not found.'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error unassigning course: {str(e)}'})


@login_required
def super_admin_assign_roles(request):
    return render(request, 'placeholder.html', {'page_title': 'Assign Roles', 'message': 'Assign roles to users'})

@login_required
def super_admin_user_reports(request):
    return render(request, 'placeholder.html', {'page_title': 'User Reports', 'message': 'Generate user reports'})

@login_required
def super_admin_role_overview(request):
    return render(request, 'placeholder.html', {'page_title': 'Role Overview', 'message': 'Overview of all user roles'})

@login_required
def super_admin_bulk_assign(request):
    return render(request, 'placeholder.html', {'page_title': 'Bulk Assign Roles', 'message': 'Bulk assign roles to users'})

@login_required
def super_admin_audit_log(request):
    return render(request, 'placeholder.html', {'page_title': 'Audit Log', 'message': 'System audit log'})



@login_required
def super_admin_assign_dean_single(request, faculty_id):
    """Assign dean to a specific faculty"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    try:
        faculty = Faculty.objects.get(id=faculty_id)
    except Faculty.DoesNotExist:
        messages.error(request, 'Faculty not found.')
        return redirect('super_admin_dashboard')

    # Get current dean if exists
    current_dean = None
    dean_role = None
    try:
        dean_role = UserRole.objects.filter(role='FACULTY_DEAN', faculty=faculty).first()
        current_dean = dean_role.user if dean_role else None
    except Exception:
        pass

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'assign_existing':
            user_id = request.POST.get('user_id')
            if not user_id:
                messages.error(request, 'Please select a user.')
                return redirect('super_admin_assign_dean_single', faculty_id=faculty_id)

            try:
                user = User.objects.get(id=user_id)

                # Remove current dean if exists
                if dean_role:
                    dean_role.delete()

                # Assign new dean
                UserRole.objects.create(
                    user=user,
                    role='FACULTY_DEAN',
                    faculty=faculty,
                    created_by=request.user
                )

                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='ASSIGN_DEAN',
                    description=f'Assigned {user.get_full_name()} as Faculty Dean of {faculty.name}',
                    level='INFO',
                    faculty=faculty
                )

                messages.success(request, f'{user.get_full_name()} has been assigned as Faculty Dean of {faculty.name}!')
                return redirect('super_admin_dashboard')

            except User.DoesNotExist:
                messages.error(request, 'Selected user not found.')

        elif action == 'create_and_assign':
            # Create new user and assign as dean
            first_name = request.POST.get('first_name', '').strip()
            last_name = request.POST.get('last_name', '').strip()
            email = request.POST.get('email', '').strip()
            username = request.POST.get('username', '').strip()
            password = request.POST.get('password', '')
            confirm_password = request.POST.get('confirm_password', '')

            errors = []

            # Validate user data
            if not first_name:
                errors.append('First name is required')
            if not last_name:
                errors.append('Last name is required')
            if not email:
                errors.append('Email is required')
            elif User.objects.filter(email=email).exists():
                errors.append('User with this email already exists')
            if not username:
                errors.append('Username is required')
            elif User.objects.filter(username=username).exists():
                errors.append('User with this username already exists')
            if not password:
                errors.append('Password is required')
            elif len(password) < 8:
                errors.append('Password must be at least 8 characters long')
            if password != confirm_password:
                errors.append('Passwords do not match')

            if not errors:
                try:
                    from django.db import transaction

                    with transaction.atomic():
                        # Create new user
                        new_user = User.objects.create_user(
                            username=username,
                            email=email,
                            first_name=first_name,
                            last_name=last_name,
                            password=password
                        )

                        # Remove current dean if exists
                        if dean_role:
                            dean_role.delete()

                        # Assign as Faculty Dean
                        UserRole.objects.create(
                            user=new_user,
                            role='FACULTY_DEAN',
                            faculty=faculty,
                            created_by=request.user
                        )

                        # Log the action
                        AuditLog.objects.create(
                            user=request.user,
                            action='CREATE_USER',
                            description=f'Created user {new_user.get_full_name()} and assigned as Faculty Dean of {faculty.name}',
                            level='INFO',
                            faculty=faculty
                        )

                        messages.success(request, f'User {new_user.get_full_name()} created and assigned as Faculty Dean of {faculty.name}!')
                        return redirect('super_admin_dashboard')

                except Exception as e:
                    messages.error(request, f'Error creating user: {str(e)}')
            else:
                for error in errors:
                    messages.error(request, error)

        elif action == 'remove_dean':
            if dean_role:
                dean_name = current_dean.get_full_name()
                dean_role.delete()

                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='ASSIGN_DEAN',
                    description=f'Removed {dean_name} as Faculty Dean of {faculty.name}',
                    level='INFO',
                    faculty=faculty
                )

                messages.success(request, f'{dean_name} has been removed as Faculty Dean of {faculty.name}.')
                return redirect('super_admin_assign_dean_single', faculty_id=faculty_id)

    # Get available users (users without Faculty Dean role)
    faculty_dean_user_ids = UserRole.objects.filter(role='FACULTY_DEAN').values_list('user_id', flat=True)
    available_users = User.objects.exclude(id__in=faculty_dean_user_ids).filter(is_active=True).order_by('first_name', 'last_name')

    context = {
        'faculty': faculty,
        'current_dean': current_dean,
        'dean_role': dean_role,
        'available_users': available_users,
    }

    return render(request, 'super_admin_assign_dean_single.html', context)

@login_required
def super_admin_system_settings(request):
    """System Settings Management"""
    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        messages.error(request, 'Access denied. Super Admin role required.')
        return redirect('dashboard')

    if request.method == 'POST':
        # Handle settings updates
        setting_type = request.POST.get('setting_type')

        if setting_type == 'email':
            # Update email settings
            messages.success(request, 'Email settings updated successfully.')
        elif setting_type == 'security':
            # Update security settings
            messages.success(request, 'Security settings updated successfully.')
        elif setting_type == 'system':
            # Update system settings
            messages.success(request, 'System settings updated successfully.')

        return redirect('super_admin_system_settings')

    # Get system statistics
    total_users = User.objects.count()
    total_faculties = Faculty.objects.count()
    total_departments = Department.objects.count()
    total_students = Student.objects.count()
    active_sessions = AcademicSession.objects.filter(is_active=True).count()

    context = {
        'total_users': total_users,
        'total_faculties': total_faculties,
        'total_departments': total_departments,
        'total_students': total_students,
        'active_sessions': active_sessions,
    }

    return render(request, 'super_admin_system_settings.html', context)


# ============================================================================
# SUPER ADMIN SESSION MANAGEMENT
# ============================================================================

@login_required
def super_admin_create_session(request):
    """Super Admin Create Academic Session"""
    # Check if user has Super Admin or DAAA role
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['SUPER_ADMIN', 'DAAA'])
    if not has_access:
        messages.error(request, 'Access denied. Super Admin or DAAA role required.')
        return redirect('dashboard')

    if request.method == 'POST':
        try:
            # Get session data
            name = request.POST.get('name', '').strip()
            start_date = request.POST.get('start_date', '').strip()
            end_date = request.POST.get('end_date', '').strip()

            # Validate required fields
            if not all([name, start_date, end_date]):
                messages.error(request, 'All fields are required.')
                return render(request, 'super_admin_create_session.html', {})

            # Validate date format and logic
            from datetime import datetime
            try:
                start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
                end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()

                if start_date_obj >= end_date_obj:
                    messages.error(request, 'End date must be after start date.')
                    return render(request, 'super_admin_create_session.html', {})

            except ValueError:
                messages.error(request, 'Invalid date format.')
                return render(request, 'super_admin_create_session.html', {})

            # Check if session name already exists
            if AcademicSession.objects.filter(name=name).exists():
                messages.error(request, f'Academic session "{name}" already exists.')
                return render(request, 'super_admin_create_session.html', {})

            # Create session
            session = AcademicSession.objects.create(
                name=name,
                start_date=start_date_obj,
                end_date=end_date_obj,
                is_active=False,  # Created as inactive
                is_locked=False,
                created_by=request.user
            )

            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='CREATE_SESSION',
                description=f'Created academic session: {name} ({start_date} to {end_date})',
                level='INFO'
            )

            messages.success(request, f'Academic session "{name}" created successfully!')
            return redirect('super_admin_manage_sessions')

        except Exception as e:
            messages.error(request, f'Error creating session: {str(e)}')

    return render(request, 'super_admin_create_session.html', {})

@login_required
def super_admin_manage_sessions(request):
    """Super Admin Manage Academic Sessions"""
    # Check if user has Super Admin or DAAA role
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['SUPER_ADMIN', 'DAAA'])
    if not has_access:
        messages.error(request, 'Access denied. Super Admin or DAAA role required.')
        return redirect('dashboard')

    # Get all sessions
    sessions = AcademicSession.objects.all().order_by('-created_at')
    active_session = sessions.filter(is_active=True).first()

    context = {
        'sessions': sessions,
        'active_session': active_session,
        'total_sessions': sessions.count(),
        'active_sessions': sessions.filter(is_active=True).count(),
        'locked_sessions': sessions.filter(is_locked=True).count(),
    }

    return render(request, 'super_admin_manage_sessions.html', context)

@login_required
def super_admin_activate_session(request):
    """Super Admin Activate Academic Session (AJAX endpoint)"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})

    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        return JsonResponse({'success': False, 'message': 'Access denied. Super Admin role required.'})

    try:
        session_id = request.POST.get('session_id')
        if not session_id:
            return JsonResponse({'success': False, 'message': 'Session ID is required.'})

        # Get the session
        session = AcademicSession.objects.get(id=session_id)

        # Deactivate all other sessions
        AcademicSession.objects.all().update(is_active=False)

        # Activate this session
        session.is_active = True
        session.save()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='ACTIVATE_SESSION',
            description=f'Activated academic session: {session.name}',
            level='INFO'
        )

        return JsonResponse({
            'success': True,
            'message': f'Academic session "{session.name}" activated successfully!'
        })

    except AcademicSession.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Session not found.'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error activating session: {str(e)}'})

@login_required
def super_admin_lock_session(request, session_id):
    """Super Admin Lock Academic Session (AJAX endpoint)"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})

    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        return JsonResponse({'success': False, 'message': 'Access denied. Super Admin role required.'})

    try:
        session = AcademicSession.objects.get(id=session_id)
        session.is_locked = True
        session.save()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='LOCK_SESSION',
            description=f'Locked academic session: {session.name}',
            level='WARNING'
        )

        return JsonResponse({
            'success': True,
            'message': f'Academic session "{session.name}" locked successfully!'
        })

    except AcademicSession.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Session not found.'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error locking session: {str(e)}'})

@login_required
def super_admin_unlock_session(request, session_id):
    """Super Admin Unlock Academic Session (AJAX endpoint)"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})

    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        return JsonResponse({'success': False, 'message': 'Access denied. Super Admin role required.'})

    try:
        session = AcademicSession.objects.get(id=session_id)
        session.is_locked = False
        session.save()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='UNLOCK_SESSION',
            description=f'Unlocked academic session: {session.name}',
            level='INFO'
        )

        return JsonResponse({
            'success': True,
            'message': f'Academic session "{session.name}" unlocked successfully!'
        })

    except AcademicSession.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Session not found.'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error unlocking session: {str(e)}'})


@login_required
def super_admin_deactivate_session(request, session_id):
    """Super Admin Deactivate Academic Session (AJAX endpoint)"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})

    # Check if user has Super Admin or DAAA role
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['SUPER_ADMIN', 'DAAA'])
    if not has_access:
        return JsonResponse({'success': False, 'message': 'Access denied. Super Admin or DAAA role required.'})

    try:
        session = AcademicSession.objects.get(id=session_id)

        if not session.is_active:
            return JsonResponse({'success': False, 'message': 'Session is already inactive.'})

        # Deactivate this session
        session.is_active = False
        session.save()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='DEACTIVATE_SESSION',
            description=f'Deactivated academic session: {session.name}',
            level='INFO'
        )

        return JsonResponse({'success': True, 'message': f'Session "{session.name}" deactivated successfully!'})

    except AcademicSession.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Session not found.'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error deactivating session: {str(e)}'})


@login_required
def super_admin_delete_session(request, session_id):
    """Super Admin Delete Academic Session (AJAX endpoint)"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})

    # Check if user has Super Admin role
    super_admin_roles = UserRole.objects.filter(user=request.user, role='SUPER_ADMIN')
    if not super_admin_roles.exists():
        return JsonResponse({'success': False, 'message': 'Access denied. Super Admin role required.'})

    try:
        session = AcademicSession.objects.get(id=session_id)

        # Auto-deactivate if session is active
        if session.is_active:
            session.is_active = False
            session.save()

            # Log the deactivation
            AuditLog.objects.create(
                user=request.user,
                action='AUTO_DEACTIVATE_SESSION',
                description=f'Auto-deactivated academic session before deletion: {session.name}',
                level='INFO'
            )

        # Check if session has associated data (courses, enrollments, etc.)
        course_count = Course.objects.filter(session=session).count()
        enrollment_count = CourseEnrollment.objects.filter(session=session).count()

        if course_count > 0 or enrollment_count > 0:
            return JsonResponse({
                'success': False,
                'message': f'Cannot delete session with associated data. Found {course_count} courses and {enrollment_count} enrollments.'
            })

        session_name = session.name
        session.delete()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='DELETE_SESSION',
            description=f'Deleted academic session: {session_name}',
            level='WARNING'
        )

        return JsonResponse({'success': True, 'message': f'Session "{session_name}" deleted successfully!'})

    except AcademicSession.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Session not found.'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error deleting session: {str(e)}'})


# ============================================================================
# HOD VIEWS - Professional Interface
# ============================================================================

@login_required
def hod_dashboard(request):
    """Professional HOD Dashboard"""
    # Check if user has HOD role or is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['HOD'])
    if not has_access:
        messages.error(request, 'Access denied. HOD or Super Admin role required.')
        return redirect('dashboard')

    if not department:
        messages.error(request, 'No departments exist in the system.')
        return redirect('dashboard')

    if not faculty:
        faculty = department.faculty
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Get department courses
    department_courses = Course.objects.filter(departments=department)

    # Get department lecturers (users with lecturer role assigned to courses in this department)
    lecturer_assignments = CourseAssignment.objects.filter(
        course__departments=department
    ).values_list('lecturer', flat=True).distinct()

    # Calculate department statistics
    stats = {
        'total_students': Student.objects.filter(department=department).count(),
        'total_courses': department_courses.count(),
        'total_lecturers': len(lecturer_assignments),
        'pending_results': Result.objects.filter(
            enrollment__course__departments=department,
            status='SUBMITTED_TO_HOD'
        ).count(),
        'approved_results': Result.objects.filter(
            enrollment__course__departments=department,
            status__in=['APPROVED_BY_HOD', 'SUBMITTED_TO_DEAN']
        ).count(),
    }

    # Get pending results for approval
    pending_results = Result.objects.filter(
        enrollment__course__departments=department,
        status='SUBMITTED_TO_HOD'
    ).select_related(
        'enrollment__student',
        'enrollment__course',
        'created_by'
    ).order_by('-updated_at')[:10]

    # Get level statistics
    level_statistics = []
    for level in Level.objects.all().order_by('numeric_value'):
        level_courses = department_courses.filter(level=level).count()
        level_students = Student.objects.filter(
            department=department,
            current_level=level
        ).count()

        if level_courses > 0 or level_students > 0:
            level_statistics.append({
                'level_name': level.name,
                'courses_count': level_courses,
                'students_count': level_students,
            })

    context = {
        'department': department,
        'faculty': faculty,
        'current_session': current_session,
        'stats': stats,
        'pending_results': pending_results,
        'level_statistics': level_statistics,
    }

    return render(request, 'hod_dashboard.html', context)


# ============================================================================
# FACULTY DEAN VIEWS - Professional Interface
# ============================================================================

@login_required
def faculty_dean_dashboard(request):
    """Professional Faculty Dean Dashboard"""
    # Check if user has Faculty Dean role or is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['FACULTY_DEAN'])
    if not has_access:
        messages.error(request, 'Access denied. Faculty Dean or Super Admin role required.')
        return redirect('dashboard')

    if not faculty:
        messages.error(request, 'No faculties exist in the system.')
        return redirect('dashboard')

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Get departments in this faculty
    departments = Department.objects.filter(faculty=faculty).annotate(
        students_count=Count('student')
    )

    # Calculate comprehensive faculty statistics
    total_students = Student.objects.filter(faculty=faculty).count()
    total_lecturers = UserRole.objects.filter(role='LECTURER', faculty=faculty).count()
    total_courses = Course.objects.filter(departments__faculty=faculty).distinct().count()

    # Results statistics
    pending_results_count = Result.objects.filter(
        enrollment__student__faculty=faculty,
        status__in=['SUBMITTED_TO_DEAN', 'APPROVED_BY_HOD']
    ).count()

    approved_results = Result.objects.filter(
        enrollment__student__faculty=faculty,
        status='APPROVED_BY_DEAN'
    ).count()

    published_results = Result.objects.filter(
        enrollment__student__faculty=faculty,
        status='PUBLISHED'
    ).count()

    # Course assignments needing attention
    unassigned_courses = Course.objects.filter(
        departments__faculty=faculty
    ).exclude(
        id__in=CourseAssignment.objects.values_list('course_id', flat=True)
    ).distinct().count()

    # Students by level
    students_by_level = {}
    for level in Level.objects.all():
        count = Student.objects.filter(faculty=faculty, current_level=level).count()
        if count > 0:
            students_by_level[level.name] = count

    stats = {
        'total_departments': departments.count(),
        'total_students': total_students,
        'total_lecturers': total_lecturers,
        'total_courses': total_courses,
        'pending_results': pending_results_count,
        'approved_results': approved_results,
        'published_results': published_results,
        'unassigned_courses': unassigned_courses,
        'students_by_level': students_by_level,
        'departments_with_hod': departments.filter(hod__isnull=False).count(),
        'departments_without_hod': departments.filter(hod__isnull=True).count(),
    }

    # Get recent results awaiting approval
    pending_results = Result.objects.filter(
        enrollment__student__faculty=faculty,
        status__in=['SUBMITTED_TO_DEAN', 'APPROVED_BY_HOD']
    ).select_related(
        'enrollment__student',
        'enrollment__course',
        'enrollment__student__department'
    ).order_by('-updated_at')[:10]

    context = {
        'faculty': faculty,
        'current_session': current_session,
        'departments': departments,
        'stats': stats,
        'pending_results': pending_results,
    }

    return render(request, 'faculty_dean_dashboard.html', context)


# Faculty Dean Placeholder Views (to be implemented)
@login_required
def faculty_dean_departments(request):
    """Faculty Dean Department Management"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Faculty Dean role.')
        return redirect('dashboard')

    # Get departments in this faculty with statistics
    departments = Department.objects.filter(faculty=faculty).select_related('hod').annotate(
        students_count=Count('student'),
        courses_count=Count('course')
    ).order_by('name')

    # Calculate statistics
    stats = {
        'total_departments': departments.count(),
        'total_students': sum(dept.students_count for dept in departments),
        'total_courses': sum(dept.courses_count for dept in departments),
        'departments_with_hod': departments.filter(hod__isnull=False).count(),
    }

    context = {
        'faculty': faculty,
        'departments': departments,
        'stats': stats,
    }

    return render(request, 'faculty_dean_departments.html', context)

@login_required
def faculty_dean_create_department(request):
    """Faculty Dean Create Department with HOD"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Faculty Dean role.')
        return redirect('dashboard')

    if request.method == 'POST':
        try:
            # Get department data
            department_name = request.POST.get('department_name', '').strip()
            department_code = request.POST.get('department_code', '').strip().upper()

            # Get HOD data
            hod_first_name = request.POST.get('hod_first_name', '').strip()
            hod_last_name = request.POST.get('hod_last_name', '').strip()
            hod_email = request.POST.get('hod_email', '').strip()
            hod_username = request.POST.get('hod_username', '').strip()
            hod_password = request.POST.get('hod_password', '').strip()
            hod_confirm_password = request.POST.get('hod_confirm_password', '').strip()

            # Validate required fields
            if not all([department_name, department_code, hod_first_name, hod_last_name, hod_email, hod_username, hod_password]):
                messages.error(request, 'All required fields must be filled.')
                return render(request, 'faculty_dean_create_department.html', {'faculty': faculty})

            # Validate password confirmation
            if hod_password != hod_confirm_password:
                messages.error(request, 'Passwords do not match.')
                return render(request, 'faculty_dean_create_department.html', {'faculty': faculty})

            # Check if department code already exists
            if Department.objects.filter(code=department_code).exists():
                messages.error(request, 'Department code already exists.')
                return render(request, 'faculty_dean_create_department.html', {'faculty': faculty})

            # Check if department name already exists in this faculty
            if Department.objects.filter(name=department_name, faculty=faculty).exists():
                messages.error(request, 'Department name already exists in this faculty.')
                return render(request, 'faculty_dean_create_department.html', {'faculty': faculty})

            # Check if HOD email or username already exists
            if User.objects.filter(email=hod_email).exists():
                messages.error(request, 'A user with this email already exists.')
                return render(request, 'faculty_dean_create_department.html', {'faculty': faculty})

            if User.objects.filter(username=hod_username).exists():
                messages.error(request, 'A user with this username already exists.')
                return render(request, 'faculty_dean_create_department.html', {'faculty': faculty})

            # Create department
            department = Department.objects.create(
                name=department_name,
                code=department_code,
                faculty=faculty
            )

            # Create HOD user
            hod_user = User.objects.create_user(
                username=hod_username,
                email=hod_email,
                first_name=hod_first_name,
                last_name=hod_last_name,
                password=hod_password
            )

            # Create HOD role
            UserRole.objects.create(
                user=hod_user,
                role='HOD',
                faculty=faculty,
                department=department,
                created_by=request.user
            )

            # Assign HOD to department
            department.hod = hod_user
            department.save()

            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='CREATE_DEPARTMENT_WITH_HOD',
                description=f'Created department: {department_name} ({department_code}) with HOD {hod_first_name} {hod_last_name}',
                level='INFO'
            )

            messages.success(request, f'Department "{department_name}" created successfully with HOD {hod_first_name} {hod_last_name}!')
            return redirect('faculty_dean_departments')

        except Exception as e:
            messages.error(request, f'Error creating department: {str(e)}')
            return render(request, 'faculty_dean_create_department.html', {'faculty': faculty})

    # GET request - show form
    context = {
        'faculty': faculty,
    }

    return render(request, 'faculty_dean_create_department.html', context)

@login_required
def faculty_dean_hods(request):
    return render(request, 'placeholder.html', {'page_title': 'Manage HODs', 'message': 'Manage Head of Departments'})

@login_required
def faculty_dean_create_hod(request):
    """Faculty Dean Create HOD User"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Faculty Dean role.')
        return redirect('dashboard')

    # Get departments in this faculty
    departments = Department.objects.filter(faculty=faculty)

    # Get available users (users without HOD role)
    hod_user_ids = UserRole.objects.filter(role='HOD').values_list('user_id', flat=True)
    available_users = User.objects.exclude(id__in=hod_user_ids).filter(is_active=True).order_by('first_name', 'last_name')

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'create_and_assign':
            # Create new user and assign as HOD
            first_name = request.POST.get('first_name', '').strip()
            last_name = request.POST.get('last_name', '').strip()
            email = request.POST.get('email', '').strip()
            username = request.POST.get('username', '').strip()
            password = request.POST.get('password', '')
            confirm_password = request.POST.get('confirm_password', '')
            department_id = request.POST.get('department_id')

            errors = []

            # Validate user data
            if not first_name:
                errors.append('First name is required')
            if not last_name:
                errors.append('Last name is required')
            if not email:
                errors.append('Email is required')
            elif User.objects.filter(email=email).exists():
                errors.append('User with this email already exists')
            if not username:
                errors.append('Username is required')
            elif User.objects.filter(username=username).exists():
                errors.append('User with this username already exists')
            if not password:
                errors.append('Password is required')
            elif len(password) < 8:
                errors.append('Password must be at least 8 characters long')
            if password != confirm_password:
                errors.append('Passwords do not match')
            if not department_id:
                errors.append('Please select a department')

            if not errors:
                try:
                    from django.db import transaction

                    with transaction.atomic():
                        # Create new user
                        new_user = User.objects.create_user(
                            username=username,
                            email=email,
                            first_name=first_name,
                            last_name=last_name,
                            password=password
                        )

                        # Get department
                        department = Department.objects.get(id=department_id, faculty=faculty)

                        # Assign as HOD
                        UserRole.objects.create(
                            user=new_user,
                            role='HOD',
                            faculty=faculty,
                            department=department,
                            created_by=request.user
                        )

                        # Log the action
                        AuditLog.objects.create(
                            user=request.user,
                            action='CREATE_USER',
                            description=f'Created user {new_user.get_full_name()} and assigned as HOD of {department.name}',
                            level='INFO',
                            faculty=faculty,
                            department=department
                        )

                        messages.success(request, f'User {new_user.get_full_name()} created and assigned as HOD of {department.name}!')
                        return redirect('faculty_dean_departments')

                except Department.DoesNotExist:
                    messages.error(request, 'Selected department not found.')
                except Exception as e:
                    messages.error(request, f'Error creating user: {str(e)}')
            else:
                for error in errors:
                    messages.error(request, error)

    context = {
        'faculty': faculty,
        'departments': departments,
        'available_users': available_users,
    }

    return render(request, 'faculty_dean_create_hod.html', context)


# Additional Faculty Dean Views for new workflow
@login_required
def faculty_dean_department_details(request, department_id):
    """Faculty Dean Department Details"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    try:
        department = Department.objects.get(id=department_id, faculty=faculty)
    except Department.DoesNotExist:
        messages.error(request, 'Department not found.')
        return redirect('faculty_dean_departments')

    # Get department statistics
    total_students = Student.objects.filter(department=department).count()
    total_courses = Course.objects.filter(departments=department).count()
    total_lecturers = User.objects.filter(
        rms_roles__role='LECTURER',
        rms_roles__department=department
    ).distinct().count()

    context = {
        'department': department,
        'faculty': faculty,
        'total_students': total_students,
        'total_courses': total_courses,
        'total_lecturers': total_lecturers,
    }

    return render(request, 'faculty_dean_department_details.html', context)

@login_required
def faculty_dean_assign_hod_single(request, department_id):
    """Faculty Dean Assign HOD to Single Department"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    try:
        department = Department.objects.get(id=department_id, faculty=faculty)
    except Department.DoesNotExist:
        messages.error(request, 'Department not found.')
        return redirect('faculty_dean_departments')

    if request.method == 'POST':
        user_id = request.POST.get('user_id')

        if not user_id:
            messages.error(request, 'Please select a user.')
        else:
            try:
                user = User.objects.get(id=user_id)

                # Remove existing HOD role for this department if exists
                existing_hod_role = UserRole.objects.filter(role='HOD', department=department).first()
                if existing_hod_role:
                    existing_hod_role.delete()

                # Create new HOD role
                UserRole.objects.create(
                    user=user,
                    role='HOD',
                    faculty=faculty,
                    department=department,
                    created_by=request.user,
                    is_primary=False
                )

                # Update department HOD field
                department.hod = user
                department.save()

                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='ASSIGN_HOD',
                    description=f'Assigned {user.get_full_name()} as HOD of {department.name}',
                    level='INFO'
                )

                messages.success(request, f'{user.get_full_name()} has been assigned as HOD of {department.name}!')
                return redirect('faculty_dean_departments')

            except User.DoesNotExist:
                messages.error(request, 'User not found.')
            except Exception as e:
                messages.error(request, f'Error assigning HOD: {str(e)}')

    # Get eligible users (lecturers in this faculty)
    eligible_users = User.objects.filter(
        rms_roles__role='LECTURER',
        rms_roles__faculty=faculty
    ).distinct().order_by('first_name', 'last_name')

    context = {
        'department': department,
        'faculty': faculty,
        'eligible_users': eligible_users,
    }

    return render(request, 'faculty_dean_assign_hod_single.html', context)

@login_required
def faculty_dean_change_hod(request, department_id):
    """Faculty Dean Change HOD for Department"""
    # This redirects to the same assign HOD view since the logic is the same
    return faculty_dean_assign_hod_single(request, department_id)

@login_required
def faculty_dean_grading_system(request):
    """Faculty Dean Grading System Management"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Faculty Dean role.')
        return redirect('dashboard')

    # Get existing grading scale and carry-over criteria
    try:
        grading_scale = GradingScale.objects.get(faculty=faculty)
        grade_ranges = grading_scale.ranges.all().order_by('-min_score')
    except GradingScale.DoesNotExist:
        grading_scale = None
        grade_ranges = []

    try:
        carryover_criteria = CarryOverCriteria.objects.get(faculty=faculty)
    except CarryOverCriteria.DoesNotExist:
        carryover_criteria = None

    context = {
        'faculty': faculty,
        'grading_scale': grading_scale,
        'grade_ranges': grade_ranges,
        'carryover_criteria': carryover_criteria,
    }

    return render(request, 'faculty_dean_grading_system.html', context)

@login_required
def faculty_dean_course_offerings(request):
    return render(request, 'placeholder.html', {'page_title': 'Course Offerings', 'message': 'Manage course offerings for academic sessions'})



@login_required
def faculty_dean_bulk_approve(request):
    return render(request, 'placeholder.html', {'page_title': 'Bulk Approve Results', 'message': 'Bulk approval interface for results'})



@login_required
def faculty_dean_courses(request):
    """Faculty Dean Courses Management"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    # Handle course creation
    if request.method == 'POST':
        title = request.POST.get('title', '').strip()
        code = request.POST.get('code', '').strip()
        credit_units = request.POST.get('credit_units')
        level = request.POST.get('level')
        semester = request.POST.get('semester')
        department_ids = request.POST.getlist('departments')
        description = request.POST.get('description', '').strip()

        if not all([title, code, credit_units, level, semester, department_ids]):
            messages.error(request, 'Please fill in all required fields.')
        else:
            try:
                # Check if course code already exists
                if Course.objects.filter(code=code).exists():
                    messages.error(request, f'Course code "{code}" already exists.')
                else:
                    # Create the course
                    course = Course.objects.create(
                        title=title,
                        code=code.upper(),
                        credit_units=int(credit_units),
                        level=int(level),
                        semester=int(semester),
                        description=description,
                        created_by=request.user
                    )

                    # Add departments
                    departments = Department.objects.filter(id__in=department_ids, faculty=faculty)
                    course.departments.set(departments)

                    # Log the action
                    AuditLog.objects.create(
                        user=request.user,
                        action='CREATE_COURSE',
                        description=f'Created course: {code} - {title}',
                        level='INFO'
                    )

                    messages.success(request, f'Course "{code} - {title}" created successfully!')
                    return redirect('faculty_dean_courses')

            except Exception as e:
                messages.error(request, f'Error creating course: {str(e)}')

    # Get all courses in this faculty
    courses = Course.objects.filter(departments__faculty=faculty).distinct().prefetch_related('departments', 'courseassignment_set__lecturer').order_by('code')

    # Get departments in this faculty
    departments = Department.objects.filter(faculty=faculty).order_by('name')

    # Get sessions
    sessions = AcademicSession.objects.all().order_by('-name')

    # Calculate statistics
    assigned_courses = CourseAssignment.objects.filter(course__in=courses).values('course').distinct().count()
    stats = {
        'total_courses': courses.count(),
        'assigned_courses': assigned_courses,
        'unassigned_courses': courses.count() - assigned_courses,
        'total_enrollments': CourseEnrollment.objects.filter(course__in=courses).count(),
    }

    context = {
        'faculty': faculty,
        'courses': courses,
        'departments': departments,
        'sessions': sessions,
        'stats': stats,
    }

    return render(request, 'faculty_dean_courses.html', context)



@login_required
def faculty_dean_create_lecturer(request):
    """Faculty Dean Create Lecturer"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if request.method == 'POST':
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        email = request.POST.get('email', '').strip()
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()
        department_id = request.POST.get('department_id')

        if not all([first_name, last_name, email, username, password, department_id]):
            messages.error(request, 'Please fill in all required fields.')
        else:
            try:
                # Check if username or email already exists
                if User.objects.filter(username=username).exists():
                    messages.error(request, f'Username "{username}" already exists.')
                elif User.objects.filter(email=email).exists():
                    messages.error(request, f'Email "{email}" already exists.')
                else:
                    # Get department
                    department = Department.objects.get(id=department_id, faculty=faculty)

                    # Create the user
                    user = User.objects.create_user(
                        username=username,
                        email=email,
                        password=password,
                        first_name=first_name,
                        last_name=last_name
                    )

                    # Create lecturer role
                    UserRole.objects.create(
                        user=user,
                        role='LECTURER',
                        faculty=faculty,
                        department=department,
                        created_by=request.user,
                        is_primary=True
                    )

                    # Log the action
                    AuditLog.objects.create(
                        user=request.user,
                        action='CREATE_LECTURER',
                        description=f'Created lecturer: {user.get_full_name()} ({username})',
                        level='INFO'
                    )

                    messages.success(request, f'Lecturer "{user.get_full_name()}" created successfully!')
                    return redirect('faculty_dean_lecturers')

            except Department.DoesNotExist:
                messages.error(request, 'Department not found.')
            except Exception as e:
                messages.error(request, f'Error creating lecturer: {str(e)}')

    # Get departments in this faculty
    departments = Department.objects.filter(faculty=faculty).order_by('name')

    context = {
        'faculty': faculty,
        'departments': departments,
    }

    return render(request, 'faculty_dean_create_lecturer.html', context)

@login_required
def faculty_dean_all_results(request):
    return render(request, 'placeholder.html', {'page_title': 'All Results', 'message': 'View all results in your faculty'})

@login_required
def faculty_dean_result_search(request):
    return render(request, 'placeholder.html', {'page_title': 'Search Results', 'message': 'Search and filter faculty results'})

@login_required
def faculty_dean_statistics(request):
    return render(request, 'placeholder.html', {'page_title': 'Faculty Statistics', 'message': 'View detailed faculty statistics'})

@login_required
def faculty_dean_pass_rates(request):
    return render(request, 'placeholder.html', {'page_title': 'Pass Rates Analysis', 'message': 'Analyze pass rates by department and course'})

@login_required
def faculty_dean_export(request):
    """Faculty Dean Data Export"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Faculty Dean role.')
        return redirect('dashboard')

    # Get export type from query parameter
    export_type = request.GET.get('type', 'faculty_summary')

    try:
        from .reporting_service import ReportingService, export_faculty_summary, export_student_results, export_carryover_list

        if export_type == 'faculty_summary':
            return export_faculty_summary(faculty)

        elif export_type == 'student_results':
            return export_student_results(faculty=faculty)

        elif export_type == 'carryover_list':
            return export_carryover_list(faculty=faculty)

        elif export_type == 'student_list':
            data = ReportingService.get_student_list_data(faculty=faculty)
            filename = f"student_list_{faculty.name}"
            return ReportingService.generate_excel_response(data, filename, "Student List")

        elif export_type == 'course_performance':
            data = ReportingService.get_course_performance_data(faculty=faculty)
            filename = f"course_performance_{faculty.name}"
            return ReportingService.generate_excel_response(data, filename, "Course Performance")

        else:
            messages.error(request, 'Invalid export type.')
            return redirect('faculty_dean_dashboard')

    except Exception as e:
        messages.error(request, f'Export failed: {str(e)}')
        return redirect('faculty_dean_dashboard')

@login_required
def faculty_dean_approve_result(request, result_id):
    return render(request, 'placeholder.html', {'page_title': 'Approve Result', 'message': f'Approve result ID: {result_id}'})

@login_required
def faculty_dean_view_result(request, result_id):
    return render(request, 'placeholder.html', {'page_title': 'View Result', 'message': f'View result details ID: {result_id}'})

# Additional Faculty Dean Views
@login_required
def faculty_dean_create_grading_scale(request):
    return render(request, 'placeholder.html', {'page_title': 'Create Grading Scale', 'message': 'Create new grading scale for faculty'})

@login_required
def faculty_dean_edit_grading_scale(request):
    return render(request, 'placeholder.html', {'page_title': 'Edit Grading Scale', 'message': 'Edit existing grading scale'})

@login_required
def faculty_dean_add_grade_range(request):
    return render(request, 'placeholder.html', {'page_title': 'Add Grade Range', 'message': 'Add new grade range to grading scale'})

@login_required
def faculty_dean_edit_grade_range(request, range_id):
    return render(request, 'placeholder.html', {'page_title': 'Edit Grade Range', 'message': f'Edit grade range ID: {range_id}'})

@login_required
def faculty_dean_create_carryover_criteria(request):
    return render(request, 'placeholder.html', {'page_title': 'Create Carry-over Criteria', 'message': 'Set carry-over criteria for faculty'})

@login_required
def faculty_dean_edit_carryover_criteria(request):
    return render(request, 'placeholder.html', {'page_title': 'Edit Carry-over Criteria', 'message': 'Edit carry-over criteria'})

@login_required
def faculty_dean_apply_template(request, template_type):
    return render(request, 'placeholder.html', {'page_title': 'Apply Template', 'message': f'Apply grading template: {template_type}'})

# Duplicate function removed - using the implemented version above

@login_required
def faculty_dean_edit_department(request, department_id):
    """Faculty Dean Edit Department"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    # Get the faculty for this dean
    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    try:
        department = Department.objects.get(id=department_id, faculty=faculty)
    except Department.DoesNotExist:
        messages.error(request, 'Department not found.')
        return redirect('faculty_dean_departments')

    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        code = request.POST.get('code', '').strip()
        description = request.POST.get('description', '').strip()

        if not name or not code:
            messages.error(request, 'Department name and code are required.')
        else:
            try:
                # Check if code is unique (excluding current department)
                if Department.objects.filter(code=code).exclude(id=department.id).exists():
                    messages.error(request, f'Department code "{code}" already exists.')
                else:
                    department.name = name
                    department.code = code
                    department.description = description
                    department.save()

                    # Log the action
                    AuditLog.objects.create(
                        user=request.user,
                        action='UPDATE_DEPARTMENT',
                        description=f'Updated department: {name}',
                        level='INFO'
                    )

                    messages.success(request, f'Department "{name}" updated successfully!')
                    return redirect('faculty_dean_departments')

            except Exception as e:
                messages.error(request, f'Error updating department: {str(e)}')

    context = {
        'department': department,
        'faculty': faculty,
    }

    return render(request, 'faculty_dean_edit_department.html', context)



@login_required
def faculty_dean_bulk_import_departments(request):
    return render(request, 'placeholder.html', {'page_title': 'Bulk Import Departments', 'message': 'Bulk import departments from Excel'})

@login_required
def faculty_dean_department_reports(request):
    return render(request, 'placeholder.html', {'page_title': 'Department Reports', 'message': 'Generate department reports'})

@login_required
def faculty_dean_export_departments(request):
    return render(request, 'placeholder.html', {'page_title': 'Export Departments', 'message': 'Export department data'})


# ============================================================================
# LECTURER PLACEHOLDER VIEWS (to be implemented)
# ============================================================================

@login_required
def lecturer_enroll_students(request):
    """Lecturer Student Enrollment"""
    # Check if user has Lecturer role
    lecturer_roles = UserRole.objects.filter(user=request.user, role='LECTURER')
    if not lecturer_roles.exists():
        messages.error(request, 'Access denied. Lecturer role required.')
        return redirect('dashboard')

    # Get lecturer's assigned courses
    assigned_courses = CourseAssignment.objects.filter(
        lecturer=request.user
    ).select_related('course', 'course__level', 'course__session').prefetch_related('course__departments')

    # Get sessions
    sessions = AcademicSession.objects.all().order_by('-start_date')

    # Handle AJAX search requests
    if request.method == 'GET' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        search_query = request.GET.get('search', '').strip()
        course_id = request.GET.get('course_id')

        if search_query and course_id:
            try:
                course = Course.objects.get(id=course_id)

                # Verify lecturer has access to this course
                if not CourseAssignment.objects.filter(lecturer=request.user, course=course).exists():
                    return JsonResponse({'error': 'Access denied'}, status=403)

                # Search students by matric number or name
                students = Student.objects.filter(
                    Q(matric_number__icontains=search_query) |
                    Q(user__first_name__icontains=search_query) |
                    Q(user__last_name__icontains=search_query),
                    department__in=course.departments.all(),
                    current_level=course.level
                ).exclude(
                    courseenrollment__course=course,
                    courseenrollment__session=course.session
                ).select_related('user', 'current_level', 'department')[:10]  # Limit to 10 results

                student_data = []
                for student in students:
                    student_data.append({
                        'id': student.id,
                        'matric_number': student.matric_number,
                        'name': student.get_full_name(),
                        'department': student.department.name,
                        'level': student.current_level.name
                    })

                return JsonResponse({'students': student_data})

            except Course.DoesNotExist:
                return JsonResponse({'error': 'Course not found'}, status=404)

        return JsonResponse({'students': []})

    # Handle enrollment POST request
    if request.method == 'POST':
        course_id = request.POST.get('course_id')
        session_id = request.POST.get('session_id')
        student_ids = request.POST.getlist('student_ids')

        if course_id and session_id and student_ids:
            try:
                course = Course.objects.get(id=course_id)
                session = AcademicSession.objects.get(id=session_id)

                # Verify lecturer has access to this course
                if not CourseAssignment.objects.filter(lecturer=request.user, course=course).exists():
                    messages.error(request, 'You do not have permission to enroll students in this course.')
                    return redirect('lecturer_enroll_students')

                enrolled_count = 0
                for student_id in student_ids:
                    try:
                        student = Student.objects.get(id=student_id)

                        # Check if already enrolled
                        if not CourseEnrollment.objects.filter(
                            student=student, course=course, session=session
                        ).exists():
                            CourseEnrollment.objects.create(
                                student=student,
                                course=course,
                                session=session,
                                enrolled_by=request.user
                            )
                            enrolled_count += 1
                    except Student.DoesNotExist:
                        continue

                messages.success(request, f'Successfully enrolled {enrolled_count} students in {course.code}.')
                return redirect('lecturer_courses')

            except (Course.DoesNotExist, AcademicSession.DoesNotExist):
                messages.error(request, 'Invalid course or session selected.')
        else:
            messages.error(request, 'Please select course, session, and at least one student.')

    context = {
        'assigned_courses': assigned_courses,
        'sessions': sessions,
    }

    return render(request, 'lecturer_enroll_students.html', context)

@login_required
def lecturer_bulk_enroll(request):
    return render(request, 'placeholder.html', {'page_title': 'Bulk Enroll Students', 'message': 'Bulk student enrollment via Excel upload'})

@login_required
def lecturer_manage_enrollments(request):
    return render(request, 'placeholder.html', {'page_title': 'Manage Enrollments', 'message': 'Manage student enrollments in your courses'})

@login_required
def lecturer_student_list(request):
    return render(request, 'placeholder.html', {'page_title': 'Student Lists', 'message': 'View student lists by course'})

@login_required
def lecturer_courses(request):
    """Lecturer Courses Management"""
    # Check if user has Lecturer role
    lecturer_roles = UserRole.objects.filter(user=request.user, role='LECTURER')
    if not lecturer_roles.exists():
        messages.error(request, 'Access denied. Lecturer role required.')
        return redirect('dashboard')

    # Get lecturer's assigned courses
    assigned_courses = CourseAssignment.objects.filter(
        lecturer=request.user
    ).select_related('course', 'course__level', 'course__session').prefetch_related('course__departments')

    # Get sessions for filtering
    sessions = AcademicSession.objects.all().order_by('-start_date')

    # Add enrollment counts and result statistics
    for assignment in assigned_courses:
        assignment.enrolled_count = CourseEnrollment.objects.filter(
            course=assignment.course,
            session=assignment.course.session
        ).count()

        # Get result statistics
        enrollments = CourseEnrollment.objects.filter(
            course=assignment.course,
            session=assignment.course.session
        )
        assignment.draft_count = Result.objects.filter(
            enrollment__in=enrollments,
            status='DRAFT'
        ).count()
        assignment.submitted_count = Result.objects.filter(
            enrollment__in=enrollments,
            status='SUBMITTED'
        ).count()
        assignment.published_count = Result.objects.filter(
            enrollment__in=enrollments,
            status='PUBLISHED'
        ).count()

    context = {
        'assigned_courses': assigned_courses,
        'sessions': sessions,
    }

    return render(request, 'lecturer_courses.html', context)

@login_required
def lecturer_course_details(request):
    return render(request, 'placeholder.html', {'page_title': 'Course Details', 'message': 'Detailed course information'})

@login_required
def lecturer_enter_results(request):
    """Lecturer Enter Results"""
    # Check if user has Lecturer role
    lecturer_roles = UserRole.objects.filter(user=request.user, role='LECTURER')
    if not lecturer_roles.exists():
        messages.error(request, 'Access denied. Lecturer role required.')
        return redirect('dashboard')

    # Get lecturer's assigned courses
    assigned_courses = CourseAssignment.objects.filter(
        lecturer=request.user
    ).select_related('course', 'course__level', 'course__session').prefetch_related('course__departments')

    # Get sessions
    sessions = AcademicSession.objects.all().order_by('-start_date')

    selected_course = None
    selected_session = None
    enrolled_students = None

    # Get selected course and session
    course_id = request.GET.get('course_id') or request.POST.get('course_id')
    session_id = request.GET.get('session_id') or request.POST.get('session_id')

    if course_id and session_id:
        try:
            selected_course = Course.objects.get(id=course_id)
            selected_session = AcademicSession.objects.get(id=session_id)

            # Verify lecturer has access to this course
            if not CourseAssignment.objects.filter(lecturer=request.user, course=selected_course).exists():
                messages.error(request, 'You do not have permission to enter results for this course.')
                return redirect('lecturer_enter_results')

            # Get enrolled students with existing results
            enrolled_students = CourseEnrollment.objects.filter(
                course=selected_course,
                session=selected_session
            ).select_related('student', 'student__user').prefetch_related('result_set')

            # Add result data to each enrollment
            for enrollment in enrolled_students:
                try:
                    enrollment.result = enrollment.result_set.first()
                except:
                    enrollment.result = None

        except (Course.DoesNotExist, AcademicSession.DoesNotExist):
            messages.error(request, 'Invalid course or session selected.')

    if request.method == 'POST' and selected_course and selected_session:
        save_as_draft = request.POST.get('save_as_draft') == 'true'

        try:
            for enrollment in enrolled_students:
                ca_score = request.POST.get(f'ca_score_{enrollment.id}')
                exam_score = request.POST.get(f'exam_score_{enrollment.id}')

                if ca_score or exam_score:
                    ca_score = float(ca_score) if ca_score else 0
                    exam_score = float(exam_score) if exam_score else 0
                    total_score = ca_score + exam_score

                    # Calculate grade
                    if total_score >= 70:
                        grade = 'A'
                    elif total_score >= 60:
                        grade = 'B'
                    elif total_score >= 50:
                        grade = 'C'
                    elif total_score >= 45:
                        grade = 'D'
                    else:
                        grade = 'F'

                    # Create or update result
                    result, created = Result.objects.get_or_create(
                        enrollment=enrollment,
                        defaults={
                            'ca_score': ca_score,
                            'exam_score': exam_score,
                            'total_score': total_score,
                            'grade': grade,
                            'status': 'DRAFT' if save_as_draft else 'SUBMITTED',
                            'entered_by': request.user
                        }
                    )

                    if not created:
                        result.ca_score = ca_score
                        result.exam_score = exam_score
                        result.total_score = total_score
                        result.grade = grade
                        result.status = 'DRAFT' if save_as_draft else 'SUBMITTED'
                        result.save()

            if save_as_draft:
                return JsonResponse({'success': True, 'message': 'Results saved as draft'})
            else:
                messages.success(request, 'Results submitted successfully!')
                return redirect('lecturer_result_status')

        except Exception as e:
            if save_as_draft:
                return JsonResponse({'success': False, 'error': str(e)})
            else:
                messages.error(request, f'Error saving results: {str(e)}')

    context = {
        'assigned_courses': assigned_courses,
        'sessions': sessions,
        'selected_course': selected_course,
        'selected_session': selected_session,
        'enrolled_students': enrolled_students,
    }

    return render(request, 'lecturer_enter_results.html', context)

@login_required
def lecturer_bulk_results(request):
    return render(request, 'placeholder.html', {'page_title': 'Bulk Upload Results', 'message': 'Upload results via Excel template'})

@login_required
def lecturer_draft_results(request):
    return render(request, 'placeholder.html', {'page_title': 'Draft Results', 'message': 'View and edit draft results'})

@login_required
def lecturer_edit_results(request):
    return render(request, 'placeholder.html', {'page_title': 'Edit Results', 'message': 'Edit existing results before submission'})

@login_required
def lecturer_submit_results(request):
    return render(request, 'placeholder.html', {'page_title': 'Submit Results', 'message': 'Submit results to Exam Officer'})

@login_required
def lecturer_result_status(request):
    """Lecturer Result Status Tracking"""
    # Check if user has Lecturer role
    lecturer_roles = UserRole.objects.filter(user=request.user, role='LECTURER')
    if not lecturer_roles.exists():
        messages.error(request, 'Access denied. Lecturer role required.')
        return redirect('dashboard')

    # Get lecturer's courses with results
    assigned_courses = CourseAssignment.objects.filter(
        lecturer=request.user
    ).select_related('course', 'course__session')

    # Get all result submissions
    result_submissions = []

    for assignment in assigned_courses:
        enrollments = CourseEnrollment.objects.filter(
            course=assignment.course,
            session=assignment.course.session
        )

        if enrollments.exists():
            # Get results for this course/session combination
            results = Result.objects.filter(enrollment__in=enrollments)

            if results.exists():
                # Group by status
                status_counts = results.values('status').annotate(count=models.Count('id'))

                # Calculate statistics
                total_results = results.count()
                pass_count = results.filter(total_score__gte=45).count()
                fail_count = results.filter(total_score__lt=45).count()
                average_score = results.aggregate(avg=models.Avg('total_score'))['avg'] or 0

                # Get the most recent status
                latest_result = results.order_by('-created_at').first()

                submission_data = {
                    'course': assignment.course,
                    'session': assignment.course.session,
                    'status': latest_result.status if latest_result else 'DRAFT',
                    'student_count': enrollments.count(),
                    'total_results': total_results,
                    'pass_count': pass_count,
                    'fail_count': fail_count,
                    'average_score': average_score,
                    'last_updated': latest_result.updated_at if latest_result else None,
                    'rejection_reason': getattr(latest_result, 'rejection_reason', None)
                }

                result_submissions.append(submission_data)

    # Calculate summary statistics
    total_results = len(result_submissions)
    draft_count = len([r for r in result_submissions if r['status'] == 'DRAFT'])
    submitted_count = len([r for r in result_submissions if r['status'] == 'SUBMITTED'])
    approved_count = len([r for r in result_submissions if r['status'] == 'APPROVED'])
    rejected_count = len([r for r in result_submissions if r['status'] == 'REJECTED'])

    # Get sessions for filtering
    sessions = AcademicSession.objects.all().order_by('-start_date')

    context = {
        'result_submissions': result_submissions,
        'sessions': sessions,
        'total_results': total_results,
        'draft_count': draft_count,
        'submitted_count': submitted_count,
        'approved_count': approved_count,
        'rejected_count': rejected_count,
    }

    return render(request, 'lecturer_result_status.html', context)

@login_required
def lecturer_corrections(request):
    return render(request, 'placeholder.html', {'page_title': 'Correction Requests', 'message': 'View and handle correction requests'})

@login_required
def lecturer_resubmit(request):
    return render(request, 'placeholder.html', {'page_title': 'Resubmit Results', 'message': 'Resubmit corrected results'})

@login_required
def lecturer_course_students(request, course_id):
    """View students enrolled in a specific course"""
    # Check if user has Lecturer role
    lecturer_roles = UserRole.objects.filter(user=request.user, role='LECTURER')
    if not lecturer_roles.exists():
        messages.error(request, 'Access denied. Lecturer role required.')
        return redirect('dashboard')

    try:
        course = Course.objects.select_related('level', 'session').prefetch_related('departments').get(id=course_id)

        # Verify lecturer has access to this course
        if not CourseAssignment.objects.filter(lecturer=request.user, course=course).exists():
            messages.error(request, 'You do not have permission to view students for this course.')
            return redirect('lecturer_courses')

        # Get enrolled students
        enrollments = CourseEnrollment.objects.filter(
            course=course,
            session=course.session
        ).select_related('student', 'student__user', 'student__department', 'student__current_level').order_by('student__matric_number')

        # Get enrollment statistics
        total_enrolled = enrollments.count()
        active_students = enrollments.filter(student__user__is_active=True).count()

        # Get departments for this course
        course_departments = course.departments.all()

        # Statistics by department
        dept_stats = {}
        for dept in course_departments:
            dept_count = enrollments.filter(student__department=dept).count()
            dept_stats[dept.name] = dept_count

        context = {
            'course': course,
            'enrollments': enrollments,
            'total_enrolled': total_enrolled,
            'active_students': active_students,
            'course_departments': course_departments,
            'dept_stats': dept_stats,
        }

        return render(request, 'lecturer_course_students.html', context)

    except Course.DoesNotExist:
        messages.error(request, 'Course not found.')
        return redirect('lecturer_courses')

@login_required
def lecturer_course_results(request, course_id):
    """View and manage results for a specific course"""
    # Check if user has Lecturer role
    lecturer_roles = UserRole.objects.filter(user=request.user, role='LECTURER')
    if not lecturer_roles.exists():
        messages.error(request, 'Access denied. Lecturer role required.')
        return redirect('dashboard')

    try:
        course = Course.objects.select_related('level', 'session').get(id=course_id)

        # Verify lecturer has access to this course
        if not CourseAssignment.objects.filter(lecturer=request.user, course=course).exists():
            messages.error(request, 'You do not have permission to view results for this course.')
            return redirect('lecturer_courses')

        # Get enrolled students with their results
        enrollments = CourseEnrollment.objects.filter(
            course=course,
            session=course.session
        ).select_related('student', 'student__user').prefetch_related('result_set').order_by('student__matric_number')

        # Add result data to each enrollment
        for enrollment in enrollments:
            try:
                enrollment.result = enrollment.result_set.first()
            except:
                enrollment.result = None

        # Calculate statistics
        total_students = enrollments.count()
        results_entered = enrollments.filter(result_set__isnull=False).count()
        results_pending = total_students - results_entered

        # Grade distribution
        grade_stats = {}
        if results_entered > 0:
            from django.db.models import Count
            grade_distribution = Result.objects.filter(
                enrollment__in=enrollments
            ).values('grade').annotate(count=Count('grade'))

            for item in grade_distribution:
                grade_stats[item['grade']] = item['count']

        context = {
            'course': course,
            'enrollments': enrollments,
            'total_students': total_students,
            'results_entered': results_entered,
            'results_pending': results_pending,
            'grade_stats': grade_stats,
        }

        return render(request, 'lecturer_course_results.html', context)

    except Course.DoesNotExist:
        messages.error(request, 'Course not found.')
        return redirect('lecturer_courses')


# ============================================================================
# EXAM OFFICER PLACEHOLDER VIEWS (to be implemented)
# ============================================================================

@login_required
def exam_officer_pending_results(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Pending Results - {level}L', 'message': f'Review pending results for {level}L students'})

@login_required
def exam_officer_validate_results(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Validate Results - {level}L', 'message': f'Validate results for {level}L students'})

@login_required
def exam_officer_approve_results(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Approve Results - {level}L', 'message': f'Approve results for {level}L students'})

@login_required
def exam_officer_reject_results(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Rejection Notes - {level}L', 'message': f'Manage rejection notes for {level}L'})

@login_required
def exam_officer_submit_to_hod(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Submit to HOD - {level}L', 'message': f'Submit approved results to HOD for {level}L'})

@login_required
def exam_officer_result_history(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Result History - {level}L', 'message': f'View result history for {level}L'})

@login_required
def exam_officer_add_students(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Add Students - {level}L', 'message': f'Add new students to {level}L'})

@login_required
def exam_officer_bulk_students(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Bulk Upload Students - {level}L', 'message': f'Bulk upload students for {level}L'})

@login_required
def exam_officer_student_list(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Student List - {level}L', 'message': f'View all {level}L students'})

@login_required
def exam_officer_student_records(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Student Records - {level}L', 'message': f'Manage {level}L student records'})

@login_required
def exam_officer_carryovers(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Carryovers - {level}L', 'message': f'Manage carryover students for {level}L'})

@login_required
def exam_officer_carryover_export(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Export Carryovers - {level}L', 'message': f'Export carryover data for {level}L'})

@login_required
def exam_officer_export_students(request):
    """Exam Officer Student Export by Level"""
    # Check if user has Exam Officer role
    exam_officer_roles = UserRole.objects.filter(user=request.user, role='EXAM_OFFICER')
    if not exam_officer_roles.exists():
        messages.error(request, 'Access denied. Exam Officer role required.')
        return redirect('dashboard')

    # Get the faculty for this exam officer
    exam_officer_role = exam_officer_roles.first()
    faculty = exam_officer_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Exam Officer role.')
        return redirect('dashboard')

    # Get level from query parameter
    level_param = request.GET.get('level', '100')
    try:
        level = Level.objects.get(numeric_value=int(level_param))
    except (Level.DoesNotExist, ValueError):
        messages.error(request, 'Invalid level specified.')
        return redirect('exam_officer_dashboard')

    try:
        from .reporting_service import ReportingService

        # Export students for this level and faculty
        data = ReportingService.get_student_list_data(faculty=faculty, level=level)
        filename = f"students_{faculty.name}_{level.name}"
        return ReportingService.generate_excel_response(data, filename, f"Students - {level.name}")

    except Exception as e:
        messages.error(request, f'Export failed: {str(e)}')
        return redirect('exam_officer_dashboard')

@login_required
def exam_officer_export_gpa(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Export GPA - {level}L', 'message': f'Export GPA sheet for {level}L'})

@login_required
def exam_officer_export_results(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Export Results - {level}L', 'message': f'Export all results for {level}L'})

@login_required
def exam_officer_export_approved(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Export Approved - {level}L', 'message': f'Export approved results for {level}L'})

@login_required
def exam_officer_export_carryovers(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Export Carryovers by Course - {level}L', 'message': f'Export carryovers by course for {level}L'})

@login_required
def exam_officer_export_carryover_students(request):
    level = request.GET.get('level', '100')
    return render(request, 'placeholder.html', {'page_title': f'Export Carryover Students - {level}L', 'message': f'Export carryover students for {level}L'})

@login_required
def exam_officer_review_result(request, result_id):
    return render(request, 'placeholder.html', {'page_title': 'Review Result', 'message': f'Review result ID: {result_id}'})

@login_required
def exam_officer_approve_single(request, result_id):
    return render(request, 'placeholder.html', {'page_title': 'Quick Approve', 'message': f'Quick approve result ID: {result_id}'})


# ============================================================================
# DAAA PLACEHOLDER VIEWS (to be implemented)
# ============================================================================

@login_required
def daaa_create_session(request):
    """DAAA Create Academic Session"""
    # Check if user has DAAA role or is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['DAAA', 'SUPER_ADMIN'])
    if not has_access:
        messages.error(request, 'Access denied. DAAA or Super Admin role required.')
        return redirect('dashboard')

    if request.method == 'POST':
        try:
            # Get session data
            name = request.POST.get('name', '').strip()
            start_date = request.POST.get('start_date', '').strip()
            end_date = request.POST.get('end_date', '').strip()

            # Validate required fields
            if not all([name, start_date, end_date]):
                messages.error(request, 'All fields are required.')
                return render(request, 'daaa_create_session.html', {})

            # Validate date format and logic
            from datetime import datetime
            try:
                start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
                end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()

                if start_date_obj >= end_date_obj:
                    messages.error(request, 'End date must be after start date.')
                    return render(request, 'daaa_create_session.html', {})

            except ValueError:
                messages.error(request, 'Invalid date format.')
                return render(request, 'daaa_create_session.html', {})

            # Check if session name already exists
            if AcademicSession.objects.filter(name=name).exists():
                messages.error(request, f'Academic session "{name}" already exists.')
                return render(request, 'daaa_create_session.html', {})

            # Create session
            session = AcademicSession.objects.create(
                name=name,
                start_date=start_date_obj,
                end_date=end_date_obj,
                is_active=False,  # Created as inactive
                is_locked=False,
                created_by=request.user
            )

            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='CREATE_SESSION',
                description=f'Created academic session: {name} ({start_date} to {end_date})',
                level='INFO'
            )

            messages.success(request, f'Academic session "{name}" created successfully!')
            return redirect('daaa_manage_sessions')

        except Exception as e:
            messages.error(request, f'Error creating session: {str(e)}')

    return render(request, 'daaa_create_session.html', {})




@login_required
def daaa_manage_sessions(request):
    """DAAA Session Management Interface"""
    # Check if user has DAAA role or is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['DAAA', 'SUPER_ADMIN'])
    if not has_access:
        messages.error(request, 'Access denied. DAAA or Super Admin role required.')
        return redirect('dashboard')

    # Get current active session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Get all sessions with statistics
    sessions = AcademicSession.objects.annotate(
        total_results=Count('courseenrollment__result'),
        published_results=Count(
            'courseenrollment__result',
            filter=Q(courseenrollment__result__status='PUBLISHED')
        )
    ).order_by('-created_at')

    # Calculate session statistics
    session_stats = {
        'total_sessions': sessions.count(),
        'active_sessions': sessions.filter(is_active=True).count(),
        'locked_sessions': sessions.filter(is_locked=True).count(),
        'total_results': sum(session.total_results for session in sessions),
    }

    context = {
        'current_session': current_session,
        'sessions': sessions,
        'session_stats': session_stats,
    }

    return render(request, 'daaa_session_management.html', context)

@login_required
def daaa_activate_session(request):
    """DAAA Activate Academic Session (AJAX endpoint)"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})

    # Check if user has DAAA role or is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['DAAA'])
    if not has_access:
        return JsonResponse({'success': False, 'message': 'Access denied. DAAA or Super Admin role required.'})

    try:
        session_id = request.POST.get('session_id')
        if not session_id:
            return JsonResponse({'success': False, 'message': 'Session ID is required.'})

        # Get the session
        session = AcademicSession.objects.get(id=session_id)

        # Deactivate all other sessions
        AcademicSession.objects.all().update(is_active=False)

        # Activate this session
        session.is_active = True
        session.save()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='ACTIVATE_SESSION',
            description=f'Activated academic session: {session.name}',
            level='INFO'
        )

        return JsonResponse({
            'success': True,
            'message': f'Academic session "{session.name}" activated successfully!'
        })

    except AcademicSession.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Session not found.'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error activating session: {str(e)}'})

@login_required
def daaa_lock_session(request, session_id):
    """DAAA Lock Academic Session (AJAX endpoint)"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})

    # Check if user has DAAA role or is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['DAAA'])
    if not has_access:
        return JsonResponse({'success': False, 'message': 'Access denied. DAAA or Super Admin role required.'})

    try:
        session = AcademicSession.objects.get(id=session_id)
        session.is_locked = True
        session.save()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='LOCK_SESSION',
            description=f'Locked academic session: {session.name}',
            level='WARNING'
        )

        return JsonResponse({
            'success': True,
            'message': f'Academic session "{session.name}" locked successfully!'
        })

    except AcademicSession.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Session not found.'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error locking session: {str(e)}'})

@login_required
def daaa_unlock_session(request, session_id):
    """DAAA Unlock Academic Session (AJAX endpoint)"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})

    # Check if user has DAAA role or is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['DAAA'])
    if not has_access:
        return JsonResponse({'success': False, 'message': 'Access denied. DAAA or Super Admin role required.'})

    try:
        session = AcademicSession.objects.get(id=session_id)
        session.is_locked = False
        session.save()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='UNLOCK_SESSION',
            description=f'Unlocked academic session: {session.name}',
            level='INFO'
        )

        return JsonResponse({
            'success': True,
            'message': f'Academic session "{session.name}" unlocked successfully!'
        })

    except AcademicSession.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Session not found.'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error unlocking session: {str(e)}'})


@login_required
def daaa_deactivate_session(request, session_id):
    """DAAA Deactivate Academic Session (AJAX endpoint)"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})

    # Check if user has DAAA role or is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['DAAA', 'SUPER_ADMIN'])
    if not has_access:
        return JsonResponse({'success': False, 'message': 'Access denied. DAAA or Super Admin role required.'})

    try:
        session = AcademicSession.objects.get(id=session_id)

        if not session.is_active:
            return JsonResponse({'success': False, 'message': 'Session is already inactive.'})

        # Deactivate this session
        session.is_active = False
        session.save()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='DEACTIVATE_SESSION',
            description=f'Deactivated academic session: {session.name}',
            level='INFO'
        )

        return JsonResponse({'success': True, 'message': f'Session "{session.name}" deactivated successfully!'})

    except AcademicSession.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Session not found.'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error deactivating session: {str(e)}'})


@login_required
def daaa_delete_session(request, session_id):
    """DAAA Delete Academic Session (AJAX endpoint)"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})

    # Check if user has DAAA role or is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['DAAA'])
    if not has_access:
        return JsonResponse({'success': False, 'message': 'Access denied. DAAA or Super Admin role required.'})

    try:
        session = AcademicSession.objects.get(id=session_id)

        # Auto-deactivate if session is active
        if session.is_active:
            session.is_active = False
            session.save()

            # Log the deactivation
            AuditLog.objects.create(
                user=request.user,
                action='AUTO_DEACTIVATE_SESSION',
                description=f'Auto-deactivated academic session before deletion: {session.name}',
                level='INFO'
            )

        # Check if session has associated data (courses, enrollments, etc.)
        course_count = Course.objects.filter(session=session).count()
        enrollment_count = CourseEnrollment.objects.filter(session=session).count()

        if course_count > 0 or enrollment_count > 0:
            return JsonResponse({
                'success': False,
                'message': f'Cannot delete session with associated data. Found {course_count} courses and {enrollment_count} enrollments.'
            })

        session_name = session.name
        session.delete()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='DELETE_SESSION',
            description=f'Deleted academic session: {session_name}',
            level='WARNING'
        )

        return JsonResponse({'success': True, 'message': f'Session "{session_name}" deleted successfully!'})

    except AcademicSession.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Session not found.'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error deleting session: {str(e)}'})


@login_required
def daaa_pending_results(request):
    """DAAA Pending Results Management"""
    # Check if user has DAAA role
    daaa_roles = UserRole.objects.filter(user=request.user, role='DAAA')
    if not daaa_roles.exists():
        messages.error(request, 'Access denied. DAAA role required.')
        return redirect('dashboard')

    # Get results submitted to DAAA (approved by Faculty Dean)
    pending_results = Result.objects.filter(
        status='SUBMITTED_TO_DAAA'
    ).select_related(
        'course', 'student', 'session', 'lecturer'
    ).prefetch_related(
        'course__departments__faculty'
    ).order_by('-created_at')

    # Get statistics
    stats = {
        'total_pending': pending_results.count(),
        'by_faculty': {},
        'by_level': {},
        'total_students': pending_results.values('student').distinct().count(),
    }

    # Calculate faculty-wise statistics
    for result in pending_results:
        for dept in result.course.departments.all():
            faculty_name = dept.faculty.name
            if faculty_name not in stats['by_faculty']:
                stats['by_faculty'][faculty_name] = 0
            stats['by_faculty'][faculty_name] += 1

    # Calculate level-wise statistics
    for result in pending_results:
        level = result.course.level
        if level not in stats['by_level']:
            stats['by_level'][level] = 0
        stats['by_level'][level] += 1

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    context = {
        'pending_results': pending_results,
        'stats': stats,
        'current_session': current_session,
    }

    return render(request, 'daaa_pending_results.html', context)

@login_required
def daaa_review_results(request):
    """DAAA Review Individual Results"""
    # Check if user has DAAA role
    daaa_roles = UserRole.objects.filter(user=request.user, role='DAAA')
    if not daaa_roles.exists():
        messages.error(request, 'Access denied. DAAA role required.')
        return redirect('dashboard')

    # Handle bulk actions
    if request.method == 'POST':
        action = request.POST.get('action')
        result_ids = request.POST.getlist('result_ids')

        if action and result_ids:
            results = Result.objects.filter(id__in=result_ids, status='SUBMITTED_TO_DAAA')

            if action == 'approve':
                for result in results:
                    result.status = 'APPROVED_BY_DAAA'
                    result.save()

                    # Create approval record
                    ResultApproval.objects.create(
                        result=result,
                        approved_by=request.user,
                        action='APPROVE',
                        role='DAAA',
                        comments='Bulk approved by DAAA'
                    )

                    # Log the action
                    AuditLog.objects.create(
                        user=request.user,
                        action='APPROVE_RESULT',
                        description=f'Approved result for {result.student.get_full_name()} in {result.course.code}',
                        level='INFO'
                    )

                messages.success(request, f'Successfully approved {len(results)} results.')

            elif action == 'reject':
                rejection_reason = request.POST.get('rejection_reason', 'No reason provided')
                for result in results:
                    result.status = 'REJECTED'
                    result.save()

                    # Create approval record
                    ResultApproval.objects.create(
                        result=result,
                        approved_by=request.user,
                        action='REJECT',
                        role='DAAA',
                        comments=rejection_reason
                    )

                    # Log the action
                    AuditLog.objects.create(
                        user=request.user,
                        action='REJECT_RESULT',
                        description=f'Rejected result for {result.student.get_full_name()} in {result.course.code}: {rejection_reason}',
                        level='WARNING'
                    )

                messages.warning(request, f'Rejected {len(results)} results.')

            return redirect('daaa_review_results')

    # Get results for review
    results = Result.objects.filter(
        status='SUBMITTED_TO_DAAA'
    ).select_related(
        'course', 'student', 'session', 'lecturer'
    ).prefetch_related(
        'course__departments__faculty'
    ).order_by('-created_at')

    # Filter by faculty if specified
    faculty_filter = request.GET.get('faculty')
    if faculty_filter:
        results = results.filter(course__departments__faculty__id=faculty_filter)

    # Filter by level if specified
    level_filter = request.GET.get('level')
    if level_filter:
        results = results.filter(course__level=level_filter)

    # Get faculties for filter
    faculties = Faculty.objects.all().order_by('name')

    context = {
        'results': results,
        'faculties': faculties,
        'selected_faculty': faculty_filter,
        'selected_level': level_filter,
    }

    return render(request, 'daaa_review_results.html', context)

@login_required
def daaa_approve_results(request):
    """DAAA Approve Results for Senate Submission"""
    # Check if user has DAAA role
    daaa_roles = UserRole.objects.filter(user=request.user, role='DAAA')
    if not daaa_roles.exists():
        messages.error(request, 'Access denied. DAAA role required.')
        return redirect('dashboard')

    if request.method == 'POST':
        result_ids = request.POST.getlist('result_ids')
        action = request.POST.get('action')

        if action == 'submit_to_senate' and result_ids:
            results = Result.objects.filter(id__in=result_ids, status='APPROVED_BY_DAAA')

            for result in results:
                result.status = 'SUBMITTED_TO_SENATE'
                result.save()

                # Create approval record
                ResultApproval.objects.create(
                    result=result,
                    approved_by=request.user,
                    action='SUBMIT_TO_SENATE',
                    role='DAAA',
                    comments='Submitted to Senate by DAAA'
                )

                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='SUBMIT_TO_SENATE',
                    description=f'Submitted result to Senate for {result.student.get_full_name()} in {result.course.code}',
                    level='INFO'
                )

            messages.success(request, f'Successfully submitted {len(results)} results to Senate.')
            return redirect('daaa_approve_results')

    # Get approved results ready for Senate submission
    approved_results = Result.objects.filter(
        status='APPROVED_BY_DAAA'
    ).select_related(
        'course', 'student', 'session', 'lecturer'
    ).prefetch_related(
        'course__departments__faculty'
    ).order_by('-created_at')

    # Calculate statistics
    stats = {
        'total_approved': approved_results.count(),
        'by_faculty': {},
        'by_level': {},
        'total_students': approved_results.values('student').distinct().count(),
    }

    # Calculate faculty-wise statistics
    for result in approved_results:
        for dept in result.course.departments.all():
            faculty_name = dept.faculty.name
            if faculty_name not in stats['by_faculty']:
                stats['by_faculty'][faculty_name] = 0
            stats['by_faculty'][faculty_name] += 1

    # Calculate level-wise statistics
    for result in approved_results:
        level = result.course.level
        if level not in stats['by_level']:
            stats['by_level'][level] = 0
        stats['by_level'][level] += 1

    context = {
        'approved_results': approved_results,
        'stats': stats,
    }

    return render(request, 'daaa_approve_results.html', context)

@login_required
def daaa_reject_results(request):
    return render(request, 'placeholder.html', {'page_title': 'Reject Results', 'message': 'Send results back for correction'})

@login_required
def daaa_submit_to_senate(request):
    return render(request, 'placeholder.html', {'page_title': 'Submit to Senate', 'message': 'Submit approved results to Senate'})

@login_required
def daaa_senate_reports(request):
    return render(request, 'placeholder.html', {'page_title': 'Senate Reports', 'message': 'Generate reports for Senate'})

@login_required
def daaa_publish_results(request):
    """DAAA Publish Results to Students"""
    # Check if user has DAAA role
    daaa_roles = UserRole.objects.filter(user=request.user, role='DAAA')
    if not daaa_roles.exists():
        messages.error(request, 'Access denied. DAAA role required.')
        return redirect('dashboard')

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'publish_results':
            session_id = request.POST.get('session_id')
            notification_method = request.POST.get('notification_method', 'IMMEDIATE')
            faculty_ids = request.POST.getlist('faculty_ids')
            department_ids = request.POST.getlist('department_ids')
            level_filter = request.POST.get('level_filter')

            try:
                session = AcademicSession.objects.get(id=session_id)

                # Get results to publish (approved by Senate)
                results_query = Result.objects.filter(
                    session=session,
                    status='PUBLISHED'  # Assuming Senate sets this status
                )

                # Apply filters based on notification method
                if notification_method == 'BY_FACULTY' and faculty_ids:
                    results_query = results_query.filter(course__departments__faculty__id__in=faculty_ids)
                elif notification_method == 'BY_DEPARTMENT' and department_ids:
                    results_query = results_query.filter(course__departments__id__in=department_ids)
                elif notification_method == 'BY_LEVEL' and level_filter:
                    results_query = results_query.filter(course__level=level_filter)

                results = results_query.distinct()

                # Create publication record
                publication = ResultPublication.objects.create(
                    session=session,
                    published_by=request.user,
                    notification_method=notification_method,
                    published_at=timezone.now()
                )

                # Add target filters
                if notification_method == 'BY_FACULTY' and faculty_ids:
                    publication.target_faculties.set(faculty_ids)
                elif notification_method == 'BY_DEPARTMENT' and department_ids:
                    publication.target_departments.set(department_ids)

                # Send notifications to students
                students = User.objects.filter(
                    rms_roles__role='STUDENT',
                    student_profile__results__in=results
                ).distinct()

                notification_count = 0
                for student in students:
                    notification = Notification.objects.create(
                        user=student,
                        title=f'Results Published - {session.name}',
                        message=f'Your results for {session.name} academic session have been published. Please check your dashboard.',
                        notification_type='RESULT_PUBLISHED',
                        created_by=request.user
                    )

                    # Send email notification
                    if notification.send_email():
                        notification_count += 1

                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='PUBLISH_RESULTS',
                    description=f'Published results for {session.name} session. Notified {notification_count} students.',
                    level='INFO'
                )

                messages.success(request, f'Successfully published results for {session.name}. Notified {notification_count} students.')
                return redirect('daaa_publish_results')

            except AcademicSession.DoesNotExist:
                messages.error(request, 'Academic session not found.')
            except Exception as e:
                messages.error(request, f'Error publishing results: {str(e)}')

    # Get sessions with results ready for publication
    sessions = AcademicSession.objects.filter(
        result__status='PUBLISHED'
    ).distinct().order_by('-name')

    # Get faculties and departments for filtering
    faculties = Faculty.objects.all().order_by('name')
    departments = Department.objects.all().order_by('name')

    # Get publication history
    publications = ResultPublication.objects.all().order_by('-published_at')[:10]

    context = {
        'sessions': sessions,
        'faculties': faculties,
        'departments': departments,
        'publications': publications,
    }

    return render(request, 'daaa_publish_results.html', context)

@login_required
def daaa_publication_settings(request):
    return render(request, 'placeholder.html', {'page_title': 'Publication Settings', 'message': 'Configure result publication settings'})

@login_required
def daaa_published_sessions(request):
    return render(request, 'placeholder.html', {'page_title': 'Published Sessions', 'message': 'View published academic sessions'})

@login_required
def daaa_notification_log(request):
    return render(request, 'placeholder.html', {'page_title': 'Notification Log', 'message': 'View notification history'})

@login_required
def daaa_send_notifications(request):
    """DAAA Notification Management Interface"""
    # Check if user has DAAA role
    daaa_roles = UserRole.objects.filter(user=request.user, role='DAAA')
    if not daaa_roles.exists():
        messages.error(request, 'Access denied. DAAA role required.')
        return redirect('dashboard')

    # Calculate notification statistics
    from datetime import datetime, timedelta
    today = datetime.now().date()

    stats = {
        'total_notifications': Notification.objects.count(),
        'unread_notifications': Notification.objects.filter(is_read=False).count(),
        'emails_sent_today': Notification.objects.filter(
            email_sent=True,
            email_sent_at__date=today
        ).count(),
        'email_success_rate': 95,  # Mock data - would calculate from actual email logs
    }

    # Get recent notifications
    recent_notifications = Notification.objects.annotate(
        recipient_count=Count('user')
    ).order_by('-created_at')[:10]

    # Email statistics
    email_stats = {
        'sent_today': stats['emails_sent_today'],
        'delivered': stats['emails_sent_today'] - 2,  # Mock data
        'failed': 2,  # Mock data
        'pending': 0,  # Mock data
    }

    context = {
        'stats': stats,
        'recent_notifications': recent_notifications,
        'email_stats': email_stats,
    }

    return render(request, 'daaa_notifications.html', context)

@login_required
def daaa_email_status(request):
    return render(request, 'placeholder.html', {'page_title': 'Email Status', 'message': 'Check email delivery status'})

# Additional DAAA Notification Views
@login_required
def daaa_bulk_email(request):
    return render(request, 'placeholder.html', {'page_title': 'Send Bulk Email', 'message': 'Send bulk email to users'})

@login_required
def daaa_notification_templates(request):
    return render(request, 'placeholder.html', {'page_title': 'Notification Templates', 'message': 'Manage notification templates'})

@login_required
def daaa_email_settings(request):
    return render(request, 'placeholder.html', {'page_title': 'Email Settings', 'message': 'Configure email settings'})

@login_required
def daaa_send_notification(request):
    return render(request, 'placeholder.html', {'page_title': 'Send Notification', 'message': 'Send single notification'})

@login_required
def daaa_notification_details(request, notification_id):
    return render(request, 'placeholder.html', {'page_title': 'Notification Details', 'message': f'Notification details ID: {notification_id}'})

@login_required
def daaa_resend_email(request, notification_id):
    return render(request, 'placeholder.html', {'page_title': 'Resend Email', 'message': f'Resend email for notification ID: {notification_id}'})

@login_required
def daaa_email_logs(request):
    return render(request, 'placeholder.html', {'page_title': 'Email Logs', 'message': 'View email delivery logs'})

@login_required
def daaa_test_email(request):
    return render(request, 'placeholder.html', {'page_title': 'Test Email', 'message': 'Send test email'})

# Additional DAAA Reporting Views
@login_required
def daaa_student_performance_report(request):
    return render(request, 'placeholder.html', {'page_title': 'Student Performance Report', 'message': 'Comprehensive student performance analysis'})

@login_required
def daaa_gpa_analysis(request):
    return render(request, 'placeholder.html', {'page_title': 'GPA Analysis', 'message': 'University-wide GPA analysis'})

@login_required
def daaa_graduation_report(request):
    return render(request, 'placeholder.html', {'page_title': 'Graduation Report', 'message': 'Graduation statistics and trends'})

@login_required
def daaa_academic_standing(request):
    return render(request, 'placeholder.html', {'page_title': 'Academic Standing', 'message': 'Student academic standing report'})

@login_required
def daaa_course_performance(request):
    return render(request, 'placeholder.html', {'page_title': 'Course Performance', 'message': 'Course performance analysis'})

@login_required
def daaa_pass_rate_analysis(request):
    return render(request, 'placeholder.html', {'page_title': 'Pass Rate Analysis', 'message': 'Pass rate trends and analysis'})

@login_required
def daaa_department_analysis(request):
    return render(request, 'placeholder.html', {'page_title': 'Department Analysis', 'message': 'Department performance analysis'})

@login_required
def daaa_enrollment_trends(request):
    return render(request, 'placeholder.html', {'page_title': 'Enrollment Trends', 'message': 'Student enrollment trends'})

@login_required
def daaa_capacity_analysis(request):
    return render(request, 'placeholder.html', {'page_title': 'Capacity Analysis', 'message': 'University capacity analysis'})

@login_required
def daaa_session_summary(request):
    return render(request, 'placeholder.html', {'page_title': 'Session Summary', 'message': 'Academic session summary report'})

@login_required
def daaa_workflow_analysis(request):
    return render(request, 'placeholder.html', {'page_title': 'Workflow Analysis', 'message': 'Result workflow analysis'})

@login_required
def daaa_custom_report(request):
    return render(request, 'placeholder.html', {'page_title': 'Custom Report', 'message': 'Generate custom report'})

@login_required
def daaa_report_history(request):
    return render(request, 'placeholder.html', {'page_title': 'Report History', 'message': 'View report generation history'})

@login_required
def daaa_download_report(request, report_id):
    return render(request, 'placeholder.html', {'page_title': 'Download Report', 'message': f'Download report ID: {report_id}'})

@login_required
def daaa_regenerate_report(request, report_id):
    return render(request, 'placeholder.html', {'page_title': 'Regenerate Report', 'message': f'Regenerate report ID: {report_id}'})

@login_required
def daaa_detailed_analytics(request):
    return render(request, 'placeholder.html', {'page_title': 'Detailed Analytics', 'message': 'Detailed analytics dashboard'})

@login_required
def daaa_trend_analysis(request):
    return render(request, 'placeholder.html', {'page_title': 'Trend Analysis', 'message': 'Academic trend analysis'})

@login_required
def daaa_comparative_analysis(request):
    return render(request, 'placeholder.html', {'page_title': 'Comparative Analysis', 'message': 'Comparative performance analysis'})

@login_required
def daaa_faculty_summary(request):
    """DAAA Faculty Summary and Reports Dashboard"""
    # Check if user has DAAA role
    daaa_roles = UserRole.objects.filter(user=request.user, role='DAAA')
    if not daaa_roles.exists():
        messages.error(request, 'Access denied. DAAA role required.')
        return redirect('dashboard')

    # Get all faculties, levels, and sessions for filters
    faculties = Faculty.objects.all()
    levels = Level.objects.all().order_by('numeric_value')
    sessions = AcademicSession.objects.all().order_by('-created_at')

    # Calculate analytics overview
    total_students = Student.objects.count()
    published_results = Result.objects.filter(status='PUBLISHED')

    # Calculate average GPA (simplified calculation)
    total_grade_points = 0
    total_credit_units = 0
    for result in published_results:
        if result.grade_point and result.enrollment.course.credit_units:
            total_grade_points += result.grade_point * result.enrollment.course.credit_units
            total_credit_units += result.enrollment.course.credit_units

    average_gpa = total_grade_points / total_credit_units if total_credit_units > 0 else 0.0

    # Calculate carryover rate
    total_results = published_results.count()
    carryover_results = published_results.filter(is_carry_over=True).count()
    carryover_rate = (carryover_results / total_results * 100) if total_results > 0 else 0

    analytics = {
        'total_students': total_students,
        'average_gpa': average_gpa,
        'carryover_rate': carryover_rate,
        'graduation_rate': 85.5,  # Mock data - would calculate from actual graduation records
    }

    # Mock recent reports data
    recent_reports = []  # Would fetch from actual report history table

    context = {
        'faculties': faculties,
        'levels': levels,
        'sessions': sessions,
        'analytics': analytics,
        'recent_reports': recent_reports,
    }

    return render(request, 'daaa_reports.html', context)

@login_required
def daaa_faculty_comparison(request):
    return render(request, 'placeholder.html', {'page_title': 'Faculty Comparison', 'message': 'Compare faculty performance'})

@login_required
def daaa_export_university(request):
    """DAAA University Data Export"""
    # Check if user has DAAA role
    daaa_roles = UserRole.objects.filter(user=request.user, role='DAAA')
    if not daaa_roles.exists():
        messages.error(request, 'Access denied. DAAA role required.')
        return redirect('dashboard')

    # Get export type from query parameter
    export_type = request.GET.get('type', 'university_summary')

    try:
        from .reporting_service import ReportingService, export_faculty_summary, export_student_results, export_carryover_list

        if export_type == 'university_summary':
            # Export all faculties summary
            return export_faculty_summary()

        elif export_type == 'all_student_results':
            # Export all student results
            return export_student_results()

        elif export_type == 'all_carryovers':
            # Export all carryovers
            return export_carryover_list()

        elif export_type == 'all_students':
            # Export all students
            data = ReportingService.get_student_list_data()
            filename = "university_student_list"
            return ReportingService.generate_excel_response(data, filename, "All Students")

        elif export_type == 'course_performance':
            # Export all course performance
            data = ReportingService.get_course_performance_data()
            filename = "university_course_performance"
            return ReportingService.generate_excel_response(data, filename, "Course Performance")

        else:
            messages.error(request, 'Invalid export type.')
            return redirect('daaa_dashboard')

    except Exception as e:
        messages.error(request, f'Export failed: {str(e)}')
        return redirect('daaa_dashboard')

@login_required
def daaa_export_senate(request):
    return render(request, 'placeholder.html', {'page_title': 'Export Senate Report', 'message': 'Export report for Senate'})

@login_required
def daaa_audit_log(request):
    return render(request, 'placeholder.html', {'page_title': 'Audit Log', 'message': 'View system audit log'})

@login_required
def daaa_system_health(request):
    return render(request, 'placeholder.html', {'page_title': 'System Health', 'message': 'Check system health status'})

@login_required
def daaa_faculty_details(request, faculty_id):
    return render(request, 'placeholder.html', {'page_title': 'Faculty Details', 'message': f'Faculty details for ID: {faculty_id}'})

@login_required
def daaa_review_single_result(request, result_id):
    return render(request, 'placeholder.html', {'page_title': 'Review Result', 'message': f'Review result ID: {result_id}'})

@login_required
def daaa_approve_single_result(request, result_id):
    return render(request, 'placeholder.html', {'page_title': 'Approve Result', 'message': f'Approve result ID: {result_id}'})

# Additional DAAA Views
@login_required
def daaa_edit_session(request, session_id):
    return render(request, 'placeholder.html', {'page_title': 'Edit Session', 'message': f'Edit session ID: {session_id}'})

@login_required
def daaa_session_details(request, session_id):
    return render(request, 'placeholder.html', {'page_title': 'Session Details', 'message': f'Session details ID: {session_id}'})

@login_required
def daaa_activate_session_single(request, session_id):
    return render(request, 'placeholder.html', {'page_title': 'Activate Session', 'message': f'Activate session ID: {session_id}'})

@login_required
def daaa_archive_sessions(request):
    return render(request, 'placeholder.html', {'page_title': 'Archive Sessions', 'message': 'Archive old academic sessions'})

@login_required
def daaa_session_reports(request):
    return render(request, 'placeholder.html', {'page_title': 'Session Reports', 'message': 'Generate session reports'})


# ============================================================================
# SENATE PLACEHOLDER VIEWS (to be implemented)
# ============================================================================

@login_required
def senate_pending_results(request):
    return render(request, 'placeholder.html', {'page_title': 'Pending Results', 'message': 'Results awaiting Senate approval'})

@login_required
def senate_review_results(request):
    return render(request, 'placeholder.html', {'page_title': 'Review Results', 'message': 'Review submitted results'})

@login_required
def senate_approve_results(request):
    return render(request, 'placeholder.html', {'page_title': 'Approve Results', 'message': 'Approve results for final sealing'})

@login_required
def senate_send_back(request):
    return render(request, 'placeholder.html', {'page_title': 'Send Back to DAAA', 'message': 'Send results back to DAAA for correction'})

@login_required
def senate_seal_results(request):
    return render(request, 'placeholder.html', {'page_title': 'Seal Results', 'message': 'Permanently seal approved results'})

@login_required
def senate_final_archive(request):
    return render(request, 'placeholder.html', {'page_title': 'Final Archive', 'message': 'Archive sealed results'})

@login_required
def senate_session_overview(request):
    return render(request, 'placeholder.html', {'page_title': 'Session Overview', 'message': 'Complete session overview'})

@login_required
def senate_session_reports(request):
    return render(request, 'placeholder.html', {'page_title': 'Session Reports', 'message': 'Generate session reports'})

@login_required
def senate_faculty_summary(request):
    return render(request, 'placeholder.html', {'page_title': 'Faculty Summary', 'message': 'Faculty performance summary'})

@login_required
def senate_university_report(request):
    return render(request, 'placeholder.html', {'page_title': 'University Report', 'message': 'Comprehensive university report'})

@login_required
def senate_faculty_details(request, faculty_id):
    return render(request, 'placeholder.html', {'page_title': 'Faculty Details', 'message': f'Faculty details ID: {faculty_id}'})

@login_required
def senate_review_single_result(request, result_id):
    return render(request, 'placeholder.html', {'page_title': 'Review Result', 'message': f'Review result ID: {result_id}'})

@login_required
def senate_approve_single_result(request, result_id):
    return render(request, 'placeholder.html', {'page_title': 'Approve Result', 'message': f'Approve result ID: {result_id}'})

@login_required
def senate_approval_history(request):
    return render(request, 'placeholder.html', {'page_title': 'Approval History', 'message': 'Senate approval history'})


# ============================================================================
# STUDENT PLACEHOLDER VIEWS (to be implemented)
# ============================================================================

@login_required
def student_current_results(request):
    return render(request, 'placeholder.html', {'page_title': 'Current Results', 'message': 'View current session results'})

@login_required
def student_all_results(request):
    return render(request, 'placeholder.html', {'page_title': 'All Results', 'message': 'View all published results'})

@login_required
def student_result_history(request):
    return render(request, 'placeholder.html', {'page_title': 'Result History', 'message': 'Complete result history'})

@login_required
def student_transcript(request):
    return render(request, 'placeholder.html', {'page_title': 'Transcript', 'message': 'Academic transcript'})

@login_required
def student_download_result(request):
    return render(request, 'placeholder.html', {'page_title': 'Download Result', 'message': 'Download result PDF'})

@login_required
def student_download_transcript(request):
    return render(request, 'placeholder.html', {'page_title': 'Download Transcript', 'message': 'Download transcript PDF'})

@login_required
def student_submit_complaint(request):
    return render(request, 'placeholder.html', {'page_title': 'Submit Complaint', 'message': 'Submit result complaint'})

@login_required
def student_my_complaints(request):
    return render(request, 'placeholder.html', {'page_title': 'My Complaints', 'message': 'View my submitted complaints'})

@login_required
def student_help(request):
    return render(request, 'placeholder.html', {'page_title': 'Help & FAQ', 'message': 'Help and frequently asked questions'})

@login_required
def student_contact(request):
    return render(request, 'placeholder.html', {'page_title': 'Contact Support', 'message': 'Contact support team'})

@login_required
def student_result_details(request, result_id):
    return render(request, 'placeholder.html', {'page_title': 'Result Details', 'message': f'Result details ID: {result_id}'})


# ============================================================================
# ADMISSION OFFICER PLACEHOLDER VIEWS (to be implemented)
# ============================================================================

@login_required
def admission_register_student(request):
    return render(request, 'placeholder.html', {'page_title': 'Register Student', 'message': 'Register new student individually'})

@login_required
def admission_quick_register(request):
    return render(request, 'placeholder.html', {'page_title': 'Quick Register', 'message': 'Quick student registration form'})

@login_required
def admission_edit_student(request):
    return render(request, 'placeholder.html', {'page_title': 'Edit Student', 'message': 'Edit student information'})

@login_required
def admission_verify_student(request):
    return render(request, 'placeholder.html', {'page_title': 'Verify Student', 'message': 'Verify student registration'})

@login_required
def admission_bulk_register(request):
    return render(request, 'placeholder.html', {'page_title': 'Bulk Register', 'message': 'Bulk student registration'})

@login_required
def admission_import_excel(request):
    return render(request, 'placeholder.html', {'page_title': 'Import Excel', 'message': 'Import students from Excel file'})

@login_required
def admission_download_template(request):
    return render(request, 'placeholder.html', {'page_title': 'Download Template', 'message': 'Download Excel template'})

@login_required
def admission_bulk_update(request):
    return render(request, 'placeholder.html', {'page_title': 'Bulk Update', 'message': 'Bulk update student information'})

@login_required
def admission_search_students(request):
    return render(request, 'placeholder.html', {'page_title': 'Search Students', 'message': 'Search registered students'})

@login_required
def admission_filter_by_faculty(request):
    return render(request, 'placeholder.html', {'page_title': 'Filter by Faculty', 'message': 'Filter students by faculty'})

@login_required
def admission_filter_by_level(request):
    return render(request, 'placeholder.html', {'page_title': 'Filter by Level', 'message': 'Filter students by level'})

@login_required
def admission_filter_by_session(request):
    return render(request, 'placeholder.html', {'page_title': 'Filter by Session', 'message': 'Filter students by session'})

@login_required
def admission_update_placement(request):
    return render(request, 'placeholder.html', {'page_title': 'Update Placement', 'message': 'Update student academic placement'})

@login_required
def admission_level_promotion(request):
    return render(request, 'placeholder.html', {'page_title': 'Level Promotion', 'message': 'Promote students to next level'})

@login_required
def admission_transfer_student(request):
    return render(request, 'placeholder.html', {'page_title': 'Transfer Student', 'message': 'Transfer student between departments'})

@login_required
def admission_placement_reports(request):
    return render(request, 'placeholder.html', {'page_title': 'Placement Reports', 'message': 'Generate placement reports'})

@login_required
def admission_all_students(request):
    return render(request, 'placeholder.html', {'page_title': 'All Students', 'message': 'View all registered students'})

@login_required
def admission_student_details(request, student_id):
    return render(request, 'placeholder.html', {'page_title': 'Student Details', 'message': f'Student details ID: {student_id}'})

@login_required
def admission_edit_student_single(request, student_id):
    return render(request, 'placeholder.html', {'page_title': 'Edit Student', 'message': f'Edit student ID: {student_id}'})

@login_required
def admission_registration_report(request):
    return render(request, 'placeholder.html', {'page_title': 'Registration Report', 'message': 'Generate registration report'})

@login_required
def admission_export_students(request):
    return render(request, 'placeholder.html', {'page_title': 'Export Students', 'message': 'Export student list'})

@login_required
def admission_faculty_summary(request):
    return render(request, 'placeholder.html', {'page_title': 'Faculty Summary', 'message': 'Faculty registration summary'})

@login_required
def admission_faculty_students(request, faculty_id):
    return render(request, 'placeholder.html', {'page_title': 'Faculty Students', 'message': f'Students in faculty ID: {faculty_id}'})

@login_required
def admission_faculty_register(request, faculty_id):
    return render(request, 'placeholder.html', {'page_title': 'Register to Faculty', 'message': f'Register student to faculty ID: {faculty_id}'})


# ============================================================================
# HOD PLACEHOLDER VIEWS (to be implemented)
# ============================================================================

@login_required
def hod_create_course(request):
    """HOD Create Course"""
    # Check if user has HOD role or is Super Admin
    has_access, user_role, department, faculty = check_if_user_has_access(request.user, ['HOD'])
    if not has_access:
        messages.error(request, 'Access denied. HOD or Super Admin role required.')
        return redirect('dashboard')

    if not department:
        messages.error(request, 'No departments exist in the system.')
        return redirect('dashboard')

    if not faculty:
        faculty = department.faculty

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()
    if not current_session:
        messages.error(request, 'No active academic session found. Please contact DAAA or Super Admin to create and activate a session.')
        return redirect('hod_dashboard')

    if request.method == 'POST':
        try:
            # Get basic course data
            title = request.POST.get('title', '').strip()
            code = request.POST.get('code', '').strip().upper()
            credit_units = request.POST.get('credit_units', '').strip()
            level_id = request.POST.get('level_id', '').strip()
            course_type = request.POST.get('course_type', '').strip()
            semester = request.POST.get('semester', '').strip()

            # Get additional course data
            description = request.POST.get('description', '').strip()
            duration_weeks = request.POST.get('duration_weeks', '15').strip()
            max_students = request.POST.get('max_students', '').strip()
            lecture_hours = request.POST.get('lecture_hours', '3').strip()
            tutorial_hours = request.POST.get('tutorial_hours', '0').strip()
            practical_hours = request.POST.get('practical_hours', '0').strip()
            ca_percentage = request.POST.get('ca_percentage', '30').strip()
            exam_percentage = request.POST.get('exam_percentage', '70').strip()
            assessment_methods = request.POST.getlist('assessment_methods')
            prerequisites = request.POST.get('prerequisites', '').strip()
            min_level = request.POST.get('min_level', '').strip()
            min_cgpa = request.POST.get('min_cgpa', '').strip()

            # Validate required fields
            if not all([title, code, credit_units, level_id, course_type, semester]):
                messages.error(request, 'All required fields must be filled.')
                return render(request, 'hod_create_course.html', {
                    'department': department,
                    'faculty': faculty,
                    'current_session': current_session,
                    'levels': Level.objects.all()
                })

            # Validate credit units
            try:
                credit_units = int(credit_units)
                if credit_units < 1 or credit_units > 6:
                    messages.error(request, 'Credit units must be between 1 and 6.')
                    return render(request, 'hod_create_course.html', {
                        'department': department,
                        'faculty': faculty,
                        'current_session': current_session,
                        'levels': Level.objects.all()
                    })
            except ValueError:
                messages.error(request, 'Credit units must be a valid number.')
                return render(request, 'hod_create_course.html', {
                    'department': department,
                    'faculty': faculty,
                    'current_session': current_session,
                    'levels': Level.objects.all()
                })

            # Get level
            try:
                level = Level.objects.get(id=level_id)
            except Level.DoesNotExist:
                messages.error(request, 'Invalid level selected.')
                return render(request, 'hod_create_course.html', {
                    'department': department,
                    'faculty': faculty,
                    'current_session': current_session,
                    'levels': Level.objects.all()
                })

            # Check if course code already exists
            if Course.objects.filter(code=code, session=current_session).exists():
                messages.error(request, f'Course code "{code}" already exists for this session.')
                return render(request, 'hod_create_course.html', {
                    'department': department,
                    'faculty': faculty,
                    'current_session': current_session,
                    'levels': Level.objects.all()
                })

            # Create course
            course = Course.objects.create(
                title=title,
                code=code,
                credit_units=credit_units,
                level=level,
                session=current_session,
                created_by=request.user
            )

            # Add department to course
            course.departments.add(department)

            # Store additional course metadata (we can extend the model later)
            # For now, we'll log this information in the audit log
            additional_info = {
                'course_type': course_type,
                'semester': semester,
                'description': description,
                'duration_weeks': duration_weeks,
                'max_students': max_students,
                'lecture_hours': lecture_hours,
                'tutorial_hours': tutorial_hours,
                'practical_hours': practical_hours,
                'ca_percentage': ca_percentage,
                'exam_percentage': exam_percentage,
                'assessment_methods': assessment_methods,
                'prerequisites': prerequisites,
                'min_level': min_level,
                'min_cgpa': min_cgpa
            }

            # Log the action with additional details
            AuditLog.objects.create(
                user=request.user,
                action='CREATE_COURSE',
                description=f'Created course: {code} - {title} ({course_type}, {semester} semester, {credit_units} units) for {department.name}',
                level='INFO'
            )

            messages.success(request, f'Course "{code} - {title}" created successfully!')
            # Stay on the same page to allow creating more courses
            return render(request, 'hod_create_course.html', {
                'department': department,
                'faculty': faculty,
                'current_session': current_session,
                'levels': Level.objects.all(),
                'success': True
            })

        except Exception as e:
            messages.error(request, f'Error creating course: {str(e)}')

    # GET request - show form
    context = {
        'department': department,
        'faculty': faculty,
        'current_session': current_session,
        'levels': Level.objects.all(),
    }

    return render(request, 'hod_create_course.html', context)

@login_required
def hod_manage_courses(request):
    """HOD Manage Courses"""
    # Check if user has HOD role
    hod_roles = UserRole.objects.filter(user=request.user, role='HOD')
    if not hod_roles.exists():
        messages.error(request, 'Access denied. HOD role required.')
        return redirect('dashboard')

    # Get the department for this HOD
    hod_role = hod_roles.first()
    department = hod_role.department
    faculty = hod_role.faculty

    if not department:
        messages.error(request, 'No department assigned to your HOD role.')
        return redirect('dashboard')

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Get all courses for this department
    courses = Course.objects.filter(
        departments=department
    ).select_related('level', 'session').prefetch_related('departments')

    if current_session:
        current_courses = courses.filter(session=current_session)
    else:
        current_courses = courses.none()

    # Get course assignments
    course_assignments = CourseAssignment.objects.filter(
        course__departments=department
    ).select_related('course', 'lecturer')

    # Create a mapping of course to lecturer
    course_lecturer_map = {}
    for assignment in course_assignments:
        course_lecturer_map[assignment.course.id] = assignment.lecturer

    # Add lecturer info to courses
    for course in current_courses:
        course.assigned_lecturer = course_lecturer_map.get(course.id)

    # Statistics
    stats = {
        'total_courses': current_courses.count(),
        'assigned_courses': len([c for c in current_courses if c.assigned_lecturer]),
        'unassigned_courses': len([c for c in current_courses if not c.assigned_lecturer]),
        'total_credit_units': sum(course.credit_units for course in current_courses),
    }

    # Group courses by level
    courses_by_level = {}
    for course in current_courses:
        level_name = course.level.name
        if level_name not in courses_by_level:
            courses_by_level[level_name] = []
        courses_by_level[level_name].append(course)

    context = {
        'department': department,
        'faculty': faculty,
        'current_session': current_session,
        'courses': current_courses,
        'courses_by_level': courses_by_level,
        'stats': stats,
    }

    return render(request, 'hod_manage_courses.html', context)

@login_required
def hod_course_assignments(request):
    return render(request, 'placeholder.html', {'page_title': 'Course Assignments', 'message': 'View course-lecturer assignments'})

@login_required
def hod_course_reports(request):
    return render(request, 'placeholder.html', {'page_title': 'Course Reports', 'message': 'Generate course performance reports'})

@login_required
def hod_assign_lecturers(request):
    """HOD Assign Lecturers to Courses"""
    # Check if user has HOD role
    hod_roles = UserRole.objects.filter(user=request.user, role='HOD')
    if not hod_roles.exists():
        messages.error(request, 'Access denied. HOD role required.')
        return redirect('dashboard')

    # Get the department for this HOD
    hod_role = hod_roles.first()
    department = hod_role.department
    faculty = hod_role.faculty

    if not department:
        messages.error(request, 'No department assigned to your HOD role.')
        return redirect('dashboard')

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Get courses in this department
    courses = Course.objects.filter(
        departments=department,
        session=current_session
    ).select_related('level')

    # Get lecturers in this department and faculty
    department_lecturers = UserRole.objects.filter(
        role='LECTURER',
        department=department
    ).select_related('user')

    faculty_lecturers = UserRole.objects.filter(
        role='LECTURER',
        faculty=faculty,
        department__isnull=True  # Faculty-wide lecturers
    ).select_related('user')

    all_lecturers = list(department_lecturers) + list(faculty_lecturers)

    # Get existing assignments
    assignments = CourseAssignment.objects.filter(
        course__departments=department
    ).select_related('course', 'lecturer')

    # Create mappings
    course_lecturer_map = {}
    lecturer_courses_map = {}

    for assignment in assignments:
        course_lecturer_map[assignment.course.id] = assignment.lecturer
        if assignment.lecturer.id not in lecturer_courses_map:
            lecturer_courses_map[assignment.lecturer.id] = []
        lecturer_courses_map[assignment.lecturer.id].append(assignment.course)

    # Add assignment info to courses and lecturers
    for course in courses:
        course.assigned_lecturer = course_lecturer_map.get(course.id)

    for lecturer_role in all_lecturers:
        lecturer_role.assigned_courses = lecturer_courses_map.get(lecturer_role.user.id, [])

    # Statistics
    assigned_courses = len([c for c in courses if c.assigned_lecturer])
    unassigned_courses = len([c for c in courses if not c.assigned_lecturer])

    stats = {
        'total_courses': courses.count(),
        'assigned_courses': assigned_courses,
        'unassigned_courses': unassigned_courses,
        'total_lecturers': len(all_lecturers),
        'active_lecturers': len([l for l in all_lecturers if l.assigned_courses]),
    }

    context = {
        'department': department,
        'faculty': faculty,
        'current_session': current_session,
        'courses': courses,
        'lecturers': all_lecturers,
        'assignments': assignments,
        'stats': stats,
    }

    # Handle POST request for creating new lecturer
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'create_lecturer':
            try:
                # Get lecturer data
                first_name = request.POST.get('first_name', '').strip()
                last_name = request.POST.get('last_name', '').strip()
                email = request.POST.get('email', '').strip()
                username = request.POST.get('username', '').strip()
                password = request.POST.get('password', '').strip()
                course_ids = request.POST.getlist('course_ids')

                # Validate required fields
                if not all([first_name, last_name, email, username, password]):
                    messages.error(request, 'All lecturer fields are required.')
                    return render(request, 'hod_assign_lecturers.html', context)

                # Check if email or username already exists
                if User.objects.filter(email=email).exists():
                    messages.error(request, 'A user with this email already exists.')
                    return render(request, 'hod_assign_lecturers.html', context)

                if User.objects.filter(username=username).exists():
                    messages.error(request, 'A user with this username already exists.')
                    return render(request, 'hod_assign_lecturers.html', context)

                # Create lecturer user
                lecturer_user = User.objects.create_user(
                    username=username,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    password=password
                )

                # Create lecturer role
                UserRole.objects.create(
                    user=lecturer_user,
                    role='LECTURER',
                    faculty=faculty,
                    department=department,
                    created_by=request.user
                )

                # Assign courses if selected
                for course_id in course_ids:
                    try:
                        course = Course.objects.get(id=course_id, departments=department)
                        # Check if course is already assigned
                        if not CourseAssignment.objects.filter(course=course).exists():
                            CourseAssignment.objects.create(
                                course=course,
                                lecturer=lecturer_user,
                                assigned_by=request.user
                            )
                    except Course.DoesNotExist:
                        continue

                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='CREATE_LECTURER',
                    description=f'Created lecturer: {first_name} {last_name} and assigned {len(course_ids)} courses',
                    level='INFO'
                )

                messages.success(request, f'Lecturer {first_name} {last_name} created successfully and assigned to {len(course_ids)} course(s)!')
                return redirect('hod_assign_lecturers')

            except Exception as e:
                messages.error(request, f'Error creating lecturer: {str(e)}')

    return render(request, 'hod_assign_lecturers.html', context)

@login_required
def hod_lecturer_performance(request):
    """HOD Lecturer Performance Review"""
    # Check if user has HOD role
    hod_roles = UserRole.objects.filter(user=request.user, role='HOD')
    if not hod_roles.exists():
        messages.error(request, 'Access denied. HOD role required.')
        return redirect('dashboard')

    # Get the department for this HOD
    hod_role = hod_roles.first()
    department = hod_role.department
    faculty = hod_role.faculty

    if not department:
        messages.error(request, 'No department assigned to your HOD role.')
        return redirect('dashboard')

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Get lecturers in this department
    lecturers = UserRole.objects.filter(
        role='LECTURER',
        department=department
    ).select_related('user')

    # Get lecturer performance data
    lecturer_performance = []
    for lecturer_role in lecturers:
        # Get courses assigned to this lecturer
        assigned_courses = CourseAssignment.objects.filter(
            lecturer=lecturer_role.user
        ).select_related('course')

        # Get results for courses taught by this lecturer
        results = Result.objects.filter(
            enrollment__course__in=[assignment.course for assignment in assigned_courses],
            enrollment__session=current_session
        ) if current_session else Result.objects.none()

        # Calculate performance metrics
        total_students = results.count()
        passed_students = results.filter(grade__in=['A', 'B', 'C', 'D']).count()
        failed_students = results.filter(grade__in=['E', 'F']).count()
        pass_rate = (passed_students / total_students * 100) if total_students > 0 else 0

        lecturer_performance.append({
            'lecturer': lecturer_role.user,
            'department': lecturer_role.department,
            'courses_count': assigned_courses.count(),
            'total_students': total_students,
            'passed_students': passed_students,
            'failed_students': failed_students,
            'pass_rate': round(pass_rate, 1),
            'assigned_courses': assigned_courses,
        })

    # Overall department statistics
    total_lecturers = len(lecturer_performance)
    total_courses_assigned = sum(lp['courses_count'] for lp in lecturer_performance)
    avg_pass_rate = sum(lp['pass_rate'] for lp in lecturer_performance) / total_lecturers if total_lecturers > 0 else 0

    stats = {
        'total_lecturers': total_lecturers,
        'total_courses_assigned': total_courses_assigned,
        'avg_pass_rate': round(avg_pass_rate, 1),
        'active_lecturers': len([lp for lp in lecturer_performance if lp['courses_count'] > 0]),
    }

    context = {
        'department': department,
        'faculty': faculty,
        'current_session': current_session,
        'lecturer_performance': lecturer_performance,
        'stats': stats,
    }

    return render(request, 'hod_lecturer_performance.html', context)

@login_required
def hod_lecturer_list(request):
    return render(request, 'placeholder.html', {'page_title': 'Lecturer List', 'message': 'View all department lecturers'})

@login_required
def hod_workload_analysis(request):
    return render(request, 'placeholder.html', {'page_title': 'Workload Analysis', 'message': 'Analyze lecturer workload distribution'})

@login_required
def hod_pending_results(request):
    """HOD Pending Results for Approval"""
    # Check if user has HOD role
    hod_roles = UserRole.objects.filter(user=request.user, role='HOD')
    if not hod_roles.exists():
        messages.error(request, 'Access denied. HOD role required.')
        return redirect('dashboard')

    # Get the department for this HOD
    hod_role = hod_roles.first()
    department = hod_role.department
    faculty = hod_role.faculty

    if not department:
        messages.error(request, 'No department assigned to your HOD role.')
        return redirect('dashboard')

    # Get current session
    current_session = AcademicSession.objects.filter(is_active=True).first()

    # Get pending results for this department
    pending_results = Result.objects.filter(
        enrollment__student__department=department,
        status='SUBMITTED_TO_HOD'
    ).select_related(
        'enrollment__student__user',
        'enrollment__course',
        'enrollment__session'
    ).order_by('-updated_at')

    # Get results by status for statistics
    all_results = Result.objects.filter(
        enrollment__student__department=department,
        enrollment__session=current_session
    ) if current_session else Result.objects.none()

    # Statistics
    stats = {
        'pending_approval': pending_results.count(),
        'approved_by_hod': all_results.filter(status='APPROVED_BY_HOD').count(),
        'submitted_to_dean': all_results.filter(status='SUBMITTED_TO_DEAN').count(),
        'published': all_results.filter(status='PUBLISHED').count(),
        'total_results': all_results.count(),
    }

    # Group results by course
    results_by_course = {}
    for result in pending_results:
        course_code = result.enrollment.course.code
        if course_code not in results_by_course:
            results_by_course[course_code] = {
                'course': result.enrollment.course,
                'results': []
            }
        results_by_course[course_code]['results'].append(result)

    context = {
        'department': department,
        'faculty': faculty,
        'current_session': current_session,
        'pending_results': pending_results,
        'results_by_course': results_by_course,
        'stats': stats,
    }

    return render(request, 'hod_pending_results.html', context)

@login_required
def hod_review_results(request):
    return render(request, 'placeholder.html', {'page_title': 'Review Results', 'message': 'Review submitted results'})

@login_required
def hod_approve_results(request):
    return render(request, 'placeholder.html', {'page_title': 'Approve Results', 'message': 'Approve results for Faculty Dean'})

@login_required
def hod_reject_results(request):
    return render(request, 'placeholder.html', {'page_title': 'Reject Results', 'message': 'Send results back to Exam Officer'})

@login_required
def hod_submit_to_dean(request):
    return render(request, 'placeholder.html', {'page_title': 'Submit to Dean', 'message': 'Submit approved results to Faculty Dean'})

@login_required
def hod_result_status(request):
    return render(request, 'placeholder.html', {'page_title': 'Result Status', 'message': 'Track result approval status'})

# HOD Course Management API endpoints
@login_required
def hod_get_lecturers(request):
    """Get available lecturers for assignment"""
    # Check if user has HOD role
    hod_roles = UserRole.objects.filter(user=request.user, role='HOD')
    if not hod_roles.exists():
        return JsonResponse({'error': 'Access denied. HOD role required.'}, status=403)

    hod_role = hod_roles.first()
    faculty = hod_role.faculty

    # Get lecturers in the same faculty
    lecturer_roles = UserRole.objects.filter(
        role='LECTURER',
        faculty=faculty
    ).select_related('user', 'department')

    lecturers = []
    for role in lecturer_roles:
        lecturers.append({
            'id': role.user.id,
            'name': role.user.get_full_name(),
            'email': role.user.email,
            'department': role.department.name if role.department else 'Faculty-wide'
        })

    return JsonResponse({'lecturers': lecturers})

@login_required
def hod_assign_course_lecturer(request, course_id):
    """Assign or change lecturer for a course"""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required'}, status=405)

    # Check if user has HOD role
    hod_roles = UserRole.objects.filter(user=request.user, role='HOD')
    if not hod_roles.exists():
        return JsonResponse({'error': 'Access denied. HOD role required.'}, status=403)

    hod_role = hod_roles.first()
    department = hod_role.department

    try:
        course = Course.objects.get(id=course_id, departments=department)
    except Course.DoesNotExist:
        return JsonResponse({'error': 'Course not found'}, status=404)

    lecturer_id = request.POST.get('lecturer_id')
    if not lecturer_id:
        return JsonResponse({'error': 'Lecturer ID required'}, status=400)

    try:
        lecturer_user = User.objects.get(id=lecturer_id)
        # Verify lecturer is in the same faculty
        lecturer_role = UserRole.objects.filter(
            user=lecturer_user,
            role='LECTURER',
            faculty=hod_role.faculty
        ).first()

        if not lecturer_role:
            return JsonResponse({'error': 'Lecturer not found in your faculty'}, status=400)

    except User.DoesNotExist:
        return JsonResponse({'error': 'Lecturer not found'}, status=404)

    # Remove existing assignment if any
    CourseAssignment.objects.filter(course=course).delete()

    # Create new assignment
    assignment = CourseAssignment.objects.create(
        course=course,
        lecturer=lecturer_user,
        assigned_by=request.user
    )

    # Log the action
    AuditLog.objects.create(
        user=request.user,
        action='ASSIGN_LECTURER',
        description=f'Assigned {lecturer_user.get_full_name()} to course {course.code}',
        level='INFO'
    )

    return JsonResponse({
        'success': True,
        'message': f'Lecturer {lecturer_user.get_full_name()} assigned to {course.code}',
        'lecturer_name': lecturer_user.get_full_name(),
        'lecturer_email': lecturer_user.email
    })

@login_required
def hod_edit_course(request, course_id):
    """Edit course details"""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required'}, status=405)

    # Check if user has HOD role
    hod_roles = UserRole.objects.filter(user=request.user, role='HOD')
    if not hod_roles.exists():
        return JsonResponse({'error': 'Access denied. HOD role required.'}, status=403)

    hod_role = hod_roles.first()
    department = hod_role.department

    try:
        course = Course.objects.get(id=course_id, departments=department)
    except Course.DoesNotExist:
        return JsonResponse({'error': 'Course not found'}, status=404)

    # Get form data
    title = request.POST.get('title', '').strip()
    code = request.POST.get('code', '').strip().upper()
    credit_units = request.POST.get('credit_units')

    if not title or not code or not credit_units:
        return JsonResponse({'error': 'Title, code, and credit units are required'}, status=400)

    try:
        credit_units = int(credit_units)
        if credit_units < 1 or credit_units > 6:
            return JsonResponse({'error': 'Credit units must be between 1 and 6'}, status=400)
    except ValueError:
        return JsonResponse({'error': 'Invalid credit units'}, status=400)

    # Check if code is unique (excluding current course)
    if Course.objects.filter(code=code, session=course.session).exclude(id=course.id).exists():
        return JsonResponse({'error': f'Course code {code} already exists in this session'}, status=400)

    # Update course
    course.title = title
    course.code = code
    course.credit_units = credit_units
    course.save()

    # Log the action
    AuditLog.objects.create(
        user=request.user,
        action='UPDATE_COURSE',
        description=f'Updated course {course.code}: {course.title}',
        level='INFO'
    )

    return JsonResponse({
        'success': True,
        'message': f'Course {course.code} updated successfully',
        'course': {
            'id': course.id,
            'title': course.title,
            'code': course.code,
            'credit_units': course.credit_units
        }
    })

@login_required
def hod_delete_course(request, course_id):
    """Delete a course"""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required'}, status=405)

    # Check if user has HOD role
    hod_roles = UserRole.objects.filter(user=request.user, role='HOD')
    if not hod_roles.exists():
        return JsonResponse({'error': 'Access denied. HOD role required.'}, status=403)

    hod_role = hod_roles.first()
    department = hod_role.department

    try:
        course = Course.objects.get(id=course_id, departments=department)
    except Course.DoesNotExist:
        return JsonResponse({'error': 'Course not found'}, status=404)

    # Check if course has enrollments or results
    if CourseEnrollment.objects.filter(course=course).exists():
        return JsonResponse({'error': 'Cannot delete course with existing enrollments'}, status=400)

    if Result.objects.filter(enrollment__course=course).exists():
        return JsonResponse({'error': 'Cannot delete course with existing results'}, status=400)

    course_code = course.code
    course.delete()

    # Log the action
    AuditLog.objects.create(
        user=request.user,
        action='DELETE_COURSE',
        description=f'Deleted course {course_code}',
        level='INFO'
    )

    return JsonResponse({
        'success': True,
        'message': f'Course {course_code} deleted successfully'
    })

# Faculty Dean Student Management Views
@login_required
def faculty_dean_create_student(request):
    """Faculty Dean Create Student"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Faculty Dean role.')
        return redirect('dashboard')

    if request.method == 'POST':
        # Get and sanitize form data
        first_name = sanitize_input(request.POST.get('first_name', '').strip())
        middle_name = sanitize_input(request.POST.get('middle_name', '').strip())
        last_name = sanitize_input(request.POST.get('last_name', '').strip())
        matric_number = sanitize_input(request.POST.get('matric_number', '').strip().upper())
        email = sanitize_input(request.POST.get('email', '').strip().lower())
        department_id = request.POST.get('department_id')
        level_id = request.POST.get('level_id')

        # Auto-generate username and password from matric number
        username = matric_number  # Username is the matric number
        password = matric_number.lower().replace('/', '-')  # Password is lowercase matric with dashes

        # Validation - middle name is optional, username and password are auto-generated
        required_fields = [first_name, last_name, matric_number, email, department_id, level_id]
        if not all(required_fields):
            messages.error(request, 'First name, last name, matric number, email, department, and level are required.')
            return redirect('faculty_dean_create_student')

        # Security validations
        if not validate_name(first_name):
            messages.error(request, 'First name contains invalid characters.')
            return redirect('faculty_dean_create_student')

        if middle_name and not validate_name(middle_name):
            messages.error(request, 'Middle name contains invalid characters.')
            return redirect('faculty_dean_create_student')

        if not validate_name(last_name):
            messages.error(request, 'Last name contains invalid characters.')
            return redirect('faculty_dean_create_student')

        if not validate_email(email):
            messages.error(request, 'Please enter a valid email address.')
            return redirect('faculty_dean_create_student')



        if not validate_matric_number(matric_number):
            messages.error(request, 'Invalid matriculation number format.')
            return redirect('faculty_dean_create_student')

        # Check if matric number already exists
        if Student.objects.filter(matric_number=matric_number).exists():
            messages.error(request, f'Matriculation number {matric_number} already exists.')
            return redirect('faculty_dean_create_student')

        # Check if username already exists
        if User.objects.filter(username=username).exists():
            messages.error(request, f'Username {username} already exists.')
            return redirect('faculty_dean_create_student')

        # Check if email already exists
        if User.objects.filter(email=email).exists():
            messages.error(request, f'Email {email} already exists.')
            return redirect('faculty_dean_create_student')

        try:
            department = Department.objects.get(id=department_id, faculty=faculty)
            level = Level.objects.get(id=level_id)
            current_session = AcademicSession.objects.filter(is_active=True).first()

            if not current_session:
                messages.error(request, 'No active academic session found.')
                return redirect('faculty_dean_create_student')

            # Create user account with proper password hashing
            full_first_name = f"{first_name} {middle_name}".strip() if middle_name else first_name
            user = User.objects.create_user(
                username=username,
                email=email,
                first_name=full_first_name,
                last_name=last_name,
                password=password  # Django automatically hashes this
            )

            # Create student profile
            student = Student.objects.create(
                user=user,
                matric_number=matric_number,
                faculty=faculty,
                department=department,
                current_level=level,
                admission_session=current_session,
                current_session=current_session,
                created_by=request.user
            )

            # Create student role
            UserRole.objects.create(
                user=user,
                role='STUDENT',
                faculty=faculty,
                department=department
            )

            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='CREATE_STUDENT',
                description=f'Created student: {matric_number} - {first_name} {last_name}',
                level='INFO'
            )

            messages.success(request, f'Student {matric_number} - {first_name} {last_name} created successfully!')
            return redirect('faculty_dean_students')

        except Department.DoesNotExist:
            messages.error(request, 'Invalid department selected.')
        except Level.DoesNotExist:
            messages.error(request, 'Invalid level selected.')
        except Exception as e:
            messages.error(request, f'Error creating student: {str(e)}')

        return redirect('faculty_dean_create_student')

    # GET request - show form
    departments = Department.objects.filter(faculty=faculty).order_by('name')
    levels = Level.objects.all().order_by('name')
    current_session = AcademicSession.objects.filter(is_active=True).first()

    context = {
        'faculty': faculty,
        'departments': departments,
        'levels': levels,
        'current_session': current_session,
    }

    return render(request, 'faculty_dean_create_student.html', context)

@login_required
def faculty_dean_bulk_create_students(request):
    """Faculty Dean Bulk Create Students"""
    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        messages.error(request, 'Access denied. Faculty Dean role required.')
        return redirect('dashboard')

    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        messages.error(request, 'No faculty assigned to your Faculty Dean role.')
        return redirect('dashboard')

    if request.method == 'POST':
        current_session = AcademicSession.objects.filter(is_active=True).first()

        if not current_session:
            messages.error(request, 'No active academic session found.')
            return redirect('faculty_dean_bulk_create_students')

        try:

            # Process form-based student data
            created_count = 0
            errors = []

            # Get all student data from form
            student_indices = []
            for key in request.POST.keys():
                if key.startswith('students[') and key.endswith('][first_name]'):
                    # Extract student index from key like 'students[1][first_name]'
                    index = key.split('[')[1].split(']')[0]
                    student_indices.append(index)

            for index in student_indices:
                try:
                    # Get student data
                    first_name = sanitize_input(request.POST.get(f'students[{index}][first_name]', '').strip())
                    middle_name = sanitize_input(request.POST.get(f'students[{index}][middle_name]', '').strip())
                    last_name = sanitize_input(request.POST.get(f'students[{index}][last_name]', '').strip())
                    matric_number = sanitize_input(request.POST.get(f'students[{index}][matric_number]', '').strip().upper())
                    email = sanitize_input(request.POST.get(f'students[{index}][email]', '').strip().lower())
                    department_id = request.POST.get(f'students[{index}][department_id]')
                    level_id = request.POST.get(f'students[{index}][level_id]')

                    # Auto-generate username and password
                    username = matric_number
                    password = matric_number.lower().replace('/', '-')

                    # Validation
                    if not all([first_name, last_name, matric_number, email, department_id, level_id]):
                        errors.append(f'Student {index}: All fields are required')
                        continue

                    # Security validations
                    if not validate_name(first_name):
                        errors.append(f'Student {index}: First name contains invalid characters')
                        continue

                    if middle_name and not validate_name(middle_name):
                        errors.append(f'Student {index}: Middle name contains invalid characters')
                        continue

                    if not validate_name(last_name):
                        errors.append(f'Student {index}: Last name contains invalid characters')
                        continue

                    if not validate_email(email):
                        errors.append(f'Student {index}: Invalid email address')
                        continue

                    if not validate_matric_number(matric_number):
                        errors.append(f'Student {index}: Invalid matriculation number format')
                        continue

                    # Check duplicates
                    if Student.objects.filter(matric_number=matric_number).exists():
                        errors.append(f'Student {index}: Matric number {matric_number} already exists')
                        continue

                    if User.objects.filter(username=username).exists():
                        errors.append(f'Student {index}: Username {username} already exists')
                        continue

                    if User.objects.filter(email=email).exists():
                        errors.append(f'Student {index}: Email {email} already exists')
                        continue

                    # Get department and level for this student
                    try:
                        department = Department.objects.get(id=department_id, faculty=faculty)
                        level = Level.objects.get(id=level_id)
                    except Department.DoesNotExist:
                        errors.append(f'Student {index}: Invalid department selected')
                        continue
                    except Level.DoesNotExist:
                        errors.append(f'Student {index}: Invalid level selected')
                        continue

                    # Create user account
                    full_first_name = f"{first_name} {middle_name}".strip() if middle_name else first_name
                    user = User.objects.create_user(
                        username=username,
                        email=email,
                        first_name=full_first_name,
                        last_name=last_name,
                        password=password
                    )

                    # Create student profile
                    student = Student.objects.create(
                        user=user,
                        matric_number=matric_number,
                        faculty=faculty,
                        department=department,
                        current_level=level,
                        admission_session=current_session,
                        current_session=current_session,
                        created_by=request.user
                    )

                    # Create student role
                    UserRole.objects.create(
                        user=user,
                        role='STUDENT',
                        faculty=faculty,
                        department=department
                    )

                    created_count += 1

                except Exception as e:
                    errors.append(f'Student {index}: Error creating student - {str(e)}')

            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='BULK_CREATE_STUDENTS',
                description=f'Bulk created {created_count} students in {faculty.name}',
                level='INFO'
            )

            if created_count > 0:
                messages.success(request, f'Successfully created {created_count} students!')

            if errors:
                error_msg = f'{len(errors)} errors occurred:\n' + '\n'.join(errors[:5])
                if len(errors) > 5:
                    error_msg += f'\n... and {len(errors) - 5} more errors'
                messages.error(request, error_msg)

            if created_count > 0:
                return redirect('faculty_dean_students')

        except Exception as e:
            messages.error(request, f'Error processing bulk creation: {str(e)}')

        return redirect('faculty_dean_bulk_create_students')

    # GET request - show form
    departments = Department.objects.filter(faculty=faculty).order_by('name')
    levels = Level.objects.all().order_by('name')
    current_session = AcademicSession.objects.filter(is_active=True).first()

    context = {
        'faculty': faculty,
        'departments': departments,
        'levels': levels,
        'current_session': current_session,
    }

    return render(request, 'faculty_dean_bulk_create_students.html', context)



@login_required
def faculty_dean_edit_student(request, student_id):
    """Edit student details"""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required'}, status=405)

    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        return JsonResponse({'error': 'Access denied. Faculty Dean role required.'}, status=403)

    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    try:
        student = Student.objects.get(id=student_id, faculty=faculty)
    except Student.DoesNotExist:
        return JsonResponse({'error': 'Student not found'}, status=404)

    # Get form data
    first_name = request.POST.get('first_name', '').strip()
    middle_name = request.POST.get('middle_name', '').strip()
    last_name = request.POST.get('last_name', '').strip()
    email = request.POST.get('email', '').strip().lower()
    department_id = request.POST.get('department_id')
    level_id = request.POST.get('level_id')

    if not all([first_name, last_name, email, department_id, level_id]):
        return JsonResponse({'error': 'All fields except middle name are required'}, status=400)

    # Email validation
    import re
    email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_regex, email):
        return JsonResponse({'error': 'Please enter a valid email address'}, status=400)

    try:
        department = Department.objects.get(id=department_id, faculty=faculty)
        level = Level.objects.get(id=level_id)

        # Check if email is unique (excluding current user)
        if User.objects.filter(email=email).exclude(id=student.user.id).exists():
            return JsonResponse({'error': f'Email {email} already exists'}, status=400)

        # Update user details
        full_first_name = f"{first_name} {middle_name}".strip() if middle_name else first_name
        student.user.first_name = full_first_name
        student.user.last_name = last_name
        student.user.email = email
        student.user.save()

        # Update student details
        student.department = department
        student.current_level = level
        student.save()

        # Update user role department
        user_role = UserRole.objects.filter(user=student.user, role='STUDENT').first()
        if user_role:
            user_role.department = department
            user_role.save()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE_STUDENT',
            description=f'Updated student: {student.matric_number} - {first_name} {last_name}',
            level='INFO'
        )

        return JsonResponse({
            'success': True,
            'message': f'Student {student.matric_number} updated successfully',
            'student': {
                'id': student.id,
                'name': f'{first_name} {last_name}',
                'email': email,
                'department': department.name,
                'level': level.name
            }
        })

    except Department.DoesNotExist:
        return JsonResponse({'error': 'Invalid department selected'}, status=400)
    except Level.DoesNotExist:
        return JsonResponse({'error': 'Invalid level selected'}, status=400)
    except Exception as e:
        return JsonResponse({'error': f'Error updating student: {str(e)}'}, status=500)

@login_required
def faculty_dean_delete_student(request, student_id):
    """Delete a student"""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required'}, status=405)

    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        return JsonResponse({'error': 'Access denied. Faculty Dean role required.'}, status=403)

    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    try:
        student = Student.objects.get(id=student_id, faculty=faculty)
    except Student.DoesNotExist:
        return JsonResponse({'error': 'Student not found'}, status=404)

    # Check if student has enrollments or results
    if CourseEnrollment.objects.filter(student=student).exists():
        return JsonResponse({'error': 'Cannot delete student with existing course enrollments'}, status=400)

    if Result.objects.filter(enrollment__student=student).exists():
        return JsonResponse({'error': 'Cannot delete student with existing results'}, status=400)

    matric_number = student.matric_number
    student_name = student.get_full_name()

    # Delete user account (this will cascade delete student profile)
    student.user.delete()

    # Log the action
    AuditLog.objects.create(
        user=request.user,
        action='DELETE_STUDENT',
        description=f'Deleted student: {matric_number} - {student_name}',
        level='INFO'
    )

    return JsonResponse({
        'success': True,
        'message': f'Student {matric_number} deleted successfully'
    })

@login_required
def faculty_dean_student_results(request, student_id):
    """View student results"""
    if request.method != 'GET':
        return JsonResponse({'error': 'GET method required'}, status=405)

    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        return JsonResponse({'error': 'Access denied. Faculty Dean role required.'}, status=403)

    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    try:
        student = Student.objects.get(id=student_id, faculty=faculty)
    except Student.DoesNotExist:
        return JsonResponse({'error': 'Student not found'}, status=404)

    # Get student results
    results = []
    try:
        # Get all enrollments for this student
        enrollments = CourseEnrollment.objects.filter(student=student).select_related('course')

        for enrollment in enrollments:
            # Get results for this enrollment
            student_results = Result.objects.filter(enrollment=enrollment).first()

            if student_results:
                results.append({
                    'course_code': enrollment.course.code,
                    'course_title': enrollment.course.title,
                    'ca_score': student_results.ca_score,
                    'exam_score': student_results.exam_score,
                    'total_score': student_results.total_score,
                    'grade': student_results.grade,
                    'session': enrollment.session.name if enrollment.session else 'N/A'
                })
    except Exception as e:
        return JsonResponse({'error': f'Error fetching results: {str(e)}'}, status=500)

    return JsonResponse({
        'success': True,
        'results': results,
        'student_name': student.get_full_name(),
        'matric_number': student.matric_number
    })

@login_required
def faculty_dean_reset_password(request, student_id):
    """Reset student password"""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required'}, status=405)

    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        return JsonResponse({'error': 'Access denied. Faculty Dean role required.'}, status=403)

    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    try:
        student = Student.objects.get(id=student_id, faculty=faculty)
    except Student.DoesNotExist:
        return JsonResponse({'error': 'Student not found'}, status=404)

    try:
        # Generate new password from matric number (lowercase with dashes)
        new_password = student.matric_number.lower().replace('/', '-')

        # Update user password
        student.user.set_password(new_password)
        student.user.save()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='RESET_STUDENT_PASSWORD',
            description=f'Reset password for student: {student.matric_number} - {student.get_full_name()}',
            level='INFO'
        )

        return JsonResponse({
            'success': True,
            'message': f'Password reset successfully for {student.matric_number}',
            'new_password': new_password
        })

    except Exception as e:
        return JsonResponse({'error': f'Error resetting password: {str(e)}'}, status=500)

@login_required
def faculty_dean_progress_students(request):
    """Progress students to next level automatically"""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required'}, status=405)

    # Check if user has Faculty Dean role
    faculty_dean_roles = UserRole.objects.filter(user=request.user, role='FACULTY_DEAN')
    if not faculty_dean_roles.exists():
        return JsonResponse({'error': 'Access denied. Faculty Dean role required.'}, status=403)

    faculty_role = faculty_dean_roles.first()
    faculty = faculty_role.faculty

    if not faculty:
        return JsonResponse({'error': 'No faculty assigned to your role.'}, status=400)

    # Get the new academic session
    new_session_id = request.POST.get('new_session_id')
    if not new_session_id:
        return JsonResponse({'error': 'New academic session is required'}, status=400)

    try:
        new_session = AcademicSession.objects.get(id=new_session_id)
    except AcademicSession.DoesNotExist:
        return JsonResponse({'error': 'Invalid academic session'}, status=400)

    # Get all students in the faculty who can progress
    students = Student.objects.filter(
        faculty=faculty,
        is_graduated=False
    ).select_related('current_level', 'current_session')

    progressed_count = 0
    graduated_count = 0
    errors = []

    for student in students:
        try:
            if student.can_progress_to_next_level():
                # Check if this would be graduation
                current_level_value = int(student.current_level.name.split()[0])
                next_level_value = current_level_value + 100

                if student.progress_to_next_level(new_session, request.user):
                    if next_level_value >= 400:  # Graduation
                        graduated_count += 1
                    else:
                        progressed_count += 1
            else:
                # Student cannot progress (either graduated or at final level)
                if not student.is_graduated:
                    # Update current session even if not progressing level
                    student.current_session = new_session
                    student.save()

        except Exception as e:
            errors.append(f'Error progressing {student.matric_number}: {str(e)}')

    # Log the action
    AuditLog.objects.create(
        user=request.user,
        action='PROGRESS_STUDENTS',
        description=f'Progressed {progressed_count} students, graduated {graduated_count} students to session {new_session.name}',
        level='INFO'
    )

    result = {
        'success': True,
        'progressed_count': progressed_count,
        'graduated_count': graduated_count,
        'total_processed': progressed_count + graduated_count,
        'errors_count': len(errors),
        'message': f'Successfully processed {progressed_count + graduated_count} students. {progressed_count} progressed to next level, {graduated_count} graduated.'
    }

    if errors:
        result['errors'] = errors[:10]  # Return first 10 errors
        result['message'] += f' {len(errors)} errors occurred.'

    return JsonResponse(result)

# Utility function to automatically progress students when session changes
def auto_progress_students_on_session_change(old_session, new_session):
    """
    Automatically progress students when a new session is activated.
    This can be called from session management views.
    """
    try:
        # Get all non-graduated students
        students = Student.objects.filter(
            is_graduated=False,
            current_session=old_session
        ).select_related('current_level', 'faculty')

        progressed_count = 0
        graduated_count = 0

        for student in students:
            try:
                if student.can_progress_to_next_level():
                    current_level_value = int(student.current_level.name.split()[0])
                    next_level_value = current_level_value + 100

                    if student.progress_to_next_level(new_session):
                        if next_level_value >= 400:  # Graduation
                            graduated_count += 1
                        else:
                            progressed_count += 1
                else:
                    # Update current session even if not progressing level
                    student.current_session = new_session
                    student.save()

            except Exception as e:
                # Log individual errors but continue processing
                AuditLog.objects.create(
                    user=None,  # System action
                    action='AUTO_PROGRESS_ERROR',
                    description=f'Error auto-progressing {student.matric_number}: {str(e)}',
                    level='ERROR'
                )

        # Log the overall action
        AuditLog.objects.create(
            user=None,  # System action
            action='AUTO_PROGRESS_STUDENTS',
            description=f'Auto-progressed {progressed_count} students, graduated {graduated_count} students from {old_session.name} to {new_session.name}',
            level='INFO'
        )

        return {
            'success': True,
            'progressed_count': progressed_count,
            'graduated_count': graduated_count
        }

    except Exception as e:
        AuditLog.objects.create(
            user=None,
            action='AUTO_PROGRESS_ERROR',
            description=f'Error in auto-progression: {str(e)}',
            level='ERROR'
        )
        return {
            'success': False,
            'error': str(e)
        }

@login_required
def hod_department_summary(request):
    return render(request, 'placeholder.html', {'page_title': 'Department Summary', 'message': 'Department performance summary'})

@login_required
def hod_export_results(request):
    return render(request, 'placeholder.html', {'page_title': 'Export Results', 'message': 'Export department results'})

@login_required
def hod_review_single_result(request, result_id):
    """HOD Review Single Result"""
    # Check if user has HOD role
    hod_roles = UserRole.objects.filter(user=request.user, role='HOD')
    if not hod_roles.exists():
        messages.error(request, 'Access denied. HOD role required.')
        return redirect('dashboard')

    # Get the department for this HOD
    hod_role = hod_roles.first()
    department = hod_role.department

    if not department:
        messages.error(request, 'No department assigned to your HOD role.')
        return redirect('dashboard')

    try:
        # Get the result
        result = Result.objects.select_related(
            'enrollment__student__user',
            'enrollment__course',
            'enrollment__session'
        ).get(
            id=result_id,
            enrollment__student__department=department
        )
    except Result.DoesNotExist:
        messages.error(request, 'Result not found or access denied.')
        return redirect('hod_pending_results')

    # Handle POST request for approval/rejection
    if request.method == 'POST':
        action = request.POST.get('action')
        comments = request.POST.get('comments', '').strip()

        if action == 'approve':
            result.status = 'APPROVED_BY_HOD'
            result.hod_comments = comments
            result.approved_by_hod = request.user
            result.hod_approval_date = timezone.now()
            result.save()

            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='APPROVE_RESULT',
                description=f'Approved result for {result.enrollment.student.matric_number} in {result.enrollment.course.code}',
                level='INFO'
            )

            messages.success(request, f'Result approved for {result.enrollment.student.matric_number}!')
            return redirect('hod_pending_results')

        elif action == 'reject':
            result.status = 'REJECTED_BY_HOD'
            result.hod_comments = comments
            result.save()

            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='REJECT_RESULT',
                description=f'Rejected result for {result.enrollment.student.matric_number} in {result.enrollment.course.code}',
                level='WARNING'
            )

            messages.success(request, f'Result rejected for {result.enrollment.student.matric_number}!')
            return redirect('hod_pending_results')

    context = {
        'result': result,
        'department': department,
    }

    return render(request, 'hod_review_single_result.html', context)

@login_required
def hod_approve_single_result(request, result_id):
    """HOD Approve Single Result (AJAX endpoint)"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})

    # Check if user has HOD role
    hod_roles = UserRole.objects.filter(user=request.user, role='HOD')
    if not hod_roles.exists():
        return JsonResponse({'success': False, 'message': 'Access denied. HOD role required.'})

    # Get the department for this HOD
    hod_role = hod_roles.first()
    department = hod_role.department

    if not department:
        return JsonResponse({'success': False, 'message': 'No department assigned to your HOD role.'})

    try:
        # Get the result
        result = Result.objects.select_related(
            'enrollment__student__user',
            'enrollment__course'
        ).get(
            id=result_id,
            enrollment__student__department=department,
            status='SUBMITTED_TO_HOD'
        )

        # Approve the result
        result.status = 'APPROVED_BY_HOD'
        result.approved_by_hod = request.user
        result.hod_approval_date = timezone.now()
        result.save()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='APPROVE_RESULT',
            description=f'Approved result for {result.enrollment.student.matric_number} in {result.enrollment.course.code}',
            level='INFO'
        )

        return JsonResponse({
            'success': True,
            'message': f'Result approved for {result.enrollment.student.matric_number}!'
        })

    except Result.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Result not found or already processed.'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error approving result: {str(e)}'})
