from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from .models import (
    AcademicSession, Faculty, Department, Level, Course, CourseAssignment,
    Student, GradingScale, GradeRange, CarryOverCriteria, CourseEnrollment,
    Result, ResultApproval, CarryOverList, UserRole, AlternativeLogin,
    Notification, ResultPublication, SystemConfiguration, AuditLog
)


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model with role info"""
    roles = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'roles']

    def get_roles(self, obj):
        """Gets all roles for the user"""
        user_role_list = UserRole.objects.filter(user=obj)
        role_data_list = []
        for role in user_role_list:
            role_data = {
                'id': role.id,
                'role': role.role,
                'faculty': role.faculty.name if role.faculty else None,
                'department': role.department.name if role.department else None,
                'is_primary': role.is_primary
            }
            role_data_list.append(role_data)
        return role_data_list


class LoginSerializer(serializers.Serializer):
    """Serializer for login"""
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        # Get username and password from data
        username = data.get('username')
        password = data.get('password')

        # Check if both username and password are provided
        if username and password:
            # Try to authenticate user
            user = authenticate(username=username, password=password)
            if user:
                # Check if user account is active
                if user.is_active:
                    data['user'] = user
                else:
                    raise serializers.ValidationError('User account is disabled.')
            else:
                raise serializers.ValidationError('Invalid credentials.')
        else:
            raise serializers.ValidationError('Must include username and password.')

        return data


class AlternativeLoginSerializer(serializers.Serializer):
    """Serializer for alternative login"""
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        try:
            alt_login = AlternativeLogin.objects.get(
                username=username,
                is_active=True
            )
            # Simple password check (in production, use proper hashing)
            if alt_login.password == password:
                data['user'] = alt_login.user
                data['role'] = alt_login.role
                data['faculty'] = alt_login.faculty
                data['department'] = alt_login.department
            else:
                raise serializers.ValidationError('Invalid credentials.')
        except AlternativeLogin.DoesNotExist:
            raise serializers.ValidationError('Invalid credentials.')

        return data


class AcademicSessionSerializer(serializers.ModelSerializer):
    """Serializer for Academic Sessions"""
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)

    class Meta:
        model = AcademicSession
        fields = ['id', 'name', 'start_date', 'end_date', 'is_active', 'is_locked',
                 'created_by', 'created_by_name', 'created_at']
        read_only_fields = ['created_by', 'created_at']


class FacultySerializer(serializers.ModelSerializer):
    """Serializer for Faculties"""
    dean_name = serializers.CharField(source='dean.get_full_name', read_only=True)
    departments_count = serializers.SerializerMethodField()

    class Meta:
        model = Faculty
        fields = ['id', 'name', 'code', 'dean', 'dean_name', 'departments_count', 'created_at']

    def get_departments_count(self, obj):
        return obj.department_set.count()


class DepartmentSerializer(serializers.ModelSerializer):
    """Serializer for Departments"""
    faculty_name = serializers.CharField(source='faculty.name', read_only=True)
    hod_name = serializers.CharField(source='hod.get_full_name', read_only=True)
    courses_count = serializers.SerializerMethodField()

    class Meta:
        model = Department
        fields = ['id', 'name', 'code', 'faculty', 'faculty_name', 'hod',
                 'hod_name', 'courses_count', 'created_at']

    def get_courses_count(self, obj):
        return obj.course_set.count()


class LevelSerializer(serializers.ModelSerializer):
    """Serializer for Academic Levels"""
    class Meta:
        model = Level
        fields = ['id', 'name', 'numeric_value']


class CourseSerializer(serializers.ModelSerializer):
    """Serializer for Courses"""
    level_name = serializers.CharField(source='level.name', read_only=True)
    session_name = serializers.CharField(source='session.name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    departments_names = serializers.SerializerMethodField()
    assigned_lecturers = serializers.SerializerMethodField()

    class Meta:
        model = Course
        fields = ['id', 'title', 'code', 'credit_units', 'level', 'level_name',
                 'departments', 'departments_names', 'session', 'session_name',
                 'created_by', 'created_by_name', 'assigned_lecturers', 'created_at']
        read_only_fields = ['created_by', 'created_at']

    def get_departments_names(self, obj):
        return [dept.name for dept in obj.departments.all()]

    def get_assigned_lecturers(self, obj):
        assignments = CourseAssignment.objects.filter(course=obj)
        return [{
            'id': assignment.lecturer.id,
            'name': assignment.lecturer.get_full_name(),
            'assigned_by': assignment.assigned_by.get_full_name(),
            'assigned_at': assignment.assigned_at
        } for assignment in assignments]


class StudentSerializer(serializers.ModelSerializer):
    """Serializer for Students"""
    user_details = UserSerializer(source='user', read_only=True)
    faculty_name = serializers.CharField(source='faculty.name', read_only=True)
    department_name = serializers.CharField(source='department.name', read_only=True)
    level_name = serializers.CharField(source='current_level.name', read_only=True)
    admission_session_name = serializers.CharField(source='admission_session.name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)

    class Meta:
        model = Student
        fields = ['id', 'user', 'user_details', 'matric_number', 'faculty', 'faculty_name',
                 'department', 'department_name', 'current_level', 'level_name',
                 'admission_session', 'admission_session_name', 'created_by',
                 'created_by_name', 'created_at']
        read_only_fields = ['created_by', 'created_at']


class CourseEnrollmentSerializer(serializers.ModelSerializer):
    """Serializer for Course Enrollments"""
    student_name = serializers.CharField(source='student.matric_number', read_only=True)
    course_name = serializers.CharField(source='course.title', read_only=True)
    course_code = serializers.CharField(source='course.code', read_only=True)
    session_name = serializers.CharField(source='session.name', read_only=True)
    enrolled_by_name = serializers.CharField(source='enrolled_by.get_full_name', read_only=True)

    class Meta:
        model = CourseEnrollment
        fields = ['id', 'student', 'student_name', 'course', 'course_name', 'course_code',
                 'session', 'session_name', 'enrolled_by', 'enrolled_by_name', 'enrolled_at']
        read_only_fields = ['enrolled_by', 'enrolled_at']


class ResultSerializer(serializers.ModelSerializer):
    """Serializer for Results"""
    student_name = serializers.CharField(source='enrollment.student.matric_number', read_only=True)
    course_name = serializers.CharField(source='enrollment.course.title', read_only=True)
    course_code = serializers.CharField(source='enrollment.course.code', read_only=True)
    session_name = serializers.CharField(source='enrollment.session.name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)

    class Meta:
        model = Result
        fields = ['id', 'enrollment', 'student_name', 'course_name', 'course_code',
                 'session_name', 'ca_score', 'exam_score', 'total_score',
                 'grade', 'grade_point', 'is_carry_over', 'status', 'created_by', 'created_by_name',
                 'last_modified_by', 'created_at', 'updated_at']
        read_only_fields = ['created_by', 'last_modified_by', 'created_at', 'updated_at']


class ResultApprovalSerializer(serializers.ModelSerializer):
    """Serializer for Result Approvals"""
    result_details = serializers.SerializerMethodField()
    user_name = serializers.CharField(source='user.get_full_name', read_only=True)
    sent_to_name = serializers.CharField(source='sent_to.get_full_name', read_only=True)

    class Meta:
        model = ResultApproval
        fields = ['id', 'result', 'result_details', 'action', 'role', 'user', 'user_name',
                 'comments', 'sent_to', 'sent_to_name', 'timestamp']
        read_only_fields = ['user', 'role', 'timestamp']

    def get_result_details(self, obj):
        return {
            'student': obj.result.enrollment.student.matric_number,
            'course': f"{obj.result.enrollment.course.code} - {obj.result.enrollment.course.title}",
            'total_score': obj.result.total_score,
            'grade': obj.result.grade,
            'status': obj.result.status
        }
