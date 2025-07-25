from django.db import models
from django.contrib.auth.models import User

# Create your models here.

# Academic Session Management
class AcademicSession(models.Model):
    name = models.CharField(max_length=20)  # e.g., "2023/2024"
    start_date = models.DateField()
    end_date = models.DateField()
    is_active = models.BooleanField(default=False)  # Only one can be active
    is_locked = models.BooleanField(default=False)  # DAAA can lock/unlock
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_sessions')
    created_at = models.DateTimeField(auto_now_add=True)

# University Structure
class Faculty(models.Model):
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=10, unique=True)
    description = models.TextField(blank=True)
    dean = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='dean_of_faculties')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class Department(models.Model):
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=10)
    faculty = models.ForeignKey(Faculty, on_delete=models.CASCADE)
    hod = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='hod_of_departments')
    created_at = models.DateTimeField(auto_now_add=True)

class Level(models.Model):
    name = models.CharField(max_length=10)  # 100L, 200L, etc.
    numeric_value = models.IntegerField()   # 100, 200, etc.

    def __str__(self):
        return self.name

class Semester(models.Model):
    SEMESTER_CHOICES = [
        ('FIRST', 'First Semester'),
        ('SECOND', 'Second Semester'),
    ]

    session = models.ForeignKey(AcademicSession, on_delete=models.CASCADE, related_name='semesters')
    semester = models.CharField(max_length=10, choices=SEMESTER_CHOICES)
    start_date = models.DateField()
    end_date = models.DateField()
    is_active = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_semesters')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['session', 'semester']

    def __str__(self):
        return f"{self.session.name} - {self.get_semester_display()}"

class Course(models.Model):
    title = models.CharField(max_length=200)
    code = models.CharField(max_length=20)  # CSC101, MTH201, etc.
    credit_units = models.IntegerField()
    level = models.ForeignKey(Level, on_delete=models.CASCADE)
    departments = models.ManyToManyField(Department)  # Can belong to multiple depts
    session = models.ForeignKey(AcademicSession, on_delete=models.CASCADE)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_courses')  # HOD who created it
    created_at = models.DateTimeField(auto_now_add=True)

class CourseAssignment(models.Model):
    course = models.ForeignKey(Course, on_delete=models.CASCADE)
    lecturer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='lecturer_assignments')
    assigned_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='assigned_courses')  # Faculty Dean
    assigned_at = models.DateTimeField(auto_now_add=True)

class Student(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='student_profile', null=True, blank=True)
    matric_number = models.CharField(max_length=20, unique=True)
    faculty = models.ForeignKey(Faculty, on_delete=models.CASCADE)
    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    current_level = models.ForeignKey(Level, on_delete=models.CASCADE)
    admission_session = models.ForeignKey(AcademicSession, on_delete=models.CASCADE)
    current_session = models.ForeignKey(AcademicSession, on_delete=models.CASCADE, related_name='current_students', null=True, blank=True)  # Track current academic session
    is_graduated = models.BooleanField(default=False)
    graduation_session = models.ForeignKey(AcademicSession, on_delete=models.SET_NULL, null=True, blank=True, related_name='graduated_students')
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_students')  # Admission Officer or Dean
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.matric_number} - {self.user.get_full_name() if self.user else 'No User'}"

    def get_full_name(self):
        return self.user.get_full_name() if self.user else 'No User'

    @property
    def email(self):
        return self.user.email if self.user else 'No Email'

    @property
    def level(self):
        return self.current_level.name if self.current_level else 'No Level'

    @property
    def session(self):
        return self.current_session or self.admission_session

    @property
    def is_active(self):
        return self.user.is_active if self.user else False

    def can_progress_to_next_level(self):
        """Check if student can progress to next level"""
        if self.is_graduated:
            return False

        # Get next level
        current_level_value = int(self.current_level.name.split()[0])  # Extract number from "100 Level"
        next_level_value = current_level_value + 100

        # Check if next level exists and not beyond graduation
        if next_level_value > 400:  # Assuming 400 Level is final
            return False

        try:
            Level.objects.get(name=f"{next_level_value} Level")
            return True
        except Level.DoesNotExist:
            return False

    def progress_to_next_level(self, new_session, processed_by=None):
        """Progress student to next level"""
        if not self.can_progress_to_next_level():
            return False

        current_level_value = int(self.current_level.name.split()[0])
        next_level_value = current_level_value + 100

        try:
            next_level = Level.objects.get(name=f"{next_level_value} Level")

            # Create level progression record
            LevelProgression.objects.create(
                student=self,
                from_level=self.current_level,
                to_level=next_level,
                from_session=self.current_session or self.admission_session,
                to_session=new_session,
                progression_type='AUTOMATIC',
                processed_by=processed_by
            )

            # Update student level and session
            self.current_level = next_level
            self.current_session = new_session

            # Check if this is graduation (400 Level)
            if next_level_value >= 400:
                self.is_graduated = True
                self.graduation_session = new_session

            self.save()
            return True

        except Level.DoesNotExist:
            return False

# Level Progression Tracking
class LevelProgression(models.Model):
    PROGRESSION_TYPES = [
        ('AUTOMATIC', 'Automatic Progression'),
        ('MANUAL', 'Manual Progression'),
        ('REPEAT', 'Repeat Level'),
        ('TRANSFER', 'Transfer Student'),
    ]

    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='level_progressions')
    from_level = models.ForeignKey(Level, on_delete=models.CASCADE, related_name='progressions_from')
    to_level = models.ForeignKey(Level, on_delete=models.CASCADE, related_name='progressions_to')
    from_session = models.ForeignKey(AcademicSession, on_delete=models.CASCADE, related_name='progressions_from')
    to_session = models.ForeignKey(AcademicSession, on_delete=models.CASCADE, related_name='progressions_to')
    progression_type = models.CharField(max_length=20, choices=PROGRESSION_TYPES, default='AUTOMATIC')
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    processed_at = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ['-processed_at']
        unique_together = ['student', 'from_session', 'to_session']

    def __str__(self):
        return f"{self.student.matric_number}: {self.from_level.name} → {self.to_level.name} ({self.from_session.name} → {self.to_session.name})"

# Faculty-specific grading system (set by Faculty Dean)
class GradingScale(models.Model):
    faculty = models.OneToOneField(Faculty, on_delete=models.CASCADE)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_grading_scales')  # Faculty Dean
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

class GradeRange(models.Model):
    grading_scale = models.ForeignKey(GradingScale, on_delete=models.CASCADE, related_name='ranges')
    grade = models.CharField(max_length=2)  # A, B, C, D, F
    min_score = models.DecimalField(max_digits=5, decimal_places=2)  # 70.00
    max_score = models.DecimalField(max_digits=5, decimal_places=2)  # 100.00
    grade_point = models.DecimalField(max_digits=3, decimal_places=2)  # 4.00, 3.00, etc.
    
    class Meta:
        unique_together = ['grading_scale', 'grade']

# Carry-over criteria (set by Faculty Dean)
class CarryOverCriteria(models.Model):
    faculty = models.OneToOneField(Faculty, on_delete=models.CASCADE)
    minimum_grade = models.CharField(max_length=2)  # e.g., "C" - below this is carry-over
    minimum_score = models.DecimalField(max_digits=5, decimal_places=2)  # e.g., 40.00
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_carryover_criteria')  # Faculty Dean
    updated_at = models.DateTimeField(auto_now=True)

# Student enrollment in courses (by Lecturer)
class CourseEnrollment(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    course = models.ForeignKey(Course, on_delete=models.CASCADE)
    session = models.ForeignKey(AcademicSession, on_delete=models.CASCADE)
    enrolled_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='enrolled_students')  # Lecturer
    enrolled_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)  # Auto-unenroll at session end
    
    class Meta:
        unique_together = ['student', 'course', 'session']

# Main results table
class Result(models.Model):
    STATUS_CHOICES = [
        ('DRAFT', 'Draft'),
        ('SUBMITTED_TO_EXAM_OFFICER', 'Submitted to Exam Officer'),
        ('APPROVED_BY_EXAM_OFFICER', 'Approved by Exam Officer'),
        ('SUBMITTED_TO_HOD', 'Submitted to HOD'),
        ('APPROVED_BY_HOD', 'Approved by HOD'),
        ('SUBMITTED_TO_DEAN', 'Submitted to Faculty Dean'),
        ('APPROVED_BY_DEAN', 'Approved by Faculty Dean'),
        ('SUBMITTED_TO_DAAA', 'Submitted to DAAA'),
        ('APPROVED_BY_DAAA', 'Approved by DAAA'),
        ('SUBMITTED_TO_SENATE', 'Submitted to Senate'),
        ('PUBLISHED', 'Published'),
        ('REJECTED', 'Rejected'),
    ]
    
    enrollment = models.OneToOneField(CourseEnrollment, on_delete=models.CASCADE)
    ca_score = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    exam_score = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    total_score = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    grade = models.CharField(max_length=2, null=True, blank=True)
    grade_point = models.DecimalField(max_digits=3, decimal_places=2, null=True, blank=True)
    is_carry_over = models.BooleanField(default=False)
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='DRAFT')

    # Tracking who handled the result
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='results_created')
    last_modified_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='results_modified')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def save(self, *args, **kwargs):
        # Auto-calculate total score and grade
        if self.ca_score is not None and self.exam_score is not None:
            self.total_score = self.ca_score + self.exam_score

            # Auto-calculate grade based on faculty's grading scale
            faculty = self.enrollment.course.departments.first().faculty
            try:
                grading_scale = GradingScale.objects.get(faculty=faculty)
                grade_ranges = grading_scale.ranges.filter(
                    min_score__lte=self.total_score,
                    max_score__gte=self.total_score
                ).first()

                if grade_ranges:
                    self.grade = grade_ranges.grade
                    self.grade_point = grade_ranges.grade_point
                else:
                    # Default to F if no range matches
                    self.grade = 'F'
                    self.grade_point = 0.00

            except GradingScale.DoesNotExist:
                # Default grading if no scale is set
                if self.total_score >= 70:
                    self.grade = 'A'
                    self.grade_point = 4.00
                elif self.total_score >= 60:
                    self.grade = 'B'
                    self.grade_point = 3.00
                elif self.total_score >= 50:
                    self.grade = 'C'
                    self.grade_point = 2.00
                elif self.total_score >= 40:
                    self.grade = 'D'
                    self.grade_point = 1.00
                else:
                    self.grade = 'F'
                    self.grade_point = 0.00

            # Auto-detect carry-over based on faculty criteria
            try:
                carryover_criteria = CarryOverCriteria.objects.get(faculty=faculty)
                if (self.total_score < carryover_criteria.minimum_score or
                    self.grade < carryover_criteria.minimum_grade):
                    self.is_carry_over = True
                else:
                    self.is_carry_over = False
            except CarryOverCriteria.DoesNotExist:
                # Default: F grade is carry-over
                self.is_carry_over = (self.grade == 'F')

        super().save(*args, **kwargs)

        # Create carry-over record if needed
        if self.is_carry_over and self.status == 'PUBLISHED':
            CarryOverList.objects.get_or_create(
                session=self.enrollment.session,
                faculty=self.enrollment.course.departments.first().faculty,
                department=self.enrollment.course.departments.first(),
                result=self,
                defaults={}
            )

# Track result approval workflow
class ResultApproval(models.Model):
    ACTION_CHOICES = [
        ('SUBMITTED', 'Submitted'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
        ('MODIFIED', 'Modified'),
    ]
    
    ROLE_CHOICES = [
        ('LECTURER', 'Lecturer'),
        ('EXAM_OFFICER', 'Exam Officer'),
        ('HOD', 'Head of Department'),
        ('FACULTY_DEAN', 'Faculty Dean'),
        ('DAAA', 'DAAA'),
        ('SENATE', 'Senate'),
    ]
    
    result = models.ForeignKey(Result, on_delete=models.CASCADE, related_name='approvals')
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='result_approvals')
    comments = models.TextField(blank=True)  # Rejection notes (private between rejector and recipient)
    timestamp = models.DateTimeField(auto_now_add=True)

    # For tracking who it was sent to (when rejected)
    sent_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='received_approvals')

# Carry-over tracking (for Exam Officer)
class CarryOverList(models.Model):
    session = models.ForeignKey(AcademicSession, on_delete=models.CASCADE)
    faculty = models.ForeignKey(Faculty, on_delete=models.CASCADE)
    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    result = models.ForeignKey(Result, on_delete=models.CASCADE)
    added_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['session', 'result']

# User roles in the system
class UserRole(models.Model):
    ROLE_CHOICES = [
        ('STUDENT', 'Student'),
        ('LECTURER', 'Lecturer'),
        ('ADMISSION_OFFICER', 'Admission Officer'),
        ('EXAM_OFFICER', 'Exam Officer'),
        ('HOD', 'Head of Department'),
        ('FACULTY_DEAN', 'Faculty Dean'),
        ('DAAA', 'DAAA'),
        ('SENATE', 'Senate'),
        ('SUPER_ADMIN', 'Super Admin'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='rms_roles')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    faculty = models.ForeignKey(Faculty, on_delete=models.CASCADE, null=True, blank=True)
    department = models.ForeignKey(Department, on_delete=models.CASCADE, null=True, blank=True)
    is_primary = models.BooleanField(default=True)  # Primary role vs additional role
    is_temporary = models.BooleanField(default=False)  # Temporary delegated role
    delegation = models.ForeignKey('PermissionDelegation', on_delete=models.CASCADE, null=True, blank=True)  # Link to delegation
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='roles_assigned')
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user', 'role', 'faculty', 'department']

# Alternative login credentials (created by Super Admin)
class AlternativeLogin(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='alternative_logins')
    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=128)  # Will be hashed
    role = models.CharField(max_length=20, choices=UserRole.ROLE_CHOICES)
    faculty = models.ForeignKey(Faculty, on_delete=models.CASCADE, null=True, blank=True)
    department = models.ForeignKey(Department, on_delete=models.CASCADE, null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_alternative_logins')  # Super Admin
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

# In-app notifications
class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('RESULT_SUBMITTED', 'Result Submitted'),
        ('RESULT_APPROVED', 'Result Approved'),
        ('RESULT_REJECTED', 'Result Rejected'),
        ('RESULT_PUBLISHED', 'Result Published'),
        ('CARRY_OVER_DETECTED', 'Carry Over Detected'),
        ('SESSION_CREATED', 'Session Created'),
        ('SESSION_LOCKED', 'Session Locked'),
        ('ROLE_ASSIGNED', 'Role Assigned'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=30, choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=200)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Optional links to related objects
    result = models.ForeignKey(Result, on_delete=models.CASCADE, null=True, blank=True)
    session = models.ForeignKey(AcademicSession, on_delete=models.CASCADE, null=True, blank=True)

    # Email notification tracking
    email_sent = models.BooleanField(default=False)
    email_sent_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def mark_notification_as_read(self):
        """Marks notification as read"""
        self.is_read = True
        self.save()

    def send_email_to_user(self):
        """Sends email notification to user"""
        from django.core.mail import send_mail
        from django.conf import settings
        from django.utils import timezone

        try:
            # Send the email
            send_mail(
                subject=f"RMS Notification: {self.title}",
                message=self.message,
                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@rms.edu'),
                recipient_list=[self.user.email],
                fail_silently=False,
            )
            # Mark as sent
            self.email_sent = True
            self.email_sent_at = timezone.now()
            self.save()
            return True
        except Exception as e:
            print(f"Failed to send email notification: {e}")
            return False

# Result publication settings (for DAAA)
class ResultPublication(models.Model):
    NOTIFICATION_METHODS = [
        ('IMMEDIATE', 'Immediate - All students at once'),
        ('BY_FACULTY', 'By Faculty'),
        ('BY_DEPARTMENT', 'By Department'),
        ('BY_LEVEL', 'By Level'),
        ('CUSTOM', 'Custom Selection'),
    ]
    
    session = models.ForeignKey(AcademicSession, on_delete=models.CASCADE)
    published_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='published_results')  # DAAA
    notification_method = models.CharField(max_length=20, choices=NOTIFICATION_METHODS)
    
    # For filtered notifications
    target_faculties = models.ManyToManyField(Faculty, blank=True)
    target_departments = models.ManyToManyField(Department, blank=True)
    target_levels = models.ManyToManyField(Level, blank=True)
    
    published_at = models.DateTimeField(auto_now_add=True)
    email_sent = models.BooleanField(default=False)
    
    class Meta:
        unique_together = ['session']  # One publication per session

# System-wide settings
class SystemConfiguration(models.Model):
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    description = models.TextField(blank=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='updated_configurations')
    updated_at = models.DateTimeField(auto_now=True)
    
    # Examples of keys:
    # 'CA_PERCENTAGE' = '30'  # CA contributes 30% to total
    # 'EXAM_PERCENTAGE' = '70'  # Exam contributes 70% to total
    # 'MAX_ACTIVE_SESSIONS' = '1'
    # 'EMAIL_ENABLED' = 'true'

# Audit trail for important actions
class AuditLog(models.Model):
    ACTION_TYPES = [
        ('CREATE', 'Create'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('APPROVE', 'Approve'),
        ('REJECT', 'Reject'),
        ('PUBLISH', 'Publish'),
        ('LOGIN', 'Login'),
        ('ROLE_ASSIGN', 'Role Assignment'),
        ('CREATE_FACULTY', 'Create Faculty'),
        ('CREATE_FACULTY_WITH_DEAN', 'Create Faculty with Dean'),
        ('ASSIGN_DEAN', 'Assign Faculty Dean'),
        ('CREATE_USER', 'Create User'),
    ]

    LEVEL_CHOICES = [
        ('INFO', 'Information'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('CRITICAL', 'Critical'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='audit_logs')
    action = models.CharField(max_length=30, choices=ACTION_TYPES)
    model_name = models.CharField(max_length=50, blank=True)  # 'Result', 'Student', etc.
    object_id = models.CharField(max_length=50, blank=True)
    description = models.TextField()
    level = models.CharField(max_length=10, choices=LEVEL_CHOICES, default='INFO')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    # Optional related objects for context
    faculty = models.ForeignKey(Faculty, on_delete=models.CASCADE, null=True, blank=True)
    department = models.ForeignKey(Department, on_delete=models.CASCADE, null=True, blank=True)
    student = models.ForeignKey(Student, on_delete=models.CASCADE, null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.timestamp}"


# Permission Delegation System
class PermissionDelegation(models.Model):
    """Model for temporary permission delegation"""
    DELEGATION_STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('EXPIRED', 'Expired'),
        ('REVOKED', 'Revoked'),
    ]

    # Who is delegating the permission (the original role holder)
    delegator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='delegated_permissions')

    # Who is receiving the permission
    delegate = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_permissions')

    # Which specific role is being delegated (reference to the actual UserRole)
    delegated_role = models.ForeignKey(UserRole, on_delete=models.CASCADE, help_text="The specific role being temporarily delegated")

    # Who created this delegation (usually super admin)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_delegations')

    # Status
    status = models.CharField(max_length=10, choices=DELEGATION_STATUS_CHOICES, default='ACTIVE')

    # Reason for delegation
    reason = models.TextField()

    # Optional time-based delegation
    start_date = models.DateTimeField(null=True, blank=True, help_text="When the delegation becomes active (optional)")
    end_date = models.DateTimeField(null=True, blank=True, help_text="When the delegation expires (optional)")

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['delegate', 'delegated_role', 'status']
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.delegate.get_full_name()} delegated {self.get_delegated_role_display()} by {self.delegator.get_full_name()}"

    def is_active(self):
        """Check if delegation is currently active"""
        from django.utils import timezone
        now = timezone.now()

        # Check basic status
        if self.status != 'ACTIVE':
            return False

        # Check start date if set
        if self.start_date and now < self.start_date:
            return False

        # Check end date if set
        if self.end_date and now > self.end_date:
            return False

        return True

    def is_expired(self):
        """Check if delegation has expired"""
        from django.utils import timezone
        if self.status == 'EXPIRED':
            return True
        if self.end_date and timezone.now() > self.end_date:
            return True
        return False

    def check_and_update_expiry(self):
        """Check if delegation should be expired and update status"""
        if self.is_expired() and self.status == 'ACTIVE':
            self.expire()
            return True
        return False

    def revoke(self, revoked_by, reason=""):
        """Revoke this delegation and remove temporary role"""
        self.status = 'REVOKED'
        self.save()

        # Remove temporary role
        UserRole.objects.filter(delegation=self, is_temporary=True).delete()

        # Log the revocation
        AuditLog.objects.create(
            user=revoked_by,
            action='REVOKE_DELEGATION',
            description=f'Revoked delegation: {self.delegated_role.get_role_display()} from {self.delegate.get_full_name()}. Reason: {reason}',
            level='INFO'
        )

    def expire(self):
        """Mark delegation as expired and remove temporary role"""
        self.status = 'EXPIRED'
        self.save()

        # Remove temporary role
        UserRole.objects.filter(delegation=self, is_temporary=True).delete()

        # Log the expiration
        AuditLog.objects.create(
            user=self.delegate,
            action='DELEGATION_EXPIRED',
            description=f'Delegation expired: {self.delegated_role.get_role_display()} from {self.delegator.get_full_name()}',
            level='INFO'
        )

    def get_time_remaining(self):
        """Get time remaining until expiration"""
        if not self.end_date:
            return None

        from django.utils import timezone
        now = timezone.now()

        if now >= self.end_date:
            return "Expired"

        delta = self.end_date - now
        days = delta.days
        hours = delta.seconds // 3600

        if days > 0:
            return f"{days} day{'s' if days != 1 else ''}"
        elif hours > 0:
            return f"{hours} hour{'s' if hours != 1 else ''}"
        else:
            return "Less than 1 hour"

    @classmethod
    def check_if_delegation_is_allowed(cls, delegator_role, delegate_user, created_by):
        """
        Checks if delegation is allowed based on all rules
        """
        error_list = []

        # Rule 1: Only Super Admin can create delegations
        is_super_admin = cls.check_if_super_admin(created_by)
        if not is_super_admin:
            error_list.append("Only Super Admin users can create delegations")
            return False, error_list

        # Rule 2: Students cannot be delegated any roles
        is_student = cls.check_if_student(delegate_user)
        if is_student:
            error_list.append("Students cannot be delegated any roles")

        # Rule 3: Single delegation limit - each user can hold only ONE delegated role
        existing_delegation_list = cls.objects.filter(
            delegate=delegate_user,
            status='ACTIVE'
        ).exclude(delegated_role=delegator_role)

        if existing_delegation_list.exists():
            existing_role = existing_delegation_list.first().delegated_role.get_role_display()
            error_list.append(f"User already has an active delegation ({existing_role}). Only one delegated role allowed per user.")

        # Rule 4: Faculty-based restrictions (unless Super Admin is creating)
        if not cls.check_if_super_admin(created_by):
            # For non-Super Admin creators, enforce faculty restrictions
            is_same_faculty = cls.check_same_faculty(delegator_role, delegate_user)
            if not is_same_faculty:
                error_list.append("Cross-faculty delegation is only allowed for Super Admin users")

        # Rule 5: Prevent delegation to users who already have the same role
        user_has_role = cls.check_if_user_has_role(delegate_user, delegator_role.role)
        if user_has_role:
            error_list.append(f"User already has {delegator_role.get_role_display()} role")

        return len(error_list) == 0, error_list

    @staticmethod
    def check_if_super_admin(user):
        """Check if user is Super Admin"""
        has_super_admin_role = UserRole.objects.filter(
            user=user,
            role='SUPER_ADMIN',
            is_temporary=False
        ).exists()
        return has_super_admin_role

    @staticmethod
    def check_if_student(user):
        """Check if user is a student"""
        from .models import Student
        is_student = Student.objects.filter(user=user).exists()
        return is_student

    @staticmethod
    def check_same_faculty(delegator_role, delegate_user):
        """Check if delegator and delegate are in same faculty"""
        # Get delegate's faculty from their primary role
        delegate_role = UserRole.objects.filter(
            user=delegate_user,
            is_temporary=False,
            is_primary=True
        ).first()

        if not delegate_role or not delegate_role.faculty:
            return False

        # Compare faculties
        same_faculty = delegator_role.faculty == delegate_role.faculty
        return same_faculty

    @staticmethod
    def check_if_user_has_role(user, role):
        """Check if user already has the specified role"""
        has_role = UserRole.objects.filter(
            user=user,
            role=role
        ).exists()
        return has_role

    @classmethod
    def find_eligible_users_for_delegation(cls, delegator_role, created_by):
        """
        Finds users who can receive delegation
        """
        from django.contrib.auth.models import User
        from .models import Student

        # Start with all active users
        user_list = User.objects.filter(is_active=True)

        # Remove students from the list
        student_id_list = Student.objects.values_list('user_id', flat=True)
        user_list = user_list.exclude(id__in=student_id_list)

        # Remove users who already have this role
        existing_role_id_list = UserRole.objects.filter(
            role=delegator_role.role
        ).values_list('user_id', flat=True)
        user_list = user_list.exclude(id__in=existing_role_id_list)

        # Remove users who already have an active delegation
        active_delegation_id_list = cls.objects.filter(
            status='ACTIVE'
        ).values_list('delegate_id', flat=True)
        user_list = user_list.exclude(id__in=active_delegation_id_list)

        # If not Super Admin, restrict to same faculty
        is_super_admin = cls.check_if_super_admin(created_by)
        if not is_super_admin and delegator_role.faculty:
            # Get users in the same faculty
            same_faculty_id_list = UserRole.objects.filter(
                faculty=delegator_role.faculty,
                is_temporary=False
            ).values_list('user_id', flat=True)
            user_list = user_list.filter(id__in=same_faculty_id_list)

        return user_list.distinct().order_by('first_name', 'last_name')

    @classmethod
    def get_delegatable_roles(cls, created_by, faculty=None):
        """
        Get list of roles that can be delegated by the creator

        Args:
            created_by: User creating the delegation
            faculty: Optional faculty filter

        Returns:
            QuerySet of UserRole objects that can be delegated
        """
        # Only Super Admin can create delegations
        if not cls._is_super_admin(created_by):
            return UserRole.objects.none()

        # Get all non-temporary, non-student roles
        delegatable_roles = UserRole.objects.filter(
            is_temporary=False
        ).exclude(
            role='STUDENT'  # Exclude student roles if they exist
        ).select_related('user', 'faculty', 'department')

        # Filter by faculty if specified
        if faculty:
            delegatable_roles = delegatable_roles.filter(faculty=faculty)

        # Exclude roles that are already delegated
        active_delegation_role_ids = cls.objects.filter(
            status='ACTIVE'
        ).values_list('delegated_role_id', flat=True)
        delegatable_roles = delegatable_roles.exclude(id__in=active_delegation_role_ids)

        return delegatable_roles.order_by('faculty__name', 'role', 'user__first_name')


# Student Complaint System (Post-Publication)
class StudentComplaint(models.Model):
    COMPLAINT_TYPES = [
        ('MISSING_GRADE', 'Missing Grade'),
        ('INCORRECT_GRADE', 'Incorrect Grade'),
        ('SCORE_DISCREPANCY', 'Score Discrepancy'),
        ('COURSE_NOT_LISTED', 'Course Not Listed'),
        ('OTHER', 'Other'),
    ]

    STATUS_CHOICES = [
        ('SUBMITTED', 'Submitted'),
        ('UNDER_REVIEW', 'Under Review'),
        ('ESCALATED', 'Escalated'),
        ('RESOLVED', 'Resolved'),
        ('REJECTED', 'Rejected'),
    ]

    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='complaints')
    result = models.ForeignKey(Result, on_delete=models.CASCADE, related_name='complaints', null=True, blank=True)
    course_code = models.CharField(max_length=20)  # Manual entry for reference
    complaint_type = models.CharField(max_length=20, choices=COMPLAINT_TYPES)
    description = models.TextField()
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='SUBMITTED')

    # Handling workflow
    handled_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='handled_complaints')
    resolution_notes = models.TextField(blank=True)
    escalated_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='escalated_complaints')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.student.matric_number} - {self.course_code} - {self.get_complaint_type_display()}"




