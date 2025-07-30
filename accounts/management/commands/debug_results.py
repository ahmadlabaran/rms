from django.core.management.base import BaseCommand
from accounts.models import Course, AcademicSession, CourseEnrollment, CourseAssignment, UserRole
from django.contrib.auth.models import User


class Command(BaseCommand):
    help = 'Debug result submission system'

    def handle(self, *args, **options):
        self.stdout.write("=== Debugging Result Submission System ===")
        
        # Check courses
        courses = Course.objects.all()
        self.stdout.write(f"Total courses: {courses.count()}")
        for course in courses[:5]:
            self.stdout.write(f"  Course: {course.id} - {course.code} - {course.title}")
        
        # Check sessions
        sessions = AcademicSession.objects.all()
        self.stdout.write(f"Total sessions: {sessions.count()}")
        for session in sessions[:5]:
            self.stdout.write(f"  Session: {session.id} - {session.name}")
        
        # Check course enrollments
        enrollments = CourseEnrollment.objects.all()
        self.stdout.write(f"Total enrollments: {enrollments.count()}")
        for enrollment in enrollments[:10]:
            self.stdout.write(f"  Enrollment: {enrollment.id} - Student: {enrollment.student.matric_number} - Course: {enrollment.course.code} - Session: {enrollment.session.name}")
        
        # Check specific course and session
        try:
            course = Course.objects.get(id=1)
            session = AcademicSession.objects.get(id=6)
            self.stdout.write(f"\nChecking Course ID 1: {course.code} - {course.title}")
            self.stdout.write(f"Checking Session ID 6: {session.name}")
            
            specific_enrollments = CourseEnrollment.objects.filter(course=course, session=session)
            self.stdout.write(f"Enrollments for this course/session: {specific_enrollments.count()}")
            for enrollment in specific_enrollments:
                self.stdout.write(f"  {enrollment.student.matric_number} - {enrollment.student.user.get_full_name()}")
                
        except Course.DoesNotExist:
            self.stdout.write("Course ID 1 does not exist")
        except AcademicSession.DoesNotExist:
            self.stdout.write("Session ID 6 does not exist")
        
        # Check lecturers
        lecturers = UserRole.objects.filter(role='LECTURER')
        self.stdout.write(f"\nTotal lecturers: {lecturers.count()}")
        for lecturer in lecturers[:5]:
            self.stdout.write(f"  Lecturer: {lecturer.user.username} - {lecturer.user.get_full_name()}")
            
        # Check course assignments
        assignments = CourseAssignment.objects.all()
        self.stdout.write(f"Total course assignments: {assignments.count()}")
        for assignment in assignments[:10]:
            self.stdout.write(f"  Assignment: {assignment.lecturer.username} -> {assignment.course.code}")
