"""
Notification Service for RMS
Handles in-app notifications and email alerts
"""

from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from .models import Notification, Result, AcademicSession, Student


class NotificationService:
    """Service class for managing notifications and emails"""
    
    @staticmethod
    def create_notification(user, notification_type, title, message, **kwargs):
        """
        Create a new notification for a user
        
        Args:
            user: User object
            notification_type: Type from Notification.NOTIFICATION_TYPES
            title: Notification title
            message: Notification message
            **kwargs: Optional related objects (result, session, etc.)
        
        Returns:
            Notification object
        """
        notification = Notification.objects.create(
            user=user,
            notification_type=notification_type,
            title=title,
            message=message,
            result=kwargs.get('result'),
            session=kwargs.get('session'),
        )
        
        # Send email if user has email
        if user.email:
            notification.send_email()
            
        return notification
    
    @staticmethod
    def notify_result_published(students, session):
        """
        Notify students when their results are published
        
        Args:
            students: QuerySet or list of Student objects
            session: AcademicSession object
        """
        for student in students:
            NotificationService.create_notification(
                user=student.user,
                notification_type='RESULT_PUBLISHED',
                title=f'Results Published - {session.name}',
                message=f'Your academic results for {session.name} have been published. '
                       f'Log in to view your grades and download your result.',
                session=session
            )
    
    @staticmethod
    def notify_result_correction_needed(lecturer, result, comment):
        """
        Notify lecturer when result correction is needed
        
        Args:
            lecturer: User object (lecturer)
            result: Result object
            comment: Correction comment
        """
        NotificationService.create_notification(
            user=lecturer,
            notification_type='RESULT_REJECTED',
            title=f'Result Correction Required - {result.enrollment.course.code}',
            message=f'Your submitted result for {result.enrollment.student.matric_number} '
                   f'in {result.enrollment.course.code} requires correction.\n\n'
                   f'Comment: {comment}\n\n'
                   f'Please review and resubmit the result.',
            result=result
        )
    
    @staticmethod
    def notify_result_approved(lecturer, result):
        """
        Notify lecturer when result is approved
        
        Args:
            lecturer: User object (lecturer)
            result: Result object
        """
        NotificationService.create_notification(
            user=lecturer,
            notification_type='RESULT_APPROVED',
            title=f'Result Approved - {result.enrollment.course.code}',
            message=f'Your submitted result for {result.enrollment.student.matric_number} '
                   f'in {result.enrollment.course.code} has been approved.',
            result=result
        )
    
    @staticmethod
    def notify_session_created(users, session):
        """
        Notify users when a new academic session is created
        
        Args:
            users: QuerySet or list of User objects
            session: AcademicSession object
        """
        for user in users:
            NotificationService.create_notification(
                user=user,
                notification_type='SESSION_CREATED',
                title=f'New Academic Session Created - {session.name}',
                message=f'A new academic session "{session.name}" has been created '
                       f'and is now active. All academic activities will be recorded '
                       f'under this session.',
                session=session
            )
    
    @staticmethod
    def notify_session_locked(users, session):
        """
        Notify users when an academic session is locked
        
        Args:
            users: QuerySet or list of User objects
            session: AcademicSession object
        """
        for user in users:
            NotificationService.create_notification(
                user=user,
                notification_type='SESSION_LOCKED',
                title=f'Academic Session Locked - {session.name}',
                message=f'The academic session "{session.name}" has been permanently '
                       f'locked. No further changes can be made to results in this session.',
                session=session
            )
    
    @staticmethod
    def notify_carryover_detected(student, result):
        """
        Notify student when a carryover is detected
        
        Args:
            student: Student object
            result: Result object with carryover
        """
        NotificationService.create_notification(
            user=student.user,
            notification_type='CARRY_OVER_DETECTED',
            title=f'Carryover Detected - {result.enrollment.course.code}',
            message=f'A carryover has been detected for {result.enrollment.course.code} '
                   f'({result.enrollment.course.title}). Your score of {result.total_score} '
                   f'resulted in grade {result.grade}. Please contact your academic advisor '
                   f'for guidance on retaking this course.',
            result=result
        )
    
    @staticmethod
    def send_bulk_email(users, subject, message):
        """
        Send bulk email to multiple users
        
        Args:
            users: QuerySet or list of User objects
            subject: Email subject
            message: Email message
        
        Returns:
            dict: Success and failure counts
        """
        success_count = 0
        failure_count = 0
        
        for user in users:
            if user.email:
                try:
                    send_mail(
                        subject=subject,
                        message=message,
                        from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@rms.edu'),
                        recipient_list=[user.email],
                        fail_silently=False,
                    )
                    success_count += 1
                except Exception as e:
                    print(f"Failed to send email to {user.email}: {e}")
                    failure_count += 1
            else:
                failure_count += 1
        
        return {
            'success_count': success_count,
            'failure_count': failure_count,
            'total_users': len(users)
        }
    
    @staticmethod
    def get_unread_notifications(user, limit=10):
        """
        Get unread notifications for a user
        
        Args:
            user: User object
            limit: Maximum number of notifications to return
        
        Returns:
            QuerySet of Notification objects
        """
        return Notification.objects.filter(
            user=user,
            is_read=False
        ).order_by('-created_at')[:limit]
    
    @staticmethod
    def mark_all_as_read(user):
        """
        Mark all notifications as read for a user
        
        Args:
            user: User object
        
        Returns:
            int: Number of notifications marked as read
        """
        return Notification.objects.filter(
            user=user,
            is_read=False
        ).update(is_read=True)


# Utility functions for common notification scenarios
def notify_result_workflow_update(result, action, comment=None):
    """
    Notify relevant users when result moves through workflow
    
    Args:
        result: Result object
        action: Action taken (submitted, approved, rejected)
        comment: Optional comment for rejections
    """
    if action == 'submitted_to_exam_officer':
        # Notify exam officer
        exam_officers = User.objects.filter(
            userrole__role='EXAM_OFFICER',
            userrole__faculty=result.enrollment.course.departments.first().faculty
        )
        for officer in exam_officers:
            NotificationService.create_notification(
                user=officer,
                notification_type='RESULT_SUBMITTED',
                title=f'New Result Submitted - {result.enrollment.course.code}',
                message=f'A new result has been submitted for review in {result.enrollment.course.code}.',
                result=result
            )
    
    elif action == 'approved_by_exam_officer':
        NotificationService.notify_result_approved(result.created_by, result)
    
    elif action == 'rejected_by_exam_officer':
        NotificationService.notify_result_correction_needed(result.created_by, result, comment)


def notify_session_update(session, action):
    """
    Notify all relevant users about session updates
    
    Args:
        session: AcademicSession object
        action: Action taken (created, activated, locked)
    """
    # Get all active users
    all_users = User.objects.filter(is_active=True)
    
    if action == 'created':
        NotificationService.notify_session_created(all_users, session)
    elif action == 'locked':
        NotificationService.notify_session_locked(all_users, session)
