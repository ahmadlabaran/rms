"""
Notification Service for RMS
Handles notifications and emails
"""

from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.utils import timezone
from .models import Notification, Result, AcademicSession, Student, AuditLog
import logging

logger = logging.getLogger(__name__)


class NotificationService:
    """Handles notifications and emails"""
    
    @staticmethod
    def create_new_notification(user, notification_type, title, message, **kwargs):
        """
        Creates a new notification for user
        """
        # Create the notification
        new_notification = Notification.objects.create(
            user=user,
            notification_type=notification_type,
            title=title,
            message=message,
            result=kwargs.get('result'),
            session=kwargs.get('session'),
        )

        # Send email if user has email address
        user_has_email = bool(user.email)
        if user_has_email:
            new_notification.send_email_to_user()

        return new_notification
    
    @staticmethod
    def notify_result_published(students, session):
        """
        Notify students when their results are published
        
        Args:
            students: QuerySet or list of Student objects
            session: AcademicSession object
        """
        for student in students:
            NotificationService.create_new_notification(
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
        NotificationService.create_new_notification(
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
        NotificationService.create_new_notification(
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
            NotificationService.create_new_notification(
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
            NotificationService.create_new_notification(
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
        NotificationService.create_new_notification(
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
    def notify_delegation_created(delegation):
        """
        Notify users when a delegation is created

        Args:
            delegation: PermissionDelegation object
        """
        # Notify the delegate
        NotificationService.create_new_notification(
            user=delegation.delegate,
            notification_type='DELEGATION_CREATED',
            title='Role Delegation Assigned',
            message=f'You have been granted temporary {delegation.delegated_role.get_role_display()} '
                   f'permissions by {delegation.created_by.get_full_name()}. '
                   f'Reason: {delegation.reason}'
        )

        # Notify the delegator
        NotificationService.create_new_notification(
            user=delegation.delegator,
            notification_type='DELEGATION_CREATED',
            title='Role Delegated',
            message=f'Your {delegation.delegated_role.get_role_display()} role has been '
                   f'temporarily delegated to {delegation.delegate.get_full_name()} '
                   f'by {delegation.created_by.get_full_name()}.'
        )

        # Send emails if enabled
        NotificationService._send_delegation_email(
            delegation, 'created'
        )

    @staticmethod
    def notify_delegation_revoked(delegation, revoked_by, reason=""):
        """
        Notify users when a delegation is revoked

        Args:
            delegation: PermissionDelegation object
            revoked_by: User who revoked the delegation
            reason: Reason for revocation
        """
        # Notify the delegate
        NotificationService.create_new_notification(
            user=delegation.delegate,
            notification_type='DELEGATION_REVOKED',
            title='Role Delegation Revoked',
            message=f'Your temporary {delegation.delegated_role.get_role_display()} '
                   f'permissions have been revoked by {revoked_by.get_full_name()}. '
                   f'Reason: {reason or "No reason provided"}'
        )

        # Notify the delegator
        NotificationService.create_new_notification(
            user=delegation.delegator,
            notification_type='DELEGATION_REVOKED',
            title='Role Delegation Revoked',
            message=f'The delegation of your {delegation.delegated_role.get_role_display()} '
                   f'role to {delegation.delegate.get_full_name()} has been revoked '
                   f'by {revoked_by.get_full_name()}.'
        )

        # Send emails if enabled
        NotificationService._send_delegation_email(
            delegation, 'revoked', revoked_by=revoked_by, reason=reason
        )

    @staticmethod
    def notify_delegation_expired(delegation):
        """
        Notify users when a delegation expires

        Args:
            delegation: PermissionDelegation object
        """
        # Notify the delegate
        NotificationService.create_new_notification(
            user=delegation.delegate,
            notification_type='DELEGATION_EXPIRED',
            title='Role Delegation Expired',
            message=f'Your temporary {delegation.delegated_role.get_role_display()} '
                   f'permissions have expired.'
        )

        # Notify the delegator
        NotificationService.create_new_notification(
            user=delegation.delegator,
            notification_type='DELEGATION_EXPIRED',
            title='Role Delegation Expired',
            message=f'The delegation of your {delegation.delegated_role.get_role_display()} '
                   f'role to {delegation.delegate.get_full_name()} has expired.'
        )

        # Send emails if enabled
        NotificationService._send_delegation_email(
            delegation, 'expired'
        )

    @staticmethod
    def notify_delegation_expiring_soon(delegation, hours_remaining):
        """
        Notify users when a delegation is expiring soon

        Args:
            delegation: PermissionDelegation object
            hours_remaining: Hours until expiration
        """
        time_text = f"{hours_remaining} hour{'s' if hours_remaining != 1 else ''}"

        # Notify the delegate
        NotificationService.create_new_notification(
            user=delegation.delegate,
            notification_type='DELEGATION_WARNING',
            title='Role Delegation Expiring Soon',
            message=f'Your temporary {delegation.delegated_role.get_role_display()} '
                   f'permissions will expire in {time_text}.'
        )

        # Notify the delegator
        NotificationService.create_new_notification(
            user=delegation.delegator,
            notification_type='DELEGATION_WARNING',
            title='Role Delegation Expiring Soon',
            message=f'The delegation of your {delegation.delegated_role.get_role_display()} '
                   f'role to {delegation.delegate.get_full_name()} will expire in {time_text}.'
        )

        # Send emails if enabled
        NotificationService._send_delegation_email(
            delegation, 'expiring', hours_remaining=hours_remaining
        )

    @staticmethod
    def _send_delegation_email(delegation, action, **kwargs):
        """
        Send email notifications for delegation events

        Args:
            delegation: PermissionDelegation object
            action: Type of action (created, revoked, expired, expiring)
            **kwargs: Additional context for email templates
        """
        try:
            # Email templates mapping
            templates = {
                'created': {
                    'delegate': 'emails/delegation_created_delegate.html',
                    'delegator': 'emails/delegation_created_delegator.html',
                    'subject_delegate': 'New Role Delegation Assigned',
                    'subject_delegator': 'Your Role Has Been Delegated'
                },
                'revoked': {
                    'delegate': 'emails/delegation_revoked_delegate.html',
                    'delegator': 'emails/delegation_revoked_delegator.html',
                    'subject_delegate': 'Role Delegation Revoked',
                    'subject_delegator': 'Role Delegation Revoked'
                },
                'expired': {
                    'delegate': 'emails/delegation_expired_delegate.html',
                    'delegator': 'emails/delegation_expired_delegator.html',
                    'subject_delegate': 'Role Delegation Expired',
                    'subject_delegator': 'Role Delegation Expired'
                },
                'expiring': {
                    'delegate': 'emails/delegation_expiring_delegate.html',
                    'delegator': 'emails/delegation_expiring_delegator.html',
                    'subject_delegate': 'Role Delegation Expiring Soon',
                    'subject_delegator': 'Role Delegation Expiring Soon'
                }
            }

            if action not in templates:
                return

            template_config = templates[action]

            # Common context
            context = {
                'delegation': delegation,
                'delegate': delegation.delegate,
                'delegator': delegation.delegator,
                'role': delegation.delegated_role.get_role_display(),
                'site_name': 'RMS - Result Management System',
                'current_year': timezone.now().year,
                **kwargs
            }

            # Send to delegate
            if delegation.delegate.email:
                NotificationService._send_single_email(
                    user=delegation.delegate,
                    subject=template_config['subject_delegate'],
                    template=template_config['delegate'],
                    context=context
                )

            # Send to delegator
            if delegation.delegator.email:
                NotificationService._send_single_email(
                    user=delegation.delegator,
                    subject=template_config['subject_delegator'],
                    template=template_config['delegator'],
                    context=context
                )

        except Exception as e:
            logger.error(f'Error sending delegation email: {str(e)}')

    @staticmethod
    def _send_single_email(user, subject, template, context):
        """
        Send a single email to a user

        Args:
            user: User object
            subject: Email subject
            template: Template path
            context: Template context
        """
        try:
            # Try to render the template, fall back to simple text if template doesn't exist
            try:
                html_content = render_to_string(template, context)
            except:
                # Fallback to simple text email
                html_content = f"""
                <html>
                <body>
                    <h2>{subject}</h2>
                    <p>Dear {user.get_full_name()},</p>
                    <p>This is a notification regarding role delegation in the RMS system.</p>
                    <p>Please log in to the system for more details.</p>
                    <br>
                    <p>Best regards,<br>RMS Team</p>
                </body>
                </html>
                """

            send_mail(
                subject=subject,
                message='',  # Plain text version
                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@rms.edu'),
                recipient_list=[user.email],
                html_message=html_content,
                fail_silently=True,
            )

            logger.info(f'Delegation email sent to {user.email}: {subject}')

        except Exception as e:
            logger.error(f'Error sending email to {user.email}: {str(e)}')
    
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
            NotificationService.create_new_notification(
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
