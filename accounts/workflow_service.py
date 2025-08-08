"""
Result Approval Workflow Service
Handles the complete approval workflow for results including notifications

Current Workflow: Lecturer → Exam Officer → Faculty Dean → DAAA → Senate → Published
Note: HOD role exists for administrative functions but is not part of the approval chain.
Legacy HOD workflow support is maintained for existing results only.
"""

from django.contrib.auth.models import User
from django.utils import timezone
from .models import (
    Result, ResultApprovalHistory, UserRole, Notification, 
    AuditLog, CourseEnrollment
)


class ResultWorkflowService:
    """Service class to handle result approval workflow"""
    
    # Current workflow chain (HOD removed from active workflow)
    WORKFLOW_CHAIN = {
        'DRAFT': 'SUBMITTED_TO_EXAM_OFFICER',
        'SUBMITTED_TO_EXAM_OFFICER': 'APPROVED_BY_EXAM_OFFICER',
        'APPROVED_BY_EXAM_OFFICER': 'SUBMITTED_TO_DEAN',  # Direct to Dean (HOD bypassed)
        'SUBMITTED_TO_DEAN': 'APPROVED_BY_DEAN',
        'APPROVED_BY_DEAN': 'SUBMITTED_TO_DAAA',
        'SUBMITTED_TO_DAAA': 'APPROVED_BY_DAAA',
        'APPROVED_BY_DAAA': 'SUBMITTED_TO_SENATE',
        'SUBMITTED_TO_SENATE': 'PUBLISHED',

        # Legacy HOD workflow (only for backward compatibility with existing results)
        'SUBMITTED_TO_HOD': 'APPROVED_BY_HOD',
        'APPROVED_BY_HOD': 'SUBMITTED_TO_DEAN',
    }
    
    # Define who can approve at each stage
    APPROVER_ROLES = {
        'SUBMITTED_TO_EXAM_OFFICER': 'EXAM_OFFICER',
        'SUBMITTED_TO_DEAN': 'FACULTY_DEAN',
        'SUBMITTED_TO_DAAA': 'DAAA',
        'SUBMITTED_TO_SENATE': 'SENATE',
        # Legacy HOD support (for existing results only)
        'SUBMITTED_TO_HOD': 'HOD',
    }
    
    # Define previous status for rejection handling
    PREVIOUS_STATUS = {
        'SUBMITTED_TO_EXAM_OFFICER': 'DRAFT',
        'SUBMITTED_TO_DEAN': 'APPROVED_BY_EXAM_OFFICER',  # Direct from Exam Officer (HOD bypassed)
        'SUBMITTED_TO_DAAA': 'APPROVED_BY_DEAN',
        'SUBMITTED_TO_SENATE': 'APPROVED_BY_DAAA',
        # Legacy HOD workflow (for existing results only)
        'SUBMITTED_TO_HOD': 'APPROVED_BY_EXAM_OFFICER',
    }
    
    @classmethod
    def approve_result(cls, result, approver, comments=None):
        """
        Approve a result and move it to the next stage
        """
        try:
            current_status = result.status
            next_status = cls.WORKFLOW_CHAIN.get(current_status)
            
            if not next_status:
                return False, "No next status found for current status"
            
            # Get approver role
            approver_role = cls._get_user_role_for_result(approver, result)
            if not approver_role:
                return False, f"User {approver.username} does not have permission to approve this result. Required role: {cls.APPROVER_ROLES.get(current_status, 'Unknown')}"
            
            # Update result status
            old_status = result.status
            result.status = next_status
            result.last_modified_by = approver
            result.save()

            # Create approval history record
            ResultApprovalHistory.objects.create(
                result=result,
                action='APPROVED',
                from_status=old_status,
                to_status=next_status,
                actor=approver,
                actor_role=approver_role,
                comments=comments
            )

            # Create audit log
            AuditLog.objects.create(
                user=approver,
                action='APPROVE_RESULT',
                description=f'Approved result for {result.enrollment.student.matric_number} in {result.enrollment.course.code}',
                level='INFO'
            )

            # Auto-progress certain statuses that don't require manual review
            if next_status == 'APPROVED_BY_EXAM_OFFICER':
                # Auto-progress to SUBMITTED_TO_DEAN
                final_status = 'SUBMITTED_TO_DEAN'

                # Use a separate transaction for auto-progression to ensure atomicity
                try:
                    result.status = final_status
                    result.save()

                    # Create auto-progression history record
                    ResultApprovalHistory.objects.create(
                        result=result,
                        action='AUTO_PROGRESSED',
                        from_status=next_status,
                        to_status=final_status,
                        actor=approver,
                        actor_role=approver_role,
                        comments='Auto-progressed to dean review after exam officer approval'
                    )

                    next_status = final_status  # Update for notifications

                except Exception as e:
                    # If auto-progression fails, log it but don't fail the entire approval
                    print(f"Warning: Auto-progression failed for result {result.id}: {str(e)}")
                    # Keep the original next_status

            elif next_status == 'APPROVED_BY_DEAN':
                # Auto-progress to SUBMITTED_TO_DAAA
                final_status = 'SUBMITTED_TO_DAAA'
                result.status = final_status
                result.save()

                # Create auto-progression history record
                ResultApprovalHistory.objects.create(
                    result=result,
                    action='AUTO_PROGRESSED',
                    from_status=next_status,
                    to_status=final_status,
                    actor=approver,
                    actor_role=approver_role,
                    comments='Auto-progressed to DAAA review after dean approval'
                )

                next_status = final_status  # Update for notifications

            # Send notifications
            cls._send_approval_notifications(result, approver, approver_role, old_status, next_status)

            return True, "Result approved successfully"
            
        except Exception as e:
            return False, f"Error approving result: {str(e)}"
    
    @classmethod
    def reject_result(cls, result, rejector, rejection_reason):
        """
        Reject a result and send it back to the previous stage
        """
        try:
            current_status = result.status
            previous_status = cls.PREVIOUS_STATUS.get(current_status)
            
            if not previous_status:
                return False, "Cannot reject result at this stage"
            
            # Get rejector role
            rejector_role = cls._get_user_role_for_result(rejector, result)
            if not rejector_role:
                return False, "User does not have permission to reject this result"
            
            # Update result with rejection info
            old_status = result.status
            result.status = previous_status
            result.rejected_by = rejector
            result.rejection_reason = rejection_reason
            result.rejection_date = timezone.now()
            result.last_modified_by = rejector
            result.save()
            
            # Create approval history record
            ResultApprovalHistory.objects.create(
                result=result,
                action='REJECTED',
                from_status=old_status,
                to_status=previous_status,
                actor=rejector,
                actor_role=rejector_role,
                comments=rejection_reason
            )
            
            # Create audit log
            AuditLog.objects.create(
                user=rejector,
                action='REJECT_RESULT',
                description=f'Rejected result for {result.enrollment.student.matric_number} in {result.enrollment.course.code}: {rejection_reason}',
                level='WARNING'
            )
            
            # Send notifications
            cls._send_rejection_notifications(result, rejector, rejector_role, old_status, previous_status, rejection_reason)
            
            return True, "Result rejected successfully"
            
        except Exception as e:
            return False, f"Error rejecting result: {str(e)}"
    
    @classmethod
    def forward_result(cls, result, forwarder, comments=None):
        """
        Forward an approved result to the next stage
        """
        try:
            current_status = result.status
            
            # Only forward if status is an "APPROVED" status
            if not current_status.startswith('APPROVED_BY_'):
                return False, "Can only forward approved results"
            
            next_status = cls.WORKFLOW_CHAIN.get(current_status)
            if not next_status:
                return False, "No next status found for forwarding"
            
            # Get forwarder role
            forwarder_role = cls._get_user_role_for_result(forwarder, result)
            if not forwarder_role:
                return False, "User does not have permission to forward this result"
            
            # Update result status
            old_status = result.status
            result.status = next_status
            result.last_modified_by = forwarder
            result.save()
            
            # Create approval history record
            ResultApprovalHistory.objects.create(
                result=result,
                action='FORWARDED',
                from_status=old_status,
                to_status=next_status,
                actor=forwarder,
                actor_role=forwarder_role,
                comments=comments
            )
            
            # Create audit log
            AuditLog.objects.create(
                user=forwarder,
                action='FORWARD_RESULT',
                description=f'Forwarded result for {result.enrollment.student.matric_number} in {result.enrollment.course.code}',
                level='INFO'
            )
            
            # Send notifications
            cls._send_forward_notifications(result, forwarder, forwarder_role, old_status, next_status)
            
            return True, "Result forwarded successfully"
            
        except Exception as e:
            return False, f"Error forwarding result: {str(e)}"
    
    @classmethod
    def _get_user_role_for_result(cls, user, result):
        """
        Get the user's role that is relevant for this result's approval
        """
        try:
            # Get the course's faculty and department
            course = result.enrollment.course
            faculty = course.departments.first().faculty if course.departments.exists() else None
            department = course.departments.first() if course.departments.exists() else None
            
            # Find user's role that matches the result's context
            user_roles = UserRole.objects.filter(user=user)
            
            for role in user_roles:
                # Check if role matches the context
                if role.faculty == faculty or role.department == department or (role.faculty is None and role.department is None):
                    return role.role
            
            return None
            
        except Exception:
            return None
    
    @classmethod
    def _send_approval_notifications(cls, result, approver, approver_role, old_status, new_status):
        """
        Send notifications when a result is approved
        """
        try:
            # Notify the original submitter (lecturer)
            lecturer = result.created_by
            if lecturer:
                Notification.objects.create(
                    user=lecturer,
                    title='Result Approved',
                    message=f'Your result for {result.enrollment.student.matric_number} in {result.enrollment.course.code} has been approved by {approver_role.replace("_", " ").title()}',
                    notification_type='RESULT_APPROVED',
                    is_read=False
                )
            
            # If moving to a new submission stage, notify the next approver
            if new_status.startswith('SUBMITTED_TO_'):
                next_role = cls.APPROVER_ROLES.get(new_status)
                if next_role:
                    cls._notify_next_approvers(result, next_role)
                    
        except Exception as e:
            print(f"Error sending approval notifications: {str(e)}")
    
    @classmethod
    def _send_rejection_notifications(cls, result, rejector, rejector_role, old_status, new_status, rejection_reason):
        """
        Send notifications when a result is rejected
        """
        try:
            # Notify the original submitter (lecturer)
            lecturer = result.created_by
            if lecturer:
                Notification.objects.create(
                    user=lecturer,
                    title='Result Rejected',
                    message=f'Your result for {result.enrollment.student.matric_number} in {result.enrollment.course.code} has been rejected by {rejector_role.replace("_", " ").title()}. Reason: {rejection_reason}',
                    notification_type='RESULT_REJECTED',
                    is_read=False
                )
            
            # Notify the previous handler if different from lecturer
            if new_status != 'DRAFT':
                # Find who should handle the returned result
                previous_role = cls.APPROVER_ROLES.get(f'SUBMITTED_TO_{rejector_role}')
                if previous_role:
                    cls._notify_previous_handlers(result, previous_role, rejection_reason, rejector_role)
                    
        except Exception as e:
            print(f"Error sending rejection notifications: {str(e)}")
    
    @classmethod
    def _send_forward_notifications(cls, result, forwarder, forwarder_role, old_status, new_status):
        """
        Send notifications when a result is forwarded
        """
        try:
            # Notify the original submitter (lecturer)
            lecturer = result.created_by
            if lecturer:
                Notification.objects.create(
                    user=lecturer,
                    title='Result Forwarded',
                    message=f'Your result for {result.enrollment.student.matric_number} in {result.enrollment.course.code} has been forwarded to the next stage by {forwarder_role.replace("_", " ").title()}',
                    notification_type='RESULT_FORWARDED',
                    is_read=False
                )
            
            # Notify the next approver
            if new_status.startswith('SUBMITTED_TO_'):
                next_role = cls.APPROVER_ROLES.get(new_status)
                if next_role:
                    cls._notify_next_approvers(result, next_role)
                    
        except Exception as e:
            print(f"Error sending forward notifications: {str(e)}")
    
    @classmethod
    def _notify_next_approvers(cls, result, role):
        """
        Notify users with the specified role about pending results
        """
        try:
            # Get the course's faculty for context
            course = result.enrollment.course
            faculty = course.departments.first().faculty if course.departments.exists() else None
            
            # Find users with the required role in the same faculty
            approvers = UserRole.objects.filter(
                role=role,
                faculty=faculty
            ).select_related('user')
            
            for approver_role in approvers:
                Notification.objects.create(
                    user=approver_role.user,
                    title='New Result Pending Approval',
                    message=f'A result for {result.enrollment.student.matric_number} in {result.enrollment.course.code} is pending your approval',
                    notification_type='RESULT_PENDING',
                    is_read=False
                )
                
        except Exception as e:
            print(f"Error notifying next approvers: {str(e)}")
    
    @classmethod
    def _notify_previous_handlers(cls, result, role, rejection_reason, rejector_role):
        """
        Notify previous handlers about rejected results
        """
        try:
            # Get the course's faculty for context
            course = result.enrollment.course
            faculty = course.departments.first().faculty if course.departments.exists() else None
            
            # Find users with the required role in the same faculty
            handlers = UserRole.objects.filter(
                role=role,
                faculty=faculty
            ).select_related('user')
            
            for handler_role in handlers:
                Notification.objects.create(
                    user=handler_role.user,
                    title='Result Returned for Correction',
                    message=f'A result for {result.enrollment.student.matric_number} in {result.enrollment.course.code} has been returned by {rejector_role.replace("_", " ").title()}. Reason: {rejection_reason}',
                    notification_type='RESULT_RETURNED',
                    is_read=False
                )
                
        except Exception as e:
            print(f"Error notifying previous handlers: {str(e)}")
