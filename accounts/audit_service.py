"""
Comprehensive audit logging service for result modifications and carryover management
"""
from django.utils import timezone
from django.contrib.auth.models import User
from .models import AuditLog, Result, CarryOverStudent, CarryOverList
from .notification_service import NotificationService
import logging

logger = logging.getLogger(__name__)

class AuditService:
    """Service for comprehensive audit logging and carryover management"""
    
    @classmethod
    def log_result_modification(cls, result, modifier, original_values, new_values, reason="", ip_address=None):
        """
        Log detailed result modification with before/after values
        
        Args:
            result: Result object being modified
            modifier: User making the modification
            original_values: Dict with original values (ca_score, exam_score, total_score, grade, is_carry_over)
            new_values: Dict with new values
            reason: Reason for modification
            ip_address: IP address of the modifier
        """
        try:
            # Create detailed audit log
            audit_log = AuditLog.objects.create(
                user=modifier,
                action='MODIFY_RESULT',
                model_name='Result',
                object_id=str(result.id),
                description=cls._build_modification_description(result, original_values, new_values, reason),
                level='INFO',
                ip_address=ip_address,
                result=result,
                student=result.enrollment.student,
                faculty=result.enrollment.course.departments.first().faculty if result.enrollment.course.departments.exists() else None,
                department=result.enrollment.course.departments.first() if result.enrollment.course.departments.exists() else None,
                
                # Original values
                original_ca_score=original_values.get('ca_score'),
                original_exam_score=original_values.get('exam_score'),
                original_total_score=original_values.get('total_score'),
                original_grade=original_values.get('grade'),
                original_carryover_status=original_values.get('is_carry_over'),
                
                # New values
                new_ca_score=new_values.get('ca_score'),
                new_exam_score=new_values.get('exam_score'),
                new_total_score=new_values.get('total_score'),
                new_grade=new_values.get('grade'),
                new_carryover_status=new_values.get('is_carry_over'),
                
                modification_reason=reason
            )
            
            logger.info(f"Result modification logged: {result.enrollment.student.matric_number} by {modifier.username}")
            return audit_log
            
        except Exception as e:
            logger.error(f"Error logging result modification: {str(e)}")
            return None
    
    @classmethod
    def _build_modification_description(cls, result, original_values, new_values, reason):
        """Build a human-readable description of the modification"""
        student = result.enrollment.student
        course = result.enrollment.course
        
        changes = []
        
        # Check each field for changes
        if original_values.get('ca_score') != new_values.get('ca_score'):
            changes.append(f"CA Score: {original_values.get('ca_score')} → {new_values.get('ca_score')}")
        
        if original_values.get('exam_score') != new_values.get('exam_score'):
            changes.append(f"Exam Score: {original_values.get('exam_score')} → {new_values.get('exam_score')}")
        
        if original_values.get('total_score') != new_values.get('total_score'):
            changes.append(f"Total Score: {original_values.get('total_score')} → {new_values.get('total_score')}")
        
        if original_values.get('grade') != new_values.get('grade'):
            changes.append(f"Grade: {original_values.get('grade')} → {new_values.get('grade')}")
        
        if original_values.get('is_carry_over') != new_values.get('is_carry_over'):
            old_status = "Carryover" if original_values.get('is_carry_over') else "Passing"
            new_status = "Carryover" if new_values.get('is_carry_over') else "Passing"
            changes.append(f"Status: {old_status} → {new_status}")
        
        change_summary = "; ".join(changes) if changes else "No changes detected"
        
        description = f"Modified result for {student.matric_number} ({student.user.get_full_name()}) in {course.code}. Changes: {change_summary}"
        
        if reason:
            description += f". Reason: {reason}"
        
        return description
    
    @classmethod
    def handle_carryover_status_change(cls, result, modifier, old_carryover_status, new_carryover_status, reason=""):
        """
        Handle carryover status changes and update tracking systems
        
        Args:
            result: Result object
            modifier: User making the change
            old_carryover_status: Previous carryover status (boolean)
            new_carryover_status: New carryover status (boolean)
            reason: Reason for the change
        """
        try:
            student = result.enrollment.student
            course = result.enrollment.course
            session = result.enrollment.session
            
            if old_carryover_status == new_carryover_status:
                return  # No change in carryover status
            
            if new_carryover_status:
                # Student is now a carryover - add to tracking systems
                cls._add_to_carryover_tracking(result, modifier, reason)
                
                # Notify student
                NotificationService.notify_carryover_detected(student, result)
                
                # Log the change
                AuditLog.objects.create(
                    user=modifier,
                    action='CARRYOVER_STATUS_CHANGE',
                    model_name='Result',
                    object_id=str(result.id),
                    description=f"Student {student.matric_number} added to carryover tracking for {course.code} due to score modification. New score: {result.total_score}",
                    level='WARNING',
                    result=result,
                    student=student,
                    modification_reason=reason
                )
                
            else:
                # Student is no longer a carryover - remove from tracking systems
                cls._remove_from_carryover_tracking(result, modifier, reason)
                
                # Notify student of improvement
                NotificationService.create_new_notification(
                    user=student.user,
                    notification_type='CARRYOVER_REMOVED',
                    title=f'Carryover Status Removed - {course.code}',
                    message=f'Great news! Your carryover status for {course.code} has been removed due to score improvement. Your new score is {result.total_score}.',
                    result=result
                )
                
                # Log the change
                AuditLog.objects.create(
                    user=modifier,
                    action='CARRYOVER_STATUS_CHANGE',
                    model_name='Result',
                    object_id=str(result.id),
                    description=f"Student {student.matric_number} removed from carryover tracking for {course.code} due to score improvement. New score: {result.total_score}",
                    level='INFO',
                    result=result,
                    student=student,
                    modification_reason=reason
                )
            
            logger.info(f"Carryover status change handled for {student.matric_number}: {old_carryover_status} → {new_carryover_status}")
            
        except Exception as e:
            logger.error(f"Error handling carryover status change: {str(e)}")
    
    @classmethod
    def _add_to_carryover_tracking(cls, result, modifier, reason):
        """Add student to carryover tracking systems"""
        try:
            student = result.enrollment.student
            course = result.enrollment.course
            session = result.enrollment.session
            
            if course.departments.exists():
                department = course.departments.first()
                faculty = department.faculty
                
                # Get passing threshold
                passing_threshold = 45.0  # Default
                try:
                    from .models import CarryOverCriteria
                    carryover_criteria = CarryOverCriteria.objects.get(faculty=faculty)
                    passing_threshold = carryover_criteria.minimum_score
                except CarryOverCriteria.DoesNotExist:
                    pass
                
                # Add to CarryOverList
                CarryOverList.objects.get_or_create(
                    session=session,
                    faculty=faculty,
                    department=department,
                    result=result,
                    defaults={}
                )
                
                # Add to CarryOverStudent
                CarryOverStudent.objects.get_or_create(
                    student=student,
                    course=course,
                    session=session,
                    defaults={
                        'result': result,
                        'faculty': faculty,
                        'department': department,
                        'level': course.level,
                        'failed_score': result.total_score,
                        'failed_grade': result.grade,
                        'passing_threshold': passing_threshold,
                        'status': 'IDENTIFIED'
                    }
                )
                
        except Exception as e:
            logger.error(f"Error adding to carryover tracking: {str(e)}")
    
    @classmethod
    def _remove_from_carryover_tracking(cls, result, modifier, reason):
        """Remove student from carryover tracking systems"""
        try:
            student = result.enrollment.student
            course = result.enrollment.course
            session = result.enrollment.session
            
            # Remove from CarryOverList
            CarryOverList.objects.filter(
                session=session,
                result=result
            ).delete()
            
            # Remove from CarryOverStudent
            CarryOverStudent.objects.filter(
                student=student,
                course=course,
                session=session
            ).delete()
            
        except Exception as e:
            logger.error(f"Error removing from carryover tracking: {str(e)}")
    
    @classmethod
    def get_result_modification_history(cls, result):
        """Get complete modification history for a result"""
        return AuditLog.objects.filter(
            result=result,
            action='MODIFY_RESULT'
        ).order_by('-timestamp')
    
    @classmethod
    def get_student_carryover_history(cls, student):
        """Get carryover status change history for a student"""
        return AuditLog.objects.filter(
            student=student,
            action='CARRYOVER_STATUS_CHANGE'
        ).order_by('-timestamp')
