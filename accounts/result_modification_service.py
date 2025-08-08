"""
Service for handling administrative result modifications with comprehensive audit logging
"""
from django.db import transaction
from django.utils import timezone
from django.contrib.auth.models import User
from .models import Result, CarryOverStudent, CarryOverList, CarryOverCriteria
from .audit_service import AuditService
import logging

logger = logging.getLogger(__name__)

class ResultModificationService:
    """Service for handling administrative result modifications"""
    
    AUTHORIZED_ROLES = [
        'EXAM_OFFICER', 'FACULTY_DEAN', 'DAAA', 'HOD', 'SUPER_ADMIN'
    ]
    
    @classmethod
    def modify_result(cls, result_id, modifier, new_ca_score=None, new_exam_score=None, 
                     reason="", ip_address=None):
        """
        Modify a result with comprehensive audit logging and carryover re-evaluation
        
        Args:
            result_id: ID of the result to modify
            modifier: User making the modification
            new_ca_score: New CA score (optional)
            new_exam_score: New exam score (optional)
            reason: Reason for modification
            ip_address: IP address of the modifier
            
        Returns:
            tuple: (success: bool, message: str, result: Result or None)
        """
        try:
            # Verify user authorization
            if not cls._is_authorized_user(modifier):
                return False, "User not authorized to modify results", None
            
            # Get the result
            try:
                result = Result.objects.get(id=result_id)
            except Result.DoesNotExist:
                return False, "Result not found", None
            
            # Check if result can be modified
            if not cls._can_modify_result(result):
                return False, f"Result cannot be modified in current status: {result.get_status_display()}", None
            
            # Capture original values
            original_values = {
                'ca_score': result.ca_score,
                'exam_score': result.exam_score,
                'total_score': result.total_score,
                'grade': result.grade,
                'is_carry_over': result.is_carry_over
            }
            
            # Apply modifications
            with transaction.atomic():
                modified = False
                
                if new_ca_score is not None and new_ca_score != result.ca_score:
                    result.ca_score = new_ca_score
                    modified = True
                
                if new_exam_score is not None and new_exam_score != result.exam_score:
                    result.exam_score = new_exam_score
                    modified = True
                
                if modified:
                    # Recalculate total score and grade
                    result.total_score = result.ca_score + result.exam_score
                    result.grade = cls._calculate_grade(result.total_score)
                    
                    # Store old carryover status
                    old_carryover_status = result.is_carry_over
                    
                    # Re-evaluate carryover status
                    result.is_carry_over = cls._evaluate_carryover_status(result)
                    
                    # Update modification metadata
                    result.last_modified_by = modifier
                    result.save()
                    
                    # Capture new values
                    new_values = {
                        'ca_score': result.ca_score,
                        'exam_score': result.exam_score,
                        'total_score': result.total_score,
                        'grade': result.grade,
                        'is_carry_over': result.is_carry_over
                    }
                    
                    # Log the modification
                    AuditService.log_result_modification(
                        result=result,
                        modifier=modifier,
                        original_values=original_values,
                        new_values=new_values,
                        reason=reason,
                        ip_address=ip_address
                    )
                    
                    # Handle carryover status changes
                    if old_carryover_status != result.is_carry_over:
                        AuditService.handle_carryover_status_change(
                            result=result,
                            modifier=modifier,
                            old_carryover_status=old_carryover_status,
                            new_carryover_status=result.is_carry_over,
                            reason=reason
                        )
                    
                    logger.info(f"Result modified successfully: {result.enrollment.student.matric_number} by {modifier.username}")
                    return True, "Result modified successfully", result
                
                else:
                    return False, "No changes were made to the result", result
                    
        except Exception as e:
            logger.error(f"Error modifying result: {str(e)}")
            return False, f"Error modifying result: {str(e)}", None
    
    @classmethod
    def bulk_modify_results(cls, modifications, modifier, reason="", ip_address=None):
        """
        Modify multiple results in a single transaction
        
        Args:
            modifications: List of dicts with result_id, new_ca_score, new_exam_score
            modifier: User making the modifications
            reason: Reason for modifications
            ip_address: IP address of the modifier
            
        Returns:
            tuple: (success_count: int, error_count: int, messages: list)
        """
        success_count = 0
        error_count = 0
        messages = []
        
        try:
            with transaction.atomic():
                for modification in modifications:
                    result_id = modification.get('result_id')
                    new_ca_score = modification.get('new_ca_score')
                    new_exam_score = modification.get('new_exam_score')
                    
                    success, message, result = cls.modify_result(
                        result_id=result_id,
                        modifier=modifier,
                        new_ca_score=new_ca_score,
                        new_exam_score=new_exam_score,
                        reason=reason,
                        ip_address=ip_address
                    )
                    
                    if success:
                        success_count += 1
                        messages.append(f"✅ {result.enrollment.student.matric_number}: {message}")
                    else:
                        error_count += 1
                        messages.append(f"❌ Result ID {result_id}: {message}")
                        
        except Exception as e:
            logger.error(f"Error in bulk modification: {str(e)}")
            messages.append(f"❌ Bulk modification failed: {str(e)}")
            error_count = len(modifications)
            success_count = 0
        
        return success_count, error_count, messages
    
    @classmethod
    def _is_authorized_user(cls, user):
        """Check if user is authorized to modify results"""
        from .models import UserRole
        
        user_roles = UserRole.objects.filter(user=user, role__in=cls.AUTHORIZED_ROLES)
        return user_roles.exists()
    
    @classmethod
    def _can_modify_result(cls, result):
        """Check if result can be modified based on its current status"""
        # Results can be modified if they're not yet published
        modifiable_statuses = [
            'DRAFT',
            'SUBMITTED_TO_EXAM_OFFICER',
            'APPROVED_BY_EXAM_OFFICER',
            'SUBMITTED_TO_HOD',
            'APPROVED_BY_HOD',
            'SUBMITTED_TO_DEAN',
            'APPROVED_BY_DEAN',
            'SUBMITTED_TO_DAAA',
            'APPROVED_BY_DAAA'
        ]
        return result.status in modifiable_statuses
    
    @classmethod
    def _calculate_grade(cls, total_score):
        """Calculate grade based on total score"""
        if total_score >= 70:
            return 'A'
        elif total_score >= 60:
            return 'B'
        elif total_score >= 50:
            return 'C'
        elif total_score >= 45:
            return 'D'
        else:
            return 'F'
    
    @classmethod
    def _evaluate_carryover_status(cls, result):
        """Evaluate if result should be marked as carryover"""
        try:
            # Get faculty for carryover criteria
            if result.enrollment.course.departments.exists():
                faculty = result.enrollment.course.departments.first().faculty
                
                try:
                    carryover_criteria = CarryOverCriteria.objects.get(faculty=faculty)
                    # Check if score is below minimum or grade is F
                    return (result.total_score < carryover_criteria.minimum_score or result.grade == 'F')
                except CarryOverCriteria.DoesNotExist:
                    pass
            
            # Default: F grade or score below 45 is carryover
            return (result.grade == 'F' or result.total_score < 45)
            
        except Exception as e:
            logger.error(f"Error evaluating carryover status: {str(e)}")
            return (result.grade == 'F' or result.total_score < 45)
    
    @classmethod
    def get_modifiable_results(cls, user, course=None, session=None):
        """Get results that can be modified by the user"""
        from .models import UserRole
        
        # Check user authorization
        if not cls._is_authorized_user(user):
            return Result.objects.none()
        
        # Get user's role and faculty context
        user_role = UserRole.objects.filter(user=user, role__in=cls.AUTHORIZED_ROLES).first()
        if not user_role:
            return Result.objects.none()
        
        # Base query for modifiable results
        results = Result.objects.filter(
            status__in=[
                'DRAFT', 'SUBMITTED_TO_EXAM_OFFICER', 'APPROVED_BY_EXAM_OFFICER',
                'SUBMITTED_TO_HOD', 'APPROVED_BY_HOD', 'SUBMITTED_TO_DEAN',
                'APPROVED_BY_DEAN', 'SUBMITTED_TO_DAAA', 'APPROVED_BY_DAAA'
            ]
        )
        
        # Filter by faculty context if user is not super admin
        if user_role.role != 'SUPER_ADMIN' and user_role.faculty:
            results = results.filter(
                enrollment__course__departments__faculty=user_role.faculty
            )
        
        # Apply additional filters
        if course:
            results = results.filter(enrollment__course=course)
        
        if session:
            results = results.filter(enrollment__session=session)
        
        return results.select_related(
            'enrollment__student__user',
            'enrollment__course',
            'enrollment__session'
        ).distinct()
    
    @classmethod
    def get_modification_statistics(cls, user, days=30):
        """Get modification statistics for the user"""
        from django.utils import timezone
        from datetime import timedelta
        
        since_date = timezone.now() - timedelta(days=days)
        
        modifications = AuditService.get_result_modification_history(None).filter(
            user=user,
            timestamp__gte=since_date
        )
        
        return {
            'total_modifications': modifications.count(),
            'carryover_changes': modifications.filter(action='CARRYOVER_STATUS_CHANGE').count(),
            'recent_modifications': modifications[:10]
        }
