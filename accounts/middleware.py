from django.utils import timezone
from django.core.cache import cache
from accounts.models import PermissionDelegation
import logging

logger = logging.getLogger(__name__)


class DelegationExpirationMiddleware:
    """
    Middleware to automatically check and expire delegations.
    Runs periodically to avoid performance impact.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        # Cache key for tracking last expiration check
        self.cache_key = 'delegation_expiration_last_check'
        # Check every 30 minutes
        self.check_interval = 30 * 60  # seconds

    def __call__(self, request):
        # Check for expired delegations periodically
        self.check_expired_delegations()
        
        response = self.get_response(request)
        return response

    def check_expired_delegations(self):
        """Check and expire delegations if enough time has passed"""
        try:
            now = timezone.now()
            last_check = cache.get(self.cache_key)
            
            # If we haven't checked recently, do the check
            if not last_check or (now - last_check).total_seconds() > self.check_interval:
                expired_count = self.expire_overdue_delegations()
                
                if expired_count > 0:
                    logger.info(f'Automatically expired {expired_count} delegations')
                
                # Update the last check time
                cache.set(self.cache_key, now, timeout=self.check_interval * 2)
                
        except Exception as e:
            logger.error(f'Error in delegation expiration check: {str(e)}')

    def expire_overdue_delegations(self):
        """Expire delegations that are past their end date"""
        now = timezone.now()
        
        # Find active delegations that should be expired
        expired_delegations = PermissionDelegation.objects.filter(
            status='ACTIVE',
            end_date__lt=now
        )
        
        expired_count = 0
        for delegation in expired_delegations:
            try:
                delegation.expire()
                expired_count += 1
            except Exception as e:
                logger.error(f'Error expiring delegation {delegation.id}: {str(e)}')
        
        return expired_count


class DelegationContextMiddleware:
    """
    Middleware to add delegation context to requests.
    Useful for templates and views that need delegation information.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Add delegation context to authenticated users
        if hasattr(request, 'user') and request.user.is_authenticated:
            self.add_delegation_context(request)
        
        response = self.get_response(request)
        return response

    def add_delegation_context(self, request):
        """Add delegation-related context to the request"""
        try:
            from accounts.permissions import (
                get_user_roles_context, 
                get_active_delegations_for_user,
                count_active_delegations
            )
            
            # Add delegation info to request for easy access in templates
            request.delegation_context = {
                'roles_with_context': get_user_roles_context(request.user),
                'active_delegations': get_active_delegations_for_user(request.user),
                'delegation_count': count_active_delegations(request.user),
                'has_delegated_roles': False
            }
            
            # Check if user has any delegated roles
            roles_info = request.delegation_context['roles_with_context']
            request.delegation_context['has_delegated_roles'] = any(
                role['is_delegated'] for role in roles_info
            )
            
        except Exception as e:
            logger.error(f'Error adding delegation context: {str(e)}')
            # Provide empty context on error
            request.delegation_context = {
                'roles_with_context': [],
                'active_delegations': [],
                'delegation_count': 0,
                'has_delegated_roles': False
            }
