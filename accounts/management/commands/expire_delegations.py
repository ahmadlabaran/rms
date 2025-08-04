from django.core.management.base import BaseCommand
from django.utils import timezone
from accounts.models import PermissionDelegation, AuditLog
from accounts.notification_service import NotificationService


class Command(BaseCommand):
    help = 'Check and expire delegation permissions that have passed their end date'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be expired without actually expiring',
        )
        parser.add_argument(
            '--notify',
            action='store_true',
            help='Send notifications to affected users',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        send_notifications = options['notify']
        
        now = timezone.now()
        
        # Find delegations that should be expired
        expired_delegations = PermissionDelegation.objects.filter(
            status='ACTIVE',
            end_date__lt=now
        ).select_related('delegate', 'delegator', 'delegated_role')
        
        # Find delegations expiring soon (within 24 hours)
        soon_expiring = PermissionDelegation.objects.filter(
            status='ACTIVE',
            end_date__gte=now,
            end_date__lt=now + timezone.timedelta(hours=24)
        ).select_related('delegate', 'delegator', 'delegated_role')
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING(f'DRY RUN: Would expire {expired_delegations.count()} delegations')
            )
            for delegation in expired_delegations:
                self.stdout.write(
                    f'  - {delegation.delegate.get_full_name()}: {delegation.delegated_role.get_role_display()}'
                )
            
            self.stdout.write(
                self.style.WARNING(f'DRY RUN: {soon_expiring.count()} delegations expiring soon')
            )
            for delegation in soon_expiring:
                time_left = delegation.get_time_remaining()
                self.stdout.write(
                    f'  - {delegation.delegate.get_full_name()}: {delegation.delegated_role.get_role_display()} ({time_left})'
                )
            return
        
        # Expire overdue delegations
        expired_count = 0
        for delegation in expired_delegations:
            try:
                self.stdout.write(
                    f'Expiring delegation: {delegation.delegate.get_full_name()} - {delegation.delegated_role.get_role_display()}'
                )
                
                # Expire the delegation
                delegation.expire()
                expired_count += 1
                
                # Send notification if requested
                if send_notifications:
                    self.send_expiration_notification(delegation)
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Error expiring delegation {delegation.id}: {str(e)}')
                )
        
        # Send warning notifications for soon-expiring delegations
        warning_count = 0
        if send_notifications:
            for delegation in soon_expiring:
                try:
                    self.send_expiration_warning(delegation)
                    warning_count += 1
                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f'Error sending warning for delegation {delegation.id}: {str(e)}')
                    )
        
        # Summary
        self.stdout.write(
            self.style.SUCCESS(f'Successfully expired {expired_count} delegations')
        )
        
        if send_notifications:
            self.stdout.write(
                self.style.SUCCESS(f'Sent {warning_count} expiration warnings')
            )
        
        # Log the cleanup operation
        if expired_count > 0:
            AuditLog.objects.create(
                user=None,  # System operation
                action='DELEGATION_CLEANUP',
                description=f'Automatic delegation cleanup: expired {expired_count} delegations',
                level='INFO'
            )

    def send_expiration_notification(self, delegation):
        """Send notification when delegation expires"""
        try:
            notification_service = NotificationService()
            
            # Notify the delegate
            notification_service.create_notification(
                user=delegation.delegate,
                title='Role Delegation Expired',
                message=f'Your delegated {delegation.delegated_role.get_role_display()} permissions have expired.',
                notification_type='DELEGATION_EXPIRED'
            )
            
            # Notify the delegator
            notification_service.create_notification(
                user=delegation.delegator,
                title='Delegation Expired',
                message=f'The {delegation.delegated_role.get_role_display()} delegation to {delegation.delegate.get_full_name()} has expired.',
                notification_type='DELEGATION_EXPIRED'
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error sending expiration notification: {str(e)}')
            )

    def send_expiration_warning(self, delegation):
        """Send warning notification for soon-expiring delegation"""
        try:
            notification_service = NotificationService()
            time_remaining = delegation.get_time_remaining()
            
            # Notify the delegate
            notification_service.create_notification(
                user=delegation.delegate,
                title='Role Delegation Expiring Soon',
                message=f'Your delegated {delegation.delegated_role.get_role_display()} permissions will expire in {time_remaining}.',
                notification_type='DELEGATION_WARNING'
            )
            
            # Notify the delegator
            notification_service.create_notification(
                user=delegation.delegator,
                title='Delegation Expiring Soon',
                message=f'The {delegation.delegated_role.get_role_display()} delegation to {delegation.delegate.get_full_name()} will expire in {time_remaining}.',
                notification_type='DELEGATION_WARNING'
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error sending expiration warning: {str(e)}')
            )
