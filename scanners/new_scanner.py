"""
דוגמה להוספת סקנר חדש - פשוט וקל!
"""

from typing import List, Dict, Any, Optional
from datetime import datetime

from gcp_scanner.base_scanner import BaseScanner
from gcp_scanner.models import (
    ResourceReport, ResourceMetadata, Finding, Severity, 
    FindingType, UsageInfo, SecurityInfo, HealthInfo
)

class BucketScanner(BaseScanner):
    """
    סקנר ל-Cloud Storage Buckets
    הדגמה כמה קל להוסיף סקנר חדש
    """
    
    # רק צריך להגדיר אילו סוגי משאבים הסקנר מטפל בהם
    SUPPORTED_TYPES = [
        'storage.googleapis.com/Bucket'
    ]
    
    def can_handle(self, asset_type: str) -> bool:
        return asset_type in self.SUPPORTED_TYPES
    
    # כל הפונקציות האוטומטיות יקראו לפי שמן:
    # analyze_usage, analyze_security, analyze_health וכו'
    
    def analyze_usage(self, asset, metadata):
        """ניתוח שימוש בבאקט"""
        return {
            'last_access': None,
            'access_count_30d': 0,
            'metrics': {
                'size_gb': self._get_bucket_size(asset),
                'object_count': self._get_object_count(asset)
            }
        }
    
    def analyze_security(self, asset, metadata):
        """ניתוח אבטחה"""
        security_info = {
            'has_public_access': self._check_public_access(asset),
            'encryption_at_rest': self._check_encryption(asset),
            'versioning_enabled': self._check_versioning(asset)
        }
        
        # אפשר להוסיף ממצאים
        # if security_info['has_public_access']:
        #     self._add_finding(
        #         FindingType.SECURITY,
        #         Severity.HIGH,
        #         "Bucket is publicly accessible",
        #         "Bucket allows public access",
        #         "Restrict access to authorized users only"
        #     )
        
        return security_info
    
    def analyze_health(self, asset, metadata):
        """ניתוח בריאות"""
        return {
            'status': 'healthy',
            'metrics': {
                'age_days': (datetime.utcnow() - metadata.creation_time).days if metadata.creation_time else 0
            }
        }
    
    # פונקציות עזר פרטיות
    def _get_bucket_size(self, asset):
        # מימוש...
        return 0
    
    def _get_object_count(self, asset):
        # מימוש...
        return 0
    
    def _check_public_access(self, asset):
        # מימוש...
        return False
    
    def _check_encryption(self, asset):
        # מימוש...
        return True
    
    def _check_versioning(self, asset):
        # מימוש...
        return False