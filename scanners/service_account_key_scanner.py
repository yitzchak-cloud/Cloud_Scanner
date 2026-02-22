from typing import List, Dict, Any, Optional
from collections import Counter
from datetime import datetime, timedelta, timezone

from google.cloud import asset_v1, logging_v2
from google.cloud import iam_admin_v1 as iam_v1
from google.protobuf.struct_pb2 import Struct
from google.protobuf import json_format
import googleapiclient.discovery

from gcp_scanner.base_scanner import BaseScanner
from gcp_scanner.mixins import LoggingMixin, MonitoringMixin, IamMixin, ComplianceMixin
from gcp_scanner.models import (
    ResourceReport, ResourceMetadata, Finding, Severity,
    FindingType, AccessInfo, UsageInfo, SecurityInfo,
    HealthInfo, CostInfo, ComplianceInfo, RelationshipInfo,
    MetricValue
)

def _to_dict(obj: Any) -> Any:
    """ממיר Struct/MapComposite/protobuf לאובייקט Python רגיל. בטוח גם על dict."""
    if isinstance(obj, Struct):
        return json_format.MessageToDict(obj)
    if hasattr(obj, 'items'):
        return {k: _to_dict(v) for k, v in obj.items()}
    if hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
        return [_to_dict(i) for i in obj]
    return obj


def _get_email(asset: asset_v1.ResourceSearchResult) -> str:
    """חילוץ email מ-SA asset בצורה בטוחה."""
    attrs = asset.additional_attributes
    if attrs is None:
        return ''
    return _to_dict(attrs).get('email', '')


# ══════════════════════════════════════════════════════════════════════
#  ServiceAccountKeyScanner — מטפל ב-ServiceAccountKey
#  סקנר נפרד לגמרי — לו מבנה נתונים, שדות ולוגיקה שונים לחלוטין
# ══════════════════════════════════════════════════════════════════════

class ServiceAccountKeyScanner(BaseScanner, LoggingMixin, ComplianceMixin):
    """סקנר ל-Service Account Keys"""

    SUPPORTED_TYPES = ['iam.googleapis.com/ServiceAccountKey']

    def __init__(self, project_id: str, config: Optional[Dict] = None):
        super().__init__(project_id, config)
        self._setup_clients()

    def _setup_clients(self) -> None:
        self.iam_client = iam_v1.IAMClient()
        self.setup_logging_client()

    def can_handle(self, asset_type: str) -> bool:
        return asset_type in self.SUPPORTED_TYPES

    def _get_key_attrs(self, asset: asset_v1.ResourceSearchResult) -> Dict:
        """חילוץ attributes של Key בצורה בטוחה"""
        if asset.additional_attributes is None:
            return {}
        return _to_dict(asset.additional_attributes)

    def analyze_health(self, asset: asset_v1.ResourceSearchResult,
                       metadata: ResourceMetadata) -> HealthInfo:
        """
        בדיקת תוקף ה-Key — זה הניתוח העיקרי ל-Key.
        valid_after_time ו-valid_before_time נמצאים ב-additional_attributes.
        """
        attrs = self._get_key_attrs(asset)
        health_info = HealthInfo(status='healthy')

        try:
            now = datetime.now(timezone.utc)

            # תוקף מתי פג
            valid_before = attrs.get('validBeforeTime') or attrs.get('valid_before_time')
            if valid_before:
                if isinstance(valid_before, str):
                    expiry = datetime.fromisoformat(valid_before.replace('Z', '+00:00'))
                elif hasattr(valid_before, 'seconds'):
                    expiry = datetime.fromtimestamp(valid_before.seconds, tz=timezone.utc)
                else:
                    expiry = valid_before
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)

                days_left = (expiry - now).days
                health_info.metrics['days_to_expiry'] = MetricValue(days_left, 'days')

                if days_left < 0:
                    health_info.errors.append(Finding(
                        id=f"key_expired_{metadata.resource_id}",
                        type=FindingType.SECURITY, severity=Severity.HIGH,
                        title="Service Account Key is expired",
                        description=f"Key expired {abs(days_left)} days ago",
                        recommendation="Rotate or delete this key immediately",
                        resource_id=metadata.resource_id,
                        resource_type=metadata.resource_type,
                        metadata={'days_expired': abs(days_left)}
                    ))
                elif days_left < 30:
                    health_info.warnings.append(Finding(
                        id=f"key_expiring_{metadata.resource_id}",
                        type=FindingType.OPERATIONAL, severity=Severity.MEDIUM,
                        title="Service Account Key expiring soon",
                        description=f"Key expires in {days_left} days",
                        recommendation="Rotate key before expiry",
                        resource_id=metadata.resource_id,
                        resource_type=metadata.resource_type,
                        metadata={'days_to_expiry': days_left}
                    ))

            # גיל ה-Key
            if metadata.creation_time:
                ct = metadata.creation_time
                if ct.tzinfo is None:
                    ct = ct.replace(tzinfo=timezone.utc)
                age_days = (now - ct).days
                health_info.metrics['age_days'] = MetricValue(age_days, 'days')
                if age_days > 90:
                    health_info.warnings.append(Finding(
                        id=f"key_old_{metadata.resource_id}",
                        type=FindingType.SECURITY, severity=Severity.MEDIUM,
                        title="Service Account Key is old",
                        description=f"Key is {age_days} days old — best practice is rotation every 90 days",
                        recommendation="Rotate this key",
                        resource_id=metadata.resource_id,
                        resource_type=metadata.resource_type,
                        metadata={'age_days': age_days}
                    ))

            health_info.status = (
                'unhealthy' if health_info.errors
                else 'degraded' if health_info.warnings
                else 'healthy'
            )

        except Exception as e:
            self.logger.error(f"Error analyzing key health for {metadata.resource_id}: {e}")

        return health_info

    def analyze_security(self, asset: asset_v1.ResourceSearchResult,
                         metadata: ResourceMetadata) -> SecurityInfo:
        """בדיקת סוג ה-Key — USER_MANAGED מסוכן יותר מ-SYSTEM_MANAGED"""
        attrs = self._get_key_attrs(asset)
        security_info = SecurityInfo()

        try:
            key_type = attrs.get('keyType') or attrs.get('key_type', 'UNKNOWN')
            key_algorithm = attrs.get('keyAlgorithm') or attrs.get('key_algorithm', 'UNKNOWN')

            security_info.authentication_required = True

            if key_type == 'USER_MANAGED':
                security_info.overly_permissive_findings.append(
                    "USER_MANAGED key — requires manual rotation"
                )

            metadata_extra = {
                'key_type': key_type,
                'key_algorithm': key_algorithm,
            }
            # שמירת מידע נוסף על ה-key ב-iam_bindings כ-workaround
            # (אין שדה ייעודי ב-SecurityInfo למידע זה)
            security_info.iam_bindings = [metadata_extra]

        except Exception as e:
            self.logger.error(f"Error analyzing key security for {metadata.resource_id}: {e}")

        return security_info

    def analyze_relationships(self, asset: asset_v1.ResourceSearchResult,
                              metadata: ResourceMetadata) -> RelationshipInfo:
        """ה-Key שייך ל-SA שמזוהה מתוך שם המשאב"""
        rel_info = RelationshipInfo()
        try:
            # שם: projects/.../serviceAccounts/{sa_id}/keys/{key_id}
            # parent הוא ה-SA
            parts = asset.name.split('/keys/')
            if len(parts) == 2:
                rel_info.parent = f"iam.googleapis.com/ServiceAccount///{parts[0]}"
        except Exception as e:
            self.logger.error(f"Error analyzing key relationships for {metadata.resource_id}: {e}")
        return rel_info

    def _run_custom_analyzers(self, asset: asset_v1.ResourceSearchResult,
                              report: ResourceReport) -> None:
        pass