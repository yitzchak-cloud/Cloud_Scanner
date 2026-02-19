from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from google.cloud import asset_v1, logging_v2
from google.cloud import iam_admin_v1 as iam_v1
import googleapiclient.discovery

from gcp_scanner.base_scanner import BaseScanner
from mixins import LoggingMixin, MonitoringMixin, IamMixin, ComplianceMixin
from gcp_scanner.models import (
    ResourceReport, ResourceMetadata, Finding, Severity, 
    FindingType, AccessInfo, UsageInfo, SecurityInfo,
    HealthInfo, CostInfo, ComplianceInfo, RelationshipInfo,
    MetricValue
)

class ServiceAccountScanner(BaseScanner, LoggingMixin, MonitoringMixin, IamMixin, ComplianceMixin):
    """
    סקנר ל-Service Accounts - עם כל המיקסינים
    """
    
    # סוגי משאבים שהסקנר מטפל בהם
    SUPPORTED_TYPES = [
        'iam.googleapis.com/ServiceAccount',
        'iam.googleapis.com/ServiceAccountKey'
    ]
    
    def __init__(self, project_id: str, config: Optional[Dict] = None):
        super().__init__(project_id, config)
        self._setup_clients()
    
    def _setup_clients(self):
        """הגדרת כל הלקוחות"""
        self.iam_client = iam_v1.IAMClient()
        self.cloudresourcemanager = googleapiclient.discovery.build('cloudresourcemanager', 'v3')
        
        # הפעלת מיקסינים
        self.setup_logging_client()
        self.setup_monitoring_client()
        self.setup_iam_client()
    
    def can_handle(self, asset_type: str) -> bool:
        return asset_type in self.SUPPORTED_TYPES
    
    def analyze_access(self, asset: asset_v1.ResourceSearchResult, 
                      metadata: ResourceMetadata) -> AccessInfo:
        """ניתוח גישה ל-SA"""
        email = asset.additional_attributes.get('email', '')
        
        access_info = AccessInfo()
        
        try:
            # מי יכול להשתמש ב-SA (actAs)
            policy = self._get_project_iam_policy()
            member = f'serviceAccount:{email}'
            
            for binding in policy.get('bindings', []):
                if member in binding.get('members', []):
                    access_info.principals.extend(binding.get('members', []))
                    access_info.roles.append(binding['role'])
            
            # בדיקת גישה ציבורית
            if 'allUsers' in access_info.principals or 'allAuthenticatedUsers' in access_info.principals:
                access_info.is_public = True
                access_info.public_principals = [p for p in access_info.principals 
                                                if p in ['allUsers', 'allAuthenticatedUsers']]
            
        except Exception as e:
            self.logger.error(f"Error analyzing access for {email}: {e}")
        
        return access_info
    
    def analyze_usage(self, asset: asset_v1.ResourceSearchResult, 
                     metadata: ResourceMetadata) -> UsageInfo:
        """ניתוח שימוש מתקדם"""
        email = asset.additional_attributes.get('email', '')
        usage_info = UsageInfo()
        
        try:
            # ניתוח לוגים
            filter_str = f'protoPayload.authenticationInfo.principalEmail="{email}"'
            logs = self.query_logs(filter_str, days_back=90)
            
            timestamps = []
            users = set()
            operations = []
            
            for entry in logs:
                timestamps.append(entry.timestamp)
                if hasattr(entry, 'proto_payload'):
                    method = entry.proto_payload.get('methodName', 'unknown')
                    operations.append(method)
                    
                    auth_info = entry.proto_payload.get('authenticationInfo', {})
                    if auth_info.get('principalEmail'):
                        users.add(auth_info['principalEmail'])
            
            if timestamps:
                usage_info.last_access = max(timestamps)
                usage_info.access_count_90d = len(timestamps)
                usage_info.accessed_by = list(users)
                usage_info.operations = Counter(operations)
                
                # חלוקה לתקופות
                now = datetime.utcnow()
                usage_info.access_count_7d = sum(1 for t in timestamps if t > now - timedelta(days=7))
                usage_info.access_count_30d = sum(1 for t in timestamps if t > now - timedelta(days=30))
                usage_info.unique_users_7d = len(set(u for u in users))  # approximation
            
            # מציאת משאבים שמשתמשים ב-SA
            usage_info.used_by_resources = self._find_resources_using_sa(email)
            
            # מטריקות מה-monitoring
            metric_filter = f'metric.labels.service_account_id="{metadata.resource_id}"'
            metrics = self.get_metric('iam.googleapis.com/service_account/key_validation_count', 
                                     metric_filter, days_back=7)
            if metrics:
                usage_info.metrics['key_validation_count'] = metrics[-1]  # הכי עדכני
            
        except Exception as e:
            self.logger.error(f"Error analyzing usage for {email}: {e}")
        
        return usage_info
    
    def analyze_security(self, asset: asset_v1.ResourceSearchResult, 
                        metadata: ResourceMetadata) -> SecurityInfo:
        """ניתוח אבטחה מתקדם"""
        email = asset.additional_attributes.get('email', '')
        security_info = SecurityInfo()
        
        try:
            # IAM bindings
            policy = self._get_project_iam_policy()
            member = f'serviceAccount:{email}'
            
            iam_bindings = []
            for binding in policy.get('bindings', []):
                if member in binding.get('members', []):
                    iam_bindings.append(binding)
            
            security_info.iam_bindings = iam_bindings
            
            # ניתוח הרשאות
            perm_analysis = self.analyze_permissions(iam_bindings)
            security_info.overly_permissive = perm_analysis['overly_permissive']
            security_info.has_public_access = perm_analysis['public_access']
            
            # בדיקת מפתחות
            keys = self._list_service_account_keys(email)
            if keys:
                security_info.overly_permissive_findings.append(f"Has {len(keys)} keys")
            
            # Access info
            security_info.access_info = self.analyze_access(asset, metadata)
            
            # יצירת ממצאים
            if security_info.overly_permissive:
                for dangerous in perm_analysis.get('dangerous_roles', []):
                    finding = Finding(
                        id=f"sa_dangerous_role_{metadata.resource_id}",
                        type=FindingType.SECURITY,
                        severity=Severity.HIGH,
                        title="Service Account has dangerous role",
                        description=f"SA has role {dangerous['role']}",
                        recommendation="Remove unnecessary permissions",
                        resource_id=metadata.resource_id,
                        resource_type=metadata.resource_type,
                        metadata=dangerous
                    )
                    # נוסיף מאוחר יותר ל-report
                    self._pending_findings = getattr(self, '_pending_findings', [])
                    self._pending_findings.append(finding)
            
        except Exception as e:
            self.logger.error(f"Error analyzing security for {email}: {e}")
        
        return security_info
    
    def analyze_health(self, asset: asset_v1.ResourceSearchResult, 
                      metadata: ResourceMetadata) -> HealthInfo:
        """ניתוח בריאות מתקדם"""
        email = asset.additional_attributes.get('email', '')
        health_info = HealthInfo(status='healthy')
        
        try:
            # בדיקת גיל
            if metadata.creation_time:
                age_days = (datetime.utcnow() - metadata.creation_time).days
                health_info.metrics['age_days'] = MetricValue(age_days, 'days')
                
                if age_days > 365:
                    health_info.warnings.append(Finding(
                        id=f"sa_old_{metadata.resource_id}",
                        type=FindingType.OPERATIONAL,
                        severity=Severity.LOW,
                        title="Service Account is old",
                        description=f"SA is {age_days} days old",
                        recommendation="Review if still needed",
                        resource_id=metadata.resource_id,
                        resource_type=metadata.resource_type,
                        metadata={'age_days': age_days}
                    ))
            
            # בדיקת שימוש אחרון
            usage = self.analyze_usage(asset, metadata)
            if usage.last_access:
                days_since_use = (datetime.utcnow() - usage.last_access).days
                health_info.metrics['days_since_last_use'] = MetricValue(days_since_use, 'days')
                
                if days_since_use > 90:
                    health_info.warnings.append(Finding(
                        id=f"sa_unused_{metadata.resource_id}",
                        type=FindingType.USAGE,
                        severity=Severity.MEDIUM,
                        title="Service Account is unused",
                        description=f"Not used in {days_since_use} days",
                        recommendation="Consider disabling or deleting",
                        resource_id=metadata.resource_id,
                        resource_type=metadata.resource_type,
                        metadata={'days_since_last_use': days_since_use}
                    ))
            
            # בדיקת מפתחות שעומדים לפוג
            keys = self._list_service_account_keys(email)
            expiring_soon = []
            for key in keys:
                if key.valid_before_time:
                    days_to_expiry = (key.valid_before_time - datetime.utcnow()).days
                    if 0 < days_to_expiry < 30:
                        expiring_soon.append({
                            'key_id': key.name.split('/')[-1],
                            'days_to_expiry': days_to_expiry
                        })
            
            if expiring_soon:
                health_info.warnings.append(Finding(
                    id=f"sa_keys_expiring_{metadata.resource_id}",
                    type=FindingType.OPERATIONAL,
                    severity=Severity.MEDIUM,
                    title="Service Account keys expiring soon",
                    description=f"{len(expiring_soon)} keys expire in <30 days",
                    recommendation="Rotate keys before expiry",
                    resource_id=metadata.resource_id,
                    resource_type=metadata.resource_type,
                    metadata={'expiring_keys': expiring_soon}
                ))
            
            # קביעת סטטוס כללי
            if health_info.errors:
                health_info.status = 'unhealthy'
            elif health_info.warnings:
                health_info.status = 'degraded'
            else:
                health_info.status = 'healthy'
            
        except Exception as e:
            self.logger.error(f"Error analyzing health for {email}: {e}")
        
        return health_info
    
    def analyze_compliance(self, asset: asset_v1.ResourceSearchResult, 
                        metadata: ResourceMetadata) -> ComplianceInfo:
        """ניתוח תאימות"""
        compliance_info = ComplianceInfo()
        
        try:
            # בדיקת תאימות לסטנדרטים
            standards = ['hipaa', 'pci', 'soc2']  # אפשר להפוך לקונפיג
            findings = self.check_compliance({
                'id': metadata.resource_id,
                'type': metadata.resource_type,
                'data': asset.additional_attributes
            }, standards)
            
            compliance_info.violations = findings
            compliance_info.compliant = len(findings) == 0
            compliance_info.standards = standards
            
        except Exception as e:
            self.logger.error(f"Error analyzing compliance for {metadata.resource_id}: {e}")
        
        return compliance_info
    
    def analyze_relationships(self, asset: asset_v1.ResourceSearchResult, 
                            metadata: ResourceMetadata) -> RelationshipInfo:
        """ניתוח קשרים"""
        email = asset.additional_attributes.get('email', '')
        rel_info = RelationshipInfo()
        
        try:
            # מציאת משאבים שמשתמשים ב-SA
            rel_info.dependents = self._find_resources_using_sa(email)
            
            # פרויקט parent
            rel_info.parent = f"projects/{self.project_id}"
            
            # SA keys כ-children
            keys = self._list_service_account_keys(email)
            for key in keys:
                rel_info.children.append(f"iam.googleapis.com/ServiceAccountKey/{key.name}")
            
        except Exception as e:
            self.logger.error(f"Error analyzing relationships for {email}: {e}")
        
        return rel_info
    
    def _get_project_iam_policy(self) -> Dict:
        """קבלת IAM policy של הפרויקט"""
        try:
            request = {
                'resource': f'projects/{self.project_id}'
            }
            response = self.cloudresourcemanager.projects().getIamPolicy(**request).execute()
            return response
        except Exception as e:
            self.logger.error(f"Error getting IAM policy: {e}")
            return {'bindings': []}
    
    def _list_service_account_keys(self, email: str) -> List[iam_v1.ServiceAccountKey]:
        """רשימת מפתחות של Service Account"""
        try:
            name = f'projects/{self.project_id}/serviceAccounts/{email}'
            request = iam_v1.ListServiceAccountKeysRequest(
                name=name,
                key_types=[iam_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED]
            )
            response = self.iam_client.list_service_account_keys(request=request)
            return list(response)
        except Exception as e:
            self.logger.error(f"Error listing keys for {email}: {e}")
            return []
    
    def _find_resources_using_sa(self, email: str) -> List[str]:
        """מציאת משאבים שמשתמשים ב-SA"""
        resources = []
        
        try:
            # חיפוש ב-Asset Inventory
            client = asset_v1.AssetServiceClient()
            scope = f"projects/{self.project_id}"
            
            request = asset_v1.SearchAllResourcesRequest(
                scope=scope,
                query=f"serviceAccounts:{email}",
                asset_types=[
                    'compute.googleapis.com/Instance',
                    'run.googleapis.com/Service',
                    'cloudfunctions.googleapis.com/Function',
                    'container.googleapis.com/Cluster'
                ]
            )
            
            response = client.search_all_resources(request=request)
            for asset in response:
                resources.append(f"{asset.asset_type}:{asset.display_name or asset.name}")
                
        except Exception as e:
            self.logger.error(f"Error finding resources using SA {email}: {e}")
            
        return resources
    
    def _run_custom_analyzers(self, asset: asset_v1.ResourceSearchResult, 
                            report: ResourceReport):
        """
        אנלייזרים מותאמים אישית
        """
        # הוספת ממצאים שנאספו במהלך הניתוח
        if hasattr(self, '_pending_findings'):
            for finding in self._pending_findings:
                report.add_finding(finding)
            self._pending_findings = []