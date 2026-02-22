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
    """Recursively convert Protocol Buffer objects to native Python dictionaries.
    
    Handles conversion of Struct, MapComposite, and other protobuf types to
    JSON-serializable Python objects for downstream processing.
    
    Args:
        obj: Input object of any type, potentially containing protobuf structures
        
    Returns:
        A pure Python representation with all nested protobufs converted to dicts/lists
    """
    if isinstance(obj, Struct):
        return json_format.MessageToDict(obj)
    if hasattr(obj, 'items'):
        return {k: _to_dict(v) for k, v in obj.items()}
    if hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
        return [_to_dict(i) for i in obj]
    return obj


def _get_email(asset: asset_v1.ResourceSearchResult) -> str:
    """Extract the email address from a Service Account asset with null safety.
    
    Args:
        asset: GCP asset search result containing a service account resource
        
    Returns:
        The service account email address if present, empty string otherwise
    """
    attrs = asset.additional_attributes
    if attrs is None:
        return ''
    return _to_dict(attrs).get('email', '')


# ══════════════════════════════════════════════════════════════════════
#  ServiceAccountScanner — GCP Service Account Analysis Scanner
# ══════════════════════════════════════════════════════════════════════

class ServiceAccountScanner(BaseScanner, LoggingMixin, MonitoringMixin, IamMixin, ComplianceMixin):
    """Scanner specialized in analyzing Google Cloud Platform Service Accounts.
    
    Performs comprehensive analysis of service accounts including access patterns,
    security posture, usage metrics, health status, compliance, and relationships
    with other resources. Inherits from BaseScanner and various capability mixins.
    
    Supported asset types:
        - iam.googleapis.com/ServiceAccount
    """

    SUPPORTED_TYPES = ['iam.googleapis.com/ServiceAccount']

    def __init__(self, project_id: str, config: Optional[Dict] = None):
        """Initialize the ServiceAccountScanner with project context.
        
        Args:
            project_id: GCP project identifier to scan
            config: Optional configuration dictionary for scanner customization
        """
        super().__init__(project_id, config)
        self._pending_findings: List[Finding] = []
        self._iam_policy_cache: Optional[Dict] = None
        self._setup_clients()

    def _setup_clients(self) -> None:
        """Initialize and configure all required GCP API clients.
        
        Sets up clients for IAM, Cloud Resource Manager, logging, monitoring,
        and compliance checks. Handles authentication via application default credentials.
        """
        self.iam_client = iam_v1.IAMClient()
        self.cloudresourcemanager = googleapiclient.discovery.build('cloudresourcemanager', 'v3')
        self.setup_logging_client()
        self.setup_monitoring_client()
        self.setup_iam_client()

    def can_handle(self, asset_type: str) -> bool:
        """Determine if this scanner can process the given asset type.
        
        Args:
            asset_type: GCP asset type string (e.g., 'iam.googleapis.com/ServiceAccount')
            
        Returns:
            True if the asset type is supported by this scanner, False otherwise
        """
        return asset_type in self.SUPPORTED_TYPES

    # ─── Core Analyzers ────────────────────────────────────────────────────

    def analyze_access(self, asset: asset_v1.ResourceSearchResult,
                       metadata: ResourceMetadata) -> AccessInfo:
        """Analyze access controls and permissions for a service account.
        
        Examines the project-level IAM policy to determine which roles are granted
        to the service account. Filters out deleted principals and identifies whether
        any bindings expose the project to public access via 'allUsers' or
        'allAuthenticatedUsers'. Builds a clean AccessInfo object scoped only to
        the given service account.
        
        Args:
            asset (asset_v1.ResourceSearchResult): The GCP asset representing the 
                service account, used to extract the account email via _get_email().
            metadata (ResourceMetadata): Pre-extracted resource metadata providing
                additional context such as resource_id and resource_type.
                
        Returns:
            AccessInfo: An object containing:
                - principals (List[str]): List with the service account member string
                  in the format 'serviceAccount:<email>'.
                - roles (List[str]): All IAM roles granted to this service account
                  at the project level (e.g. 'roles/cloudsql.client').
                - is_public (bool): True if the project policy contains 'allUsers'
                  or 'allAuthenticatedUsers' in any binding.
                - public_principals (List[str]): The specific public principals found
                  ('allUsers' and/or 'allAuthenticatedUsers') if is_public is True.
                - permissions (List): Empty list, reserved for future use.
                - conditions (List): Empty list, reserved for future use.
        """
        email = _get_email(asset)
        access_info = AccessInfo()
        try:
            policy = self._get_project_iam_policy()
            member = f'serviceAccount:{email}'
            
            for binding in policy.get('bindings', []):
                members = [
                    m for m in binding.get('members', [])
                    if not m.startswith('deleted:')
                ]
                if member in members:
                    access_info.roles.append(binding['role'])
            
            access_info.principals = [member]
            
            all_members = []
            for binding in policy.get('bindings', []):
                all_members.extend(binding.get('members', []))
            
            public_members = {'allUsers', 'allAuthenticatedUsers'}
            public_found = public_members.intersection(set(all_members))
            if public_found:
                access_info.is_public = True
                access_info.public_principals = list(public_found)
    
        except Exception as e:
            self.logger.error(f"Error analyzing access for {email}: {e}")
        return access_info
    
    
    def analyze_usage(self, asset: asset_v1.ResourceSearchResult,
                      metadata: ResourceMetadata) -> UsageInfo:
        """Analyze usage patterns and activity metrics for a service account.
        
        Queries Cloud Logging for all audit log entries where the service account
        was the authenticated principal over the past 90 days. Aggregates timestamps,
        unique callers, and method names to produce access frequency metrics across
        multiple time windows. Also discovers which GCP resources reference this
        service account, and fetches key validation metrics from Cloud Monitoring.
        
        Args:
            asset (asset_v1.ResourceSearchResult): The GCP asset representing the
                service account, used to extract the account email via _get_email().
            metadata (ResourceMetadata): Pre-extracted resource metadata providing
                additional context such as resource_id and resource_type.
                
        Returns:
            UsageInfo: An object containing:
                - last_access (datetime | None): UTC timestamp of the most recent
                  log entry found, or None if no logs exist.
                - access_count_7d (int): Number of log entries in the last 7 days.
                - access_count_30d (int): Number of log entries in the last 30 days.
                - access_count_90d (int): Total number of log entries in the last 90 days.
                - unique_users_7d (int): Number of distinct principal emails found
                  across all log entries (approximated over the full 90d window).
                - operations (Counter): Frequency map of methodName values seen in
                  the audit logs (e.g. {'storage.objects.get': 42}).
                - accessed_by (List[str]): List of unique principal emails that
                  authenticated as or acted on behalf of this service account.
                - used_by_resources (List[str]): GCP resource names that reference
                  this service account, as returned by _find_resources_using_sa().
                - metrics (dict): Cloud Monitoring metric snapshots, currently includes
                  'key_validation_count' (latest value over 7 days) if available.
        """
        email = _get_email(asset)
        usage_info = UsageInfo()
        try:
            logs = self.query_logs(
                f'protoPayload.authenticationInfo.principalEmail="{email}"',
                days_back=90
            )
            timestamps = []
            users: set = set()
            operations: List[str] = []
    
            for entry in logs:
                ts = entry.timestamp
                if hasattr(ts, 'seconds'):
                    ts = datetime.fromtimestamp(ts.seconds, tz=timezone.utc)
                elif ts and getattr(ts, 'tzinfo', None) is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                timestamps.append(ts)
                
                if hasattr(entry, 'proto_payload'):
                    proto = _to_dict(entry.proto_payload)
                    operations.append(proto.get('methodName', 'unknown'))
                    auth_info = proto.get('authenticationInfo', {})
                    if auth_info.get('principalEmail'):
                        users.add(auth_info['principalEmail'])
    
            if timestamps:
                now = datetime.now(timezone.utc)
                usage_info.last_access = max(timestamps)
                usage_info.access_count_90d = len(timestamps)
                usage_info.accessed_by = list(users)
                usage_info.operations = Counter(operations)
                usage_info.access_count_7d = sum(
                    1 for t in timestamps if t > now - timedelta(days=7)
                )
                usage_info.access_count_30d = sum(
                    1 for t in timestamps if t > now - timedelta(days=30)
                )
                usage_info.unique_users_7d = len(users)
    
            usage_info.used_by_resources = self._find_resources_using_sa(email)
    
            try:
                metrics = self.get_metric(
                    'iam.googleapis.com/service_account/key_validation_count',
                    f'resource.labels.email_id="{email}"',
                    days_back=7
                )
                if metrics:
                    usage_info.metrics['key_validation_count'] = metrics[-1]
            except Exception:
                pass
            
        except Exception as e:
            self.logger.error(f"Error analyzing usage for {email}: {e}")
        return usage_info
    
    
    def analyze_security(self, asset: asset_v1.ResourceSearchResult,
                         metadata: ResourceMetadata) -> SecurityInfo:
        """Evaluate the security posture of a service account.
        
        Retrieves the project-level IAM policy and extracts only the bindings
        relevant to this service account, stripping out deleted principals and
        other members to produce a clean, minimal binding list. Delegates permission
        risk evaluation to check_iam_permissions(), enumerates any user-managed keys,
        and emits high-severity findings for any dangerous roles detected.
        
        Args:
            asset (asset_v1.ResourceSearchResult): The GCP asset representing the
                service account, used to extract the account email via _get_email().
            metadata (ResourceMetadata): Pre-extracted resource metadata used to
                populate finding fields such as resource_id and resource_type.
                
        Returns:
            SecurityInfo: An object containing:
                - iam_bindings (List[dict]): Simplified list of IAM bindings scoped
                  to this service account. Each entry contains:
                    - 'role' (str): The IAM role name (e.g. 'roles/editor').
                    - 'condition' (dict, optional): Present only if a condition is
                      attached to the binding.
                - has_public_access (bool): True if check_iam_permissions() detects
                  public access exposure for this account.
                - overly_permissive (bool): True if the account holds roles deemed
                  excessively privileged by check_iam_permissions().
                - overly_permissive_findings (List[str]): Human-readable descriptions
                  of permissiveness issues, including key count if user-managed keys
                  exist (e.g. 'Has 3 keys').
                - encryption_at_rest (bool): Always False; not evaluated for SAs.
                - encryption_in_transit (bool): Always False; not evaluated for SAs.
                - authentication_required (bool): Always True for service accounts.
                - shielded_vm (bool): Always False; not applicable to SAs.
                - confidential_computing (bool): Always False; not applicable to SAs.
        
        Side effects:
            Appends one Finding per dangerous role to self._pending_findings with
            severity HIGH and type SECURITY, including the role name and resource
            context in the finding metadata.
        """
        email = _get_email(asset)
        security_info = SecurityInfo()
        try:
            policy = self._get_project_iam_policy()
            member = f'serviceAccount:{email}'
    
            iam_bindings = []
            for b in policy.get('bindings', []):
                members = [
                    m for m in b.get('members', [])
                    if not m.startswith('deleted:')
                ]
                if member in members:
                    binding_entry = {'role': b['role']}
                    if b.get('condition'):
                        binding_entry['condition'] = b['condition']
                    iam_bindings.append(binding_entry)
    
            security_info.iam_bindings = iam_bindings
    
            perm_analysis = self.check_iam_permissions(iam_bindings)
            security_info.overly_permissive = perm_analysis['overly_permissive']
            security_info.has_public_access = perm_analysis['public_access']
    
            keys = self._list_service_account_keys(email)
            if keys:
                security_info.overly_permissive_findings.append(f"Has {len(keys)} keys")
    
            if security_info.overly_permissive:
                for dangerous in perm_analysis.get('dangerous_roles', []):
                    self._pending_findings.append(Finding(
                        id=f"sa_dangerous_role_{metadata.resource_id}",
                        type=FindingType.SECURITY,
                        severity=Severity.HIGH,
                        title="Service Account has dangerous role",
                        description=f"SA has role {dangerous['role']}",
                        recommendation="Remove unnecessary permissions",
                        resource_id=metadata.resource_id,
                        resource_type=metadata.resource_type,
                        metadata=dangerous
                    ))
    
        except Exception as e:
            self.logger.error(f"Error analyzing security for {email}: {e}")
        return security_info

    def analyze_health(self, asset: asset_v1.ResourceSearchResult,
                    metadata: ResourceMetadata) -> HealthInfo:
        """Assess the health and operational status of a service account.
        
        Evaluates age, usage patterns, key expiration, and generates warnings
        for unused accounts, expiring keys, and other operational concerns.
        
        Args:
            asset: The GCP asset representing the service account
            metadata: Pre-extracted resource metadata for context
            
        Returns:
            HealthInfo object with status, warnings, errors, and health metrics
        """
        email = _get_email(asset)
        health_info = HealthInfo(status='healthy')
        try:
            if metadata.creation_time:
                ct = metadata.creation_time
                if ct.tzinfo is None:
                    ct = ct.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - ct).days
                health_info.metrics['age_days'] = MetricValue(age_days, 'days')
                if age_days > 365:
                    health_info.warnings.append(Finding(
                        id=f"sa_old_{metadata.resource_id}",
                        type=FindingType.OPERATIONAL, severity=Severity.LOW,
                        title="Service Account is old",
                        description=f"SA is {age_days} days old",
                        recommendation="Review if still needed",
                        resource_id=metadata.resource_id,
                        resource_type=metadata.resource_type,
                        metadata={'age_days': age_days}
                    ))

            usage = self.analyze_usage(asset, metadata)
            if usage.last_access:
                la = usage.last_access
                if la.tzinfo is None:
                    la = la.replace(tzinfo=timezone.utc)
                days_since = (datetime.now(timezone.utc) - la).days
                health_info.metrics['days_since_last_use'] = MetricValue(days_since, 'days')
                if days_since > 90:
                    health_info.warnings.append(Finding(
                        id=f"sa_unused_{metadata.resource_id}",
                        type=FindingType.USAGE, severity=Severity.MEDIUM,
                        title="Service Account is unused",
                        description=f"Not used in {days_since} days",
                        recommendation="Consider disabling or deleting",
                        resource_id=metadata.resource_id,
                        resource_type=metadata.resource_type,
                        metadata={'days_since_last_use': days_since}
                    ))

            keys = self._list_service_account_keys(email)
            expiring_soon = []
            for key in keys:
                if key.valid_before_time:
                    vbt = key.valid_before_time
                    if vbt.tzinfo is None:
                        vbt = vbt.replace(tzinfo=timezone.utc)
                    days_left = (vbt - datetime.now(timezone.utc)).days
                    if 0 < days_left < 30:
                        expiring_soon.append({
                            'key_id': key.name.split('/')[-1],
                            'days_to_expiry': days_left
                        })
            if expiring_soon:
                health_info.warnings.append(Finding(
                    id=f"sa_keys_expiring_{metadata.resource_id}",
                    type=FindingType.OPERATIONAL, severity=Severity.MEDIUM,
                    title="Service Account keys expiring soon",
                    description=f"{len(expiring_soon)} keys expire in <30 days",
                    recommendation="Rotate keys before expiry",
                    resource_id=metadata.resource_id,
                    resource_type=metadata.resource_type,
                    metadata={'expiring_keys': expiring_soon}
                ))

            health_info.status = (
                'unhealthy' if health_info.errors
                else 'degraded' if health_info.warnings
                else 'healthy'
            )
        except Exception as e:
            self.logger.error(f"Error analyzing health for {email}: {e}")
        return health_info

    def analyze_compliance(self, asset: asset_v1.ResourceSearchResult,
                        metadata: ResourceMetadata) -> ComplianceInfo:
        """Evaluate compliance posture against industry standards.
        
        Checks the service account against common compliance frameworks
        (HIPAA, PCI, SOC2) and identifies violations.
        
        Args:
            asset: The GCP asset representing the service account
            metadata: Pre-extracted resource metadata for context
            
        Returns:
            ComplianceInfo object with standards status and violations
        """
        compliance_info = ComplianceInfo()
        try:
            standards = ['hipaa', 'pci', 'soc2']
            findings = self.check_compliance({
                'id': metadata.resource_id,
                'type': metadata.resource_type,
                'data': _to_dict(asset.additional_attributes) if asset.additional_attributes else {}
            }, standards)
            compliance_info.violations = findings
            compliance_info.compliant = len(findings) == 0
            compliance_info.standards = standards
        except Exception as e:
            self.logger.error(f"Error analyzing compliance for {metadata.resource_id}: {e}")
        return compliance_info

    def analyze_relationships(self, asset: asset_v1.ResourceSearchResult,
                              metadata: ResourceMetadata) -> RelationshipInfo:
        """Map resource relationships and dependencies.
        
        Identifies parent project, dependent resources that use this service account,
        and associated resources like service account keys.
        
        Args:
            asset: The GCP asset representing the service account
            metadata: Pre-extracted resource metadata for context
            
        Returns:
            RelationshipInfo object with parent, children, and dependents
        """
        email = _get_email(asset)
        rel_info = RelationshipInfo()
        try:
            rel_info.dependents = self._find_resources_using_sa(email)
            rel_info.parent = f"projects/{self.project_id}"
            for key in self._list_service_account_keys(email):
                rel_info.children.append(f"iam.googleapis.com/ServiceAccountKey/{key.name}")
        except Exception as e:
            self.logger.error(f"Error analyzing relationships for {email}: {e}")
        return rel_info

    # ─── Helper Methods ──────────────────────────────────────────────────────

    def _get_project_iam_policy(self) -> Dict:
        """Retrieve the IAM policy for the current GCP project.
        
        Implements caching to avoid repeated API calls during a scan session.
        Falls back to empty policy on API errors.
        
        Returns:
            Dictionary containing IAM policy bindings in the format:
            {'bindings': [{'role': 'roles/...', 'members': [...]}]}
        """
        if self._iam_policy_cache is not None:
            return self._iam_policy_cache
        try:
            response = (
                self.cloudresourcemanager.projects()
                .getIamPolicy(resource=f'projects/{self.project_id}')
                .execute()
            )
            self._iam_policy_cache = response
            return response
        except Exception as e:
            self.logger.error(f"Error getting IAM policy: {e}")
            return {'bindings': []}

    def _list_service_account_keys(self, email: str) -> List:
        """List all user-managed keys associated with a service account.
        
        Args:
            email: Service account email address
            
        Returns:
            List of service account key objects (may be empty on error)
        """
        try:
            response = self.iam_client.list_service_account_keys(
                request=iam_v1.ListServiceAccountKeysRequest(
                    name=f'projects/{self.project_id}/serviceAccounts/{email}',
                    key_types=[iam_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED]
                )
            )
            return list(response.keys)
        except Exception as e:
            self.logger.error(f"Error listing keys for {email}: {e}")
            return []

    def _find_resources_using_sa(self, email: str) -> List[str]:
        """Discover GCP resources that reference or use this service account.
        
        Searches IAM policies across all resources in the project to find
        bindings that include the service account.
        
        Args:
            email: Service account email address
            
        Returns:
            List of resource identifiers that reference this service account
        """
        resources = []
        try:
            response = asset_v1.AssetServiceClient().search_all_iam_policies(
                request=asset_v1.SearchAllIamPoliciesRequest(
                    scope=f"projects/{self.project_id}",
                    query=f'policy:"serviceAccount:{email}"'
                )
            )
            for result in response:
                resources.append(result.resource)
        except Exception as e:
            self.logger.error(f"Error finding resources using SA {email}: {e}")
        return resources

    def _run_custom_analyzers(self, asset: asset_v1.ResourceSearchResult,
                              report: ResourceReport) -> None:
        """Execute custom analysis logic and attach findings to the report.
        
        Processes any findings accumulated during analysis and adds them
        to the resource report.
        
        Args:
            asset: The GCP asset being analyzed
            report: The resource report to update with findings
        """
        for finding in self._pending_findings:
            report.add_finding(finding)
        self._pending_findings = []