from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any, Set, Union
from enum import Enum
from collections import Counter


class Severity(Enum):
    """Enumeration of severity levels for findings and issues.
    
    Attributes:
        CRITICAL: Critical severity - requires immediate attention, system impact
        HIGH: High severity - should be addressed soon, significant impact
        MEDIUM: Medium severity - moderate impact, planned remediation
        LOW: Low severity - minimal impact, informational
        INFO: Informational - no action required, for awareness
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(Enum):
    """Classification of finding types across different domains.
    
    Attributes:
        SECURITY: Security vulnerabilities, misconfigurations, or risks
        PERFORMANCE: Performance bottlenecks, optimization opportunities
        COST: Cost optimization, waste identification, savings opportunities
        COMPLIANCE: Regulatory and standard compliance violations
        RELIABILITY: Reliability concerns, availability issues, redundancy
        OPERATIONAL: Operational efficiency, monitoring, maintenance
        USAGE: Usage patterns, inactive resources, utilization metrics
        ACCESS: Access control issues, permission problems
        HEALTH: Resource health status, errors, degradation
    """
    SECURITY = "security"
    PERFORMANCE = "performance"
    COST = "cost"
    COMPLIANCE = "compliance"
    RELIABILITY = "reliability"
    OPERATIONAL = "operational"
    USAGE = "usage"
    ACCESS = "access"
    HEALTH = "health"


@dataclass
class Finding:
    """Represents a single finding or issue discovered during analysis.
    
    A finding encapsulates a specific observation about a resource, including
    its severity, type, and recommended remediation steps.
    
    Attributes:
        id: Unique identifier for the finding
        type: Category of the finding from FindingType enum
        severity: Severity level from Severity enum
        title: Concise, human-readable title
        description: Detailed description of the issue
        recommendation: Actionable steps to resolve the finding
        resource_id: Identifier of the affected resource
        resource_type: Type of the affected resource (e.g., 'compute_instance')
        metadata: Additional key-value pairs with context-specific data
        created_at: Timestamp when the finding was created (UTC)
    """
    id: str
    type: FindingType
    severity: Severity
    title: str
    description: str
    recommendation: str
    resource_id: str
    resource_type: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the finding to a dictionary representation.
        
        Returns:
            Dictionary with all fields, with enums converted to strings
            and datetime to ISO format.
        """
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['type'] = self.type.value
        data['severity'] = self.severity.value
        return data


@dataclass
class MetricValue:
    """Represents a metric value with optional unit and timestamp.
    
    Attributes:
        value: The actual metric value (numeric, string, or boolean)
        unit: Optional unit of measurement (e.g., 'bytes', 'seconds')
        timestamp: When the metric was recorded (UTC)
    """
    value: Union[int, float, str, bool]
    unit: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with ISO-formatted timestamp."""
        return {
            'value': self.value,
            'unit': self.unit,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ResourceMetadata:
    """Core metadata information for any cloud resource.
    
    Provides essential identification and descriptive information about
    a resource, including its hierarchy and lifecycle state.
    
    Attributes:
        resource_id: Unique identifier of the resource
        resource_type: Type classification of the resource
        project_id: Project or account identifier containing the resource
        name: Resource name
        display_name: Optional human-readable display name
        location: Geographic location or region
        labels: Key-value pairs for resource categorization
        creation_time: When the resource was created (UTC)
        update_time: Last modification timestamp (UTC)
        deletion_time: When the resource was deleted, if applicable (UTC)
        parent: Identifier of the parent resource, if any
        state: Current lifecycle state of the resource
        etag: Entity tag for concurrency control
        raw_data: Original raw data from the cloud provider
    """
    resource_id: str
    resource_type: str
    project_id: str
    name: str
    display_name: Optional[str] = None
    location: Optional[str] = None
    labels: Dict[str, str] = field(default_factory=dict)
    creation_time: Optional[datetime] = None
    update_time: Optional[datetime] = None
    deletion_time: Optional[datetime] = None
    parent: Optional[str] = None
    state: Optional[str] = None
    etag: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with datetime fields as ISO strings."""
        data = asdict(self)
        for time_field in ['creation_time', 'update_time', 'deletion_time']:
            if data.get(time_field):
                data[time_field] = data[time_field].isoformat()
        return data


@dataclass
class AccessInfo:
    """Comprehensive access control information for a resource.
    
    Details who can access the resource, with what permissions,
    and under what conditions.
    
    Attributes:
        principals: List of identities (users, groups, SAs) with access
        roles: IAM roles assigned to principals
        permissions: Specific permissions granted
        is_public: Whether the resource is publicly accessible
        public_principals: Special public principals (allUsers, allAuthenticatedUsers)
        conditions: Access conditions (time-based, resource-based, etc.)
    """
    principals: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    is_public: bool = False
    public_principals: List[str] = field(default_factory=list)
    conditions: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


@dataclass
class UsageInfo:
    """Usage patterns and metrics for a resource.
    
    Tracks access patterns, usage frequency, and resource utilization.
    
    Attributes:
        last_access: Most recent access timestamp (UTC)
        access_count_7d: Number of accesses in last 7 days
        access_count_30d: Number of accesses in last 30 days
        access_count_90d: Number of accesses in last 90 days
        unique_users_7d: Unique users in last 7 days
        unique_users_30d: Unique users in last 30 days
        unique_users_90d: Unique users in last 90 days
        operations: Counter of operation types performed
        accessed_by: List of identities that accessed the resource
        used_by_resources: Resources that depend on/use this resource
        metrics: Additional usage metrics by name
    """
    last_access: Optional[datetime] = None
    access_count_7d: int = 0
    access_count_30d: int = 0
    access_count_90d: int = 0
    unique_users_7d: int = 0
    unique_users_30d: int = 0
    unique_users_90d: int = 0
    operations: Counter = field(default_factory=Counter)
    accessed_by: List[str] = field(default_factory=list)
    used_by_resources: List[str] = field(default_factory=list)
    metrics: Dict[str, MetricValue] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with proper serialization of special fields."""
        data = asdict(self)
        if self.last_access:
            data['last_access'] = self.last_access.isoformat()
        data['operations'] = dict(self.operations)
        data['metrics'] = {k: v.to_dict() for k, v in self.metrics.items()}
        return data


@dataclass
class SecurityInfo:
    """Security posture information for a resource.
    
    Encapsulates security configurations, findings, and access controls.
    
    Attributes:
        iam_bindings: Raw IAM policy bindings
        has_public_access: Flag indicating public exposure
        overly_permissive: Whether resource has excessive permissions
        overly_permissive_findings: IDs of related security findings
        encryption_at_rest: Whether data is encrypted at rest
        encryption_in_transit: Whether data is encrypted in transit
        encryption_key_type: Type of encryption key (google-managed, customer-managed)
        authentication_required: Whether authentication is enforced
        allowed_domains: Domains permitted to access the resource
        vpc_sc_perimeter: VPC Service Controls perimeter name, if any
        shielded_vm: Whether shielded VM features are enabled
        confidential_computing: Whether confidential computing is enabled
        access_info: Detailed access control information
    """
    iam_bindings: List[Dict] = field(default_factory=list)
    has_public_access: bool = False
    overly_permissive: bool = False
    overly_permissive_findings: List[str] = field(default_factory=list)
    encryption_at_rest: bool = False
    encryption_in_transit: bool = False
    encryption_key_type: Optional[str] = None
    authentication_required: bool = True
    allowed_domains: List[str] = field(default_factory=list)
    vpc_sc_perimeter: Optional[str] = None
    shielded_vm: bool = False
    confidential_computing: bool = False
    access_info: AccessInfo = field(default_factory=AccessInfo)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with nested object serialization."""
        return {
            **asdict(self),
            'access_info': self.access_info.to_dict()
        }


@dataclass
class HealthInfo:
    """Health and operational status of a resource.
    
    Attributes:
        status: Current health status (healthy, degraded, unhealthy, unknown)
        errors: Critical health findings
        warnings: Non-critical health findings
        uptime_percentage: Historical uptime percentage
        last_check: Last health check timestamp (UTC)
        metrics: Health-related metrics
        recommendations: Suggested improvements
    """
    status: str = "unknown"
    errors: List[Finding] = field(default_factory=list)
    warnings: List[Finding] = field(default_factory=list)
    uptime_percentage: Optional[float] = None
    last_check: Optional[datetime] = None
    metrics: Dict[str, MetricValue] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with nested object serialization."""
        data = asdict(self)
        if self.last_check:
            data['last_check'] = self.last_check.isoformat()
        data['errors'] = [e.to_dict() for e in self.errors]
        data['warnings'] = [w.to_dict() for w in self.warnings]
        data['metrics'] = {k: v.to_dict() for k, v in self.metrics.items()}
        return data


@dataclass
class CostInfo:
    """Cost and billing information for a resource.
    
    Attributes:
        estimated_monthly_cost: Projected monthly cost
        estimated_annual_cost: Projected annual cost
        currency: Currency code (default: USD)
        billing_account: Associated billing account
        cost_findings: Cost-related findings and recommendations
        metrics: Cost-related metrics
    """
    estimated_monthly_cost: Optional[float] = None
    estimated_annual_cost: Optional[float] = None
    currency: str = "USD"
    billing_account: Optional[str] = None
    cost_findings: List[Finding] = field(default_factory=list)
    metrics: Dict[str, MetricValue] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with nested object serialization."""
        data = asdict(self)
        data['cost_findings'] = [f.to_dict() for f in self.cost_findings]
        data['metrics'] = {k: v.to_dict() for k, v in self.metrics.items()}
        return data


@dataclass
class ComplianceInfo:
    """Compliance and regulatory information.
    
    Attributes:
        standards: List of compliance standards (e.g., SOC2, HIPAA, PCI)
        compliant: Overall compliance status
        violations: Compliance violations as findings
        evidence: Compliance evidence data
    """
    standards: List[str] = field(default_factory=list)
    compliant: bool = True
    violations: List[Finding] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with nested object serialization."""
        data = asdict(self)
        data['violations'] = [v.to_dict() for v in self.violations]
        return data


@dataclass
class RelationshipInfo:
    """Resource relationship and dependency information.
    
    Maps the hierarchical and dependency relationships between resources.
    
    Attributes:
        parent: Parent resource identifier
        children: Child resource identifiers
        dependencies: Resources this resource depends on
        dependents: Resources that depend on this resource
        service_accounts: Associated service accounts
        networks: Associated network resources
    """
    parent: Optional[str] = None
    children: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    dependents: List[str] = field(default_factory=list)
    service_accounts: List[str] = field(default_factory=list)
    networks: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return asdict(self)


@dataclass
class ResourceReport:
    """Comprehensive resource analysis report.
    
    Aggregates all information about a resource including metadata,
    security, usage, health, cost, compliance, and relationships.
    
    Attributes:
        metadata: Core resource metadata
        access: Access control information
        usage: Usage patterns and metrics
        security: Security posture information
        health: Health and operational status
        cost: Cost and billing information
        compliance: Compliance status and violations
        relationships: Resource relationships
        findings: All findings for this resource
        raw_data: Original raw data from the cloud provider
        scanner_version: Version of the scanner that generated this report
        scan_time: When the scan was performed (UTC)
    """
    metadata: ResourceMetadata
    access: AccessInfo = field(default_factory=AccessInfo)
    usage: UsageInfo = field(default_factory=UsageInfo)
    security: SecurityInfo = field(default_factory=SecurityInfo)
    health: HealthInfo = field(default_factory=HealthInfo)
    cost: CostInfo = field(default_factory=CostInfo)
    compliance: ComplianceInfo = field(default_factory=ComplianceInfo)
    relationships: RelationshipInfo = field(default_factory=RelationshipInfo)
    findings: List[Finding] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    scanner_version: str = "2.0"
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the report and update relevant sections.
        
        Args:
            finding: The finding to add
        """
        self.findings.append(finding)
        
        # Update relevant information based on finding type
        if finding.type == FindingType.SECURITY:
            self.security.overly_permissive_findings.append(finding.id)
        elif finding.type == FindingType.COMPLIANCE:
            self.compliance.violations.append(finding)
        elif finding.type == FindingType.HEALTH:
            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                self.health.errors.append(finding)
            else:
                self.health.warnings.append(finding)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the complete report to a dictionary.
        
        Returns:
            Dictionary representation with all nested objects serialized.
        """
        return {
            'metadata': self.metadata.to_dict(),
            'access': self.access.to_dict(),
            'usage': self.usage.to_dict(),
            'security': self.security.to_dict(),
            'health': self.health.to_dict(),
            'cost': self.cost.to_dict(),
            'compliance': self.compliance.to_dict(),
            'relationships': self.relationships.to_dict(),
            'findings': [f.to_dict() for f in self.findings],
            'scanner_version': self.scanner_version,
            'scan_time': self.scan_time.isoformat()
        }


@dataclass
class ProjectSummary:
    """High-level summary of a project scan.
    
    Provides aggregated statistics and key insights from scanning
    all resources within a project.
    
    Attributes:
        project_id: Project identifier
        total_resources: Total number of resources scanned
        resource_types: Count of resources by type
        findings_count: Count of findings by type
        severity_count: Count of findings by severity
        resources_with_issues: List of resource IDs that have issues
        top_findings: Most critical or important findings
        scan_time: When the scan was performed (UTC)
        scan_duration: Duration of the scan in seconds
    """
    project_id: str
    total_resources: int
    resource_types: Dict[str, int]
    findings_count: Dict[str, int]
    severity_count: Dict[str, int]
    resources_with_issues: List[str]
    top_findings: List[Finding]
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_duration: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with summary statistics.
        
        Returns:
            Dictionary with summary data, including count of resources with issues.
        """
        return {
            'project_id': self.project_id,
            'total_resources': self.total_resources,
            'resource_types': self.resource_types,
            'findings_count': self.findings_count,
            'severity_count': self.severity_count,
            'resources_with_issues_count': len(self.resources_with_issues),
            'top_findings': [f.to_dict() for f in self.top_findings[:10]],
            'scan_time': self.scan_time.isoformat()
        }