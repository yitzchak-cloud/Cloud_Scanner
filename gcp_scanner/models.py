from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any, Set, Union
from enum import Enum
from collections import Counter
import json

class Severity(Enum):
    """רמות חומרה"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FindingType(Enum):
    """סוגי ממצאים"""
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
    """ממצא מניתוח"""
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
    
    def to_dict(self):
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['type'] = self.type.value
        data['severity'] = self.severity.value
        return data

@dataclass
class MetricValue:
    """ערך מטרי"""
    value: Union[int, float, str, bool]
    unit: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self):
        return {
            'value': self.value,
            'unit': self.unit,
            'timestamp': self.timestamp.isoformat()
        }

@dataclass
class ResourceMetadata:
    """מטדאטה כללי למשאב"""
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
    
    def to_dict(self):
        data = asdict(self)
        for time_field in ['creation_time', 'update_time', 'deletion_time']:
            if data.get(time_field):
                data[time_field] = data[time_field].isoformat()
        return data

@dataclass
class AccessInfo:
    """מידע גישה"""
    principals: List[str] = field(default_factory=list)  # מי יכול לגשת
    roles: List[str] = field(default_factory=list)       # איזה roles
    permissions: List[str] = field(default_factory=list)  # איזה permissions
    is_public: bool = False
    public_principals: List[str] = field(default_factory=list)  # allUsers, allAuthenticatedUsers
    conditions: List[Dict] = field(default_factory=list)  # תנאי גישה
    
    def to_dict(self):
        return asdict(self)

@dataclass
class UsageInfo:
    """מידע שימוש"""
    last_access: Optional[datetime] = None
    access_count_7d: int = 0
    access_count_30d: int = 0
    access_count_90d: int = 0
    unique_users_7d: int = 0
    unique_users_30d: int = 0
    unique_users_90d: int = 0
    operations: Counter = field(default_factory=Counter)  # סוגי פעולות
    accessed_by: List[str] = field(default_factory=list)  # מי ניגש
    used_by_resources: List[str] = field(default_factory=list)  # אילו משאבים משתמשים בזה
    metrics: Dict[str, MetricValue] = field(default_factory=dict)
    
    def to_dict(self):
        data = asdict(self)
        if self.last_access:
            data['last_access'] = self.last_access.isoformat()
        data['operations'] = dict(self.operations)
        data['metrics'] = {k: v.to_dict() for k, v in self.metrics.items()}
        return data

@dataclass
class SecurityInfo:
    """מידע אבטחה"""
    iam_bindings: List[Dict] = field(default_factory=list)
    has_public_access: bool = False
    overly_permissive: bool = False
    overly_permissive_findings: List[str] = field(default_factory=list)
    encryption_at_rest: bool = False
    encryption_in_transit: bool = False
    encryption_key_type: Optional[str] = None  # google-managed, customer-managed
    authentication_required: bool = True
    allowed_domains: List[str] = field(default_factory=list)
    vpc_sc_perimeter: Optional[str] = None
    shielded_vm: bool = False
    confidential_computing: bool = False
    access_info: AccessInfo = field(default_factory=AccessInfo)
    
    def to_dict(self):
        return {
            **asdict(self),
            'access_info': self.access_info.to_dict()
        }

@dataclass
class HealthInfo:
    """מידע בריאות"""
    status: str = "unknown"  # healthy, degraded, unhealthy, unknown
    errors: List[Finding] = field(default_factory=list)
    warnings: List[Finding] = field(default_factory=list)
    uptime_percentage: Optional[float] = None
    last_check: Optional[datetime] = None
    metrics: Dict[str, MetricValue] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self):
        data = asdict(self)
        if self.last_check:
            data['last_check'] = self.last_check.isoformat()
        data['errors'] = [e.to_dict() for e in self.errors]
        data['warnings'] = [w.to_dict() for w in self.warnings]
        data['metrics'] = {k: v.to_dict() for k, v in self.metrics.items()}
        return data

@dataclass
class CostInfo:
    """מידע עלויות"""
    estimated_monthly_cost: Optional[float] = None
    estimated_annual_cost: Optional[float] = None
    currency: str = "USD"
    billing_account: Optional[str] = None
    cost_findings: List[Finding] = field(default_factory=list)
    metrics: Dict[str, MetricValue] = field(default_factory=dict)
    
    def to_dict(self):
        data = asdict(self)
        data['cost_findings'] = [f.to_dict() for f in self.cost_findings]
        data['metrics'] = {k: v.to_dict() for k, v in self.metrics.items()}
        return data

@dataclass
class ComplianceInfo:
    """מידע תאימות"""
    standards: List[str] = field(default_factory=list)  # SOC2, HIPAA, PCI, etc
    compliant: bool = True
    violations: List[Finding] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self):
        data = asdict(self)
        data['violations'] = [v.to_dict() for v in self.violations]
        return data

@dataclass
class RelationshipInfo:
    """מידע קשרי גומלין"""
    parent: Optional[str] = None
    children: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)  # תלוי ב
    dependents: List[str] = field(default_factory=list)     # תלויים בו
    service_accounts: List[str] = field(default_factory=list)  # SA קשורים
    networks: List[str] = field(default_factory=list)  # רשתות קשורות
    
    def to_dict(self):
        return asdict(self)

@dataclass
class ResourceReport:
    """דוח מלא למשאב"""
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
    scan_time: datetime = field(default_factory=datetime.utcnow)
    
    def add_finding(self, finding: Finding):
        """הוספת ממצא"""
        self.findings.append(finding)
        
        # עדכון המידע הרלוונטי
        if finding.type == FindingType.SECURITY:
            self.security.overly_permissive_findings.append(finding.id)
        elif finding.type == FindingType.COMPLIANCE:
            self.compliance.violations.append(finding)
        elif finding.type == FindingType.HEALTH:
            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                self.health.errors.append(finding)
            else:
                self.health.warnings.append(finding)
    
    def to_dict(self):
        """המרה למילון"""
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
    """סיכום פרויקט"""
    project_id: str
    total_resources: int
    resource_types: Dict[str, int]  # סוג משאב -> כמות
    findings_count: Dict[str, int]   # סוג ממצא -> כמות
    severity_count: Dict[str, int]    # חומרה -> כמות
    resources_with_issues: List[str]
    top_findings: List[Finding]
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_duration: Optional[float] = None
    
    def to_dict(self):
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