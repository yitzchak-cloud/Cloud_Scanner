# GCP Scanner Framework — Developer Guide

> **Everything you need to add a new scanner without reading any other file.**

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Data Models](#data-models)
3. [Mixins Reference](#mixins-reference)
4. [BaseScanner — Full API](#basescanner--full-api)
5. [Building a New Scanner — Step-by-Step](#building-a-new-scanner--step-by-step)
6. [Complete Scanner Example](#complete-scanner-example)
7. [Registering Your Scanner](#registering-your-scanner)
8. [Configuration Reference](#configuration-reference)
9. [Findings & Severity Guide](#findings--severity-guide)
10. [Common Patterns & Recipes](#common-patterns--recipes)
11. [Testing Your Scanner](#testing-your-scanner)
12. [Checklist](#checklist)

---

## Architecture Overview

```
ScanEngine
│
├── discovers all GCP resources via Asset Inventory API
│
├── routes each resource to the correct scanner (via can_handle())
│
└── scanners/
    ├── BaseScanner (abstract base — you inherit from this)
    │     ├── Mixins (LoggingMixin, MonitoringMixin, IamMixin, ComplianceMixin)
    │     └── auto-registers every method named analyze_*()
    │
    ├── ServiceAccountScanner
    ├── ServiceAccountKeyScanner
    └── YOUR NEW SCANNER HERE
```

### How a scan flows

```
ScanEngine.scan_all()
  └── discover_all_resources()          # fetches all assets from GCP
        └── scanner.can_handle(type)    # routes asset to the right scanner
  └── scanner.scan_resource(asset)
        ├── _create_metadata(asset)     # builds ResourceMetadata
        ├── analyze_usage(asset, meta)  # auto-discovered
        ├── analyze_security(asset, meta)
        ├── analyze_health(asset, meta)
        ├── analyze_compliance(asset, meta)
        └── _run_custom_analyzers()     # hook for extra logic
```

---

## Data Models

All models live in `gcp_scanner/models.py`. You never need to create raw dicts — use these dataclasses.

### `ResourceReport` — what your scanner returns for each resource

```python
@dataclass
class ResourceReport:
    metadata:      ResourceMetadata   # who/what/where
    access:        AccessInfo         # who can access it
    usage:         UsageInfo          # how actively it's used
    security:      SecurityInfo       # encryption, IAM, public access
    health:        HealthInfo         # is it working?
    cost:          CostInfo           # estimated cost
    compliance:    ComplianceInfo     # HIPAA/PCI/etc
    relationships: RelationshipInfo   # parent/children/deps
    findings:      List[Finding]      # all issues discovered
```

`ResourceReport` is **created for you** by `BaseScanner.scan_resource()`. Your `analyze_*` methods just need to return the right data — the base class writes it into the report automatically.

---

### `Finding` — one issue discovered during analysis

```python
Finding(
    id="unique_id",
    type=FindingType.SECURITY,        # see FindingType enum
    severity=Severity.HIGH,           # see Severity enum
    title="Short title",
    description="What is wrong and why it matters",
    recommendation="How to fix it",
    resource_id="projects/my-proj/...",
    resource_type="iam.googleapis.com/ServiceAccount",
    metadata={"extra": "context"},    # any extra key-value data
)
```

**`FindingType` options:**

| Value | Use when |
|---|---|
| `SECURITY` | IAM issues, public access, missing encryption |
| `PERFORMANCE` | CPU/memory bottlenecks |
| `COST` | Waste, idle resources |
| `COMPLIANCE` | HIPAA, PCI, SOC2, GDPR violations |
| `RELIABILITY` | No redundancy, SLA risks |
| `OPERATIONAL` | Missing monitoring, scan errors |
| `USAGE` | Unused/idle resources |
| `ACCESS` | Permission problems |
| `HEALTH` | Errors, degraded state |

**`Severity` options:**

| Value | Meaning |
|---|---|
| `CRITICAL` | Immediate action required — system at risk |
| `HIGH` | Fix soon — significant impact |
| `MEDIUM` | Plan remediation — moderate impact |
| `LOW` | Nice to fix — minimal impact |
| `INFO` | Informational only |

---

### `ResourceMetadata` — auto-populated for you

```python
@dataclass
class ResourceMetadata:
    resource_id:   str
    resource_type: str               # e.g. "iam.googleapis.com/ServiceAccount"
    project_id:    str
    name:          str               # short name, last segment of full path
    display_name:  Optional[str]
    location:      Optional[str]
    labels:        Dict[str, str]
    creation_time: Optional[datetime]
    update_time:   Optional[datetime]
    state:         Optional[str]
```

You receive this as the second argument to every `analyze_*` method. You don't create it yourself.

---

### Other model fields your `analyze_*` methods should return

| Analyzer method | Expected return type | Key fields to populate |
|---|---|---|
| `analyze_usage` | `UsageInfo` or `dict` | `last_access`, `access_count_*d`, `unique_users_*d`, `metrics` |
| `analyze_security` | `SecurityInfo` or `dict` | `has_public_access`, `encryption_at_rest`, `iam_bindings` |
| `analyze_health` | `HealthInfo` or `dict` | `status`, `errors`, `warnings`, `uptime_percentage` |
| `analyze_cost` | `CostInfo` or `dict` | `estimated_monthly_cost`, `currency` |
| `analyze_compliance` | `ComplianceInfo` or `dict` | `standards`, `compliant`, `violations` |
| `analyze_access` | `AccessInfo` or `dict` | `principals`, `roles`, `is_public` |
| `analyze_relationships` | `RelationshipInfo` or `dict` | `parent`, `children`, `dependencies` |

You can also return a plain `dict` with a `findings` key containing `List[Finding]`:

```python
return {
    'status': 'degraded',
    'findings': [Finding(...)]
}
```

---

## Mixins Reference

Mixins add ready-made capabilities. Inherit from them alongside `BaseScanner`.

```python
class MyScanner(BaseScanner, LoggingMixin, MonitoringMixin, IamMixin, ComplianceMixin):
    ...
```

Call the corresponding `setup_*_client()` in your `__init__`:

```python
def __init__(self, project_id: str, config=None):
    super().__init__(project_id, config)
    self.setup_logging_client()
    self.setup_monitoring_client()
    self.setup_iam_client()
```

---

### `LoggingMixin`

```python
# Low-level log search
entries = self.query_logs(filter_str="resource.type=gcs_bucket", days_back=7)

# High-level access summary
summary = self.get_access_logs_summary(resource_name="my-bucket", days_back=30)
# Returns:
# {
#   'total_access':   142,
#   'unique_users':   5,
#   'users':          ['alice@example.com', ...],
#   'operations':     {'storage.objects.get': 120, ...},
#   'first_access':   datetime(...),
#   'last_access':    datetime(...)
# }
```

---

### `MonitoringMixin`

```python
# Fetch time-series metrics
metrics = self.get_metric(
    metric_type="run.googleapis.com/container/cpu/utilization",
    filter_str='resource.labels.service_name="my-service"',
    days_back=7
)
# Returns List[MetricValue]
# Each MetricValue: .value (float), .unit (str), .timestamp (datetime)
```

Common GCP metric types:

| Resource | Metric |
|---|---|
| Cloud Run | `run.googleapis.com/container/cpu/utilization` |
| GCS | `storage.googleapis.com/api/request_count` |
| Compute | `compute.googleapis.com/instance/cpu/utilization` |
| Functions | `cloudfunctions.googleapis.com/function/execution_count` |

---

### `IamMixin`

```python
# Analyze IAM bindings for risks
result = self.check_iam_permissions(iam_bindings=asset.iam_policy.bindings)
# Returns:
# {
#   'overly_permissive': True,
#   'public_access':     False,
#   'dangerous_roles':   [{'role': 'roles/owner', 'members': [...]}],
#   'findings':          [{'type': 'public_access', 'role': ..., 'members': [...]}]
# }
```

Dangerous roles checked automatically: `roles/owner`, `roles/editor`, `roles/iam.securityAdmin`, `roles/iam.serviceAccountAdmin`.

---

### `ComplianceMixin`

```python
# Check against compliance frameworks
violations = self.check_compliance(
    resource_data={'id': resource_id, 'type': asset_type, 'encryption': False},
    standards=['hipaa', 'pci', 'soc2', 'gdpr']
)
# Returns List[Finding] — one per missing control
```

Available standards and their requirements:

| Standard | Requirements checked |
|---|---|
| `hipaa` | encryption, audit_logs, access_controls |
| `pci` | encryption, network_security, access_controls |
| `soc2` | encryption, audit_logs, availability |
| `gdpr` | data_residency, access_controls, retention |

To add custom requirement logic, override `_check_requirement(resource_data, requirement)` in your scanner.

---

## BaseScanner — Full API

### Abstract method you **must** implement

```python
@abstractmethod
def can_handle(self, asset_type: str) -> bool:
    """Return True if this scanner handles the given GCP asset type."""
    pass
```

### Methods you **should** implement (auto-discovered)

Name them exactly `analyze_<something>`. The base class finds and runs them automatically.

```python
def analyze_usage(self, asset, metadata: ResourceMetadata) -> UsageInfo | dict:
    ...

def analyze_security(self, asset, metadata: ResourceMetadata) -> SecurityInfo | dict:
    ...

def analyze_health(self, asset, metadata: ResourceMetadata) -> HealthInfo | dict:
    ...

def analyze_compliance(self, asset, metadata: ResourceMetadata) -> ComplianceInfo | dict:
    ...

def analyze_access(self, asset, metadata: ResourceMetadata) -> AccessInfo | dict:
    ...

def analyze_cost(self, asset, metadata: ResourceMetadata) -> CostInfo | dict:
    ...

def analyze_relationships(self, asset, metadata: ResourceMetadata) -> RelationshipInfo | dict:
    ...
```

### Optional hook

```python
def _run_custom_analyzers(self, asset, report: ResourceReport):
    """
    Called after all analyze_* methods. Use for cross-cutting logic
    that needs results from multiple analyzers.
    """
    pass
```

### What `scan_resource()` does (you do NOT override this)

1. Checks cache — returns cached result if fresh
2. Calls `_create_metadata(asset)` → `ResourceMetadata`
3. Creates empty `ResourceReport`
4. Discovers and runs every `analyze_*` method
5. Maps each result into the correct `report.*` field
6. Calls `_run_custom_analyzers()`
7. Caches the result
8. Updates stats

---

## Building a New Scanner — Step-by-Step

### Step 1 — Create your file

```
scanners/
└── my_resource_scanner.py   ← new file
```

### Step 2 — Inherit from `BaseScanner` and any needed mixins

```python
from gcp_scanner.base_scanner import BaseScanner
from gcp_scanner.mixins import LoggingMixin, MonitoringMixin, IamMixin, ComplianceMixin
from gcp_scanner.models import (
    ResourceMetadata, Finding, Severity, FindingType,
    UsageInfo, SecurityInfo, HealthInfo, ComplianceInfo,
    AccessInfo, RelationshipInfo, MetricValue
)
from google.cloud import asset_v1
from typing import Optional, Dict

class MyResourceScanner(BaseScanner, LoggingMixin, MonitoringMixin, IamMixin, ComplianceMixin):
    ...
```

### Step 3 — Define the asset types you handle

```python
HANDLED_ASSET_TYPES = {
    "storage.googleapis.com/Bucket",        # example
    "compute.googleapis.com/Instance",      # example
}
```

### Step 4 — Write `__init__`

```python
def __init__(self, project_id: str, config: Optional[Dict] = None):
    super().__init__(project_id, config)
    # Initialize only the mixin clients you actually use:
    self.setup_logging_client()
    self.setup_monitoring_client()
    self.setup_iam_client()
```

### Step 5 — Implement `can_handle`

```python
def can_handle(self, asset_type: str) -> bool:
    return asset_type in self.HANDLED_ASSET_TYPES
```

### Step 6 — Write your `analyze_*` methods

Each method:
- Receives `(self, asset: asset_v1.ResourceSearchResult, metadata: ResourceMetadata)`
- Returns the matching model object **or** a plain `dict` (optionally with a `findings` key)
- Should not raise exceptions — catch errors and return partial data instead

```python
def analyze_security(self, asset, metadata: ResourceMetadata) -> dict:
    findings = []
    iam_result = self.check_iam_permissions(asset.iam_policy.bindings)

    if iam_result['public_access']:
        findings.append(Finding(
            id=f"public_access_{metadata.resource_id}",
            type=FindingType.SECURITY,
            severity=Severity.CRITICAL,
            title="Resource is publicly accessible",
            description="The resource allows access by allUsers or allAuthenticatedUsers.",
            recommendation="Remove public IAM bindings unless explicitly required.",
            resource_id=metadata.resource_id,
            resource_type=metadata.resource_type,
        ))

    return {
        'has_public_access': iam_result['public_access'],
        'overly_permissive': iam_result['overly_permissive'],
        'iam_bindings': [dict(b) for b in asset.iam_policy.bindings],
        'findings': findings
    }
```

### Step 7 — Register your scanner

Open `scanners/registry.py` and add your class:

```python
from scanners.my_resource_scanner import MyResourceScanner

def get_default_scanner_classes():
    return [
        ServiceAccountScanner,
        ServiceAccountKeyScanner,
        MyResourceScanner,   # ← add here
    ]
```

That's it. `ScanEngine` picks it up automatically.

---

## Complete Scanner Example

Below is a full, working example of a **Cloud Storage Bucket scanner** that you can use as a template.

```python
"""
scanners/gcs_bucket_scanner.py

Scans Cloud Storage buckets for security, usage, and compliance issues.
"""

from typing import Optional, Dict, List
from datetime import datetime, timezone

from google.cloud import asset_v1
from google.cloud import storage

from gcp_scanner.base_scanner import BaseScanner
from gcp_scanner.mixins import LoggingMixin, MonitoringMixin, IamMixin, ComplianceMixin
from gcp_scanner.models import (
    ResourceMetadata, Finding, Severity, FindingType,
    UsageInfo, SecurityInfo, HealthInfo, ComplianceInfo,
    AccessInfo, RelationshipInfo, MetricValue
)


class GcsBucketScanner(BaseScanner, LoggingMixin, MonitoringMixin, IamMixin, ComplianceMixin):
    """
    Scans Cloud Storage buckets.
    
    Asset type handled: storage.googleapis.com/Bucket
    
    Checks:
      - Public access (allUsers / allAuthenticatedUsers)
      - Encryption (CMEK vs Google-managed)
      - Versioning enabled
      - Lifecycle rules exist
      - Recent usage / access logs
      - HIPAA, PCI, SOC2 compliance
      - Uniform bucket-level access
    """

    HANDLED_ASSET_TYPES = {"storage.googleapis.com/Bucket"}

    # Scanner-specific config defaults (merged with BaseScanner defaults)
    DEFAULT_CONFIG = {
        **BaseScanner.DEFAULT_CONFIG,
        'check_versioning': True,
        'check_lifecycle': True,
        'compliance_standards': ['hipaa', 'pci', 'soc2'],
    }

    def __init__(self, project_id: str, config: Optional[Dict] = None):
        super().__init__(project_id, config)
        self.setup_logging_client()
        self.setup_monitoring_client()
        self.setup_iam_client()
        self.storage_client = storage.Client(project=project_id)

    # ------------------------------------------------------------------ #
    # Required: routing                                                    #
    # ------------------------------------------------------------------ #

    def can_handle(self, asset_type: str) -> bool:
        return asset_type in self.HANDLED_ASSET_TYPES

    # ------------------------------------------------------------------ #
    # analyze_* methods — auto-discovered by BaseScanner                  #
    # ------------------------------------------------------------------ #

    def analyze_security(self, asset: asset_v1.ResourceSearchResult,
                         metadata: ResourceMetadata) -> dict:
        """
        Checks IAM bindings, public access, encryption, and uniform access.
        Returns a dict with security fields + list of Findings.
        """
        findings: List[Finding] = []
        bucket_name = metadata.name

        # --- IAM / public access ---
        bindings = list(getattr(asset, 'iam_policy', {}).get('bindings', []))
        iam_result = self.check_iam_permissions(bindings)

        if iam_result['public_access']:
            findings.append(Finding(
                id=f"gcs_public_{metadata.resource_id}",
                type=FindingType.SECURITY,
                severity=Severity.CRITICAL,
                title="GCS bucket is publicly accessible",
                description=(
                    f"Bucket '{bucket_name}' grants access to allUsers or "
                    "allAuthenticatedUsers. Anyone on the internet can read it."
                ),
                recommendation=(
                    "Remove allUsers/allAuthenticatedUsers bindings. "
                    "If public access is required, enable Cloud CDN instead."
                ),
                resource_id=metadata.resource_id,
                resource_type=metadata.resource_type,
            ))

        # --- Fetch live bucket config ---
        encryption_at_rest = False
        encryption_key_type = "google-managed"
        uniform_access = False

        try:
            bucket = self.storage_client.get_bucket(bucket_name)

            # Encryption
            if bucket.default_kms_key_name:
                encryption_at_rest = True
                encryption_key_type = "customer-managed"
            else:
                encryption_at_rest = True  # always encrypted by Google
                encryption_key_type = "google-managed"

            # Uniform bucket-level access
            uniform_access = bucket.iam_configuration.uniform_bucket_level_access_enabled

            if not uniform_access:
                findings.append(Finding(
                    id=f"gcs_no_uniform_access_{metadata.resource_id}",
                    type=FindingType.SECURITY,
                    severity=Severity.MEDIUM,
                    title="Uniform bucket-level access is disabled",
                    description=(
                        f"Bucket '{bucket_name}' uses legacy ACLs alongside IAM. "
                        "This complicates access auditing."
                    ),
                    recommendation=(
                        "Enable uniform bucket-level access to enforce IAM-only controls."
                    ),
                    resource_id=metadata.resource_id,
                    resource_type=metadata.resource_type,
                ))

        except Exception as e:
            self.logger.warning(f"Could not fetch live bucket config for {bucket_name}: {e}")

        return {
            'has_public_access': iam_result['public_access'],
            'overly_permissive': iam_result['overly_permissive'],
            'encryption_at_rest': encryption_at_rest,
            'encryption_key_type': encryption_key_type,
            'iam_bindings': bindings,
            'findings': findings,
        }

    def analyze_usage(self, asset: asset_v1.ResourceSearchResult,
                      metadata: ResourceMetadata) -> dict:
        """
        Pulls access logs and request-count metrics to assess bucket activity.
        """
        lookback = self.config.get('usage_lookback_days', 90)
        bucket_name = metadata.name
        findings: List[Finding] = []

        # Cloud Logging summary
        log_summary = self.get_access_logs_summary(bucket_name, days_back=lookback)

        # Cloud Monitoring — request count metric
        metrics = self.get_metric(
            metric_type="storage.googleapis.com/api/request_count",
            filter_str=f'resource.labels.bucket_name="{bucket_name}"',
            days_back=30
        )

        total_requests_30d = sum(m.value for m in metrics)

        # Detect idle bucket
        if log_summary['total_access'] == 0 and total_requests_30d == 0:
            findings.append(Finding(
                id=f"gcs_idle_{metadata.resource_id}",
                type=FindingType.USAGE,
                severity=Severity.LOW,
                title="Bucket appears to be idle",
                description=(
                    f"Bucket '{bucket_name}' had no access logs or API calls "
                    f"in the last {lookback} days."
                ),
                recommendation=(
                    "Consider archiving or deleting this bucket if it is no longer needed."
                ),
                resource_id=metadata.resource_id,
                resource_type=metadata.resource_type,
            ))

        return {
            'last_access': log_summary.get('last_access'),
            'access_count_30d': log_summary['total_access'],
            'unique_users_30d': log_summary['unique_users'],
            'accessed_by': log_summary['users'],
            'metrics': {
                'request_count_30d': MetricValue(
                    value=total_requests_30d,
                    unit='requests',
                    timestamp=datetime.now(timezone.utc)
                )
            },
            'findings': findings,
        }

    def analyze_health(self, asset: asset_v1.ResourceSearchResult,
                       metadata: ResourceMetadata) -> dict:
        """
        Checks versioning and lifecycle rules as proxy health indicators.
        """
        findings: List[Finding] = []
        bucket_name = metadata.name
        versioning_enabled = False
        has_lifecycle = False

        try:
            bucket = self.storage_client.get_bucket(bucket_name)
            versioning_enabled = bucket.versioning_enabled

            if self.config.get('check_versioning') and not versioning_enabled:
                findings.append(Finding(
                    id=f"gcs_no_versioning_{metadata.resource_id}",
                    type=FindingType.RELIABILITY,
                    severity=Severity.MEDIUM,
                    title="Object versioning is disabled",
                    description=(
                        f"Bucket '{bucket_name}' has no versioning. "
                        "Accidental deletions or overwrites cannot be recovered."
                    ),
                    recommendation="Enable object versioning for critical data buckets.",
                    resource_id=metadata.resource_id,
                    resource_type=metadata.resource_type,
                ))

            has_lifecycle = bool(bucket.lifecycle_rules)
            if self.config.get('check_lifecycle') and not has_lifecycle:
                findings.append(Finding(
                    id=f"gcs_no_lifecycle_{metadata.resource_id}",
                    type=FindingType.COST,
                    severity=Severity.LOW,
                    title="No lifecycle rules configured",
                    description=(
                        f"Bucket '{bucket_name}' has no lifecycle policy. "
                        "Old objects accumulate indefinitely, increasing cost."
                    ),
                    recommendation=(
                        "Add lifecycle rules to transition or delete objects after a defined period."
                    ),
                    resource_id=metadata.resource_id,
                    resource_type=metadata.resource_type,
                ))

        except Exception as e:
            self.logger.warning(f"Health check failed for {bucket_name}: {e}")
            return {
                'status': 'unknown',
                'findings': [Finding(
                    id=f"gcs_health_error_{metadata.resource_id}",
                    type=FindingType.OPERATIONAL,
                    severity=Severity.MEDIUM,
                    title="Health check failed",
                    description=str(e),
                    recommendation="Check scanner permissions for storage.buckets.get",
                    resource_id=metadata.resource_id,
                    resource_type=metadata.resource_type,
                )]
            }

        status = "healthy" if not findings else "degraded"
        return {
            'status': status,
            'findings': findings,
            'metrics': {
                'versioning_enabled': MetricValue(value=versioning_enabled, unit='bool'),
                'lifecycle_configured': MetricValue(value=has_lifecycle, unit='bool'),
            }
        }

    def analyze_compliance(self, asset: asset_v1.ResourceSearchResult,
                           metadata: ResourceMetadata) -> dict:
        """
        Checks HIPAA, PCI, SOC2 requirements.
        """
        standards = self.config.get('compliance_standards', [])
        resource_data = {
            'id': metadata.resource_id,
            'type': metadata.resource_type,
        }
        violations = self.check_compliance(resource_data, standards)
        return {
            'standards': standards,
            'compliant': len(violations) == 0,
            'violations': violations,
        }

    def analyze_relationships(self, asset: asset_v1.ResourceSearchResult,
                              metadata: ResourceMetadata) -> dict:
        """
        Identifies parent project and any linked service accounts.
        """
        return {
            'parent': f"projects/{metadata.project_id}",
            'dependencies': [],
            'dependents': [],
        }

    # ------------------------------------------------------------------ #
    # Optional: cross-analyzer logic                                       #
    # ------------------------------------------------------------------ #

    def _run_custom_analyzers(self, asset, report):
        """
        After all analyze_* run: promote severity if bucket is both
        public AND contains sensitive labels.
        """
        labels = report.metadata.labels
        is_sensitive = any(
            v.lower() in ('sensitive', 'pii', 'phi', 'confidential')
            for v in labels.values()
        )
        if report.security.has_public_access and is_sensitive:
            report.add_finding(Finding(
                id=f"gcs_public_sensitive_{report.metadata.resource_id}",
                type=FindingType.SECURITY,
                severity=Severity.CRITICAL,
                title="Sensitive bucket is publicly accessible",
                description=(
                    "This bucket is labeled as sensitive/PII/PHI but is publicly accessible. "
                    "This is a critical data exposure risk."
                ),
                recommendation="Immediately restrict public access and review data contents.",
                resource_id=report.metadata.resource_id,
                resource_type=report.metadata.resource_type,
                metadata={'labels': labels}
            ))
```

---

## Registering Your Scanner

Open **`scanners/registry.py`** — the only file you need to edit:

```python
from typing import List, Type
from gcp_scanner.base_scanner import BaseScanner

from scanners.service_account_scanner import ServiceAccountScanner
from scanners.service_account_key_scanner import ServiceAccountKeyScanner
from scanners.gcs_bucket_scanner import GcsBucketScanner       # ← import
# from scanners.compute_scanner import ComputeScanner           # ← future


def get_default_scanner_classes() -> List[Type[BaseScanner]]:
    return [
        ServiceAccountScanner,
        ServiceAccountKeyScanner,
        GcsBucketScanner,       # ← add here
        # ComputeScanner,       # ← future
    ]
```

No other file needs to change. `ScanEngine` calls `get_default_scanner_classes()` at startup and automatically instantiates and routes to every scanner in the list.

---

## Configuration Reference

### BaseScanner defaults (inherited by all scanners)

| Key | Default | Description |
|---|---|---|
| `analyze_usage` | `True` | Run `analyze_usage()` |
| `analyze_security` | `True` | Run `analyze_security()` |
| `analyze_health` | `True` | Run `analyze_health()` |
| `analyze_cost` | `False` | Run `analyze_cost()` (needs billing permissions) |
| `analyze_compliance` | `True` | Run `analyze_compliance()` |
| `max_findings_per_resource` | `100` | Cap findings per resource |
| `include_raw_data` | `False` | Include full raw GCP asset in report |
| `usage_lookback_days` | `90` | Days of history for usage analysis |
| `cache_results` | `True` | Cache scan results |
| `cache_ttl_seconds` | `3600` | Cache TTL (1 hour) |

### Adding scanner-specific config

```python
class MyScanner(BaseScanner, ...):

    DEFAULT_CONFIG = {
        **BaseScanner.DEFAULT_CONFIG,     # always start with this
        'my_custom_flag': True,
        'threshold_days': 30,
    }

    def analyze_something(self, asset, metadata):
        if self.config.get('my_custom_flag'):
            threshold = self.config['threshold_days']
            ...
```

### Disabling an analyzer via config

```python
# In ScanEngine initialization
engine = ScanEngine(project_id="my-project", config={
    'scanners': {
        'GcsBucketScanner': {
            'analyze_cost': False,
            'check_versioning': False,
        }
    }
})
```

---

## Findings & Severity Guide

### When to use each severity

```
CRITICAL → data exposed publicly, credentials leaked, active exploit possible
HIGH     → encryption missing on sensitive data, dangerous IAM role assignment
MEDIUM   → best-practice deviation, indirect risk, operational gap
LOW      → cost waste, idle resource, minor config drift
INFO     → informational observation, no action required
```

### Finding ID conventions

Always make IDs unique and deterministic so deduplication works correctly:

```python
# Pattern: {scanner_prefix}_{check_name}_{resource_id}
id = f"gcs_public_{metadata.resource_id}"
id = f"sa_key_old_{metadata.resource_id}_{key_id}"
id = f"compliance_hipaa_encryption_{metadata.resource_id}"
```

---

## Common Patterns & Recipes

### Pattern: Check if a resource is older than N days

```python
from datetime import datetime, timedelta, timezone

def _is_old(self, metadata: ResourceMetadata, days: int = 90) -> bool:
    if not metadata.creation_time:
        return False
    age = datetime.now(timezone.utc) - metadata.creation_time
    return age > timedelta(days=days)
```

### Pattern: Fetch live resource data (beyond asset inventory)

```python
def analyze_health(self, asset, metadata):
    try:
        live_data = self.my_client.get_resource(metadata.name)
        # use live_data...
    except PermissionDenied:
        self.logger.warning(f"No permission to fetch {metadata.name}")
        return {'status': 'unknown'}
    except Exception as e:
        self.logger.error(f"Error fetching {metadata.name}: {e}")
        return {'status': 'unknown', 'findings': [self._create_error_finding(...)]}
```

### Pattern: Multiple findings from one analyzer

```python
def analyze_security(self, asset, metadata):
    findings = []

    if condition_a:
        findings.append(Finding(...))

    if condition_b:
        findings.append(Finding(...))

    return {
        'has_public_access': True,
        'findings': findings   # ← base class adds all of them to report
    }
```

### Pattern: Custom requirement logic in ComplianceMixin

```python
def _check_requirement(self, resource_data: dict, requirement: str) -> bool:
    if requirement == 'encryption':
        return resource_data.get('encryption_at_rest', False)
    if requirement == 'audit_logs':
        return resource_data.get('access_count_30d', 0) > 0
    return True  # unknown requirement → assume compliant
```

### Pattern: Cross-analyzer logic in `_run_custom_analyzers`

```python
def _run_custom_analyzers(self, asset, report):
    # Both security AND usage data are available here
    if report.security.has_public_access and report.usage.access_count_30d == 0:
        # Public but nobody uses it → strong candidate for deletion
        report.add_finding(Finding(
            id=f"idle_public_{report.metadata.resource_id}",
            type=FindingType.COST,
            severity=Severity.MEDIUM,
            title="Public bucket is idle — consider deleting",
            ...
        ))
```

---

## Testing Your Scanner

### Minimal unit test template

```python
# tests/test_my_scanner.py

import pytest
from unittest.mock import MagicMock, patch
from scanners.gcs_bucket_scanner import GcsBucketScanner
from google.cloud import asset_v1


def make_mock_asset(name="my-bucket", asset_type="storage.googleapis.com/Bucket",
                    project="projects/test-proj"):
    asset = MagicMock(spec=asset_v1.ResourceSearchResult)
    asset.name = f"//storage.googleapis.com/b/{name}"
    asset.asset_type = asset_type
    asset.project = project
    asset.display_name = name
    asset.location = "us-central1"
    asset.labels = {}
    asset.create_time = None
    asset.update_time = None
    asset.iam_policy = MagicMock(bindings=[])
    return asset


@pytest.fixture
def scanner():
    with patch("google.cloud.logging_v2.Client"), \
         patch("google.cloud.monitoring_v3.MetricServiceClient"), \
         patch("google.cloud.resourcemanager_v3.ProjectsClient"), \
         patch("google.cloud.storage.Client"):
        return GcsBucketScanner(project_id="test-proj")


def test_can_handle(scanner):
    assert scanner.can_handle("storage.googleapis.com/Bucket") is True
    assert scanner.can_handle("iam.googleapis.com/ServiceAccount") is False


def test_scan_produces_report(scanner):
    asset = make_mock_asset()
    scanner.storage_client.get_bucket.return_value = MagicMock(
        versioning_enabled=False,
        lifecycle_rules=[],
        iam_configuration=MagicMock(uniform_bucket_level_access_enabled=False),
        default_kms_key_name=None
    )
    scanner.logging_client.list_entries = MagicMock(return_value=[])
    scanner.monitoring_client.list_time_series = MagicMock(return_value=[])

    report = scanner.scan_resource(asset)

    assert report is not None
    assert report.metadata.name == "my-bucket"
    # versioning + uniform access findings expected
    finding_titles = [f.title for f in report.findings]
    assert any("versioning" in t.lower() for t in finding_titles)


def test_public_access_finding(scanner):
    asset = make_mock_asset()
    binding = MagicMock()
    binding.role = "roles/storage.objectViewer"
    binding.members = ["allUsers"]
    asset.iam_policy.bindings = [binding]

    scanner.storage_client.get_bucket.return_value = MagicMock(
        versioning_enabled=True,
        lifecycle_rules=[MagicMock()],
        iam_configuration=MagicMock(uniform_bucket_level_access_enabled=True),
        default_kms_key_name=None
    )
    scanner.logging_client.list_entries = MagicMock(return_value=[])
    scanner.monitoring_client.list_time_series = MagicMock(return_value=[])

    report = scanner.scan_resource(asset)

    critical_findings = [f for f in report.findings if f.severity.value == "critical"]
    assert len(critical_findings) >= 1
    assert report.security.has_public_access is True
```

---

## Checklist

Use this before opening a PR for a new scanner.

```
Scanner file
  [ ] Placed in scanners/my_scanner.py
  [ ] Class inherits BaseScanner + required mixins
  [ ] DEFAULT_CONFIG extends BaseScanner.DEFAULT_CONFIG
  [ ] __init__ calls super().__init__() and setup_*_client() for each mixin used
  [ ] can_handle() returns True only for the correct asset type(s)

Analyzers
  [ ] analyze_security() implemented — checks IAM, encryption, public access
  [ ] analyze_usage() implemented — checks last access, request counts
  [ ] analyze_health() implemented — checks resource-specific health signals
  [ ] analyze_compliance() implemented (if resource stores sensitive data)
  [ ] All analyze_* methods catch exceptions and return partial data on error
  [ ] Findings have deterministic, unique IDs
  [ ] Findings use the correct FindingType and Severity

Registration
  [ ] Scanner imported in scanners/registry.py
  [ ] Scanner class added to the list in get_default_scanner_classes()

Tests
  [ ] test_can_handle() passes for handled and unhandled types
  [ ] scan_resource() returns a valid ResourceReport
  [ ] At least one positive finding test (known bad config → expected finding)
  [ ] All GCP clients are mocked (no real API calls in tests)
```
