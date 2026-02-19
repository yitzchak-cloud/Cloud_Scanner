from typing import List, Dict, Any, Optional, Union
from datetime import datetime, timedelta, timezone
from collections import Counter

from google.cloud import logging_v2, asset_v1, monitoring_v3, resourcemanager_v3
from google.protobuf.timestamp_pb2 import Timestamp

from gcp_scanner.models import Finding, Severity, FindingType, MetricValue


class LoggingMixin:
    """מיקסין לעבודה עם לוגים"""
    project_id: str

    def setup_logging_client(self):
        self.logging_client = logging_v2.Client(project=self.project_id)

    def query_logs(self, filter_str: str, days_back: int = 7) -> List[Any]:
        """חיפוש בלוגים"""
        entries = self.logging_client.list_entries(
            filter_=filter_str,
            order_by=logging_v2.DESCENDING
        )
        return list(entries)

    # FIX: שינוי שם מ-analyze_access_logs ל-get_access_logs_summary
    # כך ה-base_scanner לא ירשום אותה אוטומטית (לא מתחילה ב-analyze_)
    def get_access_logs_summary(self, resource_name: str, days_back: int = 30) -> Dict:
        """ניתוח לוגי גישה לפי שם משאב"""
        filter_str = f'resource.labels.resource_name="{resource_name}"'
        entries = self.query_logs(filter_str, days_back)

        users = set()
        operations: Counter = Counter()
        timestamps = []

        for entry in entries:
            raw_ts = entry.timestamp
            if hasattr(raw_ts, 'seconds'):
                ts = datetime.fromtimestamp(raw_ts.seconds, tz=timezone.utc)
            else:
                ts = raw_ts
            timestamps.append(ts)

            payload = getattr(entry, 'proto_payload', {})
            if payload:
                operation = payload.get('methodName', 'unknown')
                operations[operation] += 1
                auth_info = payload.get('authenticationInfo', {})
                if auth_info.get('principalEmail'):
                    users.add(auth_info['principalEmail'])

        return {
            'total_access': len(entries),
            'unique_users': len(users),
            'users': list(users),
            'operations': dict(operations),
            'first_access': min(timestamps) if timestamps else None,
            'last_access': max(timestamps) if timestamps else None
        }


class MonitoringMixin:
    """מיקסין לעבודה עם monitoring metrics"""
    project_id: str
    project_name: str

    def setup_monitoring_client(self):
        self.monitoring_client = monitoring_v3.MetricServiceClient()
        self.project_name = f"projects/{self.project_id}"

    def get_metric(self, metric_type: str, filter_str: str = "",
                   days_back: int = 7) -> List[MetricValue]:
        """קבלת מטריקה"""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days_back)

        interval = monitoring_v3.TimeInterval({
            'end_time': end_time,
            'start_time': start_time
        })

        results = self.monitoring_client.list_time_series(
            name=self.project_name,
            filter=f'metric.type="{metric_type}" {f"AND {filter_str}" if filter_str else ""}',
            interval=interval,
            view=monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL
        )

        metrics = []
        for series in results:
            unit = getattr(series, 'unit', '1')
            for point in series.points:
                raw_ts = point.interval.end_time
                dt_ts = datetime.fromtimestamp(
                    raw_ts.seconds + raw_ts.nanos / 1e9, tz=timezone.utc
                )
                val = 0.0
                if point.value.double_value is not None:
                    val = point.value.double_value
                elif point.value.int64_value is not None:
                    val = float(point.value.int64_value)

                metrics.append(MetricValue(value=val, unit=unit, timestamp=dt_ts))

        return metrics


class IamMixin:
    """מיקסין לעבודה עם IAM"""
    project_id: str

    def setup_iam_client(self):
        self.resource_manager = resourcemanager_v3.ProjectsClient()

    def get_iam_policy(self, resource: str) -> Dict:
        return {}

    # FIX: שינוי שם מ-analyze_permissions ל-check_iam_permissions
    # כך ה-base_scanner לא ירשום אותה אוטומטית (לא מתחילה ב-analyze_)
    def check_iam_permissions(self, iam_bindings: List[Any]) -> Dict:
        """ניתוח הרשאות IAM — מקבל רשימת bindings, מחזיר ניתוח"""
        result: Dict[str, Any] = {
            'overly_permissive': False,
            'public_access': False,
            'dangerous_roles': [],
            'findings': []
        }

        dangerous_roles = [
            'roles/owner',
            'roles/editor',
            'roles/iam.securityAdmin',
            'roles/iam.serviceAccountAdmin'
        ]

        for binding in iam_bindings:
            members = (
                getattr(binding, 'members', [])
                if not isinstance(binding, dict)
                else binding.get('members', [])
            )
            role = (
                getattr(binding, 'role', '')
                if not isinstance(binding, dict)
                else binding.get('role', '')
            )

            if any(m in ['allUsers', 'allAuthenticatedUsers'] for m in members):
                result['public_access'] = True
                result['findings'].append({
                    'type': 'public_access',
                    'role': role,
                    'members': list(members)
                })

            if role in dangerous_roles:
                result['overly_permissive'] = True
                result['dangerous_roles'].append({
                    'role': role,
                    'members': list(members)
                })

        return result


class ComplianceMixin:
    """מיקסין לבדיקות תאימות"""

    COMPLIANCE_STANDARDS = {
        'hipaa': ['encryption', 'audit_logs', 'access_controls'],
        'pci': ['encryption', 'network_security', 'access_controls'],
        'soc2': ['encryption', 'audit_logs', 'availability'],
        'gdpr': ['data_residency', 'access_controls', 'retention']
    }

    def check_compliance(self, resource_data: Dict, standards: List[str]) -> List[Finding]:
        findings = []
        for standard in standards:
            if standard in self.COMPLIANCE_STANDARDS:
                for requirement in self.COMPLIANCE_STANDARDS[standard]:
                    if not self._check_requirement(resource_data, requirement):
                        findings.append(
                            self._create_compliance_finding(standard, requirement, resource_data)
                        )
        return findings

    def _check_requirement(self, resource_data: Dict, requirement: str) -> bool:
        return True

    def _create_compliance_finding(self, standard: str, requirement: str,
                                   resource_data: Dict) -> Finding:
        return Finding(
            id=f"compliance_{standard}_{requirement}_{resource_data.get('id', 'unknown')}",
            type=FindingType.COMPLIANCE,
            severity=Severity.HIGH,
            title=f"Compliance violation: {standard} - {requirement}",
            description=f"Resource does not meet {requirement} requirement for {standard}",
            recommendation=f"Implement {requirement} controls",
            resource_id=resource_data.get('id', 'unknown'),
            resource_type=resource_data.get('type', 'unknown'),
            metadata={'standard': standard, 'requirement': requirement},
            created_at=datetime.now(timezone.utc)
        )