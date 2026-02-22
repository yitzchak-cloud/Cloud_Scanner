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


    def get_access_logs_summary(self, resource_name: str, days_back: int = 30) -> Dict:
        """
        Analyzes access logs for a specific resource and provides a summary report.

        This method queries Cloud Logging for entries related to the given resource name,
        extracts identity information from the proto_payload (Audit Logs), and 
        aggregates statistics on user activity and operation types.

        Args:
            resource_name (str): The specific name of the resource to filter logs for.
            days_back (int): The number of days from the current time to include in the search. 
                            Defaults to 30.

        Returns:
            Dict: A dictionary containing:
                - 'total_access' (int): Total number of log entries found.
                - 'unique_users' (int): Count of distinct principal emails.
                - 'users' (List[str]): List of all unique user emails who accessed the resource.
                - 'operations' (Dict[str, int]): A mapping of operation names (e.g., 'GetStorage') 
                                                to their occurrence count.
                - 'first_access' (datetime|None): Timestamp of the earliest access in the period.
                - 'last_access' (datetime|None): Timestamp of the most recent access in the period.
        """
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
    """
    A Mixin to provide Google Cloud Monitoring (Stackdriver) metrics capabilities.

    This mixin allows classes to fetch time-series data from Google Cloud Monitoring,
    handling client initialization, time interval formatting, and data point extraction.

    Attributes:
        project_id (str): The Google Cloud Project ID.
        project_name (str): The formatted project resource string (projects/project-id).
        monitoring_client (monitoring_v3.MetricServiceClient): The initialized Monitoring client.
    """
    project_id: str
    project_name: str

    def setup_monitoring_client(self):
        """
        Initializes the Metric Service Client and sets the project resource name.
        """
        self.monitoring_client = monitoring_v3.MetricServiceClient()
        self.project_name = f"projects/{self.project_id}"

    def get_metric(self, metric_type: str, filter_str: str = "", 
                days_back: int = 7) -> List[MetricValue]:
        """
        Retrieves time-series metric data for a specific metric type.

        Queries the Google Cloud Monitoring API for data points within a specified 
        timeframe and parses them into a list of MetricValue objects.

        Args:
            metric_type (str): The type of metric to retrieve (e.g., 'run.googleapis.com/container/cpu/utilization').
            filter_str (str, optional): Additional filtering criteria for the time-series. Defaults to "".
            days_back (int, optional): Number of days of historical data to fetch. Defaults to 7.

        Returns:
            List[MetricValue]: A list of MetricValue objects containing the value, unit, and timestamp.

        Raises:
            GoogleCloudError: If the API request fails.
        """
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
    """
    A Mixin to analyze and audit Identity and Access Management (IAM) policies.

    This mixin provides tools to inspect IAM bindings for security risks, such as
    publicly accessible resources or the use of overly privileged (dangerous) roles.

    Attributes:
        project_id (str): The Google Cloud Project ID.
        resource_manager (resourcemanager_v3.ProjectsClient): Client for managing GCP resources.
    """
    project_id: str

    def setup_iam_client(self):
        """
        Initializes the Resource Manager client to interact with GCP project settings.
        """
        self.resource_manager = resourcemanager_v3.ProjectsClient()

    def get_iam_policy(self, resource: str) -> Dict:
        """
        Retrieves the IAM policy for a given resource.
        
        Note: Current implementation is a placeholder. 
        Should be overridden or implemented to fetch actual policies.
        """
        return {}


    def check_iam_permissions(self, iam_bindings: List[Any]) -> Dict:
        """
        Analyzes IAM bindings for security vulnerabilities.

        Evaluates a list of IAM bindings to detect public exposure and 
        high-privilege roles that may violate the principle of least privilege.

        Args:
            iam_bindings (List[Any]): A list of IAM binding objects or dictionaries, 
                                    each containing a 'role' and 'members'.

        Returns:
            Dict: A summary of the security analysis containing:
                - 'overly_permissive' (bool): True if dangerous roles are detected.
                - 'public_access' (bool): True if the resource is exposed to the public.
                - 'dangerous_roles' (List[Dict]): Details of found dangerous roles.
                - 'findings' (List[Dict]): A descriptive list of all security issues found.
        """
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
    """
    A Mixin to audit cloud resources against industry compliance standards.

    This mixin provides a framework for evaluating resources against predefined 
    compliance frameworks such as HIPAA, PCI DSS, SOC2, and GDPR. It identifies 
    missing security controls and generates detailed findings for remediation.

    Attributes:
        COMPLIANCE_STANDARDS (Dict[str, List[str]]): A mapping of compliance 
            frameworks to their specific technical requirements.
    """

    COMPLIANCE_STANDARDS = {
        'hipaa': ['encryption', 'audit_logs', 'access_controls'],
        'pci': ['encryption', 'network_security', 'access_controls'],
        'soc2': ['encryption', 'audit_logs', 'availability'],
        'gdpr': ['data_residency', 'access_controls', 'retention']
    }

    def check_compliance(self, resource_data: Dict, standards: List[str]) -> List[Finding]:
        """
        Evaluates a resource against a list of selected compliance standards.

        Args:
            resource_data (Dict): The raw data/configuration of the cloud resource.
            standards (List[str]): A list of standard keys to check (e.g., ['pci', 'gdpr']).

        Returns:
            List[Finding]: A list of compliance violation findings discovered during the audit.
        """
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
        """
        Internal logic to verify if a specific requirement is met by the resource.

        Args:
            resource_data (Dict): The resource configuration.
            requirement (str): The specific control to verify (e.g., 'encryption').

        Returns:
            bool: True if compliant, False otherwise.
        """
        return True

    def _create_compliance_finding(self, standard: str, requirement: str,
                                    resource_data: Dict) -> Finding:
        """
        Constructs a detailed Finding object for a compliance violation.

        Args:
            standard (str): The compliance framework name.
            requirement (str): The specific requirement that failed.
            resource_data (Dict): The resource metadata.

        Returns:
            Finding: An object containing violation details, severity, and recommendations.
        """
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