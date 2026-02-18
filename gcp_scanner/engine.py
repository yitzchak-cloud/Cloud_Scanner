from typing import List, Dict, Any, Optional, Type
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import logging
import json
from collections import Counter

from google.cloud import asset_v1

from .base_scanner import BaseScanner
from ..sa_scanner import ServiceAccountScanner
from .models import ProjectSummary, Finding

class ScanEngine:
    """
    מנוע סריקה ראשי - הכי גנרי שאפשר
    """
    
    def __init__(self, project_id: str, config: Optional[Dict] = None):
        self.project_id = project_id
        self.config = config or {}
        self.logger = logging.getLogger("ScanEngine")
        
        # סקנרים רשומים
        self.scanners: List[BaseScanner] = []
        
        # תוצאות
        self.results: Dict[str, Dict] = {}
        self.findings: List[Finding] = []
        
        # סטטיסטיקות
        self.stats = {
            'resource_types': Counter(),
            'findings_by_type': Counter(),
            'findings_by_severity': Counter()
        }
        
        # הפעלת Asset Inventory
        self.asset_client = asset_v1.AssetServiceClient()
        
        # הרשמת סקנרים ברירת מחדל
        self._register_default_scanners()
    
    def _register_default_scanners(self):
        """הרשמת סקנרים ברירת מחדל"""
        self.register_scanner(ServiceAccountScanner)
        # נוסיף עוד בהמשך
    
    def register_scanner(self, scanner_class: Type[BaseScanner], config: Optional[Dict] = None):
        """הרשמת סקנר חדש"""
        scanner_config = {**self.config.get('scanners', {}).get(scanner_class.__name__, {}), 
                         **(config or {})}
        scanner = scanner_class(self.project_id, scanner_config)
        self.scanners.append(scanner)
        self.logger.info(f"Registered scanner: {scanner.name}")
    
    def discover_all_resources(self, asset_types: Optional[List[str]] = None) -> tuple[dict[BaseScanner, list[Any]], list[Any]]:
        """
        גילוי כל המשאבים ומיון לפי סקנר
        """
        scope = f"projects/{self.project_id}"
        
        request = asset_v1.SearchAllResourcesRequest(
            scope=scope,
            asset_types=asset_types
        )
        
        self.logger.info(f"Discovering resources in {self.project_id}")
        
        resources_by_scanner = {scanner: [] for scanner in self.scanners}
        unscanned = []
        
        page_token = None
        while True:
            if page_token:
                request.page_token = page_token
                
            response = self.asset_client.search_all_resources(request=request)
            
            for resource in response.results:
                # עדכון סטטיסטיקות
                self.stats['resource_types'][resource.asset_type] += 1
                
                # מציאת סקנר מתאים
                scanned = False
                for scanner in self.scanners:
                    if scanner.can_handle(resource.asset_type):
                        resources_by_scanner[scanner].append(resource)
                        scanned = True
                        break
                
                if not scanned:
                    unscanned.append({
                        'name': resource.name,
                        'type': resource.asset_type,
                        'project': resource.project
                    })
            
            page_token = response.next_page_token
            if not page_token:
                break
        
        self.logger.info(f"Found {self.stats['resource_types'].total()} resources")
        return resources_by_scanner, unscanned
    
    def scan_all(self, parallel: bool = True, max_workers: int = 10) -> ProjectSummary:
        """
        סריקת כל המשאבים
        """
        start_time = datetime.now(timezone.utc)
        
        # גילוי משאבים
        resources_by_scanner, unscanned = self.discover_all_resources()
        
        # סריקה
        if parallel:
            self._scan_parallel(resources_by_scanner, max_workers)
        else:
            self._scan_sequential(resources_by_scanner)
        
        # איסוף כל הממצאים
        all_findings = []
        for scanner_name, scanner_results in self.results.items():
            for resource_id, report in scanner_results.items():
                if hasattr(report, 'findings'):
                    for finding in report.findings:
                        all_findings.append(finding)
                        self.stats['findings_by_type'][finding.type.value] += 1
                        self.stats['findings_by_severity'][finding.severity.value] += 1
        
        # יצירת סיכום
        summary = ProjectSummary(
            project_id=self.project_id,
            total_resources=sum(self.stats['resource_types'].values()),
            resource_types=dict(self.stats['resource_types']),
            findings_count=dict(self.stats['findings_by_type']),
            severity_count=dict(self.stats['findings_by_severity']),
            resources_with_issues=list(set(f.resource_id for f in all_findings)),
            top_findings=sorted(all_findings, 
                            key=lambda x: (x.severity.value, x.created_at), 
                            reverse=True)[:20]
        )
        
        # שמירת סיכום
        summary.scan_time = datetime.now(timezone.utc)
        summary.scan_duration = (summary.scan_time - start_time).total_seconds()
        
        return summary
    
    def _scan_sequential(self, resources_by_scanner: Dict):
        """סריקה סדרתית"""
        for scanner, resources in resources_by_scanner.items():
            if resources:
                self.logger.info(f"Scanning {len(resources)} resources with {scanner.name}")
                results = scanner.scan_resources(resources)
                self.results[scanner.name] = results
                
                # איסוף סטטיסטיקות סקנר
                scanner_stats = scanner.get_stats()
                self.logger.info(f"{scanner.name} stats: {scanner_stats}")
    
    def _scan_parallel(self, resources_by_scanner: Dict, max_workers: int):
        """סריקה במקביל"""
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_scanner = {}
            
            for scanner, resources in resources_by_scanner.items():
                if resources:
                    self.logger.info(f"Submitting {len(resources)} resources to {scanner.name}")
                    future = executor.submit(scanner.scan_resources, resources)
                    future_to_scanner[future] = scanner
            
            for future in as_completed(future_to_scanner):
                scanner = future_to_scanner[future]
                try:
                    results = future.result()
                    self.results[scanner.name] = results
                    
                    # איסוף סטטיסטיקות
                    scanner_stats = scanner.get_stats()
                    self.logger.info(f"{scanner.name} completed: {scanner_stats}")
                    
                except Exception as e:
                    self.logger.error(f"{scanner.name} failed: {e}")
                    self.results[scanner.name] = {'error': str(e)}
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """קבלת ממצאים לפי חומרה"""
        findings = []
        for scanner_results in self.results.values():
            if isinstance(scanner_results, dict):
                for report in scanner_results.values():
                    if hasattr(report, 'findings'):
                        findings.extend([f for f in report.findings 
                                    if f.severity.value == severity])
        return findings
    
    def get_findings_by_type(self, finding_type: str) -> List[Finding]:
        """קבלת ממצאים לפי סוג"""
        findings = []
        for scanner_results in self.results.values():
            if isinstance(scanner_results, dict):
                for report in scanner_results.values():
                    if hasattr(report, 'findings'):
                        findings.extend([f for f in report.findings 
                                    if f.type.value == finding_type])
        return findings
    
    def export_results(self, format: str = 'json', filepath: Optional[str] = None) -> Dict:
        """ייצוא תוצאות"""
        output = {
            'project_id': self.project_id,
            'scan_time': datetime.utcnow().isoformat(),
            'stats': {
                'total_resources': self.stats['resource_types'].total(),
                'resource_types': dict(self.stats['resource_types']),
                'findings_by_type': dict(self.stats['findings_by_type']),
                'findings_by_severity': dict(self.stats['findings_by_severity'])
            },
            'results': {}
        }
        
        # המרת תוצאות למילונים
        for scanner_name, scanner_results in self.results.items():
            output['results'][scanner_name] = {}
            for resource_id, report in scanner_results.items():
                if hasattr(report, 'to_dict'):
                    output['results'][scanner_name][resource_id] = report.to_dict()
                else:
                    output['results'][scanner_name][resource_id] = report
        
        # שמירה לקובץ
        if filepath:
            with open(filepath, 'w') as f:
                json.dump(output, f, indent=2, default=str)
            self.logger.info(f"Results exported to {filepath}")
        
        return output