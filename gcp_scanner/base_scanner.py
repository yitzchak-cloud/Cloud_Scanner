from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Set, Type, Union, Callable
from datetime import datetime, timedelta, timezone
import logging
from collections import Counter
import importlib
import inspect
from google.protobuf.timestamp_pb2 import Timestamp

from google.cloud import asset_v1

from .models import (
    ResourceReport, ResourceMetadata, Finding, Severity, 
    FindingType, AccessInfo, UsageInfo, SecurityInfo,
    HealthInfo, CostInfo, ComplianceInfo, RelationshipInfo,
    MetricValue
)

class BaseScanner(ABC):
    """
    מחלקת בסיס אבסטרקטית
    """
    
    # הגדרות ברירת מחדל - אפשר לדרוס
    DEFAULT_CONFIG = {
        'analyze_usage': True,
        'analyze_security': True,
        'analyze_health': True,
        'analyze_cost': False,  # דורש הרשאות נוספות
        'analyze_compliance': True,
        'max_findings_per_resource': 100,
        'include_raw_data': False,
        'usage_lookback_days': 90,
        'cache_results': True,
        'cache_ttl_seconds': 3600
    }
    
    def __init__(self, project_id: str, config: Optional[Dict] = None):
        self.project_id = project_id
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}
        self.name = self.__class__.__name__
        self.logger = logging.getLogger(f"scanner.{self.name}")
        
        # מטמון
        self.cache: Dict[str, tuple] = {}  # resource_id -> (timestamp, result)
        
        # סטטיסטיקות
        self.stats = {
            'scanned': 0,
            'failed': 0,
            'cached': 0,
            'findings': Counter()
        }
        
        # רישום הפונקציות הספציפיות
        self._registered_analyzers = self._register_analyzers()
        
    @abstractmethod
    def can_handle(self, asset_type: str) -> bool:
        """
        בודק אם הסקנר יכול לטפל בסוג משאב מסוים
        """
        pass
    
    def _register_analyzers(self) -> Dict[str, Callable]:
        """
        רישום אוטומטי של כל פונקציות ה-analyze_
        מאפשר הרחבה קלה - כל פונקציה שמתחילה ב-analyze_ תירשם אוטומטית
        """
        analyzers = {}
        for name, method in inspect.getmembers(self, predicate=inspect.ismethod):
            if name.startswith('analyze_') and name != 'analyze_resource':
                analyzers[name] = method
                self.logger.debug(f"Registered analyzer: {name}")
        return analyzers
    
    def scan_resource(self, asset: asset_v1.ResourceSearchResult) -> ResourceReport:
        """
        סריקת משאב בודד - הפונקציה הראשית
        """
        resource_id = self._get_resource_id(asset)
        now = datetime.now(timezone.utc)
        
        # בדיקת מטמון
        if self.config['cache_results'] and resource_id in self.cache:
            timestamp, result = self.cache[resource_id]
            if (now - timestamp).total_seconds() < self.config['cache_ttl_seconds']:
                self.stats['cached'] += 1
                return result
        
        try:
            # יצירת מטדאטה בסיסי
            metadata = self._create_metadata(asset)
            
            # יצירת דוח ריק
            report = ResourceReport(
                metadata=metadata,
                scan_time=datetime.now(timezone.utc)
            )
            
            # הרצת כל האנלייזרים הרשומים
            for analyzer_name, analyzer_func in self._registered_analyzers.items():
                if self._should_run_analyzer(analyzer_name):
                    try:
                        result = analyzer_func(asset, metadata)
                        self._update_report(report, analyzer_name, result)
                    except Exception as e:
                        self.logger.error(f"Error in {analyzer_name} for {resource_id}: {e}")
                        report.add_finding(self._create_error_finding(
                            resource_id, metadata.resource_type, analyzer_name, str(e)
                        ))
            
            # הרצת אנלייזרים מותאמים אישית
            self._run_custom_analyzers(asset, report)
            
            # שמירה במטמון
            if self.config['cache_results']:
                self.cache[resource_id] = (datetime.now(timezone.utc), report)
            
            self.stats['scanned'] += 1
            self.stats['findings'].update([f.type.value for f in report.findings])
            
            return report
            
        except Exception as e:
            self.stats['failed'] += 1
            self.logger.error(f"Failed to scan {resource_id}: {e}")
            raise
    
    def _should_run_analyzer(self, analyzer_name: str) -> bool:
        """
        בודק אם צריך להריץ אנלייזר מסוים לפי הקונפיג
        """
        # example: analyze_usage -> check config['analyze_usage']
        return self.config.get(analyzer_name, True)
    
    def _update_report(self, report: ResourceReport, analyzer_name: str, result: Any):
        """
        עדכון הדוח לפי תוצאת האנלייזר
        """
        if not result:
            return
            
        # מיפוי אנלייזר לשדה בדוח
        field_mapping = {
            'analyze_usage': 'usage',
            'analyze_security': 'security',
            'analyze_health': 'health',
            'analyze_cost': 'cost',
            'analyze_compliance': 'compliance',
            'analyze_relationships': 'relationships',
            'analyze_access': 'access'
        }
        
        field_name = field_mapping.get(analyzer_name)
        if field_name and hasattr(report, field_name):
            current = getattr(report, field_name)
            if isinstance(result, dict):
                # עדכון שדות קיימים
                for key, value in result.items():
                    if hasattr(current, key):
                        setattr(current, key, value)
            elif hasattr(result, 'to_dict'):
                # אם זה אובייקט עם to_dict
                setattr(report, field_name, result)
        
        # טיפול בממצאים
        if isinstance(result, dict) and 'findings' in result:
            for finding_data in result['findings']:
                if isinstance(finding_data, Finding):
                    report.add_finding(finding_data)
    
    def _create_metadata(self, asset: asset_v1.ResourceSearchResult) -> ResourceMetadata:
        """
        יצירת מטדאטה בסיסי מהאסט
        """
        def convert_time(ts):
            if not ts: return None
            return datetime.fromtimestamp(ts.timestamp(), tz=timezone.utc)
        
        return ResourceMetadata(
            resource_id=self._get_resource_id(asset),
            resource_type=asset.asset_type,
            project_id=self._extract_project_id(asset.project),
            name=asset.name.split('/')[-1],
            display_name=asset.display_name,
            location=asset.location,
            labels=dict(asset.labels) if asset.labels else {},
            creation_time=convert_time(asset.create_time),
            update_time=convert_time(asset.update_time),
            state=getattr(asset, 'state', None),
            raw_data=asset_v1.ResourceSearchResult.to_dict(asset) if self.config['include_raw_data'] else {}
        )
    
    def _get_resource_id(self, asset: asset_v1.ResourceSearchResult) -> str:
        """קבלת מזהה ייחודי למשאב"""
        return f"{asset.asset_type}/{asset.name}"
    
    def _extract_project_id(self, project: str) -> str:
        """חילוץ project ID"""
        if not project:
            return self.project_id
        return project.split('/')[-1]
    
    def _create_error_finding(self, resource_id: str, resource_type: str, 
                            analyzer: str, error: str) -> Finding:
        """יצירת ממצא לשגיאה"""
        return Finding(
            id=f"error_{resource_id}_{analyzer}",
            type=FindingType.OPERATIONAL,
            severity=Severity.MEDIUM,
            title=f"Analysis failed for {analyzer}",
            description=f"Failed to analyze {analyzer}: {error}",
            recommendation="Check logs and permissions",
            resource_id=resource_id,
            resource_type=resource_type,
            metadata={'analyzer': analyzer, 'error': error}
        )
    
    def _run_custom_analyzers(self, asset: asset_v1.ResourceSearchResult, 
                            report: ResourceReport):
        """
        הרצת אנלייזרים מותאמים אישית - אפשר לדרוס
        """
        pass
    
    def scan_resources(self, assets: List[asset_v1.ResourceSearchResult]) -> Dict[str, ResourceReport]:
        """
        סריקת רשימת משאבים
        """
        results = {}
        for asset in assets:
            try:
                report = self.scan_resource(asset)
                results[self._get_resource_id(asset)] = report
            except Exception as e:
                self.logger.error(f"Error scanning {asset.name}: {e}")
                
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """קבלת סטטיסטיקות"""
        return {
            'scanner_name': self.name,
            'stats': self.stats,
            'cache_size': len(self.cache),
            'config': self.config
        }