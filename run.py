#!/usr/bin/env python3
"""
דוגמה מתקדמת לשימוש במנוע הסריקה
"""

import logging
import sys
import os
from datetime import datetime
from pprint import pprint

from gcp_scanner.engine import ScanEngine
from gcp_scanner.models import Severity, FindingType

def setup_logging():
    """הגדרת לוגינג מתקדם"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f'scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def print_summary(summary):
    """הדפסת סיכום יפה"""
    print("\n" + "="*70)
    print(f"{'SCAN SUMMARY':^70}")
    print("="*70)
    
    print(f"\n📊 Project: {summary.project_id}")
    print(f"🕒 Scan time: {summary.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"⏱️  Duration: {getattr(summary, 'scan_duration', 0):.2f} seconds")
    
    print(f"\n📦 RESOURCES FOUND: {summary.total_resources}")
    print("-"*70)
    for resource_type, count in sorted(summary.resource_types.items(), 
                                    key=lambda x: x[1], reverse=True)[:10]:
        print(f"  • {resource_type.split('/')[-1]}: {count}")
    if len(summary.resource_types) > 10:
        print(f"  ... and {len(summary.resource_types) - 10} more types")
    
    print(f"\n🔍 FINDINGS SUMMARY: {sum(summary.findings_count.values())}")
    print("-"*70)
    
    # הדפסת ממצאים לפי חומרה
    severity_colors = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢',
        'info': '🔵'
    }
    
    for severity, count in sorted(summary.severity_count.items(), 
                                key=lambda x: {'critical':0,'high':1,'medium':2,'low':3,'info':4}[x[0]]):
        icon = severity_colors.get(severity, '⚪')
        print(f"  {icon} {severity.upper()}: {count}")
    
    print(f"\n📋 FINDINGS BY TYPE:")
    for ftype, count in sorted(summary.findings_count.items(), key=lambda x: x[1], reverse=True):
        print(f"  • {ftype}: {count}")
    
    print(f"\n⚠️  Resources with issues: {len(summary.resources_with_issues)}")
    
    if summary.top_findings:
        print(f"\n🏆 TOP FINDINGS:")
        for finding in summary.top_findings[:5]:
            icon = severity_colors.get(finding.severity.value, '⚪')
            print(f"  {icon} {finding.title}")
            print(f"     └─ {finding.resource_type.split('/')[-1]}")
            print(f"     └─ {finding.recommendation}")

def main():
    """הרצה ראשית"""
    setup_logging()
    logger = logging.getLogger("main")
    
    # קבלת project ID
    project_id = os.environ.get('GCP_PROJECT_ID')
    if not project_id:
        project_id = input("Enter GCP Project ID: ")
    
    # קונפיגורציה מותאמת
    config = {
        'scanners': {
            'ServiceAccountScanner': {
                'analyze_cost': False,
                'analyze_compliance': True,
                'usage_lookback_days': 90,
                'cache_results': True
            }
        },
        'parallel_workers': 10,
        'include_raw_data': False
    }
    
    print(f"\n{'='*70}")
    print(f"GCP ADVANCED SCANNER v2.0")
    print(f"{'='*70}")
    print(f"\nProject: {project_id}")
    print(f"Configuration: {config}")
    
    # יצירת מנוע סריקה
    engine = ScanEngine(project_id, config)
    
    # הרצת סריקה
    print("\n🚀 Starting scan...")
    summary = engine.scan_all(parallel=True, max_workers=config['parallel_workers'])
    
    # הדפסת סיכום
    print_summary(summary)
    
    # ייצוא תוצאות
    output_file = f"gcp_scan_{project_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    engine.export_results(filepath=output_file)
    print(f"\n💾 Full results saved to: {output_file}")
    
    # שאילתות לדוגמה
    print(f"\n🔍 EXAMPLE QUERIES:")
    
    critical_findings = engine.get_findings_by_severity('critical')
    print(f"  • Critical findings: {len(critical_findings)}")
    
    security_findings = engine.get_findings_by_type('security')
    print(f"  • Security findings: {len(security_findings)}")
    
    print(f"\n{'='*70}")
    print("SCAN COMPLETED SUCCESSFULLY")
    print(f"{'='*70}")

if __name__ == "__main__":
    main()