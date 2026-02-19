from typing import List, Type
from gcp_scanner.base_scanner import BaseScanner


from scanners.service_account_scanner import ServiceAccountScanner, ServiceAccountKeyScanner


def get_default_scanner_classes() -> List[Type[BaseScanner]]:
    """
    מחזירה רשימה של כל מחלקות הסורקים שרוצים להפעיל כברירת מחדל
    """
    return [
        ServiceAccountScanner,
        ServiceAccountKeyScanner
        # ArtifactRegistryScanner,
        # ComputeScanner,
    ]