from typing import List, Type
from gcp_scanner.base_scanner import BaseScanner

# ייבוא כל הסורקים הקיימים
from scanners.sa_scanner import ServiceAccountScanner
# from .ar_scanner import ArtifactRegistryScanner
# כאן תוסיף סורקים חדשים בעתיד, למשל:
# from .compute_scanner import ComputeScanner

def get_default_scanner_classes() -> List[Type[BaseScanner]]:
    """
    מחזירה רשימה של כל מחלקות הסורקים שרוצים להפעיל כברירת מחדל
    """
    return [
        ServiceAccountScanner,
        # ArtifactRegistryScanner,
        # ComputeScanner,
    ]