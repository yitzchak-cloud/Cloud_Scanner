from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
import logging
from google.cloud import asset_v1

class BaseScanner(ABC):
    """
    מחלקת בסיס אבסטרקטית לכל הסקנרים
    מגדירה ממשק אחיד לכולם
    """
    
    def __init__(self, project_id: str, credentials_path: Optional[str] = None):
        self.project_id = project_id
        self.credentials_path = credentials_path
        self.name = self.__class__.__name__
        self.supported_asset_types: List[str] = self._get_supported_asset_types()
        self.results: Dict[str, Dict] = {}
        self.logger = logging.getLogger(self.name)
        
    @abstractmethod
    def _get_supported_asset_types(self) -> List[str]:
        """
        מחזיר רשימת סוגי משאבים שהסקנר תומך בהם
        למשל: ['cloudresourcemanager.googleapis.com/Project', 'iam.googleapis.com/ServiceAccount']
        """
        pass
    
    @abstractmethod
    def can_handle(self, asset_type: str) -> bool:
        """
        בודק אם הסקנר יכול לטפל בסוג משאב מסוים
        """
        return asset_type in self.supported_asset_types
    
    @abstractmethod
    def scan_resource(self, asset: asset_v1.ResourceSearchResult) -> Dict[str, Any]:
        """
        סורק משאב בודד ומחזיר דוח מלא
        """
        pass
    
    def scan_resources(self, assets: List[asset_v1.ResourceSearchResult]) -> Dict[str, Any]:
        """
        סורק רשימת משאבים
        """
        results = {}
        for asset in assets:
            try:
                result = self.scan_resource(asset)
                results[asset.name] = result
                self.logger.info(f"Scanned {asset.asset_type}: {asset.display_name or asset.name}")
            except Exception as e:
                self.logger.error(f"Error scanning {asset.name}: {str(e)}")
                results[asset.name] = {'error': str(e)}
        
        self.results.update(results)
        return results