# import logging
# from dataclasses import dataclass, field
# from datetime import datetime, timezone
# from typing import Any, Optional, Dict, List
# from functools import lru_cache

# from google.cloud import asset_v1, iam_admin_v1
# from google.api_core import exceptions

# # --- הגדרת המבנה של הנתונים ---
# @dataclass
# class ResourceMetadata:
#     resource_id: str
#     resource_type: str
#     project_id: str
#     name: str
#     display_name: Optional[str] = None
#     location: Optional[str] = None
#     labels: Dict[str, str] = field(default_factory=dict)
#     creation_time: Optional[datetime] = None
#     update_time: Optional[datetime] = None
#     state: Optional[str] = None
#     raw_data: Dict[str, Any] = field(default_factory=dict)

# class CloudScanner:
#     def __init__(self, project_id: str, include_raw_data: bool = True):
#         self.project_id = project_id
#         self.config = {'include_raw_data': include_raw_data}
#         self.asset_client = asset_v1.AssetServiceClient()
#         self.iam_client = iam_admin_v1.IAMClient()

#     @lru_cache(maxsize=1024)
#     def _fetch_iam_creation_time(self, asset_name: str) -> Optional[datetime]:
#         try:
#             # ניקוי השם לפורמט הנכון
#             formatted_name = asset_name
#             if formatted_name.startswith("//"):
#                 formatted_name = formatted_name.split("/", 3)[-1]
            
#             # קריאה ל-API
#             sa = self.iam_client.get_service_account(request={"name": formatted_name})
            
#             # המרת אובייקט ה-Protobuf למילון פייתון רגיל
#             # זה פותר את השגיאה של "Unknown field"
#             sa_dict = iam_admin_v1.ServiceAccount.to_dict(sa)
            
#             # ב-IAM API, השדה בדרך כלל לא מופיע ב-to_dict אם הוא ריק,
#             # אבל כאן נוכל לבדוק שמות חלופיים שגוגל משתמשת בהם
#             raw_time = sa_dict.get('create_time') or getattr(sa, 'create_time', None)
            
#             return raw_time

#         except Exception as e:
#             print(f"DEBUG: IAM API failed for {asset_name}: {e}")
#             return None

#     def _create_metadata(self, asset: asset_v1.ResourceSearchResult) -> ResourceMetadata:
#         """יצירת המטא-דאטה והמרת זמנים"""
        
#         def convert_time(ts: Any) -> Optional[datetime]:
#             if ts is None: return None
#             if hasattr(ts, 'seconds') and not isinstance(ts, datetime):
#                 return datetime.fromtimestamp(ts.seconds, tz=timezone.utc)
#             if isinstance(ts, datetime):
#                 return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts
#             if isinstance(ts, str):
#                 try:
#                     return datetime.fromisoformat(ts.replace('Z', '+00:00'))
#                 except ValueError:
#                     return None
#             return None

#         # חילוץ תאריכים (וניסיון השלמה אם חסר)
#         c_time = convert_time(asset.create_time)
#         u_time = convert_time(asset.update_time)

#         if c_time is None and asset.asset_type == "iam.googleapis.com/ServiceAccount":
#             raw_time = self._fetch_iam_creation_time(asset.name)
#             c_time = convert_time(raw_time)

#         return ResourceMetadata(
#             resource_id=asset.name,
#             resource_type=asset.asset_type,
#             project_id=asset.project.split('/')[-1] if asset.project else self.project_id,
#             name=asset.name.split('/')[-1],
#             display_name=asset.display_name,
#             location=asset.location,
#             labels=dict(asset.labels) if asset.labels else {},
#             creation_time=c_time,
#             update_time=u_time,
#             state=getattr(asset, 'state', None),
#             raw_data=asset_v1.ResourceSearchResult.to_dict(asset) if self.config.get('include_raw_data') else {}
#         )

#     def scan(self, asset_types: List[str] = None) -> List[ResourceMetadata]:
#         """הקריאה בפועל ל-GCP והרצת הלוגיקה"""
#         scope = f"projects/{self.project_id}"
#         results = []
        
#         print(f"Starting scan for project: {self.project_id}...")
        
#         try:
#             pager = self.asset_client.search_all_resources(
#                 request={
#                     "scope": scope,
#                     "asset_types": asset_types or ["iam.googleapis.com/ServiceAccount"],
#                 }
#             )

#             for asset in pager:
#                 metadata = self._create_metadata(asset)
#                 results.append(metadata)
#                 print(f"Scanned: {metadata.name} | Created: {metadata.creation_time}")

#         except Exception as e:
#             print(f"Scan failed: {e}")
            
#         return results

# # --- הרצה לבדיקה ---
# if __name__ == "__main__":    
#     # החלף ב-Project ID האמיתי שלך
#     MY_PROJECT = "sky-geo-dig-dev-t-cant-1" 
    
#     scanner = CloudScanner(MY_PROJECT)
#     all_assets = scanner.scan()
    
#     print(f"\nTotal assets found: {len(all_assets)}")