"""
scanners/artifact_registry_scanner.py

Scans Artifact Registry repositories. Analyzes Docker image metadata (tags, update times)
and identifies which GCP resources are consuming these images using audit logs.
"""

from typing import Optional, Dict, List
from google.cloud import artifactregistry_v1
from gcp_scanner.base_scanner import BaseScanner
from gcp_scanner.mixins import LoggingMixin, IamMixin
from gcp_scanner.models import (
    ResourceMetadata, Finding, Severity, FindingType, RelationshipInfo
)

class ArtifactRegistryScanner(BaseScanner, LoggingMixin, IamMixin):
    
    HANDLED_ASSET_TYPES = {"artifactregistry.googleapis.com/Repository"}

    def __init__(self, project_id: str, config: Optional[Dict] = None):
        """
        Initializes the scanner and its required clients.
        
        Args:
            project_id (str): The GCP project ID.
            config (dict, optional): Scanner configuration.
        """
        super().__init__(project_id, config)
        self.setup_logging_client()
        self.setup_iam_client()
        self.ar_client = artifactregistry_v1.ArtifactRegistryClient()

    def can_handle(self, asset_type: str) -> bool:
        """
        Determines if the scanner supports the specific GCP asset type.
        """
        return asset_type in self.HANDLED_ASSET_TYPES

    def analyze_health(self, asset, metadata: ResourceMetadata) -> dict:
        """
        Retrieves metadata for every image, including formatted update timestamps.
        
        Args:
            asset: Raw asset data.
            metadata: Resource metadata with ID.

        Returns:
            dict: List of image details (URI, tags, update_time).
        """
        image_details = []
        
        # Clean the resource_id to match: projects/{p}/locations/{l}/repositories/{r}
        raw_id = metadata.resource_id
        clean_parent = raw_id.split('artifactregistry.googleapis.com/')[-1].strip('/')

        try:
            request = artifactregistry_v1.ListDockerImagesRequest(parent=clean_parent)
            images = self.ar_client.list_docker_images(request=request)
            
            for img in images:
                image_details.append({
                    'uri': img.uri,
                    'tags': list(img.tags),
                    # Direct call to isoformat() as confirmed in your test
                    'update_time': img.update_time.isoformat() if img.update_time else None, # type: ignore
                })
        except Exception as e:
            self.logger.error(f"Failed to fetch image data for {metadata.name}: {e}")

        return {
            'images_details': image_details,
            'image_count': len(image_details)
        }

    def analyze_relationships(self, asset, metadata: ResourceMetadata) -> dict:
        """
        Identifies dependent resources (GKE, Cloud Run, etc.) by analyzing access logs.
        
        Args:
            asset: Raw asset data.
            metadata: Resource metadata.

        Returns:
            dict: Dependent resource types and principals who pulled images.
        """
        lookback = self.config.get('usage_lookback_days', 90)
        
        # Use LoggingMixin to fetch logs related to this repository
        # This will look for operations like 'google.devtools.artifactregistry.v1.ArtifactRegistry.DownloadDockerImage'
        log_summary = self.get_access_logs_summary(metadata.name, days_back=lookback)

        # Extract unique resource types that pulled images (e.g., 'gke_cluster', 'cloud_run_revision')
        dependents = list(set([
            log.get('resource_type') 
            for log in log_summary.get('raw_logs', []) 
            if log.get('resource_type')
        ]))

        return {
            'parent_project': metadata.project_id,
            'dependent_resource_types': dependents,
            'active_pullers': log_summary.get('users', []),
            'last_access': log_summary.get('last_access')
        }