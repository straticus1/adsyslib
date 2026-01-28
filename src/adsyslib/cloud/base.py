from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

class CloudProvider(ABC):
    """
    Unified interface for Cloud Providers (AWS, OCI).
    Focuses on common tasks: Compute management, Object Storage.
    """

    @abstractmethod
    def list_instances(self, region: str = None) -> List[Dict[str, Any]]:
        """List compute instances in a region."""
        pass

    @abstractmethod
    def start_instance(self, instance_id: str):
        """Start a stopped instance."""
        pass

    @abstractmethod
    def stop_instance(self, instance_id: str):
        """Stop a running instance."""
        pass

    @abstractmethod
    def upload_file(self, bucket: str, file_path: str, object_name: str = None):
        """Upload a file to object storage."""
        pass

    @abstractmethod
    def download_file(self, bucket: str, object_name: str, file_path: str):
        """Download a file from object storage."""
        pass
