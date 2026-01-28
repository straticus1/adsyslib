import logging
import os
from typing import List, Dict, Any
import oci
from adsyslib.cloud.base import CloudProvider

logger = logging.getLogger(__name__)

class OracleProvider(CloudProvider):
    """
    Oracle Cloud Infrastructure (OCI) Implementation.
    Requires ~/.oci/config or standard OCI environment variables.
    """
    def __init__(self, config_file: str = None, profile: str = "DEFAULT"):
        if config_file:
            self.config = oci.config.from_file(file_location=config_file, profile_name=profile)
        else:
            self.config = oci.config.from_file(profile_name=profile) # defaults to ~/.oci/config
        
        self.compute_client = oci.core.ComputeClient(self.config)
        self.identity_client = oci.identity.IdentityClient(self.config)
        self.object_storage_client = oci.object_storage.ObjectStorageClient(self.config)
        
        # OCI often requires compartmentalization. We try to infer or let user pass it?
        # For simplicity, we assume user passes compartment_id in methods or we fetch tenancy root.
        self.tenancy_id = self.config["tenancy"]

    def list_instances(self, region: str = None) -> List[Dict[str, Any]]:
        # OCI listing requires compartment ID. 
        # listing ALL instances in tenancy is expensive (recursive).
        # We'll list in the root compartment for now as a default.
        if region:
            self.config["region"] = region
            self.compute_client = oci.core.ComputeClient(self.config)

        # Listing instances
        logger.info(f"Listing OCI instances in compartment {self.tenancy_id}")
        instances = self.compute_client.list_instances(self.tenancy_id).data
        
        result = []
        for inst in instances:
            result.append({
                "id": inst.id,
                "name": inst.display_name,
                "state": inst.lifecycle_state,
                "region": inst.region,
                "shape": inst.shape
            })
        return result

    def start_instance(self, instance_id: str):
        logger.info(f"Starting OCI instance {instance_id}")
        self.compute_client.instance_action(instance_id, "START")

    def stop_instance(self, instance_id: str):
        logger.info(f"Stopping OCI instance {instance_id}")
        self.compute_client.instance_action(instance_id, "STOP")

    def upload_file(self, bucket: str, file_path: str, object_name: str = None):
        object_name = object_name or os.path.basename(file_path)
        namespace = self.object_storage_client.get_namespace().data
        logger.info(f"Uploading {file_path} to OCI bucket {bucket}")
        
        with open(file_path, 'rb') as f:
            self.object_storage_client.put_object(
                namespace,
                bucket,
                object_name,
                f
            )

    def download_file(self, bucket: str, object_name: str, file_path: str):
        namespace = self.object_storage_client.get_namespace().data
        logger.info(f"Downloading OCI object {object_name} from {bucket}")
        
        response = self.object_storage_client.get_object(namespace, bucket, object_name)
        with open(file_path, 'wb') as f:
            for chunk in response.data.raw.stream(1024 * 1024, decode_content=False):
                f.write(chunk)
