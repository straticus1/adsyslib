import logging
import os
import boto3
from typing import List, Dict, Any
from adsyslib.cloud.base import CloudProvider

logger = logging.getLogger(__name__)

class AWSProvider(CloudProvider):
    """
    AWS Implementation using boto3.
    """
    def __init__(self, region_name: str = None, profile_name: str = None):
        self.session = boto3.Session(region_name=region_name, profile_name=profile_name)
        self.ec2 = self.session.client("ec2")
        self.s3 = self.session.client("s3")

    def list_instances(self, region: str = None) -> List[Dict[str, Any]]:
        # If region is specified, we might need a new client/resource
        client = self.ec2
        if region:
            client = self.session.client("ec2", region_name=region)
        
        response = client.describe_instances()
        instances = []
        for reservation in response.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                instances.append({
                    "id": inst["InstanceId"],
                    "state": inst["State"]["Name"],
                    "type": inst["InstanceType"],
                    "public_ip": inst.get("PublicIpAddress"),
                    "private_ip": inst.get("PrivateIpAddress"),
                    "tags": inst.get("Tags", [])
                })
        return instances

    def start_instance(self, instance_id: str):
        logger.info(f"Starting AWS instance {instance_id}")
        self.ec2.start_instances(InstanceIds=[instance_id])

    def stop_instance(self, instance_id: str):
        logger.info(f"Stopping AWS instance {instance_id}")
        self.ec2.stop_instances(InstanceIds=[instance_id])

    def upload_file(self, bucket: str, file_path: str, object_name: str = None):
        object_name = object_name or os.path.basename(file_path)
        logger.info(f"Uploading {file_path} to s3://{bucket}/{object_name}")
        self.s3.upload_file(file_path, bucket, object_name)

    def download_file(self, bucket: str, object_name: str, file_path: str):
        logger.info(f"Downloading s3://{bucket}/{object_name} to {file_path}")
        self.s3.download_file(bucket, object_name, file_path)
