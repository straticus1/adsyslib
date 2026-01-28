"""
Cloud provider integrations.
Supports AWS (boto3) and Oracle Cloud Infrastructure (OCI).
"""
from adsyslib.cloud.base import CloudProvider
from adsyslib.cloud.aws import AWSProvider
from adsyslib.cloud.oracle import OracleProvider

def get_cloud_provider(provider_type: str, **kwargs) -> CloudProvider:
    """
    Factory function to get a cloud provider instance.
    
    Args:
        provider_type: 'aws' or 'oracle'/'oci'
        **kwargs: Provider-specific arguments (region, profile, etc.)
    
    Returns:
        CloudProvider instance.
    """
    provider_type = provider_type.lower()
    if provider_type == "aws":
        return AWSProvider(
            region_name=kwargs.get("region"),
            profile_name=kwargs.get("profile")
        )
    elif provider_type in ("oracle", "oci"):
        return OracleProvider(
            config_file=kwargs.get("config_file"),
            profile=kwargs.get("profile", "DEFAULT")
        )
    else:
        raise ValueError(f"Unknown cloud provider: {provider_type}. Supported: aws, oracle/oci")

__all__ = ["CloudProvider", "AWSProvider", "OracleProvider", "get_cloud_provider"]
