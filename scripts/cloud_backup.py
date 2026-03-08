#!/usr/bin/env python3
"""Cloud storage backup module for AgentGate.

Supports uploading and downloading backups to/from S3 and GCS.
Credentials are pulled from Azure Key Vault in production.
"""

from __future__ import annotations

import argparse
from importlib import import_module
import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path

logger = logging.getLogger(__name__)

PROVIDER_ERRORS = (
    AttributeError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
)


def _load_s3_client_factory():
    """Load the boto3 S3 client factory."""
    boto3_module = import_module("boto3")
    return getattr(boto3_module, "client")


def _load_s3_errors() -> tuple[type[Exception], ...]:
    """Load the AWS client error classes used by boto3."""
    botocore_exceptions = import_module("botocore.exceptions")
    return (
        getattr(botocore_exceptions, "BotoCoreError"),
        getattr(botocore_exceptions, "ClientError"),
    )


def _load_gcs_storage_client():
    """Load the Google Cloud Storage client class."""
    storage_module = import_module("google.cloud.storage")
    return getattr(storage_module, "Client")


def _load_gcs_errors() -> tuple[type[Exception], ...]:
    """Load the Google Cloud error classes used by storage operations."""
    exceptions_module = import_module("google.api_core.exceptions")
    return (
        getattr(exceptions_module, "GoogleAPICallError"),
        getattr(exceptions_module, "NotFound"),
        getattr(exceptions_module, "Conflict"),
        getattr(exceptions_module, "Forbidden"),
    )


def _load_azure_key_vault_clients():
    """Load Azure Key Vault credential and client classes."""
    identity_module = import_module("azure.identity")
    secrets_module = import_module("azure.keyvault.secrets")
    exceptions_module = import_module("azure.core.exceptions")
    return (
        getattr(identity_module, "DefaultAzureCredential"),
        getattr(secrets_module, "SecretClient"),
        getattr(exceptions_module, "ResourceNotFoundError"),
        getattr(exceptions_module, "ClientAuthenticationError"),
        getattr(exceptions_module, "HttpResponseError"),
    )


class BackupStorageProvider(ABC):
    """Abstract base class for cloud storage providers."""

    @abstractmethod
    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload a file to cloud storage.

        Args:
            local_path: Path to local file
            remote_path: Destination path in cloud storage

        Returns:
            True if upload succeeded, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download a file from cloud storage.

        Args:
            remote_path: Path in cloud storage
            local_path: Destination path on local filesystem

        Returns:
            True if download succeeded, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    def list_backups(self, prefix: str = "") -> list[str]:
        """List backup files in cloud storage.

        Args:
            prefix: Optional prefix to filter by

        Returns:
            List of backup file paths
        """
        raise NotImplementedError

    @abstractmethod
    def ensure_bucket_exists(self) -> bool:
        """Ensure the storage bucket exists, creating it if necessary.

        Returns:
            True if bucket exists or was created, False on error
        """
        raise NotImplementedError


class S3BackupProvider(BackupStorageProvider):
    """AWS S3 backup storage provider."""

    def __init__(
        self,
        bucket: str,
        *,
        region: str = "us-east-1",
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        auto_create_bucket: bool = False,
    ) -> None:
        self.bucket = bucket
        self.region = region
        self.auto_create_bucket = auto_create_bucket
        self._client = None

        try:
            create_client = _load_s3_client_factory()
            if access_key_id and secret_access_key:
                self._client = create_client(
                    "s3",
                    region_name=region,
                    aws_access_key_id=access_key_id,
                    aws_secret_access_key=secret_access_key,
                )
            else:
                self._client = create_client("s3", region_name=region)
        except ImportError:
            logger.error("boto3 is required for S3 backup. Install with: pip install boto3")
            raise

    def ensure_bucket_exists(self) -> bool:
        """Ensure the S3 bucket exists."""
        if self._client is None:
            return False

        try:
            self._client.head_bucket(Bucket=self.bucket)
            return True
        except _load_s3_errors() as error:
            response = getattr(error, "response", {})
            error_code = response.get("Error", {}).get("Code", "")
            if error_code == "404" and self.auto_create_bucket:
                try:
                    if self.region == "us-east-1":
                        self._client.create_bucket(Bucket=self.bucket)
                    else:
                        self._client.create_bucket(
                            Bucket=self.bucket,
                            CreateBucketConfiguration={"LocationConstraint": self.region},
                        )
                    logger.info("Created S3 bucket: %s", self.bucket)
                    return True
                except _load_s3_errors() as create_err:
                    logger.error("Failed to create S3 bucket: %s", create_err)
                    return False
            logger.error("S3 bucket does not exist: %s", self.bucket)
            return False
        except PROVIDER_ERRORS as err:
            logger.error("Error checking S3 bucket: %s", err)
            return False

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload a file to S3."""
        if self._client is None:
            return False

        try:
            self._client.upload_file(
                local_path,
                self.bucket,
                remote_path,
                ExtraArgs={"ServerSideEncryption": "AES256"},
            )
            logger.info("Uploaded %s to s3://%s/%s", local_path, self.bucket, remote_path)
            return True
        except (*_load_s3_errors(), *PROVIDER_ERRORS) as error:
            logger.error("Failed to upload to S3: %s", error)
            return False

    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download a file from S3."""
        if self._client is None:
            return False

        try:
            Path(local_path).parent.mkdir(parents=True, exist_ok=True)
            self._client.download_file(self.bucket, remote_path, local_path)
            logger.info("Downloaded s3://%s/%s to %s", self.bucket, remote_path, local_path)
            return True
        except (*_load_s3_errors(), *PROVIDER_ERRORS) as error:
            logger.error("Failed to download from S3: %s", error)
            return False

    def list_backups(self, prefix: str = "") -> list[str]:
        """List backup files in S3."""
        if self._client is None:
            return []

        try:
            response = self._client.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
            return [obj["Key"] for obj in response.get("Contents", [])]
        except (*_load_s3_errors(), *PROVIDER_ERRORS) as error:
            logger.error("Failed to list S3 objects: %s", error)
            return []


class GCSBackupProvider(BackupStorageProvider):
    """Google Cloud Storage backup provider."""

    def __init__(
        self,
        bucket: str,
        project_id: str | None = None,
        auto_create_bucket: bool = False,
    ) -> None:
        self.bucket_name = bucket
        self.project_id = project_id
        self.auto_create_bucket = auto_create_bucket
        self._client = None
        self._bucket = None

        try:
            storage_client = _load_gcs_storage_client()
            self._client = storage_client(project=project_id)
        except ImportError:
            logger.error(
                "google-cloud-storage is required for GCS backup. "
                "Install with: pip install google-cloud-storage"
            )
            raise

    def ensure_bucket_exists(self) -> bool:
        """Ensure the GCS bucket exists."""
        if self._client is None:
            return False

        try:
            self._bucket = self._client.get_bucket(self.bucket_name)
            return True
        except _load_gcs_errors() as error:
            if self.auto_create_bucket and error.__class__.__name__ == "NotFound":
                try:
                    self._bucket = self._client.create_bucket(self.bucket_name)
                    logger.info("Created GCS bucket: %s", self.bucket_name)
                    return True
                except (*_load_gcs_errors(), *PROVIDER_ERRORS) as create_err:
                    logger.error("Failed to create GCS bucket: %s", create_err)
                    return False
            logger.error("GCS bucket does not exist: %s", self.bucket_name)
            return False

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload a file to GCS."""
        if self._client is None:
            return False

        try:
            if self._bucket is None:
                self._bucket = self._client.bucket(self.bucket_name)
            blob = self._bucket.blob(remote_path)
            blob.upload_from_filename(local_path)
            logger.info("Uploaded %s to gs://%s/%s", local_path, self.bucket_name, remote_path)
            return True
        except (*_load_gcs_errors(), *PROVIDER_ERRORS) as error:
            logger.error("Failed to upload to GCS: %s", error)
            return False

    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download a file from GCS."""
        if self._client is None:
            return False

        try:
            Path(local_path).parent.mkdir(parents=True, exist_ok=True)
            if self._bucket is None:
                self._bucket = self._client.bucket(self.bucket_name)
            blob = self._bucket.blob(remote_path)
            blob.download_to_filename(local_path)
            logger.info("Downloaded gs://%s/%s to %s", self.bucket_name, remote_path, local_path)
            return True
        except (*_load_gcs_errors(), *PROVIDER_ERRORS) as error:
            logger.error("Failed to download from GCS: %s", error)
            return False

    def list_backups(self, prefix: str = "") -> list[str]:
        """List backup files in GCS."""
        if self._client is None:
            return []

        try:
            if self._bucket is None:
                self._bucket = self._client.bucket(self.bucket_name)
            blobs = self._bucket.list_blobs(prefix=prefix)
            return [blob.name for blob in blobs]
        except (*_load_gcs_errors(), *PROVIDER_ERRORS) as error:
            logger.error("Failed to list GCS objects: %s", error)
            return []


def get_akv_secret(vault_url: str, secret_id: str) -> str | None:
    """Fetch a secret from Azure Key Vault.

    Args:
        vault_url: Azure Key Vault URL
        secret_id: Secret identifier

    Returns:
        Secret value or None if not found
    """
    try:
        (
            default_azure_credential,
            secret_client_class,
            resource_not_found_error,
            client_authentication_error,
            http_response_error,
        ) = _load_azure_key_vault_clients()

        credential = default_azure_credential()
        client = secret_client_class(
            vault_url=vault_url,
            credential=credential,
        )
        secret = client.get_secret(secret_id)
        return secret.value
    except resource_not_found_error:
        logger.warning(
            "Secret not found in Azure Key Vault: %s",
            secret_id,
        )
        return None
    except ImportError:
        logger.warning("azure-identity or azure-keyvault-secrets not installed")
        return None
    except (client_authentication_error, http_response_error, *PROVIDER_ERRORS) as exc:
        logger.error(
            "Failed to fetch secret from Key Vault: %s",
            exc,
        )
        return None


def get_provider(
    provider_type: str,
    bucket: str,
    auto_create_bucket: bool = False,
    vault_url: str | None = None,
) -> BackupStorageProvider:
    """Factory function to create a backup storage provider.

    Args:
        provider_type: 's3' or 'gcs'
        bucket: Bucket name
        auto_create_bucket: Whether to create the bucket if it doesn't exist
        vault_url: Azure Key Vault URL (for credential lookup)

    Returns:
        Configured backup storage provider
    """
    if provider_type == "s3":
        # Try to get AWS credentials from Key Vault if vault_url provided
        access_key_id = None
        secret_access_key = None
        if vault_url:
            access_key_id = get_akv_secret(vault_url, "aws-access-key-id")
            secret_access_key = get_akv_secret(vault_url, "aws-secret-access-key")

        # Fall back to environment variables
        if not access_key_id:
            access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
        if not secret_access_key:
            secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")

        region = os.getenv("AWS_REGION", "us-east-1")

        return S3BackupProvider(
            bucket=bucket,
            region=region,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            auto_create_bucket=auto_create_bucket,
        )

    if provider_type == "gcs":
        return GCSBackupProvider(
            bucket=bucket,
            project_id=os.getenv("GCP_PROJECT_ID"),
            auto_create_bucket=auto_create_bucket,
        )

    raise ValueError(f"Unknown provider type: {provider_type}")


def upload_backup(
    provider: BackupStorageProvider,
    backup_dir: str,
    prefix: str = "",
) -> bool:
    """Upload all backup files from a directory to cloud storage.

    Args:
        provider: Backup storage provider
        backup_dir: Local backup directory
        prefix: Optional prefix for remote paths

    Returns:
        True if all uploads succeeded
    """
    if not provider.ensure_bucket_exists():
        return False

    backup_path = Path(backup_dir)
    if not backup_path.exists():
        logger.error("Backup directory does not exist: %s", backup_dir)
        return False

    success = True
    for file in backup_path.iterdir():
        if file.is_file() and not file.name.startswith("."):
            remote_path = f"{prefix}/{file.name}" if prefix else file.name
            if not provider.upload_file(str(file), remote_path):
                success = False

    return success


def download_backup(
    provider: BackupStorageProvider,
    remote_path: str,
    local_dir: str,
) -> bool:
    """Download a backup file from cloud storage.

    Args:
        provider: Backup storage provider
        remote_path: Path in cloud storage
        local_dir: Local directory to download to

    Returns:
        True if download succeeded
    """
    local_path = Path(local_dir) / Path(remote_path).name
    return provider.download_file(remote_path, str(local_path))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cloud backup operations for AgentGate.")

    parser.add_argument(
        "action",
        choices=["upload", "download", "list"],
        help="Action to perform",
    )
    parser.add_argument(
        "--provider",
        choices=["s3", "gcs"],
        default=os.getenv("CLOUD_PROVIDER", "gcs"),
        help="Cloud storage provider (default: $CLOUD_PROVIDER or gcs)",
    )
    parser.add_argument(
        "--bucket",
        default=os.getenv("CLOUD_BUCKET"),
        help="Bucket name (default: $CLOUD_BUCKET)",
    )
    parser.add_argument(
        "--backup-dir",
        default=os.getenv("BACKUP_DIR", "/var/backups/agentgate"),
        help="Local backup directory",
    )
    parser.add_argument(
        "--prefix",
        default="",
        help="Prefix for cloud storage paths",
    )
    parser.add_argument(
        "--remote-path",
        help="Remote path for download action",
    )
    parser.add_argument(
        "--auto-create-bucket",
        action="store_true",
        default=os.getenv("CLOUD_AUTO_CREATE_BUCKET", "").lower() == "true",
        help="Create bucket if it doesn't exist",
    )
    parser.add_argument(
        "--vault-url",
        default=os.getenv("AZURE_KEY_VAULT_URL"),
        help="Azure Key Vault URL (for credential lookup)",
    )

    return parser


def _validate_arguments(args: argparse.Namespace) -> int | None:
    """Validate command-line arguments. Returns error code or None if valid."""
    if not args.bucket:
        logger.error("Bucket name is required (--bucket or $CLOUD_BUCKET)")
        return 2

    if args.action == "download" and not args.remote_path:
        logger.error("--remote-path is required for download action")
        return 2

    return None


def _execute_action(
    provider: BackupStorageProvider,
    action: str,
    backup_dir: str,
    prefix: str,
    remote_path: str | None,
) -> int:
    """Execute the requested action. Returns exit code."""
    if action == "upload":
        success = upload_backup(provider, backup_dir, prefix)
        return 0 if success else 1

    if action == "download":
        success = download_backup(provider, remote_path, backup_dir)
        return 0 if success else 1

    if action == "list":
        backups = provider.list_backups(prefix)
        for backup in backups:
            print(backup)
        return 0

    return 0


def main() -> int:
    """CLI entry point for cloud backup operations."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = _build_parser()
    args = parser.parse_args()

    # Validate arguments
    validation_error = _validate_arguments(args)
    if validation_error is not None:
        return validation_error

    # Create provider
    try:
        provider = get_provider(
            provider_type=args.provider,
            bucket=args.bucket,
            auto_create_bucket=args.auto_create_bucket,
            vault_url=args.vault_url,
        )
    except (ImportError, *PROVIDER_ERRORS) as error:
        logger.error("Failed to create provider: %s", error)
        return 1

    # Execute action
    return _execute_action(
        provider,
        args.action,
        args.backup_dir,
        args.prefix,
        args.remote_path,
    )


if __name__ == "__main__":
    raise SystemExit(main())
