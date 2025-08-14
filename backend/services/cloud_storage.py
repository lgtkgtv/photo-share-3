"""
Secure Cloud Storage Adapter with Enterprise-Grade Encryption and Multi-Provider Support.
Provides unified interface for AWS S3, Azure Blob Storage, and Google Cloud Storage with comprehensive security.
"""
import os
import asyncio
import hashlib
import tempfile
import logging
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import AzureError
from google.cloud import storage as gcs
from google.api_core import exceptions as gcs_exceptions

from services.security import SecurityUtils

logger = logging.getLogger(__name__)

class CloudProvider(Enum):
    """Supported cloud storage providers."""
    AWS_S3 = "aws_s3"
    AZURE_BLOB = "azure_blob"
    GOOGLE_CLOUD = "google_cloud"
    LOCAL = "local"  # For development/testing

class EncryptionMethod(Enum):
    """Available encryption methods."""
    AES_256_GCM = "aes_256_gcm"
    AES_256_CBC = "aes_256_cbc"
    FERNET = "fernet"

class StorageTier(Enum):
    """Storage tier for cost optimization."""
    HOT = "hot"          # Frequently accessed
    WARM = "warm"        # Infrequently accessed
    COLD = "cold"        # Rarely accessed
    ARCHIVE = "archive"  # Long-term archival

@dataclass
class StorageLocation:
    """Represents a cloud storage location."""
    provider: CloudProvider
    bucket: str
    key: str
    region: Optional[str] = None
    tier: Optional[StorageTier] = None
    encryption_key_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class UploadResult:
    """Result of a file upload operation."""
    location: StorageLocation
    file_hash: str
    encrypted_size: int
    original_size: int
    encryption_key_id: str
    upload_time: float
    success: bool
    error_message: Optional[str] = None

@dataclass
class DownloadResult:
    """Result of a file download operation."""
    file_data: bytes
    file_hash: str
    original_size: int
    download_time: float
    success: bool
    error_message: Optional[str] = None

class EncryptionManager:
    """Handles file encryption and decryption with multiple methods."""
    
    def __init__(self, master_key: Optional[str] = None):
        self.master_key = master_key or os.getenv('CLOUD_STORAGE_MASTER_KEY')
        if not self.master_key:
            raise ValueError("Master encryption key must be provided")
        
        self.key_derivation_salt = os.getenv('ENCRYPTION_SALT', 'photo_share_salt').encode()
        
    def derive_key(self, key_id: str) -> bytes:
        """Derive encryption key from master key and key ID."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.key_derivation_salt + key_id.encode(),
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.master_key.encode())
    
    def encrypt_file(self, file_data: bytes, key_id: str, method: EncryptionMethod = EncryptionMethod.AES_256_GCM) -> Tuple[bytes, Dict[str, Any]]:
        """Encrypt file data with specified method."""
        try:
            if method == EncryptionMethod.AES_256_GCM:
                return self._encrypt_aes_gcm(file_data, key_id)
            elif method == EncryptionMethod.AES_256_CBC:
                return self._encrypt_aes_cbc(file_data, key_id)
            elif method == EncryptionMethod.FERNET:
                return self._encrypt_fernet(file_data, key_id)
            else:
                raise ValueError(f"Unsupported encryption method: {method}")
                
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_file(self, encrypted_data: bytes, key_id: str, metadata: Dict[str, Any]) -> bytes:
        """Decrypt file data using metadata."""
        try:
            method = EncryptionMethod(metadata['encryption_method'])
            
            if method == EncryptionMethod.AES_256_GCM:
                return self._decrypt_aes_gcm(encrypted_data, key_id, metadata)
            elif method == EncryptionMethod.AES_256_CBC:
                return self._decrypt_aes_cbc(encrypted_data, key_id, metadata)
            elif method == EncryptionMethod.FERNET:
                return self._decrypt_fernet(encrypted_data, key_id, metadata)
            else:
                raise ValueError(f"Unsupported encryption method: {method}")
                
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    def _encrypt_aes_gcm(self, data: bytes, key_id: str) -> Tuple[bytes, Dict[str, Any]]:
        """Encrypt using AES-256-GCM."""
        key = self.derive_key(key_id)
        iv = os.urandom(12)  # 96-bit IV for GCM
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        metadata = {
            'encryption_method': EncryptionMethod.AES_256_GCM.value,
            'iv': base64.b64encode(iv).decode(),
            'tag': base64.b64encode(encryptor.tag).decode(),
            'key_id': key_id
        }
        
        return ciphertext, metadata
    
    def _decrypt_aes_gcm(self, ciphertext: bytes, key_id: str, metadata: Dict[str, Any]) -> bytes:
        """Decrypt using AES-256-GCM."""
        key = self.derive_key(key_id)
        iv = base64.b64decode(metadata['iv'])
        tag = base64.b64decode(metadata['tag'])
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def _encrypt_aes_cbc(self, data: bytes, key_id: str) -> Tuple[bytes, Dict[str, Any]]:
        """Encrypt using AES-256-CBC with PKCS7 padding."""
        from cryptography.hazmat.primitives import padding
        
        key = self.derive_key(key_id)
        iv = os.urandom(16)  # 128-bit IV for CBC
        
        # Apply PKCS7 padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        metadata = {
            'encryption_method': EncryptionMethod.AES_256_CBC.value,
            'iv': base64.b64encode(iv).decode(),
            'key_id': key_id
        }
        
        return ciphertext, metadata
    
    def _decrypt_aes_cbc(self, ciphertext: bytes, key_id: str, metadata: Dict[str, Any]) -> bytes:
        """Decrypt using AES-256-CBC with PKCS7 padding."""
        from cryptography.hazmat.primitives import padding
        
        key = self.derive_key(key_id)
        iv = base64.b64decode(metadata['iv'])
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()
    
    def _encrypt_fernet(self, data: bytes, key_id: str) -> Tuple[bytes, Dict[str, Any]]:
        """Encrypt using Fernet (AES-128 in CBC mode with HMAC)."""
        key = self.derive_key(key_id)[:32]  # Fernet uses 32-byte keys
        fernet_key = base64.urlsafe_b64encode(key)
        
        f = Fernet(fernet_key)
        ciphertext = f.encrypt(data)
        
        metadata = {
            'encryption_method': EncryptionMethod.FERNET.value,
            'key_id': key_id
        }
        
        return ciphertext, metadata
    
    def _decrypt_fernet(self, ciphertext: bytes, key_id: str, metadata: Dict[str, Any]) -> bytes:
        """Decrypt using Fernet."""
        key = self.derive_key(key_id)[:32]
        fernet_key = base64.urlsafe_b64encode(key)
        
        f = Fernet(fernet_key)
        return f.decrypt(ciphertext)

class CloudStorageProvider(ABC):
    """Abstract base class for cloud storage providers."""
    
    @abstractmethod
    async def upload_file(self, file_data: bytes, location: StorageLocation, metadata: Dict[str, Any]) -> bool:
        """Upload file to cloud storage."""
        pass
    
    @abstractmethod
    async def download_file(self, location: StorageLocation) -> bytes:
        """Download file from cloud storage."""
        pass
    
    @abstractmethod
    async def delete_file(self, location: StorageLocation) -> bool:
        """Delete file from cloud storage."""
        pass
    
    @abstractmethod
    async def list_files(self, bucket: str, prefix: str = "") -> List[Dict[str, Any]]:
        """List files in storage."""
        pass
    
    @abstractmethod
    async def get_file_info(self, location: StorageLocation) -> Dict[str, Any]:
        """Get file metadata."""
        pass

class AWSS3Provider(CloudStorageProvider):
    """AWS S3 storage provider with server-side encryption."""
    
    def __init__(self):
        self.s3_client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize S3 client with credentials."""
        try:
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
                region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
            )
        except NoCredentialsError:
            logger.warning("AWS credentials not found - S3 provider unavailable")
            self.s3_client = None
    
    async def upload_file(self, file_data: bytes, location: StorageLocation, metadata: Dict[str, Any]) -> bool:
        """Upload file to S3 with server-side encryption."""
        if not self.s3_client:
            raise RuntimeError("S3 client not initialized")
        
        try:
            # Prepare S3 metadata
            s3_metadata = {
                'file-hash': metadata.get('file_hash', ''),
                'original-size': str(metadata.get('original_size', 0)),
                'encryption-key-id': metadata.get('encryption_key_id', ''),
                'upload-timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            # Add encryption metadata
            if 'encryption_metadata' in metadata:
                enc_meta = metadata['encryption_metadata']
                s3_metadata.update({
                    'encryption-method': enc_meta.get('encryption_method', ''),
                    'encryption-iv': enc_meta.get('iv', ''),
                    'encryption-tag': enc_meta.get('tag', '')
                })
            
            # Upload with server-side encryption
            extra_args = {
                'Metadata': s3_metadata,
                'ServerSideEncryption': 'AES256',
                'ContentType': metadata.get('content_type', 'application/octet-stream')
            }
            
            # Use KMS encryption if key ID provided
            if location.encryption_key_id:
                extra_args['ServerSideEncryption'] = 'aws:kms'
                extra_args['SSEKMSKeyId'] = location.encryption_key_id
            
            # Set storage class based on tier
            if location.tier:
                storage_class_map = {
                    StorageTier.HOT: 'STANDARD',
                    StorageTier.WARM: 'STANDARD_IA',
                    StorageTier.COLD: 'GLACIER',
                    StorageTier.ARCHIVE: 'DEEP_ARCHIVE'
                }
                extra_args['StorageClass'] = storage_class_map.get(location.tier, 'STANDARD')
            
            # Upload file
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.s3_client.put_object(
                    Bucket=location.bucket,
                    Key=location.key,
                    Body=file_data,
                    **extra_args
                )
            )
            
            return True
            
        except ClientError as e:
            logger.error(f"S3 upload failed: {e}")
            return False
    
    async def download_file(self, location: StorageLocation) -> bytes:
        """Download file from S3."""
        if not self.s3_client:
            raise RuntimeError("S3 client not initialized")
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.s3_client.get_object(
                    Bucket=location.bucket,
                    Key=location.key
                )
            )
            
            return response['Body'].read()
            
        except ClientError as e:
            logger.error(f"S3 download failed: {e}")
            raise
    
    async def delete_file(self, location: StorageLocation) -> bool:
        """Delete file from S3."""
        if not self.s3_client:
            raise RuntimeError("S3 client not initialized")
        
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.s3_client.delete_object(
                    Bucket=location.bucket,
                    Key=location.key
                )
            )
            return True
            
        except ClientError as e:
            logger.error(f"S3 delete failed: {e}")
            return False
    
    async def list_files(self, bucket: str, prefix: str = "") -> List[Dict[str, Any]]:
        """List files in S3 bucket."""
        if not self.s3_client:
            raise RuntimeError("S3 client not initialized")
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.s3_client.list_objects_v2(
                    Bucket=bucket,
                    Prefix=prefix
                )
            )
            
            files = []
            for obj in response.get('Contents', []):
                files.append({
                    'key': obj['Key'],
                    'size': obj['Size'],
                    'last_modified': obj['LastModified'],
                    'etag': obj['ETag']
                })
            
            return files
            
        except ClientError as e:
            logger.error(f"S3 list failed: {e}")
            return []
    
    async def get_file_info(self, location: StorageLocation) -> Dict[str, Any]:
        """Get S3 object metadata."""
        if not self.s3_client:
            raise RuntimeError("S3 client not initialized")
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.s3_client.head_object(
                    Bucket=location.bucket,
                    Key=location.key
                )
            )
            
            return {
                'size': response['ContentLength'],
                'last_modified': response['LastModified'],
                'etag': response['ETag'],
                'metadata': response.get('Metadata', {}),
                'server_side_encryption': response.get('ServerSideEncryption'),
                'storage_class': response.get('StorageClass', 'STANDARD')
            }
            
        except ClientError as e:
            logger.error(f"S3 head object failed: {e}")
            return {}

class AzureBlobProvider(CloudStorageProvider):
    """Azure Blob Storage provider with encryption."""
    
    def __init__(self):
        self.blob_service_client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Azure Blob client."""
        try:
            connection_string = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
            if connection_string:
                self.blob_service_client = BlobServiceClient.from_connection_string(connection_string)
            else:
                account_name = os.getenv('AZURE_STORAGE_ACCOUNT_NAME')
                account_key = os.getenv('AZURE_STORAGE_ACCOUNT_KEY')
                if account_name and account_key:
                    account_url = f"https://{account_name}.blob.core.windows.net"
                    self.blob_service_client = BlobServiceClient(account_url=account_url, credential=account_key)
        except Exception as e:
            logger.warning(f"Azure Blob client initialization failed: {e}")
            self.blob_service_client = None
    
    async def upload_file(self, file_data: bytes, location: StorageLocation, metadata: Dict[str, Any]) -> bool:
        """Upload file to Azure Blob Storage."""
        if not self.blob_service_client:
            raise RuntimeError("Azure Blob client not initialized")
        
        try:
            blob_client = self.blob_service_client.get_blob_client(
                container=location.bucket,
                blob=location.key
            )
            
            # Prepare blob metadata
            blob_metadata = {
                'file_hash': metadata.get('file_hash', ''),
                'original_size': str(metadata.get('original_size', 0)),
                'encryption_key_id': metadata.get('encryption_key_id', ''),
                'upload_timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            # Add encryption metadata
            if 'encryption_metadata' in metadata:
                enc_meta = metadata['encryption_metadata']
                blob_metadata.update({
                    'encryption_method': enc_meta.get('encryption_method', ''),
                    'encryption_iv': enc_meta.get('iv', ''),
                    'encryption_tag': enc_meta.get('tag', '')
                })
            
            # Set blob tier based on storage tier
            blob_tier = None
            if location.tier:
                tier_map = {
                    StorageTier.HOT: 'Hot',
                    StorageTier.WARM: 'Cool',
                    StorageTier.COLD: 'Archive',
                    StorageTier.ARCHIVE: 'Archive'
                }
                blob_tier = tier_map.get(location.tier)
            
            # Upload blob
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: blob_client.upload_blob(
                    file_data,
                    overwrite=True,
                    metadata=blob_metadata,
                    standard_blob_tier=blob_tier,
                    content_settings={
                        'content_type': metadata.get('content_type', 'application/octet-stream')
                    }
                )
            )
            
            return True
            
        except AzureError as e:
            logger.error(f"Azure Blob upload failed: {e}")
            return False
    
    async def download_file(self, location: StorageLocation) -> bytes:
        """Download file from Azure Blob Storage."""
        if not self.blob_service_client:
            raise RuntimeError("Azure Blob client not initialized")
        
        try:
            blob_client = self.blob_service_client.get_blob_client(
                container=location.bucket,
                blob=location.key
            )
            
            download_stream = await asyncio.get_event_loop().run_in_executor(
                None,
                blob_client.download_blob
            )
            
            return download_stream.readall()
            
        except AzureError as e:
            logger.error(f"Azure Blob download failed: {e}")
            raise
    
    async def delete_file(self, location: StorageLocation) -> bool:
        """Delete file from Azure Blob Storage."""
        if not self.blob_service_client:
            raise RuntimeError("Azure Blob client not initialized")
        
        try:
            blob_client = self.blob_service_client.get_blob_client(
                container=location.bucket,
                blob=location.key
            )
            
            await asyncio.get_event_loop().run_in_executor(
                None,
                blob_client.delete_blob
            )
            
            return True
            
        except AzureError as e:
            logger.error(f"Azure Blob delete failed: {e}")
            return False
    
    async def list_files(self, bucket: str, prefix: str = "") -> List[Dict[str, Any]]:
        """List files in Azure Blob container."""
        if not self.blob_service_client:
            raise RuntimeError("Azure Blob client not initialized")
        
        try:
            container_client = self.blob_service_client.get_container_client(bucket)
            
            blobs = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: list(container_client.list_blobs(name_starts_with=prefix))
            )
            
            files = []
            for blob in blobs:
                files.append({
                    'key': blob.name,
                    'size': blob.size,
                    'last_modified': blob.last_modified,
                    'etag': blob.etag
                })
            
            return files
            
        except AzureError as e:
            logger.error(f"Azure Blob list failed: {e}")
            return []
    
    async def get_file_info(self, location: StorageLocation) -> Dict[str, Any]:
        """Get Azure Blob properties."""
        if not self.blob_service_client:
            raise RuntimeError("Azure Blob client not initialized")
        
        try:
            blob_client = self.blob_service_client.get_blob_client(
                container=location.bucket,
                blob=location.key
            )
            
            properties = await asyncio.get_event_loop().run_in_executor(
                None,
                blob_client.get_blob_properties
            )
            
            return {
                'size': properties.size,
                'last_modified': properties.last_modified,
                'etag': properties.etag,
                'metadata': properties.metadata,
                'blob_tier': properties.blob_tier,
                'content_type': properties.content_settings.content_type if properties.content_settings else None
            }
            
        except AzureError as e:
            logger.error(f"Azure Blob get properties failed: {e}")
            return {}

class GoogleCloudProvider(CloudStorageProvider):
    """Google Cloud Storage provider with encryption."""
    
    def __init__(self):
        self.gcs_client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Google Cloud Storage client."""
        try:
            credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
            if credentials_path and os.path.exists(credentials_path):
                self.gcs_client = gcs.Client()
            else:
                logger.warning("Google Cloud credentials not found - GCS provider unavailable")
                self.gcs_client = None
        except Exception as e:
            logger.warning(f"GCS client initialization failed: {e}")
            self.gcs_client = None
    
    async def upload_file(self, file_data: bytes, location: StorageLocation, metadata: Dict[str, Any]) -> bool:
        """Upload file to Google Cloud Storage."""
        if not self.gcs_client:
            raise RuntimeError("GCS client not initialized")
        
        try:
            bucket = self.gcs_client.bucket(location.bucket)
            blob = bucket.blob(location.key)
            
            # Set metadata
            blob.metadata = {
                'file_hash': metadata.get('file_hash', ''),
                'original_size': str(metadata.get('original_size', 0)),
                'encryption_key_id': metadata.get('encryption_key_id', ''),
                'upload_timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            # Add encryption metadata
            if 'encryption_metadata' in metadata:
                enc_meta = metadata['encryption_metadata']
                blob.metadata.update({
                    'encryption_method': enc_meta.get('encryption_method', ''),
                    'encryption_iv': enc_meta.get('iv', ''),
                    'encryption_tag': enc_meta.get('tag', '')
                })
            
            # Set content type
            blob.content_type = metadata.get('content_type', 'application/octet-stream')
            
            # Set storage class based on tier
            if location.tier:
                class_map = {
                    StorageTier.HOT: 'STANDARD',
                    StorageTier.WARM: 'NEARLINE',
                    StorageTier.COLD: 'COLDLINE',
                    StorageTier.ARCHIVE: 'ARCHIVE'
                }
                blob.storage_class = class_map.get(location.tier, 'STANDARD')
            
            # Upload with customer-managed encryption key if provided
            upload_kwargs = {}
            if location.encryption_key_id:
                upload_kwargs['encryption_key'] = location.encryption_key_id
            
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: blob.upload_from_string(file_data, **upload_kwargs)
            )
            
            return True
            
        except gcs_exceptions.GoogleCloudError as e:
            logger.error(f"GCS upload failed: {e}")
            return False
    
    async def download_file(self, location: StorageLocation) -> bytes:
        """Download file from Google Cloud Storage."""
        if not self.gcs_client:
            raise RuntimeError("GCS client not initialized")
        
        try:
            bucket = self.gcs_client.bucket(location.bucket)
            blob = bucket.blob(location.key)
            
            download_kwargs = {}
            if location.encryption_key_id:
                download_kwargs['encryption_key'] = location.encryption_key_id
            
            return await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: blob.download_as_bytes(**download_kwargs)
            )
            
        except gcs_exceptions.GoogleCloudError as e:
            logger.error(f"GCS download failed: {e}")
            raise
    
    async def delete_file(self, location: StorageLocation) -> bool:
        """Delete file from Google Cloud Storage."""
        if not self.gcs_client:
            raise RuntimeError("GCS client not initialized")
        
        try:
            bucket = self.gcs_client.bucket(location.bucket)
            blob = bucket.blob(location.key)
            
            await asyncio.get_event_loop().run_in_executor(
                None,
                blob.delete
            )
            
            return True
            
        except gcs_exceptions.GoogleCloudError as e:
            logger.error(f"GCS delete failed: {e}")
            return False
    
    async def list_files(self, bucket: str, prefix: str = "") -> List[Dict[str, Any]]:
        """List files in GCS bucket."""
        if not self.gcs_client:
            raise RuntimeError("GCS client not initialized")
        
        try:
            bucket_obj = self.gcs_client.bucket(bucket)
            blobs = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: list(bucket_obj.list_blobs(prefix=prefix))
            )
            
            files = []
            for blob in blobs:
                files.append({
                    'key': blob.name,
                    'size': blob.size,
                    'last_modified': blob.time_created,
                    'etag': blob.etag
                })
            
            return files
            
        except gcs_exceptions.GoogleCloudError as e:
            logger.error(f"GCS list failed: {e}")
            return []
    
    async def get_file_info(self, location: StorageLocation) -> Dict[str, Any]:
        """Get GCS object metadata."""
        if not self.gcs_client:
            raise RuntimeError("GCS client not initialized")
        
        try:
            bucket = self.gcs_client.bucket(location.bucket)
            blob = bucket.blob(location.key)
            
            await asyncio.get_event_loop().run_in_executor(
                None,
                blob.reload
            )
            
            return {
                'size': blob.size,
                'last_modified': blob.time_created,
                'etag': blob.etag,
                'metadata': blob.metadata or {},
                'storage_class': blob.storage_class,
                'content_type': blob.content_type
            }
            
        except gcs_exceptions.GoogleCloudError as e:
            logger.error(f"GCS get metadata failed: {e}")
            return {}

class LocalStorageProvider(CloudStorageProvider):
    """Local filesystem provider for development/testing."""
    
    def __init__(self, base_path: str = "./storage"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
    
    async def upload_file(self, file_data: bytes, location: StorageLocation, metadata: Dict[str, Any]) -> bool:
        """Upload file to local storage."""
        try:
            file_path = self.base_path / location.bucket / location.key
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write file data
            with open(file_path, 'wb') as f:
                f.write(file_data)
            
            # Write metadata
            metadata_path = file_path.with_suffix(file_path.suffix + '.meta')
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2, default=str)
            
            return True
            
        except Exception as e:
            logger.error(f"Local storage upload failed: {e}")
            return False
    
    async def download_file(self, location: StorageLocation) -> bytes:
        """Download file from local storage."""
        try:
            file_path = self.base_path / location.bucket / location.key
            
            with open(file_path, 'rb') as f:
                return f.read()
                
        except Exception as e:
            logger.error(f"Local storage download failed: {e}")
            raise
    
    async def delete_file(self, location: StorageLocation) -> bool:
        """Delete file from local storage."""
        try:
            file_path = self.base_path / location.bucket / location.key
            metadata_path = file_path.with_suffix(file_path.suffix + '.meta')
            
            if file_path.exists():
                file_path.unlink()
            if metadata_path.exists():
                metadata_path.unlink()
            
            return True
            
        except Exception as e:
            logger.error(f"Local storage delete failed: {e}")
            return False
    
    async def list_files(self, bucket: str, prefix: str = "") -> List[Dict[str, Any]]:
        """List files in local storage."""
        try:
            bucket_path = self.base_path / bucket
            if not bucket_path.exists():
                return []
            
            files = []
            for file_path in bucket_path.rglob("*"):
                if file_path.is_file() and not file_path.name.endswith('.meta'):
                    relative_path = file_path.relative_to(bucket_path)
                    if str(relative_path).startswith(prefix):
                        stat = file_path.stat()
                        files.append({
                            'key': str(relative_path),
                            'size': stat.st_size,
                            'last_modified': datetime.fromtimestamp(stat.st_mtime, timezone.utc),
                            'etag': f'"{hashlib.md5(file_path.read_bytes()).hexdigest()}"'
                        })
            
            return files
            
        except Exception as e:
            logger.error(f"Local storage list failed: {e}")
            return []
    
    async def get_file_info(self, location: StorageLocation) -> Dict[str, Any]:
        """Get local file metadata."""
        try:
            file_path = self.base_path / location.bucket / location.key
            metadata_path = file_path.with_suffix(file_path.suffix + '.meta')
            
            if not file_path.exists():
                return {}
            
            stat = file_path.stat()
            info = {
                'size': stat.st_size,
                'last_modified': datetime.fromtimestamp(stat.st_mtime, timezone.utc),
                'etag': f'"{hashlib.md5(file_path.read_bytes()).hexdigest()}"'
            }
            
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    stored_metadata = json.load(f)
                    info['metadata'] = stored_metadata
            
            return info
            
        except Exception as e:
            logger.error(f"Local storage get info failed: {e}")
            return {}

class SecureCloudStorage:
    """Main secure cloud storage interface with encryption and multi-provider support."""
    
    def __init__(self, default_provider: CloudProvider = CloudProvider.LOCAL):
        self.encryption_manager = EncryptionManager()
        self.providers = {}
        self.default_provider = default_provider
        
        # Initialize available providers
        self._initialize_providers()
    
    def _initialize_providers(self):
        """Initialize all available cloud storage providers."""
        try:
            self.providers[CloudProvider.AWS_S3] = AWSS3Provider()
        except Exception as e:
            logger.warning(f"AWS S3 provider initialization failed: {e}")
        
        try:
            self.providers[CloudProvider.AZURE_BLOB] = AzureBlobProvider()
        except Exception as e:
            logger.warning(f"Azure Blob provider initialization failed: {e}")
        
        try:
            self.providers[CloudProvider.GOOGLE_CLOUD] = GoogleCloudProvider()
        except Exception as e:
            logger.warning(f"Google Cloud provider initialization failed: {e}")
        
        # Local storage always available
        self.providers[CloudProvider.LOCAL] = LocalStorageProvider()
    
    def get_provider(self, provider_type: CloudProvider) -> CloudStorageProvider:
        """Get cloud storage provider instance."""
        if provider_type not in self.providers:
            raise ValueError(f"Provider {provider_type} not available")
        return self.providers[provider_type]
    
    async def upload_file(self, 
                         file_path: str, 
                         bucket: str, 
                         key: str, 
                         provider: Optional[CloudProvider] = None,
                         tier: Optional[StorageTier] = None,
                         encryption_method: EncryptionMethod = EncryptionMethod.AES_256_GCM) -> UploadResult:
        """Upload file with encryption to cloud storage."""
        start_time = asyncio.get_event_loop().time()
        provider = provider or self.default_provider
        
        try:
            # Read file data
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            original_size = len(file_data)
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            # Generate encryption key ID
            key_id = f"file_{file_hash[:16]}_{int(datetime.now().timestamp())}"
            
            # Encrypt file data
            encrypted_data, encryption_metadata = self.encryption_manager.encrypt_file(
                file_data, key_id, encryption_method
            )
            encrypted_size = len(encrypted_data)
            
            # Create storage location
            location = StorageLocation(
                provider=provider,
                bucket=bucket,
                key=key,
                tier=tier,
                encryption_key_id=key_id
            )
            
            # Prepare upload metadata
            upload_metadata = {
                'file_hash': file_hash,
                'original_size': original_size,
                'encryption_key_id': key_id,
                'encryption_metadata': encryption_metadata,
                'content_type': self._guess_content_type(file_path)
            }
            
            # Upload to cloud storage
            storage_provider = self.get_provider(provider)
            success = await storage_provider.upload_file(encrypted_data, location, upload_metadata)
            
            upload_time = asyncio.get_event_loop().time() - start_time
            
            # Log security event
            SecurityUtils.log_security_event(
                "cloud_file_upload",
                {
                    "provider": provider.value,
                    "bucket": bucket,
                    "key": key,
                    "file_hash": file_hash,
                    "original_size": original_size,
                    "encrypted_size": encrypted_size,
                    "encryption_method": encryption_method.value,
                    "upload_time": upload_time,
                    "success": success
                }
            )
            
            return UploadResult(
                location=location,
                file_hash=file_hash,
                encrypted_size=encrypted_size,
                original_size=original_size,
                encryption_key_id=key_id,
                upload_time=upload_time,
                success=success,
                error_message=None if success else "Upload failed"
            )
            
        except Exception as e:
            upload_time = asyncio.get_event_loop().time() - start_time
            error_msg = f"Upload failed: {str(e)}"
            logger.error(error_msg)
            
            return UploadResult(
                location=None,
                file_hash="",
                encrypted_size=0,
                original_size=0,
                encryption_key_id="",
                upload_time=upload_time,
                success=False,
                error_message=error_msg
            )
    
    async def download_file(self, location: StorageLocation, output_path: Optional[str] = None) -> DownloadResult:
        """Download and decrypt file from cloud storage."""
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Get provider and download encrypted data
            storage_provider = self.get_provider(location.provider)
            encrypted_data = await storage_provider.download_file(location)
            
            # Get file metadata for decryption
            file_info = await storage_provider.get_file_info(location)
            stored_metadata = file_info.get('metadata', {})
            
            # Extract encryption metadata
            encryption_metadata = {
                'encryption_method': stored_metadata.get('encryption_method', stored_metadata.get('encryption-method', '')),
                'iv': stored_metadata.get('encryption_iv', stored_metadata.get('encryption-iv', '')),
                'tag': stored_metadata.get('encryption_tag', stored_metadata.get('encryption-tag', '')),
                'key_id': stored_metadata.get('encryption_key_id', stored_metadata.get('encryption-key-id', ''))
            }
            
            # Decrypt file data
            if encryption_metadata['encryption_method']:
                decrypted_data = self.encryption_manager.decrypt_file(
                    encrypted_data, 
                    encryption_metadata['key_id'], 
                    encryption_metadata
                )
            else:
                # Fallback for unencrypted files
                decrypted_data = encrypted_data
            
            # Calculate file hash for verification
            file_hash = hashlib.sha256(decrypted_data).hexdigest()
            
            # Write to output file if specified
            if output_path:
                with open(output_path, 'wb') as f:
                    f.write(decrypted_data)
            
            download_time = asyncio.get_event_loop().time() - start_time
            
            # Log security event
            SecurityUtils.log_security_event(
                "cloud_file_download",
                {
                    "provider": location.provider.value,
                    "bucket": location.bucket,
                    "key": location.key,
                    "file_hash": file_hash,
                    "decrypted_size": len(decrypted_data),
                    "download_time": download_time
                }
            )
            
            return DownloadResult(
                file_data=decrypted_data,
                file_hash=file_hash,
                original_size=len(decrypted_data),
                download_time=download_time,
                success=True
            )
            
        except Exception as e:
            download_time = asyncio.get_event_loop().time() - start_time
            error_msg = f"Download failed: {str(e)}"
            logger.error(error_msg)
            
            return DownloadResult(
                file_data=b'',
                file_hash="",
                original_size=0,
                download_time=download_time,
                success=False,
                error_message=error_msg
            )
    
    async def delete_file(self, location: StorageLocation) -> bool:
        """Delete file from cloud storage."""
        try:
            storage_provider = self.get_provider(location.provider)
            success = await storage_provider.delete_file(location)
            
            # Log security event
            SecurityUtils.log_security_event(
                "cloud_file_delete",
                {
                    "provider": location.provider.value,
                    "bucket": location.bucket,
                    "key": location.key,
                    "success": success
                }
            )
            
            return success
            
        except Exception as e:
            logger.error(f"Delete failed: {e}")
            return False
    
    async def list_files(self, provider: CloudProvider, bucket: str, prefix: str = "") -> List[Dict[str, Any]]:
        """List files in cloud storage."""
        try:
            storage_provider = self.get_provider(provider)
            return await storage_provider.list_files(bucket, prefix)
        except Exception as e:
            logger.error(f"List files failed: {e}")
            return []
    
    def _guess_content_type(self, file_path: str) -> str:
        """Guess content type from file extension."""
        import mimetypes
        content_type, _ = mimetypes.guess_type(file_path)
        return content_type or 'application/octet-stream'

# Global secure cloud storage instance
secure_cloud_storage = SecureCloudStorage()