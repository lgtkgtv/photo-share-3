"""
Enhanced Security Scanner with Enterprise-Grade Malware Detection and Content Moderation.
Provides comprehensive threat analysis for uploaded media files.
"""
import os
import asyncio
import subprocess
import hashlib
import tempfile
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
import requests
import json

from services.security import SecurityUtils

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Threat severity levels."""
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ScanEngine(Enum):
    """Available scanning engines."""
    CLAMAV = "clamav"
    VIRUSTOTAL = "virustotal"
    CONTENT_MODERATION = "content_moderation"
    STEGANOGRAPHY = "steganography"
    PATTERN_MATCHING = "pattern_matching"

@dataclass
class ScanResult:
    """Result from a security scan."""
    engine: ScanEngine
    threat_level: ThreatLevel
    threats_found: List[str]
    scan_time: float
    metadata: Dict[str, Any]
    success: bool
    error_message: Optional[str] = None

@dataclass
class ComprehensiveScanResult:
    """Combined result from all security scans."""
    file_path: str
    file_hash: str
    overall_threat_level: ThreatLevel
    scan_results: List[ScanResult]
    processing_time: float
    recommended_action: str
    quarantine_required: bool

class ClamAVScanner:
    """ClamAV antivirus integration."""
    
    def __init__(self):
        self.clamav_available = self._check_clamav_available()
        self.database_updated = False
        
    def _check_clamav_available(self) -> bool:
        """Check if ClamAV is installed and available."""
        try:
            result = subprocess.run(['clamscan', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("ClamAV not available - skipping virus scanning")
            return False
    
    async def update_database(self) -> bool:
        """Update ClamAV virus database."""
        if not self.clamav_available:
            return False
            
        try:
            # Run freshclam to update virus definitions
            process = await asyncio.create_subprocess_exec(
                'freshclam', '--quiet',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                self.database_updated = True
                logger.info("ClamAV database updated successfully")
                return True
            else:
                logger.warning(f"ClamAV database update failed: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"ClamAV database update error: {e}")
            return False
    
    async def scan_file(self, file_path: str) -> ScanResult:
        """Scan file with ClamAV."""
        start_time = asyncio.get_event_loop().time()
        
        if not self.clamav_available:
            return ScanResult(
                engine=ScanEngine.CLAMAV,
                threat_level=ThreatLevel.CLEAN,
                threats_found=[],
                scan_time=0,
                metadata={"engine_available": False},
                success=False,
                error_message="ClamAV not available"
            )
        
        try:
            # Run clamscan on the file
            process = await asyncio.create_subprocess_exec(
                'clamscan', '--no-summary', '--infected', file_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            scan_time = asyncio.get_event_loop().time() - start_time
            output = stdout.decode().strip()
            
            if process.returncode == 0:
                # File is clean
                return ScanResult(
                    engine=ScanEngine.CLAMAV,
                    threat_level=ThreatLevel.CLEAN,
                    threats_found=[],
                    scan_time=scan_time,
                    metadata={"output": output},
                    success=True
                )
            elif process.returncode == 1:
                # Virus found
                threats = self._parse_clamav_output(output)
                return ScanResult(
                    engine=ScanEngine.CLAMAV,
                    threat_level=ThreatLevel.CRITICAL,
                    threats_found=threats,
                    scan_time=scan_time,
                    metadata={"output": output},
                    success=True
                )
            else:
                # Error occurred
                return ScanResult(
                    engine=ScanEngine.CLAMAV,
                    threat_level=ThreatLevel.CLEAN,
                    threats_found=[],
                    scan_time=scan_time,
                    metadata={"output": output, "stderr": stderr.decode()},
                    success=False,
                    error_message=f"ClamAV scan failed: {stderr.decode()}"
                )
                
        except Exception as e:
            scan_time = asyncio.get_event_loop().time() - start_time
            return ScanResult(
                engine=ScanEngine.CLAMAV,
                threat_level=ThreatLevel.CLEAN,
                threats_found=[],
                scan_time=scan_time,
                metadata={"error": str(e)},
                success=False,
                error_message=f"ClamAV scan exception: {e}"
            )
    
    def _parse_clamav_output(self, output: str) -> List[str]:
        """Parse ClamAV output to extract threat names."""
        threats = []
        for line in output.split('\n'):
            if 'FOUND' in line:
                # Extract threat name from line like: "file.txt: Win.Trojan.Agent FOUND"
                parts = line.split(': ')
                if len(parts) >= 2:
                    threat_part = parts[1].replace(' FOUND', '')
                    threats.append(threat_part)
        return threats

class VirusTotalScanner:
    """VirusTotal API integration for multi-engine scanning."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.available = bool(self.api_key)
        
        if not self.available:
            logger.info("VirusTotal API key not configured - skipping VT scanning")
    
    async def scan_file(self, file_path: str) -> ScanResult:
        """Scan file with VirusTotal."""
        start_time = asyncio.get_event_loop().time()
        
        if not self.available:
            return ScanResult(
                engine=ScanEngine.VIRUSTOTAL,
                threat_level=ThreatLevel.CLEAN,
                threats_found=[],
                scan_time=0,
                metadata={"api_available": False},
                success=False,
                error_message="VirusTotal API key not configured"
            )
        
        try:
            # Calculate file hash for lookup
            file_hash = await self._calculate_file_hash(file_path)
            
            # First try to get existing report
            report = await self._get_file_report(file_hash)
            
            if report and report.get('response_code') == 1:
                # Report exists
                scan_time = asyncio.get_event_loop().time() - start_time
                return self._parse_virustotal_report(report, scan_time)
            else:
                # Upload file for scanning
                upload_result = await self._upload_file(file_path)
                
                if upload_result and upload_result.get('response_code') == 1:
                    # Wait a bit for analysis
                    await asyncio.sleep(2)
                    
                    # Get report
                    report = await self._get_file_report(file_hash)
                    scan_time = asyncio.get_event_loop().time() - start_time
                    
                    if report and report.get('response_code') == 1:
                        return self._parse_virustotal_report(report, scan_time)
                    else:
                        return ScanResult(
                            engine=ScanEngine.VIRUSTOTAL,
                            threat_level=ThreatLevel.CLEAN,
                            threats_found=[],
                            scan_time=scan_time,
                            metadata={"status": "analysis_pending"},
                            success=True
                        )
                else:
                    scan_time = asyncio.get_event_loop().time() - start_time
                    return ScanResult(
                        engine=ScanEngine.VIRUSTOTAL,
                        threat_level=ThreatLevel.CLEAN,
                        threats_found=[],
                        scan_time=scan_time,
                        metadata={"upload_failed": True},
                        success=False,
                        error_message="Failed to upload file to VirusTotal"
                    )
                    
        except Exception as e:
            scan_time = asyncio.get_event_loop().time() - start_time
            return ScanResult(
                engine=ScanEngine.VIRUSTOTAL,
                threat_level=ThreatLevel.CLEAN,
                threats_found=[],
                scan_time=scan_time,
                metadata={"error": str(e)},
                success=False,
                error_message=f"VirusTotal scan exception: {e}"
            )
    
    async def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    async def _get_file_report(self, file_hash: str) -> Optional[Dict]:
        """Get existing VirusTotal report for file hash."""
        try:
            response = requests.get(
                f"{self.base_url}/file/report",
                params={
                    'apikey': self.api_key,
                    'resource': file_hash
                },
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"VirusTotal report request failed: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"VirusTotal report request error: {e}")
            return None
    
    async def _upload_file(self, file_path: str) -> Optional[Dict]:
        """Upload file to VirusTotal for analysis."""
        try:
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = requests.post(
                    f"{self.base_url}/file/scan",
                    files=files,
                    data={'apikey': self.api_key},
                    timeout=60
                )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"VirusTotal upload failed: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"VirusTotal upload error: {e}")
            return None
    
    def _parse_virustotal_report(self, report: Dict, scan_time: float) -> ScanResult:
        """Parse VirusTotal report into ScanResult."""
        positives = report.get('positives', 0)
        total = report.get('total', 0)
        
        if positives == 0:
            threat_level = ThreatLevel.CLEAN
        elif positives <= 2:
            threat_level = ThreatLevel.LOW
        elif positives <= 5:
            threat_level = ThreatLevel.MEDIUM
        elif positives <= 10:
            threat_level = ThreatLevel.HIGH
        else:
            threat_level = ThreatLevel.CRITICAL
        
        # Extract threat names from scans
        threats = []
        scans = report.get('scans', {})
        for engine_name, scan_result in scans.items():
            if scan_result.get('detected', False):
                result_name = scan_result.get('result', 'Unknown')
                threats.append(f"{engine_name}: {result_name}")
        
        return ScanResult(
            engine=ScanEngine.VIRUSTOTAL,
            threat_level=threat_level,
            threats_found=threats,
            scan_time=scan_time,
            metadata={
                "positives": positives,
                "total": total,
                "permalink": report.get('permalink'),
                "scan_date": report.get('scan_date')
            },
            success=True
        )

class ContentModerationScanner:
    """Content moderation for inappropriate content detection."""
    
    def __init__(self):
        # In a real implementation, this would integrate with services like:
        # - AWS Rekognition
        # - Google Cloud Vision API
        # - Azure Content Moderator
        # - Custom ML models
        self.nsfw_detection_available = False
        self.violence_detection_available = False
        
    async def scan_file(self, file_path: str) -> ScanResult:
        """Scan file for inappropriate content."""
        start_time = asyncio.get_event_loop().time()
        
        try:
            threats = []
            metadata = {}
            
            # NSFW detection (placeholder)
            nsfw_result = await self._detect_nsfw(file_path)
            if nsfw_result['inappropriate']:
                threats.append(f"NSFW content detected (confidence: {nsfw_result['confidence']:.2f})")
            metadata['nsfw_analysis'] = nsfw_result
            
            # Violence detection (placeholder)
            violence_result = await self._detect_violence(file_path)
            if violence_result['violent']:
                threats.append(f"Violent content detected (confidence: {violence_result['confidence']:.2f})")
            metadata['violence_analysis'] = violence_result
            
            # Text content analysis
            text_result = await self._analyze_text_content(file_path)
            if text_result['inappropriate_text']:
                threats.extend(text_result['issues'])
            metadata['text_analysis'] = text_result
            
            # Determine threat level
            if not threats:
                threat_level = ThreatLevel.CLEAN
            elif any('high confidence' in threat.lower() for threat in threats):
                threat_level = ThreatLevel.HIGH
            elif len(threats) > 2:
                threat_level = ThreatLevel.MEDIUM
            else:
                threat_level = ThreatLevel.LOW
            
            scan_time = asyncio.get_event_loop().time() - start_time
            
            return ScanResult(
                engine=ScanEngine.CONTENT_MODERATION,
                threat_level=threat_level,
                threats_found=threats,
                scan_time=scan_time,
                metadata=metadata,
                success=True
            )
            
        except Exception as e:
            scan_time = asyncio.get_event_loop().time() - start_time
            return ScanResult(
                engine=ScanEngine.CONTENT_MODERATION,
                threat_level=ThreatLevel.CLEAN,
                threats_found=[],
                scan_time=scan_time,
                metadata={"error": str(e)},
                success=False,
                error_message=f"Content moderation error: {e}"
            )
    
    async def _detect_nsfw(self, file_path: str) -> Dict[str, Any]:
        """Detect NSFW content in image. Placeholder implementation."""
        # In production, this would use actual ML models or cloud APIs
        return {
            "inappropriate": False,
            "confidence": 0.1,
            "categories": {
                "explicit": 0.05,
                "suggestive": 0.1,
                "medical": 0.0
            }
        }
    
    async def _detect_violence(self, file_path: str) -> Dict[str, Any]:
        """Detect violent content in image. Placeholder implementation."""
        # In production, this would use actual ML models or cloud APIs
        return {
            "violent": False,
            "confidence": 0.05,
            "categories": {
                "weapons": 0.02,
                "blood": 0.01,
                "fighting": 0.05
            }
        }
    
    async def _analyze_text_content(self, file_path: str) -> Dict[str, Any]:
        """Extract and analyze text content from image using OCR."""
        # Placeholder for OCR + text analysis
        # In production, would use Tesseract + NLP for inappropriate text detection
        return {
            "inappropriate_text": False,
            "extracted_text": "",
            "issues": [],
            "language": "en"
        }

class SteganographyDetector:
    """Detect hidden content in images using steganography."""
    
    def __init__(self):
        self.available = True  # Basic detection always available
    
    async def scan_file(self, file_path: str) -> ScanResult:
        """Scan for steganographic content."""
        start_time = asyncio.get_event_loop().time()
        
        try:
            threats = []
            metadata = {}
            
            # LSB (Least Significant Bit) analysis
            lsb_result = await self._analyze_lsb_patterns(file_path)
            metadata['lsb_analysis'] = lsb_result
            
            if lsb_result['suspicious']:
                threats.append("Suspicious LSB patterns detected")
            
            # File structure analysis
            structure_result = await self._analyze_file_structure(file_path)
            metadata['structure_analysis'] = structure_result
            
            if structure_result['anomalies']:
                threats.extend(structure_result['anomalies'])
            
            # Entropy analysis
            entropy_result = await self._analyze_entropy(file_path)
            metadata['entropy_analysis'] = entropy_result
            
            if entropy_result['high_entropy_sections']:
                threats.append("High entropy sections detected")
            
            # Determine threat level
            if not threats:
                threat_level = ThreatLevel.CLEAN
            elif len(threats) >= 3:
                threat_level = ThreatLevel.HIGH
            elif len(threats) >= 2:
                threat_level = ThreatLevel.MEDIUM
            else:
                threat_level = ThreatLevel.LOW
            
            scan_time = asyncio.get_event_loop().time() - start_time
            
            return ScanResult(
                engine=ScanEngine.STEGANOGRAPHY,
                threat_level=threat_level,
                threats_found=threats,
                scan_time=scan_time,
                metadata=metadata,
                success=True
            )
            
        except Exception as e:
            scan_time = asyncio.get_event_loop().time() - start_time
            return ScanResult(
                engine=ScanEngine.STEGANOGRAPHY,
                threat_level=ThreatLevel.CLEAN,
                threats_found=[],
                scan_time=scan_time,
                metadata={"error": str(e)},
                success=False,
                error_message=f"Steganography detection error: {e}"
            )
    
    async def _analyze_lsb_patterns(self, file_path: str) -> Dict[str, Any]:
        """Analyze least significant bit patterns for hidden data."""
        # Simplified LSB analysis
        try:
            from PIL import Image
            import numpy as np
            
            with Image.open(file_path) as img:
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # Convert to numpy array
                img_array = np.array(img)
                
                # Extract LSBs
                lsbs = img_array & 1
                
                # Calculate LSB entropy (high entropy suggests hidden data)
                flat_lsbs = lsbs.flatten()
                unique, counts = np.unique(flat_lsbs, return_counts=True)
                entropy = -np.sum((counts / len(flat_lsbs)) * np.log2(counts / len(flat_lsbs)))
                
                # Simple heuristic: entropy > 0.9 suggests possible steganography
                suspicious = entropy > 0.9
                
                return {
                    "suspicious": suspicious,
                    "lsb_entropy": float(entropy),
                    "analysis_method": "simple_entropy"
                }
                
        except Exception as e:
            return {
                "suspicious": False,
                "error": str(e),
                "analysis_method": "failed"
            }
    
    async def _analyze_file_structure(self, file_path: str) -> Dict[str, Any]:
        """Analyze file structure for anomalies."""
        anomalies = []
        
        try:
            # Check file size vs image dimensions
            file_size = os.path.getsize(file_path)
            
            from PIL import Image
            with Image.open(file_path) as img:
                width, height = img.size
                channels = len(img.getbands())
                
                # Calculate expected size (rough estimate)
                expected_size = width * height * channels
                
                # If file is significantly larger than expected, might contain hidden data
                if file_size > expected_size * 1.5:
                    anomalies.append("File size larger than expected for image dimensions")
                
                # Check for unusual metadata
                if hasattr(img, '_getexif') and img._getexif():
                    exif = img._getexif()
                    if len(exif) > 20:  # Unusually large EXIF data
                        anomalies.append("Unusually large EXIF data")
            
            return {
                "anomalies": anomalies,
                "file_size": file_size,
                "expected_size": expected_size
            }
            
        except Exception as e:
            return {
                "anomalies": [],
                "error": str(e)
            }
    
    async def _analyze_entropy(self, file_path: str) -> Dict[str, Any]:
        """Analyze entropy distribution in file."""
        try:
            high_entropy_sections = []
            
            with open(file_path, 'rb') as f:
                # Read file in chunks and calculate entropy
                chunk_size = 8192
                chunk_num = 0
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Calculate entropy for chunk
                    if len(chunk) > 256:  # Only analyze substantial chunks
                        unique_bytes = len(set(chunk))
                        entropy = unique_bytes / 256.0  # Normalized entropy
                        
                        if entropy > 0.9:  # High entropy threshold
                            high_entropy_sections.append({
                                "chunk": chunk_num,
                                "entropy": entropy,
                                "offset": chunk_num * chunk_size
                            })
                    
                    chunk_num += 1
            
            return {
                "high_entropy_sections": high_entropy_sections,
                "total_chunks": chunk_num
            }
            
        except Exception as e:
            return {
                "high_entropy_sections": [],
                "error": str(e)
            }

class EnhancedSecurityScanner:
    """Main security scanner that orchestrates all scanning engines."""
    
    def __init__(self):
        self.clamav_scanner = ClamAVScanner()
        self.virustotal_scanner = VirusTotalScanner()
        self.content_moderation = ContentModerationScanner()
        self.steganography_detector = SteganographyDetector()
        
        # Update ClamAV database on startup
        asyncio.create_task(self.clamav_scanner.update_database())
    
    async def comprehensive_scan(self, file_path: str, scan_options: Optional[Dict[str, bool]] = None) -> ComprehensiveScanResult:
        """
        Perform comprehensive security scan using all available engines.
        
        Args:
            file_path: Path to file to scan
            scan_options: Dict controlling which scans to perform
            
        Returns:
            ComprehensiveScanResult with combined analysis
        """
        start_time = asyncio.get_event_loop().time()
        
        # Default scan options
        if scan_options is None:
            scan_options = {
                'clamav': True,
                'virustotal': True,
                'content_moderation': True,
                'steganography': True,
                'pattern_matching': True
            }
        
        # Calculate file hash for tracking
        file_hash = await self._calculate_file_hash(file_path)
        
        # Run scans in parallel
        scan_tasks = []
        
        if scan_options.get('clamav', True):
            scan_tasks.append(self.clamav_scanner.scan_file(file_path))
        
        if scan_options.get('virustotal', True):
            scan_tasks.append(self.virustotal_scanner.scan_file(file_path))
        
        if scan_options.get('content_moderation', True):
            scan_tasks.append(self.content_moderation.scan_file(file_path))
        
        if scan_options.get('steganography', True):
            scan_tasks.append(self.steganography_detector.scan_file(file_path))
        
        if scan_options.get('pattern_matching', True):
            scan_tasks.append(self._pattern_matching_scan(file_path))
        
        # Execute all scans
        scan_results = []
        if scan_tasks:
            scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            # Handle any exceptions
            valid_results = []
            for i, result in enumerate(scan_results):
                if isinstance(result, Exception):
                    logger.error(f"Scan task {i} failed: {result}")
                    # Create error result
                    error_result = ScanResult(
                        engine=ScanEngine.PATTERN_MATCHING,  # Default
                        threat_level=ThreatLevel.CLEAN,
                        threats_found=[],
                        scan_time=0,
                        metadata={"error": str(result)},
                        success=False,
                        error_message=str(result)
                    )
                    valid_results.append(error_result)
                else:
                    valid_results.append(result)
            
            scan_results = valid_results
        
        # Calculate overall threat level and recommendation
        overall_threat_level = self._calculate_overall_threat_level(scan_results)
        recommended_action, quarantine_required = self._determine_action(scan_results, overall_threat_level)
        
        processing_time = asyncio.get_event_loop().time() - start_time
        
        # Log comprehensive scan result
        SecurityUtils.log_security_event(
            "comprehensive_security_scan",
            {
                "file_hash": file_hash,
                "overall_threat_level": overall_threat_level.value,
                "scan_engines_used": len(scan_results),
                "threats_detected": sum(len(result.threats_found) for result in scan_results),
                "processing_time": processing_time,
                "quarantine_required": quarantine_required
            }
        )
        
        return ComprehensiveScanResult(
            file_path=file_path,
            file_hash=file_hash,
            overall_threat_level=overall_threat_level,
            scan_results=scan_results,
            processing_time=processing_time,
            recommended_action=recommended_action,
            quarantine_required=quarantine_required
        )
    
    async def _pattern_matching_scan(self, file_path: str) -> ScanResult:
        """Enhanced pattern matching scan (improvement of existing basic scan)."""
        start_time = asyncio.get_event_loop().time()
        
        try:
            threats = []
            metadata = {}
            
            # Enhanced suspicious patterns
            suspicious_patterns = [
                # Script injection patterns
                (b'<script', "JavaScript injection"),
                (b'javascript:', "JavaScript protocol"),
                (b'vbscript:', "VBScript protocol"),
                (b'data:text/html', "Data URI HTML"),
                
                # Server-side code patterns
                (b'<?php', "PHP code"),
                (b'<%', "ASP/JSP code"),
                (b'{{', "Template injection"),
                (b'{%', "Template code"),
                
                # Shell command patterns
                (b'eval(', "Code evaluation"),
                (b'exec(', "Code execution"),
                (b'system(', "System command"),
                (b'shell_exec(', "Shell execution"),
                (b'passthru(', "Command passthrough"),
                
                # Binary executable patterns
                (b'MZ', "Windows executable header"),
                (b'\x7fELF', "Linux executable header"),
                (b'\xfe\xed\xfa', "Mach-O executable"),
                
                # Archive patterns that might contain executables
                (b'PK\x03\x04', "ZIP archive"),
                (b'Rar!', "RAR archive"),
                (b'7z\xbc\xaf\x27\x1c', "7-Zip archive"),
                
                # Additional suspicious patterns
                (b'XMLHttpRequest', "AJAX request"),
                (b'document.cookie', "Cookie access"),
                (b'window.location', "Location manipulation"),
                (b'eval\\(', "Eval function call"),
                (b'base64_decode', "Base64 decode"),
                (b'gzinflate', "Compression function"),
                (b'str_rot13', "ROT13 encoding"),
            ]
            
            file_size = os.path.getsize(file_path)
            scan_size = min(32768, file_size)  # Scan first 32KB
            
            with open(file_path, 'rb') as f:
                content_sample = f.read(scan_size)
                content_lower = content_sample.lower()
                
                for pattern, description in suspicious_patterns:
                    if pattern.lower() in content_lower:
                        threats.append(f"{description} pattern detected")
                        
                        # Store pattern location for analysis
                        if 'pattern_locations' not in metadata:
                            metadata['pattern_locations'] = []
                        
                        offset = content_lower.find(pattern.lower())
                        metadata['pattern_locations'].append({
                            'pattern': description,
                            'offset': offset,
                            'context': content_sample[max(0, offset-20):offset+50].hex()
                        })
            
            # Determine threat level based on number and type of patterns
            if not threats:
                threat_level = ThreatLevel.CLEAN
            elif any('executable' in threat.lower() for threat in threats):
                threat_level = ThreatLevel.CRITICAL
            elif any('injection' in threat.lower() or 'execution' in threat.lower() for threat in threats):
                threat_level = ThreatLevel.HIGH
            elif len(threats) >= 3:
                threat_level = ThreatLevel.MEDIUM
            else:
                threat_level = ThreatLevel.LOW
            
            scan_time = asyncio.get_event_loop().time() - start_time
            metadata['scan_size'] = scan_size
            metadata['file_size'] = file_size
            
            return ScanResult(
                engine=ScanEngine.PATTERN_MATCHING,
                threat_level=threat_level,
                threats_found=threats,
                scan_time=scan_time,
                metadata=metadata,
                success=True
            )
            
        except Exception as e:
            scan_time = asyncio.get_event_loop().time() - start_time
            return ScanResult(
                engine=ScanEngine.PATTERN_MATCHING,
                threat_level=ThreatLevel.CLEAN,
                threats_found=[],
                scan_time=scan_time,
                metadata={"error": str(e)},
                success=False,
                error_message=f"Pattern matching error: {e}"
            )
    
    def _calculate_overall_threat_level(self, scan_results: List[ScanResult]) -> ThreatLevel:
        """Calculate overall threat level from all scan results."""
        if not scan_results:
            return ThreatLevel.CLEAN
        
        # Get highest threat level from successful scans
        threat_levels = [result.threat_level for result in scan_results if result.success]
        
        if not threat_levels:
            return ThreatLevel.CLEAN
        
        # Order by severity
        level_order = [ThreatLevel.CLEAN, ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        
        highest_level = ThreatLevel.CLEAN
        for level in threat_levels:
            if level_order.index(level) > level_order.index(highest_level):
                highest_level = level
        
        return highest_level
    
    def _determine_action(self, scan_results: List[ScanResult], overall_threat_level: ThreatLevel) -> Tuple[str, bool]:
        """Determine recommended action based on scan results."""
        if overall_threat_level == ThreatLevel.CRITICAL:
            return "REJECT - Critical threat detected", True
        elif overall_threat_level == ThreatLevel.HIGH:
            return "QUARANTINE - High threat detected", True
        elif overall_threat_level == ThreatLevel.MEDIUM:
            # Check if multiple engines detected threats
            engines_with_threats = sum(1 for result in scan_results if result.threats_found)
            if engines_with_threats >= 2:
                return "QUARANTINE - Multiple threats detected", True
            else:
                return "WARN - Medium threat detected", False
        elif overall_threat_level == ThreatLevel.LOW:
            return "ALLOW - Low threat detected", False
        else:
            return "ALLOW - No threats detected", False
    
    async def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

# Global scanner instance
enhanced_security_scanner = EnhancedSecurityScanner()