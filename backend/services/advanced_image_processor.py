"""
Advanced image processing pipeline with comprehensive optimization features.
Extends the basic image processor with smart cropping, format optimization, and quality analysis.
"""
import os
import logging
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path
from PIL import Image, ImageFilter, ImageEnhance, ImageOps
from PIL.ExifTags import TAGS
import io
import hashlib

from services.file_storage import THUMBNAIL_SIZES

logger = logging.getLogger(__name__)

class AdvancedImageProcessor:
    """
    Advanced image processing pipeline with optimization features.
    """
    
    def __init__(self):
        self.thumbnail_sizes = THUMBNAIL_SIZES
        self.optimization_settings = {
            'jpeg': {
                'quality': 85,
                'progressive': True,
                'optimize': True
            },
            'webp': {
                'quality': 80,
                'method': 6,
                'lossless': False
            },
            'png': {
                'optimize': True,
                'compress_level': 9
            }
        }
    
    def process_image_advanced(self, input_path: str, output_dir: str, 
                             filename_base: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Advanced image processing with comprehensive optimization.
        
        Args:
            input_path: Path to original image
            output_dir: Directory for processed images
            filename_base: Base filename for processed images
            options: Processing options
            
        Returns:
            Dict with processed file information and metadata
        """
        options = options or {}
        processed_files = {}
        processing_metadata = {}
        
        try:
            with Image.open(input_path) as img:
                # Analyze image quality and characteristics
                image_analysis = self._analyze_image_quality(img)
                processing_metadata['analysis'] = image_analysis
                
                # Auto-orient based on EXIF
                if options.get('auto_orient', True):
                    img = ImageOps.exif_transpose(img)
                
                # Apply image enhancements if needed
                if options.get('auto_enhance', False):
                    img = self._auto_enhance_image(img, image_analysis)
                
                # Generate optimized thumbnails
                for size_name, (width, height) in self.thumbnail_sizes.items():
                    thumbnail_info = self._create_optimized_thumbnail(
                        img, width, height, size_name, output_dir, filename_base, options
                    )
                    processed_files[size_name] = thumbnail_info
                
                # Generate WebP versions if requested
                if options.get('generate_webp', True):
                    webp_files = self._generate_webp_versions(
                        img, output_dir, filename_base, options
                    )
                    processed_files.update(webp_files)
                
                # Generate progressive JPEG if requested
                if options.get('generate_progressive', True):
                    progressive_file = self._generate_progressive_jpeg(
                        img, output_dir, filename_base, options
                    )
                    if progressive_file:
                        processed_files['progressive'] = progressive_file
                
                processing_metadata['processed_files'] = list(processed_files.keys())
                processing_metadata['optimization_applied'] = True
                
                return {
                    'files': processed_files,
                    'metadata': processing_metadata
                }
                
        except Exception as e:
            logger.error(f"Advanced image processing failed: {e}")
            # Cleanup any partially created files
            for file_info in processed_files.values():
                if isinstance(file_info, dict) and 'path' in file_info:
                    file_path = file_info['path']
                elif isinstance(file_info, str):
                    file_path = file_info
                else:
                    continue
                    
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        logger.warning(f"Failed to cleanup temporary file {file_path}: {e}")
            raise
    
    def _analyze_image_quality(self, img: Image.Image) -> Dict[str, Any]:
        """
        Analyze image quality and characteristics for optimization decisions.
        """
        analysis = {
            'width': img.width,
            'height': img.height,
            'mode': img.mode,
            'format': img.format,
            'aspect_ratio': img.width / img.height,
            'megapixels': (img.width * img.height) / 1000000,
            'estimated_quality': 'unknown'
        }
        
        # Estimate image quality based on file size and dimensions
        try:
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='JPEG', quality=95)
            high_quality_size = img_bytes.tell()
            
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='JPEG', quality=50)
            low_quality_size = img_bytes.tell()
            
            # Simple quality estimation
            if hasattr(img, 'filename') and os.path.exists(img.filename):
                actual_size = os.path.getsize(img.filename)
                if actual_size >= high_quality_size * 0.8:
                    analysis['estimated_quality'] = 'high'
                elif actual_size <= low_quality_size * 1.2:
                    analysis['estimated_quality'] = 'low'
                else:
                    analysis['estimated_quality'] = 'medium'
        except Exception as e:
            logger.debug(f"Quality estimation failed: {e}")
            analysis['estimated_quality'] = 'unknown'
        
        # Check for common issues
        analysis['has_transparency'] = img.mode in ('RGBA', 'LA', 'P')
        analysis['is_grayscale'] = img.mode in ('L', 'LA')
        analysis['is_large'] = analysis['megapixels'] > 12
        analysis['is_high_resolution'] = img.width > 3000 or img.height > 3000
        
        return analysis
    
    def _auto_enhance_image(self, img: Image.Image, analysis: Dict[str, Any]) -> Image.Image:
        """
        Apply automatic enhancements based on image analysis.
        """
        enhanced_img = img.copy()
        
        try:
            # Enhance contrast for low-quality images
            if analysis.get('estimated_quality') == 'low':
                enhancer = ImageEnhance.Contrast(enhanced_img)
                enhanced_img = enhancer.enhance(1.1)
            
            # Enhance sharpness for large, high-resolution images
            if analysis.get('is_high_resolution') and analysis.get('estimated_quality') != 'low':
                enhancer = ImageEnhance.Sharpness(enhanced_img)
                enhanced_img = enhancer.enhance(1.05)
            
            # Color enhancement for color images
            if not analysis.get('is_grayscale'):
                enhancer = ImageEnhance.Color(enhanced_img)
                enhanced_img = enhancer.enhance(1.05)
                
        except Exception as e:
            logger.warning(f"Auto-enhancement failed: {e}")
            return img
        
        return enhanced_img
    
    def _create_optimized_thumbnail(self, img: Image.Image, max_width: int, max_height: int, 
                                  size_name: str, output_dir: str, filename_base: str, 
                                  options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create optimized thumbnail with smart cropping and quality settings.
        """
        # Smart crop if requested
        if options.get('smart_crop', False) and size_name == 'small':
            thumbnail = self._smart_crop_thumbnail(img, max_width, max_height)
        else:
            thumbnail = img.copy()
            thumbnail.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
        
        # Ensure minimum quality
        if thumbnail.size[0] < 50 or thumbnail.size[1] < 50:
            raise ValueError(f"Thumbnail {size_name} would be too small")
        
        # Apply unsharp mask for better quality
        if options.get('apply_unsharp_mask', True) and thumbnail.size[0] > 200:
            thumbnail = thumbnail.filter(ImageFilter.UnsharpMask(radius=0.5, percent=50, threshold=3))
        
        # Generate filename
        ext = '.jpg'
        thumbnail_filename = f"{filename_base}_{size_name}{ext}"
        thumbnail_path = os.path.join(output_dir, thumbnail_filename)
        
        # Optimize save settings based on image characteristics
        save_kwargs = self._get_optimized_save_settings('jpeg', thumbnail.size, options)
        
        # Save thumbnail
        thumbnail.save(thumbnail_path, **save_kwargs)
        
        # Calculate file size and compression ratio
        file_size = os.path.getsize(thumbnail_path)
        
        return {
            'path': thumbnail_path,
            'width': thumbnail.width,
            'height': thumbnail.height,
            'file_size': file_size,
            'format': 'JPEG',
            'optimization_applied': True
        }
    
    def _smart_crop_thumbnail(self, img: Image.Image, width: int, height: int) -> Image.Image:
        """
        Create a smart-cropped thumbnail that focuses on the most interesting part.
        """
        # Get the target aspect ratio
        target_ratio = width / height
        img_ratio = img.width / img.height
        
        if abs(img_ratio - target_ratio) < 0.1:
            # Aspect ratios are close enough, just resize
            thumbnail = img.copy()
            thumbnail.thumbnail((width, height), Image.Resampling.LANCZOS)
            return thumbnail
        
        # Calculate crop dimensions
        if img_ratio > target_ratio:
            # Image is wider than target, crop horizontally
            new_width = int(img.height * target_ratio)
            new_height = img.height
            # Center crop
            left = (img.width - new_width) // 2
            top = 0
            right = left + new_width
            bottom = new_height
        else:
            # Image is taller than target, crop vertically
            new_width = img.width
            new_height = int(img.width / target_ratio)
            # Crop from top (often more interesting than center for photos)
            left = 0
            top = 0
            right = new_width
            bottom = new_height
        
        # Perform crop and resize
        cropped = img.crop((left, top, right, bottom))
        cropped.thumbnail((width, height), Image.Resampling.LANCZOS)
        
        return cropped
    
    def _generate_webp_versions(self, img: Image.Image, output_dir: str, 
                               filename_base: str, options: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """
        Generate WebP versions of thumbnails for better compression.
        """
        webp_files = {}
        
        for size_name, (width, height) in self.thumbnail_sizes.items():
            thumbnail = img.copy()
            thumbnail.thumbnail((width, height), Image.Resampling.LANCZOS)
            
            # WebP filename
            webp_filename = f"{filename_base}_{size_name}.webp"
            webp_path = os.path.join(output_dir, webp_filename)
            
            # WebP save settings
            save_kwargs = self._get_optimized_save_settings('webp', thumbnail.size, options)
            
            # Save WebP
            thumbnail.save(webp_path, **save_kwargs)
            
            file_size = os.path.getsize(webp_path)
            
            webp_files[f"{size_name}_webp"] = {
                'path': webp_path,
                'width': thumbnail.width,
                'height': thumbnail.height,
                'file_size': file_size,
                'format': 'WebP',
                'optimization_applied': True
            }
        
        return webp_files
    
    def _generate_progressive_jpeg(self, img: Image.Image, output_dir: str, 
                                  filename_base: str, options: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Generate progressive JPEG version for better loading experience.
        """
        # Only generate progressive JPEG for larger images
        if img.width < 800 or img.height < 600:
            return None
        
        # Resize to a reasonable size for progressive loading
        max_size = 1200
        if img.width > max_size or img.height > max_size:
            progressive_img = img.copy()
            progressive_img.thumbnail((max_size, max_size), Image.Resampling.LANCZOS)
        else:
            progressive_img = img.copy()
        
        # Progressive JPEG filename
        progressive_filename = f"{filename_base}_progressive.jpg"
        progressive_path = os.path.join(output_dir, progressive_filename)
        
        # Progressive JPEG settings
        save_kwargs = {
            'format': 'JPEG',
            'quality': 85,
            'progressive': True,
            'optimize': True
        }
        
        progressive_img.save(progressive_path, **save_kwargs)
        
        file_size = os.path.getsize(progressive_path)
        
        return {
            'path': progressive_path,
            'width': progressive_img.width,
            'height': progressive_img.height,
            'file_size': file_size,
            'format': 'JPEG',
            'progressive': True,
            'optimization_applied': True
        }
    
    def _get_optimized_save_settings(self, format_type: str, image_size: Tuple[int, int], 
                                   options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get optimized save settings based on format and image characteristics.
        """
        width, height = image_size
        pixel_count = width * height
        
        # Base settings for format
        settings = self.optimization_settings.get(format_type, {}).copy()
        
        # Adjust quality based on image size
        if format_type == 'jpeg':
            if pixel_count < 50000:  # Very small images
                settings['quality'] = max(90, settings.get('quality', 85))
            elif pixel_count > 500000:  # Large images
                settings['quality'] = min(80, settings.get('quality', 85))
        elif format_type == 'webp':
            if pixel_count < 50000:
                settings['quality'] = max(85, settings.get('quality', 80))
            elif pixel_count > 500000:
                settings['quality'] = min(75, settings.get('quality', 80))
        
        # Apply user options
        if 'quality' in options:
            settings['quality'] = options['quality']
        
        return settings
    
    def optimize_existing_image(self, input_path: str, output_path: str, 
                               optimization_level: str = 'balanced') -> Dict[str, Any]:
        """
        Optimize an existing image file.
        
        Args:
            input_path: Path to input image
            output_path: Path for optimized image
            optimization_level: 'aggressive', 'balanced', or 'conservative'
            
        Returns:
            Dict with optimization results
        """
        optimization_settings = {
            'aggressive': {'quality': 70, 'progressive': True},
            'balanced': {'quality': 85, 'progressive': True},
            'conservative': {'quality': 95, 'progressive': False}
        }
        
        settings = optimization_settings.get(optimization_level, optimization_settings['balanced'])
        
        try:
            original_size = os.path.getsize(input_path)
            
            with Image.open(input_path) as img:
                # Auto-orient
                img = ImageOps.exif_transpose(img)
                
                # Convert to RGB if necessary
                if img.mode in ('RGBA', 'LA', 'P'):
                    rgb_img = Image.new('RGB', img.size, (255, 255, 255))
                    if img.mode == 'RGBA':
                        rgb_img.paste(img, mask=img.split()[-1])
                    else:
                        rgb_img.paste(img)
                    img = rgb_img
                
                # Save with optimization
                img.save(output_path, format='JPEG', **settings, optimize=True)
            
            optimized_size = os.path.getsize(output_path)
            compression_ratio = (original_size - optimized_size) / original_size * 100
            
            return {
                'success': True,
                'original_size': original_size,
                'optimized_size': optimized_size,
                'compression_ratio': compression_ratio,
                'optimization_level': optimization_level
            }
            
        except Exception as e:
            logger.error(f"Image optimization failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }

# Global advanced image processor instance
advanced_processor = AdvancedImageProcessor()

def get_advanced_image_processor() -> AdvancedImageProcessor:
    """Get the global advanced image processor instance."""
    return advanced_processor