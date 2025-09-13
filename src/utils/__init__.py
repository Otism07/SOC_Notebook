"""
Utility functions for SOC Case Logger
"""

import hashlib
import os
import json
import re
import html
import ipaddress
from datetime import datetime
from typing import Optional, Dict, Any

def generate_case_id(prefix: str = "SOC") -> str:
    """Generate a unique case ID with timestamp"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    return f"{prefix}-{timestamp}"

def hash_file(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
    """
    Generate hash of a file using specified algorithm
    
    Args:
        file_path: Path to the file to hash
        algorithm: Hash algorithm to use (md5, sha1, sha256, sha512)
    
    Returns:
        Hex digest of the file hash, or None if error
    """
    if not os.path.exists(file_path):
        return None
    
    try:
        hash_obj = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception:
        return None

def validate_ip_address(ip: str) -> bool:
    """Validate if string is a valid IPv4 or IPv6 address"""
    if not ip or not isinstance(ip, str):
        return False
    
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False

def sanitize_input(text: str, max_length: int = 1000) -> str:
    """
    Sanitize user input to prevent injection attacks and ensure safe storage
    
    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length
    
    Returns:
        Sanitized text
    """
    if not isinstance(text, str):
        return ""
    
    # Remove potentially dangerous characters and HTML entities
    sanitized = html.escape(text)
    
    # Remove or replace potentially dangerous patterns
    sanitized = re.sub(r'[<>\"\'%;()&+\x00-\x1f\x7f-\x9f]', '', sanitized)
    
    # Limit length to prevent memory issues
    sanitized = sanitized[:max_length]
    
    # Remove leading/trailing whitespace
    return sanitized.strip()

def validate_email(email: str) -> bool:
    """
    Validate email address format
    
    Args:
        email: Email address to validate
    
    Returns:
        True if valid email format, False otherwise
    """
    if not email or not isinstance(email, str):
        return False
    
    email = email.strip()
    if len(email) > 254:  # RFC 5321 limit
        return False
    
    # Basic email validation pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_file_hash(file_hash: str, algorithm: str = 'sha256') -> bool:
    """
    Validate file hash format
    
    Args:
        file_hash: Hash string to validate
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)
    
    Returns:
        True if valid hash format, False otherwise
    """
    if not file_hash or not isinstance(file_hash, str):
        return False
    
    file_hash = file_hash.strip().lower()
    
    # Expected lengths for different algorithms
    expected_lengths = {
        'md5': 32,
        'sha1': 40,
        'sha256': 64,
        'sha512': 128
    }
    
    expected_length = expected_lengths.get(algorithm.lower())
    if not expected_length:
        return False
    
    # Check length and hex characters only
    if len(file_hash) != expected_length:
        return False
    
    pattern = r'^[a-f0-9]+$'
    return bool(re.match(pattern, file_hash))

def validate_url(url: str) -> bool:
    """
    Validate URL format (including defanged URLs)
    
    Args:
        url: URL to validate
    
    Returns:
        True if valid URL format, False otherwise
    """
    if not url or not isinstance(url, str):
        return False
    
    url = url.strip()
    if len(url) > 2000:  # Reasonable URL length limit
        return False
    
    # Allow normal URLs and defanged URLs (hxxp, www[.]example[.]com)
    # This is more permissive for SOC use cases
    pattern = r'^(https?|hxxps?|ftp)://|www\[?\.\]?|[a-zA-Z0-9.-]+\[?\.\]?[a-zA-Z]{2,}'
    return bool(re.search(pattern, url, re.IGNORECASE))

def format_timestamp(timestamp: str) -> str:
    """Format ISO timestamp to readable format"""
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return timestamp

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file operations"""
    # Remove or replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename

def export_to_csv(cases: list, filename: str) -> bool:
    """
    Export cases to CSV format
    
    Args:
        cases: List of case dictionaries
        filename: Output filename
    
    Returns:
        True if successful, False otherwise
    """
    try:
        import csv
        
        if not cases:
            return False
        
        fieldnames = cases[0].keys()
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(cases)
        
        return True
    except Exception:
        return False

def backup_data(source_file: str, backup_dir: str = None) -> Optional[str]:
    """
    Create a backup of the data file
    
    Args:
        source_file: Path to the file to backup
        backup_dir: Directory to store backup (default: same directory as source)
    
    Returns:
        Path to backup file if successful, None otherwise
    """
    try:
        if not os.path.exists(source_file):
            return None
        
        if backup_dir is None:
            backup_dir = os.path.dirname(source_file)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.basename(source_file)
        name, ext = os.path.splitext(filename)
        backup_filename = f"{name}_backup_{timestamp}{ext}"
        backup_path = os.path.join(backup_dir, backup_filename)
        
        with open(source_file, 'r') as src, open(backup_path, 'w') as dst:
            dst.write(src.read())
        
        return backup_path
    except Exception:
        return None

def search_text(text: str, search_terms: list, case_sensitive: bool = False) -> bool:
    """
    Search for multiple terms in text
    
    Args:
        text: Text to search in
        search_terms: List of terms to search for
        case_sensitive: Whether search should be case sensitive
    
    Returns:
        True if any search term is found, False otherwise
    """
    if not case_sensitive:
        text = text.lower()
        search_terms = [term.lower() for term in search_terms]
    
    return any(term in text for term in search_terms)

class DataValidator:
    """Validate case data"""
    
    @staticmethod
    def validate_case_data(case_data: Dict[str, Any]) -> tuple[bool, list]:
        """
        Validate case data
        
        Args:
            case_data: Dictionary containing case data
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Required fields
        required_fields = ['case_id']
        for field in required_fields:
            if not case_data.get(field):
                errors.append(f"Missing required field: {field}")
        
        # Validate IP address if provided
        if case_data.get('ip_address'):
            if not validate_ip_address(case_data['ip_address']):
                errors.append("Invalid IP address format")
        
        # Validate email format if provided
        if case_data.get('email'):
            email = case_data['email']
            if '@' not in email or '.' not in email.split('@')[-1]:
                errors.append("Invalid email format")
        
        return len(errors) == 0, errors

def get_file_info(file_path: str) -> Dict[str, Any]:
    """
    Get detailed file information
    
    Args:
        file_path: Path to the file
    
    Returns:
        Dictionary with file information
    """
    info = {
        'exists': False,
        'size': 0,
        'modified': None,
        'hash_md5': None,
        'hash_sha256': None
    }
    
    try:
        if os.path.exists(file_path):
            info['exists'] = True
            stat = os.stat(file_path)
            info['size'] = stat.st_size
            info['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            info['hash_md5'] = hash_file(file_path, 'md5')
            info['hash_sha256'] = hash_file(file_path, 'sha256')
    except Exception:
        pass  # Return default info if any error occurs
    
    return info
