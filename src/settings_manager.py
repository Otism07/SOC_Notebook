# Standard library imports
import json
import os
from datetime import datetime

# Third-party imports for encryption
from cryptography.fernet import Fernet
import configparser

class SettingsManager:
    # Manages application settings and encrypted API credentials
    # Handles configuration persistence, default values, and secure storage
    # of sensitive information like API keys
    
    def __init__(self):
        # Initialize the settings manager with default paths and encryption
        # Set up directory structure
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.config_dir = os.path.join(self.app_dir, 'config')
        self.data_dir = os.path.join(self.app_dir, 'data')
        
        # Ensure directories exist with fallback to user home directory
        try:
            os.makedirs(self.config_dir, exist_ok=True)
            os.makedirs(self.data_dir, exist_ok=True)
        except (OSError, PermissionError) as e:
            # If we can't create directories in app folder, use user home directory
            print(f"Warning: Could not create directories in app folder: {e}")
            user_home = os.path.expanduser("~")
            self.app_dir = os.path.join(user_home, 'SOC_Case_Logger')
            self.config_dir = os.path.join(self.app_dir, 'config')
            self.data_dir = os.path.join(self.app_dir, 'data')
            
            try:
                os.makedirs(self.config_dir, exist_ok=True)
                os.makedirs(self.data_dir, exist_ok=True)
                print(f"Using user directory: {self.app_dir}")
            except (OSError, PermissionError) as fallback_error:
                print(f"Error: Could not create directories in user home: {fallback_error}")
                raise
        
        # Define file paths for configuration storage
        self.settings_file = os.path.join(self.config_dir, 'settings.json')
        self.credentials_file = os.path.join(self.config_dir, 'credentials.enc')
        self.key_file = os.path.join(self.config_dir, '.key')
        
        # Define default application settings
        self.default_settings = {
            "case_management": {
                "case_retention_limit": 100,  # Max cases per file before creating new one
                "date_format": "YYYY-MM-DD_HH:MM:SS",  # User-friendly date format
                "auto_save_interval": 0  # 0 = disabled (auto-save feature removed)
            },
            "data_export": {
                "save_location": self.data_dir,  # Where case files are stored
                "export_format": "JSON",  # Default export format
                "compress_old_files": False,  # Whether to compress archived files
                "backup_enabled": False,  # Automatic backup feature
                "backup_location": ""  # Backup directory location
            },
            "api_settings": {
                "request_timeout": 30,  # API request timeout in seconds
                "rate_limit_delay": 1  # Delay between API calls to respect rate limits
            },
            "appearance": {
                "description_font_family": "Segoe UI",  # Font for description text
                "description_font_size": 10,
                "ui_font_family": "Segoe UI",  # Font for UI elements
                "ui_font_size": 9,
                "label_font_size": 9,
                "button_font_size": 9
            }
        }
        
        # Initialize encryption for API credentials
        self._init_encryption()
        
        # Load existing settings or create defaults
        self.settings = self.load_settings()
    
    def _init_encryption(self):
        # Initialize or load encryption key for securing API credentials
        if os.path.exists(self.key_file):
            # Load existing encryption key
            try:
                with open(self.key_file, 'rb') as f:
                    self.key = f.read()
            except (OSError, PermissionError) as e:
                print(f"Warning: Could not read encryption key file: {e}")
                # Generate a new key if we can't read the existing one
                self.key = Fernet.generate_key()
        else:
            # Generate new encryption key
            self.key = Fernet.generate_key()
            try:
                with open(self.key_file, 'wb') as f:
                    f.write(self.key)
                # Set restrictive permissions on key file (Unix-like systems only)
                try:
                    os.chmod(self.key_file, 0o600)
                except (OSError, AttributeError):
                    # Windows doesn't support Unix-style permissions, skip silently
                    pass
            except (OSError, PermissionError) as e:
                print(f"Warning: Could not save encryption key file: {e}")
                # Continue with in-memory key only
                pass
        
        # Initialize the cipher for encryption/decryption
        self.cipher = Fernet(self.key)

    def load_settings(self):
        # Load application settings from file or return defaults
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r') as f:
                    settings = json.load(f)
                # Merge with defaults to ensure all required keys exist
                return self._merge_settings(self.default_settings, settings)
            except (json.JSONDecodeError, FileNotFoundError):
                pass
        
        # Return defaults if file doesn't exist or is corrupted
        return self.default_settings.copy()
    
    def _merge_settings(self, defaults, loaded):
        # Merge loaded settings with defaults to ensure all keys exist
        # This prevents errors when new settings are added in updates
        result = defaults.copy()
        for section, values in loaded.items():
            if section in result and isinstance(values, dict):
                result[section].update(values)
            else:
                result[section] = values
        return result
    
    def save_settings(self):
        # Save current settings to file
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving settings: {e}")
            return False
    
    def get_setting(self, section, key):
        # Get a specific setting value.
        return self.settings.get(section, {}).get(key)
    
    def set_setting(self, section, key, value):
        # Set a specific setting value.
        if section not in self.settings:
            self.settings[section] = {}
        self.settings[section][key] = value
    
    def load_api_credentials(self):
        # Load and decrypt API credentials from secure storage.
        if not os.path.exists(self.credentials_file):
            return {"abuseipdb_api_key": "", "virustotal_api_key": ""}
        
        try:
            # Read and decrypt the credentials file
            with open(self.credentials_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.cipher.decrypt(encrypted_data)
            credentials = json.loads(decrypted_data.decode())
            
            # Ensure all required keys exist with default empty values
            default_creds = {"abuseipdb_api_key": "", "virustotal_api_key": ""}
            default_creds.update(credentials)
            return default_creds
            
        except Exception as e:
            print(f"Error loading credentials: {e}")
            return {"abuseipdb_api_key": "", "virustotal_api_key": ""}
    
    def save_api_credentials(self, credentials):
        # Encrypt and save API credentials to secure storage.
        try:
            # Ensure only valid credentials are saved
            valid_creds = {
                "abuseipdb_api_key": credentials.get("abuseipdb_api_key", ""),
                "virustotal_api_key": credentials.get("virustotal_api_key", "")
            }
            
            # Encrypt the credentials
            json_data = json.dumps(valid_creds)
            encrypted_data = self.cipher.encrypt(json_data.encode())
            
            # Save encrypted data to file
            with open(self.credentials_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Set restrictive permissions (Unix-like systems only)
            try:
                os.chmod(self.credentials_file, 0o600)
            except (OSError, AttributeError):
                # Windows doesn't support Unix-style permissions, skip silently
                pass
            return True
            
        except Exception as e:
            print(f"Error saving credentials: {e}")
            return False
    
    def get_case_id_format(self):
        # Get the strftime format string for case ID generation.
        date_format = self.get_setting("case_management", "date_format")
        
        # Convert user-friendly format to Python strftime format
        # Note: Colons (:) are replaced with hyphens (-) for Windows compatibility
        format_mapping = {
            "YYYY-MM-DD_HH:MM:SS": "%Y-%m-%d_%H-%M-%S",
            "YYYYMMDD_HHMMSS": "%Y%m%d_%H%M%S",
            "DD-MM-YYYY_HH:MM:SS": "%d-%m-%Y_%H-%M-%S",
            "MM-DD-YYYY_HH:MM:SS": "%m-%d-%Y_%H-%M-%S"
        }
        
        return format_mapping.get(date_format, "%Y-%m-%d_%H-%M-%S")
    
    def get_data_directory(self):
        # Get the directory where case files should be saved.
        # Returns either user-configured path or default, ensuring it exists
        configured_path = self.get_setting("data_export", "save_location")
        
        if configured_path and configured_path.strip():
            # User has configured a custom path
            target_dir = configured_path.strip()
            
            # Check if the configured directory exists and is writable
            if os.path.exists(target_dir):
                try:
                    # Test write permission
                    test_file = os.path.join(target_dir, '.write_test')
                    with open(test_file, 'w') as f:
                        f.write('test')
                    os.remove(test_file)
                    return target_dir
                except (OSError, PermissionError):
                    # Directory exists but not writable, fall back to default
                    print(f"Warning: Configured directory {target_dir} is not writable, using default")
                    pass
            else:
                # Directory doesn't exist, fall back to default
                print(f"Warning: Configured directory {target_dir} does not exist, using default")
        
        # Return default directory (self.data_dir should always be valid from __init__)
        return self.data_dir
    
    def should_create_new_file(self, current_case_count):
        # Check if a new JSON file should be created based on retention limit.
        limit = self.get_setting("case_management", "case_retention_limit")
        return current_case_count >= limit if limit > 0 else False
    
    def export_settings(self, file_path):
        # Export settings to a file for backup or sharing.
        try:
            export_data = {
                "settings": self.settings,
                "exported_at": datetime.now().isoformat(),
                "version": "1.0"
            }
            
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error exporting settings: {e}")
            return False
    
    def import_settings(self, file_path):
        # Import settings from a previously exported file.
        try:
            with open(file_path, 'r') as f:
                import_data = json.load(f)
            
            # Validate and import settings
            if "settings" in import_data:
                self.settings = self._merge_settings(self.default_settings, import_data["settings"])
                return self.save_settings()
            return False
        except Exception as e:
            print(f"Error importing settings: {e}")
            return False
