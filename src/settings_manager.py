import json
import os
from datetime import datetime
from cryptography.fernet import Fernet
import configparser

class SettingsManager:
    def __init__(self):
        self.app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.config_dir = os.path.join(self.app_dir, 'config')
        self.data_dir = os.path.join(self.app_dir, 'data')
        
        # Ensure directories exist
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.data_dir, exist_ok=True)
        
        # File paths
        self.settings_file = os.path.join(self.config_dir, 'settings.json')
        self.credentials_file = os.path.join(self.config_dir, 'credentials.enc')
        self.key_file = os.path.join(self.config_dir, '.key')
        
        # Default settings
        self.default_settings = {
            "case_management": {
                "case_retention_limit": 100,
                "date_format": "YYYY-MM-DD_HH:MM:SS",
                "auto_save_interval": 0  # 0 = disabled
            },
            "data_export": {
                "save_location": self.data_dir,
                "export_format": "JSON",
                "compress_old_files": False,
                "backup_enabled": False,
                "backup_location": ""
            },
            "api_settings": {
                "request_timeout": 30,
                "rate_limit_delay": 1
            },
            "appearance": {
                "description_font_family": "Segoe UI",
                "description_font_size": 10,
                "ui_font_family": "Segoe UI", 
                "ui_font_size": 9,
                "label_font_size": 9,
                "button_font_size": 9
            }
        }
        
        # Initialize encryption key
        self._init_encryption()
        
        # Load or create settings
        self.settings = self.load_settings()
    
    def _init_encryption(self):
        """Initialize or load encryption key for API credentials"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
            # Set restrictive permissions on key file
            os.chmod(self.key_file, 0o600)
        
        self.cipher = Fernet(self.key)
    
    def load_settings(self):
        """Load settings from file or create defaults"""
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r') as f:
                    settings = json.load(f)
                # Merge with defaults to ensure all keys exist
                return self._merge_settings(self.default_settings, settings)
            except (json.JSONDecodeError, FileNotFoundError):
                pass
        
        # Return defaults if file doesn't exist or is corrupted
        return self.default_settings.copy()
    
    def _merge_settings(self, defaults, loaded):
        """Merge loaded settings with defaults to ensure all keys exist"""
        result = defaults.copy()
        for section, values in loaded.items():
            if section in result and isinstance(values, dict):
                result[section].update(values)
            else:
                result[section] = values
        return result
    
    def save_settings(self):
        """Save current settings to file"""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving settings: {e}")
            return False
    
    def get_setting(self, section, key):
        """Get a specific setting value"""
        return self.settings.get(section, {}).get(key)
    
    def set_setting(self, section, key, value):
        """Set a specific setting value"""
        if section not in self.settings:
            self.settings[section] = {}
        self.settings[section][key] = value
    
    def load_api_credentials(self):
        """Load and decrypt API credentials"""
        if not os.path.exists(self.credentials_file):
            return {"abuseipdb_api_key": "", "virustotal_api_key": ""}
        
        try:
            with open(self.credentials_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.cipher.decrypt(encrypted_data)
            credentials = json.loads(decrypted_data.decode())
            
            # Ensure all required keys exist
            default_creds = {"abuseipdb_api_key": "", "virustotal_api_key": ""}
            default_creds.update(credentials)
            return default_creds
            
        except Exception as e:
            print(f"Error loading credentials: {e}")
            return {"abuseipdb_api_key": "", "virustotal_api_key": ""}
    
    def save_api_credentials(self, credentials):
        """Encrypt and save API credentials"""
        try:
            # Ensure only valid credentials are saved
            valid_creds = {
                "abuseipdb_api_key": credentials.get("abuseipdb_api_key", ""),
                "virustotal_api_key": credentials.get("virustotal_api_key", "")
            }
            
            json_data = json.dumps(valid_creds)
            encrypted_data = self.cipher.encrypt(json_data.encode())
            
            with open(self.credentials_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Set restrictive permissions
            os.chmod(self.credentials_file, 0o600)
            return True
            
        except Exception as e:
            print(f"Error saving credentials: {e}")
            return False
    
    def get_case_id_format(self):
        """Get the current case ID format string"""
        date_format = self.get_setting("case_management", "date_format")
        
        # Convert user-friendly format to strftime format
        format_mapping = {
            "YYYY-MM-DD_HH:MM:SS": "%Y-%m-%d_%H:%M:%S",
            "YYYYMMDD_HHMMSS": "%Y%m%d_%H%M%S",
            "DD-MM-YYYY_HH:MM:SS": "%d-%m-%Y_%H:%M:%S",
            "MM-DD-YYYY_HH:MM:SS": "%m-%d-%Y_%H:%M:%S"
        }
        
        return format_mapping.get(date_format, "%Y-%m-%d_%H:%M:%S")
    
    def get_data_directory(self):
        """Get the directory where case files should be saved"""
        return self.get_setting("data_export", "save_location") or self.data_dir
    
    def should_create_new_file(self, current_case_count):
        """Check if a new JSON file should be created based on retention limit"""
        limit = self.get_setting("case_management", "case_retention_limit")
        return current_case_count >= limit if limit > 0 else False
    
    def export_settings(self, file_path):
        """Export settings to a file (for backup/sharing)"""
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
        """Import settings from a file"""
        try:
            with open(file_path, 'r') as f:
                import_data = json.load(f)
            
            if "settings" in import_data:
                self.settings = self._merge_settings(self.default_settings, import_data["settings"])
                return self.save_settings()
            return False
        except Exception as e:
            print(f"Error importing settings: {e}")
            return False
