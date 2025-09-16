# SOC Notebook - Script Documentation

This document provides comprehensive documentation for all scripts in the SOC Notebook project, including their functions, inputs, outputs, and purposes.

## Project Overview
SOC Notebook is a GUI application for managing Security Operations Center (SOC) cases. It provides functionality for case creation, search, bulk IP analysis, and settings management.

---

## Core Scripts

### 1. run.py
**Purpose**: Main launcher script providing unified entry point for the application

**Functions**:
- `get_resource_path(relative_path)`: Get absolute path to resource, works for both development and PyInstaller bundles
  - **Input**: relative_path (str) - Path relative to application root
  - **Output**: Absolute path to the resource
  - **Purpose**: Handle path resolution for bundled and development environments

- `run_application()`: Launch the SOC Notebook application
  - **Input**: None
  - **Output**: None (launches GUI application)
  - **Purpose**: Configure environment and start main application

**Usage**:
- Development: `python3 run.py`
- Bundled: `./SOCNotebook.exe`

---

### 2. src/main.py
**Purpose**: Main application entry point with error handling and logging setup

**Functions**:
- `main()`: Main application entry point
  - **Input**: None
  - **Output**: None (starts GUI)
  - **Purpose**: Initialize logging, create GUI, handle startup errors

**Dependencies**: logger.py, gui/main_window.py

---

### 3. src/logger.py
**Purpose**: Centralized logging configuration for the application

**Functions**:
- `setup_logger(name, log_file, level)`: Configure logger with file and console output
  - **Input**: 
    - name (str) - Logger name
    - log_file (str) - Path to log file
    - level (logging.Level) - Logging level
  - **Output**: Configured logger instance
  - **Purpose**: Provide consistent logging across application

**Features**:
- File rotation (10MB max, 5 backups)
- Console and file output
- Configurable log levels

---

### 4. src/settings_manager.py
**Purpose**: Manage application settings and encrypted credential storage

**Functions**:
- `__init__(config_file)`: Initialize settings manager
  - **Input**: config_file (str) - Path to settings JSON file
  - **Output**: SettingsManager instance
  - **Purpose**: Load existing settings or create defaults

- `load_settings()`: Load settings from JSON file
  - **Input**: None
  - **Output**: None (loads into self.settings)
  - **Purpose**: Read configuration from disk

- `save_settings()`: Save current settings to JSON file
  - **Input**: None
  - **Output**: None (writes to disk)
  - **Purpose**: Persist settings changes

- `get_setting(key, default)`: Get a specific setting value
  - **Input**: key (str), default (any)
  - **Output**: Setting value or default
  - **Purpose**: Safe setting retrieval

- `update_setting(key, value)`: Update a specific setting
  - **Input**: key (str), value (any)
  - **Output**: None
  - **Purpose**: Modify and save setting

- `encrypt_credentials(api_key)`: Encrypt and store API credentials
  - **Input**: api_key (str)
  - **Output**: None
  - **Purpose**: Securely store sensitive data

- `decrypt_credentials()`: Decrypt stored API credentials
  - **Input**: None
  - **Output**: Decrypted API key (str)
  - **Purpose**: Retrieve stored credentials

**Features**:
- Fernet encryption for credentials
- JSON configuration storage
- Default value handling

---

### 5. src/case_manager.py
**Purpose**: CRUD operations and data management for SOC cases

**Functions**:
- `__init__(data_file)`: Initialize case manager
  - **Input**: data_file (str) - Path to cases JSON file
  - **Output**: CaseManager instance
  - **Purpose**: Set up case storage and load existing data

- `load_cases()`: Load all cases from JSON file
  - **Input**: None
  - **Output**: None (loads into self.cases dict)
  - **Purpose**: Read case data from disk

- `save_cases()`: Save all cases to JSON file
  - **Input**: None
  - **Output**: None (writes to disk)
  - **Purpose**: Persist case data

- `create_case(case_id, title, description, **kwargs)`: Create new case
  - **Input**: case_id (str), title (str), description (str), additional fields
  - **Output**: Case object
  - **Purpose**: Add new case to system

- `save_case(case)`: Save or update existing case
  - **Input**: case (Case object)
  - **Output**: None
  - **Purpose**: Update case in memory and disk

- `get_case(case_id)`: Retrieve specific case
  - **Input**: case_id (str)
  - **Output**: Case object or None
  - **Purpose**: Fetch case by ID

- `get_all_cases()`: Get all stored cases
  - **Input**: None
  - **Output**: List of Case objects
  - **Purpose**: Retrieve complete case collection

- `search_cases(search_term)`: Search cases by content
  - **Input**: search_term (str)
  - **Output**: List of matching Case objects
  - **Purpose**: Find cases containing search term

- `delete_case(case_id)`: Remove case from system
  - **Input**: case_id (str)
  - **Output**: Boolean success indicator
  - **Purpose**: Delete case data

- `export_cases(filename)`: Export cases to file
  - **Input**: filename (str)
  - **Output**: None (creates file)
  - **Purpose**: Backup or share case data

- `import_cases(filename)`: Import cases from file
  - **Input**: filename (str)
  - **Output**: None (adds to cases)
  - **Purpose**: Restore or merge case data

**Features**:
- JSON persistence
- In-memory case dictionary
- Full-text search capability
- Import/export functionality

---

### 6. src/models/case.py
**Purpose**: Data model representing individual SOC cases

**Functions**:
- `__init__(case_id, title, description, ...)`: Initialize case instance
  - **Input**: Case field values (strings, optional)
  - **Output**: Case object
  - **Purpose**: Create case with all required fields

- `update_timestamp()`: Update the last modified time
  - **Input**: None
  - **Output**: None
  - **Purpose**: Track when case was last changed

- `to_dict()`: Convert case to dictionary for JSON serialization
  - **Input**: None
  - **Output**: Dictionary representation
  - **Purpose**: Prepare case for storage

- `from_dict(data)`: Create case from dictionary (class method)
  - **Input**: data (dict) - Case data from JSON
  - **Output**: Case object
  - **Purpose**: Reconstruct case from stored data

**Fields**:
- case_id, title, description
- user, role, email, host, ip_address, file_hash
- outcome, status, created_at, updated_at

---

### 7. src/gui/main_window.py
**Purpose**: Main GUI interface with tabbed layout and all user interactions

**Functions**:
- `__init__(root)`: Initialize main GUI window
  - **Input**: root (tk.Tk) - Tkinter root window
  - **Output**: SOCNotebook instance
  - **Purpose**: Set up complete GUI interface

- `create_main_content(parent_frame)`: Create General tab interface
  - **Input**: parent_frame (tk.Frame)
  - **Output**: None (adds widgets to frame)
  - **Purpose**: Build case creation/editing interface

- `create_search_content(parent_frame)`: Create Search tab interface
  - **Input**: parent_frame (tk.Frame)
  - **Output**: None (adds widgets to frame)
  - **Purpose**: Build case search and display interface

- `create_bulk_lookup_content(parent_frame)`: Create Bulk Lookup tab
  - **Input**: parent_frame (tk.Frame)
  - **Output**: None (adds widgets to frame)
  - **Purpose**: Build bulk IP analysis interface

- `create_settings_content(parent_frame)`: Create Settings tab
  - **Input**: parent_frame (tk.Frame)
  - **Output**: None (adds widgets to frame)
  - **Purpose**: Build configuration interface

- `save_case()`: Save current case data
  - **Input**: None (reads from GUI fields)
  - **Output**: None (saves to storage)
  - **Purpose**: Create new case from form data

- `search_ip_abuseipdb()`: Query single IP against AbuseIPDB
  - **Input**: None (reads IP from GUI)
  - **Output**: None (displays results in notes)
  - **Purpose**: Add threat intelligence to case

- `bulk_scan_ips()`: Scan multiple IPs against AbuseIPDB
  - **Input**: None (reads IPs from bulk input)
  - **Output**: None (displays results in table)
  - **Purpose**: Analyze multiple IPs simultaneously

- `perform_search()`: Search existing cases
  - **Input**: None (reads search term from GUI)
  - **Output**: None (displays results in tree)
  - **Purpose**: Find and display matching cases

- `load_case_to_general()`: Load selected case to General tab
  - **Input**: None (uses selected case)
  - **Output**: None (populates form fields)
  - **Purpose**: Edit existing case

**Features**:
- 4-tab interface (General, Search, Bulk Lookup, Settings)
- AbuseIPDB integration
- Platform-specific styling
- Case management workflows

---

### 8. src/utils/__init__.py
**Purpose**: Utility functions and fallback implementations

**Functions**:
- `hash_string(input_string)`: Generate hash of input string
  - **Input**: input_string (str)
  - **Output**: Hexadecimal hash string
  - **Purpose**: Create secure hashes (fallback when hashlib unavailable)

**Features**:
- Fallback hash implementation using cryptography library
- Cross-platform compatibility

---

### 9. src/models/__init__.py
**Purpose**: Models package initialization

**Content**: Empty file to make models directory a Python package

---

## Helper Functions

### create_colored_button(parent, text, command, button_type, **kwargs)
**Location**: src/gui/main_window.py
**Purpose**: Create platform-compatible colored buttons

**Input**:
- parent: Parent widget
- text: Button text
- command: Click handler function
- button_type: Style type ('default', 'accent', 'success', 'urgent')
- **kwargs: Additional button parameters

**Output**: Button widget (tk.Button on Windows, ttk.Button elsewhere)

**Purpose**: Ensure colored buttons display properly across all platforms

---

## Data Formats

### Case JSON Structure
```json
{
  "case_id": "SOC-YYYY-MM-DD_HH-MM-SS",
  "title": "Case title",
  "description": "Detailed description",
  "user": "username",
  "role": "user role",
  "email": "user@email.com",
  "host": "hostname",
  "ip_address": "192.168.1.1",
  "file_hash": "sha256hash",
  "outcome": "Benign, False-Positive",
  "status": "completed",
  "created_at": "2025-09-15T10:30:00",
  "updated_at": "2025-09-15T10:35:00"
}
```

### Settings JSON Structure
```json
{
  "api_key_encrypted": "encrypted_key_data",
  "data_directory": "data/",
  "log_level": "INFO",
  "font_family": "Arial",
  "font_size": 10
}
```

---

## External Dependencies

### Required Libraries
- tkinter: GUI framework
- requests: HTTP client for API calls
- cryptography: Encryption for credentials
- json: Data serialization
- datetime: Timestamp handling
- platform: OS detection for styling

### APIs Used
- AbuseIPDB API: IP threat intelligence
  - Endpoint: https://api.abuseipdb.com/api/v2/check
  - Authentication: X-Key header
  - Rate limits: Varies by plan

---

## File Structure
```
SOC-Notebook/
├── run.py                    # Main launcher
├── requirements.txt          # Python dependencies
├── config/                   # Configuration files
│   ├── settings.json        # Application settings
│   └── credentials.enc      # Encrypted API keys
├── data/                    # Case data storage
│   └── cases.json          # Case database
├── logs/                    # Application logs
│   └── app.log             # Main log file
└── src/                     # Source code
    ├── main.py             # Application entry point
    ├── logger.py           # Logging configuration
    ├── settings_manager.py # Settings and credentials
    ├── case_manager.py     # Case CRUD operations
    ├── gui/
    │   └── main_window.py  # Main GUI interface
    ├── models/
    │   ├── __init__.py
    │   └── case.py         # Case data model
    └── utils/
        └── __init__.py     # Utility functions
```

---

## Error Handling

### Common Error Scenarios
1. **Missing API Key**: Prompts user to configure in Settings
2. **Network Errors**: Displays timeout/connection messages
3. **File Permissions**: Creates directories with proper permissions
4. **Data Corruption**: Handles JSON decode errors gracefully
5. **Platform Differences**: Adapts styling and file paths

### Logging Levels
- DEBUG: Detailed development information
- INFO: General application flow
- WARNING: Recoverable issues
- ERROR: Serious problems
- CRITICAL: Application-stopping errors

---

## Version Information
- Python Version: 3.7+
- GUI Framework: tkinter
- Encryption: Fernet (cryptography library)
- Data Format: JSON
- Supported Platforms: Windows, macOS, Linux
