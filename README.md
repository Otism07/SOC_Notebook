# SOC Case Logger

A comprehensive Python-based GUI application for Security Operations Center (SOC) analysts to document, track, and manage security incidents and investigations.

## Features

### 🔍 Case Management
- **Create & Track Cases**: Generate unique case IDs with timestamps
- **Comprehensive Data Capture**: Record user details, IP addresses, file hashes, URLs, and hostnames
- **Case Classification**: Categorize incidents as Benign, Suspicious, or Malicious
- **Outcome Tracking**: Document resolution outcomes (True Positive, False Positive, etc.)
- **Rich Note-Taking**: Detailed description and investigation notes with formatting support

### 🌐 Threat Intelligence Integration
- **AbuseIPDB Integration**: Automated IP reputation checks with abuse confidence scoring
- **VirusTotal Integration**: File hash analysis with malware detection results
- **API Management**: Secure credential storage with encrypted API key management

### 🔎 Search & Analysis
- **Advanced Search**: Filter cases by date range, status, classification, and custom criteria
- **Case History**: View and load previous investigations
- **Export Capabilities**: Save cases in multiple formats (JSON, CSV)
- **Data Validation**: Automatic validation of IP addresses, emails, and other input data

### ⚙️ Customization & Settings
- **Appearance Options**: Customizable fonts and interface styling
- **Data Management**: Configurable retention policies and backup locations
- **Export Settings**: Flexible data export formats and compression options
- **Secure Configuration**: Encrypted storage of sensitive settings and API credentials

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Required Dependencies
```bash
pip install requests>=2.25.0 cryptography>=3.0.0 pandas>=1.3.0 loguru>=0.6.0 jsonschema>=4.0.0 pillow>=8.0.0
```

### Quick Setup
1. **Clone or download** the SOC Case Logger files
2. **Navigate** to the project directory:
   ```bash
   cd soc-case-logger
   ```
3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Launch the application**:
   ```bash
   python3 run.py
   ```

## Usage

### Getting Started
1. **Launch the application** using `python3 run.py`
2. **Configure API keys** (optional but recommended):
   - Go to Settings tab
   - Add your AbuseIPDB API key for IP reputation checks
   - Add your VirusTotal API key for file hash analysis
3. **Create your first case** in the General tab

### Creating a Case
1. **General Tab**: Enter incident details
   - User information (name, role, email)
   - System details (hostname, IP address)
   - Indicators (file hashes, URLs)
   - Investigation notes

2. **Threat Intelligence**: Use integrated tools
   - Click "Search AbuseIPDB" to check IP reputation
   - Click "Scan VirusTotal" to analyze file hashes
   - Results are automatically added to case notes

3. **Classification**: Set case outcome
   - Choose classification (Benign/Suspicious/Malicious)
   - Select outcome type (True Positive, False Positive, etc.)

4. **Save Case**: Click "Save Case" to store the investigation

### Searching Cases
1. **Search Tab**: Find existing cases
   - Filter by date range
   - Search by case status or classification
   - Use custom search terms
   - Load cases back to General tab for editing

### Configuration
1. **Settings Tab**: Customize application behavior
   - API credentials for threat intelligence
   - Appearance and font settings
   - Data export and backup locations
   - Case retention policies

## File Structure
```
soc-case-logger/
├── src/                    # Source code
│   ├── gui/               # User interface
│   ├── models/            # Data models
│   ├── utils/             # Utility functions
│   └── main.py           # Application entry point
├── data/                  # Case storage
├── config/               # Configuration files
├── logs/                 # Application logs
├── requirements.txt      # Dependencies
└── run.py               # Launch script
```

## Data Storage

### Case Data
- Cases are stored in JSON format in the `data/` directory
- Each case includes timestamps, user details, indicators, and outcomes
- Individual case files are created for backup purposes

### Security
- API credentials are encrypted using the `cryptography` library
- Configuration files use secure storage mechanisms
- No sensitive data is stored in plain text

## API Integration

### AbuseIPDB
- Provides IP reputation and abuse confidence scoring
- Returns ISP, country, and usage type information
- Requires free API key from [AbuseIPDB](https://www.abuseipdb.com/)

### VirusTotal
- Analyzes file hashes for malware detection
- Provides scan results from multiple antivirus engines
- Requires free API key from [VirusTotal](https://www.virustotal.com/)

## Troubleshooting

### Common Issues
- **API Key Errors**: Ensure API keys are properly configured in Settings
- **Permission Issues**: Check file system permissions for data directory
- **Import Errors**: Verify all required dependencies are installed

### Support
- Check the `logs/app.log` file for detailed error information
- Ensure Python 3.7+ is installed
- Verify network connectivity for API integrations
