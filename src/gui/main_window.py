# Standard library imports
import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import json
from datetime import datetime
import requests
import re
import time

# Add parent directory to path for module imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Local imports
from models.case import Case
from case_manager import CaseManager
from settings_manager import SettingsManager

def create_colored_button(parent, text, command, button_type='default', **kwargs):
    # Create a standard button without custom coloring
    return ttk.Button(parent, text=text, command=command, **kwargs)

class SOCCaseLogger:
    # Main GUI application for SOC (Security Operations Center) case logging
    # Provides a tabbed interface for case management, search functionality, and settings
    
    def __init__(self, root):
        # Initialize the SOC Case Logger application
        self.root = root
        self.root.title("SOC Case Logger")
        self.root.geometry("950x850")
        
        # Initialize settings manager first (handles configuration and API keys)
        self.settings_manager = SettingsManager()
        
        # Initialize case manager with configured data directory
        data_directory = self.settings_manager.get_data_directory()
        cases_file_path = os.path.join(data_directory, 'cases.json')
        self.case_manager = CaseManager(cases_file_path)
        self.current_case = Case()
        
        # Track the current case ID for updating existing cases
        self.current_case_id = None
        
        # Create the main interface
        self.create_widgets()
        
        # Add trace callbacks to automatically update header when fields change
        # (Must be done after create_widgets where the variables are created)
        self.user_var.trace('w', self.on_field_change)
        self.email_var.trace('w', self.on_field_change)
        self.role_var.trace('w', self.on_field_change)
        self.host_var.trace('w', self.on_field_change)
        
        # Load any existing cases on startup
        self.load_existing_cases()
        
        # Apply font settings after all widgets are created
        self.apply_font_settings()
        
    def create_widgets(self):
        # Create the main UI structure with tabbed interface
        # Create main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create notebook (tab container)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        general_frame = ttk.Frame(self.notebook)
        self.notebook.add(general_frame, text="General")
        
        search_frame = ttk.Frame(self.notebook)
        self.notebook.add(search_frame, text="Search")
        
        bulk_lookup_frame = ttk.Frame(self.notebook)
        self.notebook.add(bulk_lookup_frame, text="Bulk Lookup")
        
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Settings")
        
        # Create content for each tab
        self.create_main_content(general_frame)
        self.create_search_content(search_frame)
        self.create_bulk_lookup_content(bulk_lookup_frame)
        self.create_settings_content(settings_frame)
        
    def create_main_content(self, parent_frame):
        # Create the General tab content for case creation and editing
        # Main content area (previously general tab)
        content_frame = ttk.Frame(parent_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left column - Fixed width for input fields
        left_frame = ttk.Frame(content_frame, width=350)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, expand=False, padx=5, pady=5)
        left_frame.pack_propagate(False)  # Prevent frame from shrinking to fit contents
        
        # Details section for case information input
        details_frame = ttk.LabelFrame(left_frame, text="Details")
        details_frame.pack(fill=tk.X, pady=5)
        
        # Configure grid columns for proper layout
        details_frame.grid_columnconfigure(1, weight=1)  # Make entry column expandable
        
        # User input field
        ttk.Label(details_frame, text="User:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.user_var = tk.StringVar()
        ttk.Entry(details_frame, textvariable=self.user_var, width=20).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        
        # Email input field
        ttk.Label(details_frame, text="Email:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.email_var = tk.StringVar()
        ttk.Entry(details_frame, textvariable=self.email_var, width=20).grid(row=1, column=1, sticky=tk.EW, padx=5, pady=2)
        
        # Role
        ttk.Label(details_frame, text="Role:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.role_var = tk.StringVar()
        ttk.Entry(details_frame, textvariable=self.role_var, width=20).grid(row=2, column=1, sticky=tk.EW, padx=5, pady=2)
        
        # Hostname
        ttk.Label(details_frame, text="Hostname:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        self.host_var = tk.StringVar()
        ttk.Entry(details_frame, textvariable=self.host_var, width=20).grid(row=3, column=1, sticky=tk.EW, padx=5, pady=2)
        
        # Single Add button below hostname
        ttk.Button(details_frame, text="Add", width=10, command=self.add_details_to_notes).grid(row=4, column=1, pady=10)

        # Technical Information section
        tech_frame = ttk.LabelFrame(left_frame, text="Technical Information")
        tech_frame.pack(fill=tk.X, pady=5)
        
        # Configure grid columns for proper button visibility
        tech_frame.grid_columnconfigure(1, weight=1)  # Make entry column expandable
        
        # IP Address
        ttk.Label(tech_frame, text="IP Address:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.ip_var = tk.StringVar()
        ttk.Entry(tech_frame, textvariable=self.ip_var, width=20).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        ttk.Button(tech_frame, text="Search", width=8, command=self.search_ip_abuseipdb).grid(row=0, column=2, padx=2, pady=2)
        
        # File Hash
        ttk.Label(tech_frame, text="File Hash:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.file_hash_var = tk.StringVar()
        ttk.Entry(tech_frame, textvariable=self.file_hash_var, width=15).grid(row=1, column=1, sticky=tk.EW, padx=5, pady=2)
        ttk.Button(tech_frame, text="Scan", width=8, command=self.scan_hash_virustotal).grid(row=1, column=2, padx=2, pady=2)
        
        # URL section
        url_frame = ttk.LabelFrame(left_frame, text="URL")
        url_frame.pack(fill=tk.X, pady=5)
        
        # Configure grid columns for proper button visibility
        url_frame.grid_columnconfigure(1, weight=1)  # Make entry column expandable
        
        # URL field
        ttk.Label(url_frame, text="URL:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.url_var = tk.StringVar()
        ttk.Entry(url_frame, textvariable=self.url_var, width=20).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        ttk.Button(url_frame, text="Defang", width=8, command=self.defang_url).grid(row=0, column=2, padx=2, pady=2)
        
        # Outcome section (moved from right side)
        outcome_frame = ttk.LabelFrame(left_frame, text="Outcome")
        outcome_frame.pack(fill=tk.X, pady=5)
        
        # First dropdown - Classification
        ttk.Label(outcome_frame, text="Classification:").pack(anchor=tk.W, padx=5, pady=(5,0))
        self.classification_var = tk.StringVar()
        classification_combo = ttk.Combobox(outcome_frame, textvariable=self.classification_var, width=25, state='readonly')
        classification_combo['values'] = ('Benign', 'Suspicious', 'Malicious')
        classification_combo.pack(padx=5, pady=2)
        classification_combo.set('Benign')
        
        # Second dropdown - Type
        ttk.Label(outcome_frame, text="Type:").pack(anchor=tk.W, padx=5, pady=(5,0))
        self.outcome_type_var = tk.StringVar()
        outcome_type_combo = ttk.Combobox(outcome_frame, textvariable=self.outcome_type_var, width=25, state='readonly')
        outcome_type_combo['values'] = ('False-Positive', 'Blocked-True Positive', 'Malicious-True Positive', 'Benign-True Positive')
        outcome_type_combo.pack(padx=5, pady=2)
        outcome_type_combo.set('False-Positive')
        
        # Add button
        ttk.Button(outcome_frame, text="Add", width=10, command=self.add_outcome_to_notes).pack(pady=10)

        # Create a frame for the text action buttons to arrange them horizontally
        buttons_frame = ttk.Frame(left_frame)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        # Copy All button - centered with equal spacing
        ttk.Button(buttons_frame, text="Copy All", width=12, command=self.copy_all_text).pack(side=tk.LEFT, expand=True, padx=10)
        
        # Clear button - centered with equal spacing
        ttk.Button(buttons_frame, text="Clear", width=12, command=self.clear_all_text).pack(side=tk.LEFT, expand=True, padx=10)
        
        # Save Case button - full width underneath
        save_button = create_colored_button(left_frame, text="Save Case", command=self.save_case, width=25)
        save_button.pack(fill=tk.X, pady=(5, 10), padx=20)
        
        # Status bar - anchored to bottom (pack from bottom up)
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(left_frame, textvariable=self.status_var, anchor='center')
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(0, 10), padx=20)
        
        # Last Action title - anchored above status bar
        ttk.Label(left_frame, text="Last Action", font=('Segoe UI', 15, 'bold')).pack(side=tk.BOTTOM, pady=(0, 5))
        
        # Right column - Expandable to fill remaining space
        right_frame = ttk.Frame(content_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Notes section (now fills the entire right side)
        notes_frame = ttk.LabelFrame(right_frame, text="Case Notes")
        notes_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.notes_text = scrolledtext.ScrolledText(notes_frame, wrap=tk.WORD, width=190, height=15)
        self.notes_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def create_search_content(self, parent_frame):
        # Create the Search tab content for finding and managing saved cases.
        # Provides search controls, results table, and case detail view.
        # Main search frame container
        search_main_frame = ttk.Frame(parent_frame)
        search_main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Search controls section for input criteria
        search_controls_frame = ttk.LabelFrame(search_main_frame, text="Search Criteria")
        search_controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Configure grid columns for proper layout
        search_controls_frame.grid_columnconfigure(1, weight=1)
        search_controls_frame.grid_columnconfigure(3, weight=1)
        
        # Search term input field
        ttk.Label(search_controls_frame, text="Search Term:").grid(row=0, column=0, sticky=tk.W, padx=(10, 5), pady=5)
        self.search_term_var = tk.StringVar()
        search_entry = ttk.Entry(search_controls_frame, textvariable=self.search_term_var, width=30)
        search_entry.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
        
        # Search category dropdown
        ttk.Label(search_controls_frame, text="Search In:").grid(row=0, column=2, sticky=tk.W, padx=(20, 5), pady=5)
        self.search_category_var = tk.StringVar()
        search_category_combo = ttk.Combobox(search_controls_frame, textvariable=self.search_category_var, 
                                           width=15, state='readonly')
        search_category_combo['values'] = ('All Fields', 'Case ID', 'User', 'Email', 'Hostname', 
                                          'IP Address', 'File Hash', 'URL', 'Classification', 
                                          'Outcome Type', 'Notes')
        search_category_combo.grid(row=0, column=3, sticky=tk.EW, padx=5, pady=5)
        search_category_combo.set('All Fields')
        
        # Search buttons frame
        buttons_frame = ttk.Frame(search_controls_frame)
        buttons_frame.grid(row=1, column=0, columnspan=4, pady=10)
        
        # Search and Clear buttons
        search_button = create_colored_button(buttons_frame, text="Search Cases", command=self.perform_search)
        search_button.pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Clear Results", command=self.clear_search_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Load All Cases", command=self.load_all_cases).pack(side=tk.LEFT, padx=5)
        
        # Create a container for the two main sections to split space equally
        content_container = ttk.Frame(search_main_frame)
        content_container.pack(fill=tk.BOTH, expand=True)
        
        # Results frame - takes top half
        results_frame = ttk.LabelFrame(content_container, text="Search Results")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        # Create treeview for search results
        columns = ('Case ID', 'Date', 'User', 'Classification', 'Outcome', 'Notes Preview')
        self.search_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=10)
        
        # Configure column headings and widths
        self.search_tree.heading('Case ID', text='Case ID')
        self.search_tree.heading('Date', text='Date')
        self.search_tree.heading('User', text='User')
        self.search_tree.heading('Classification', text='Classification')
        self.search_tree.heading('Outcome', text='Outcome')
        self.search_tree.heading('Notes Preview', text='Notes Preview')

        # Set column widths
        self.search_tree.column('Case ID', width=150, minwidth=120)
        self.search_tree.column('Date', width=100, minwidth=80)
        self.search_tree.column('User', width=120, minwidth=100)
        self.search_tree.column('Classification', width=100, minwidth=80)
        self.search_tree.column('Outcome', width=120, minwidth=100)
        self.search_tree.column('Notes Preview', width=300, minwidth=200)
        
        # Add scrollbar for treeview
        tree_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.search_tree.yview)
        self.search_tree.configure(yscrollcommand=tree_scrollbar.set)
        
        # Pack treeview and scrollbar
        self.search_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=10)
        
        # Bind double-click to load case
        self.search_tree.bind('<Double-1>', self.load_selected_search_case)
        
        # Case details frame (shows details of selected case) - takes bottom half
        details_frame = ttk.LabelFrame(content_container, text="Case Details")
        details_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        # Text widget to show full case details
        self.search_details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, height=12)
        self.search_details_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 5))
        
        # Load button to transfer case to General tab
        load_button_frame = ttk.Frame(details_frame)
        load_button_frame.pack(fill=tk.X, pady=(0, 10))
        
        load_case_button = create_colored_button(load_button_frame, text="Load Case to General Tab", 
                                               command=self.load_case_to_general)
        load_case_button.pack(pady=5)

    def create_bulk_lookup_content(self, parent_frame):
        # Create the Bulk Lookup tab content for mass IP address scanning.
        # Allows users to paste multiple IP addresses and scan them against AbuseIPDB,
        # displaying results in an easy-to-read table format for copying to notes.
        # Main bulk lookup frame
        bulk_main_frame = ttk.Frame(parent_frame)
        bulk_main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Input section for IP addresses
        input_frame = ttk.LabelFrame(bulk_main_frame, text="IP Address Input")
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Instructions label
        instructions = ttk.Label(input_frame, 
                               text="Paste IP addresses below (one per line or separated by commas/spaces):",
                               font=('Segoe UI', 9))
        instructions.pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        # IP input text area
        self.bulk_ip_text = scrolledtext.ScrolledText(input_frame, height=8, width=70)
        self.bulk_ip_text.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Control buttons frame
        control_frame = ttk.Frame(input_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Scan button
        bulk_scan_button = create_colored_button(control_frame, text="Scan All IPs", 
                                               command=self.bulk_scan_ips)
        bulk_scan_button.pack(side=tk.LEFT, padx=(0, 5))
        
        # Clear input button
        ttk.Button(control_frame, text="Clear Input", 
                  command=self.clear_bulk_input).pack(side=tk.LEFT, padx=5)
        
        # Copy results button
        ttk.Button(control_frame, text="Copy Results", 
                  command=self.copy_bulk_results).pack(side=tk.LEFT, padx=5)
        
        # Insert into notes button  
        ttk.Button(control_frame, text="Insert into Notes", 
                  command=self.insert_bulk_results_into_notes).pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.bulk_progress = ttk.Progressbar(control_frame, mode='determinate')
        self.bulk_progress.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(20, 0))
        
        # Results section
        results_frame = ttk.LabelFrame(bulk_main_frame, text="Scan Results")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        # Create treeview for results display
        columns = ('IP Address', 'Reports', 'Confidence %', 'Country', 'ISP', 'Usage Type', 'Hostnames')
        self.bulk_results_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        # Configure column headings and widths
        self.bulk_results_tree.heading('IP Address', text='IP Address')
        self.bulk_results_tree.heading('Reports', text='Reports')
        self.bulk_results_tree.heading('Confidence %', text='Confidence %')
        self.bulk_results_tree.heading('Country', text='Country')
        self.bulk_results_tree.heading('ISP', text='ISP')
        self.bulk_results_tree.heading('Usage Type', text='Usage Type')
        self.bulk_results_tree.heading('Hostnames', text='Hostnames')

        # Set column widths
        self.bulk_results_tree.column('IP Address', width=120, minwidth=100)
        self.bulk_results_tree.column('Reports', width=80, minwidth=60)
        self.bulk_results_tree.column('Confidence %', width=100, minwidth=80)
        self.bulk_results_tree.column('Country', width=100, minwidth=80)
        self.bulk_results_tree.column('ISP', width=150, minwidth=120)
        self.bulk_results_tree.column('Usage Type', width=120, minwidth=100)
        self.bulk_results_tree.column('Hostnames', width=200, minwidth=150)
        
        # Add scrollbar for results treeview
        results_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.bulk_results_tree.yview)
        self.bulk_results_tree.configure(yscrollcommand=results_scrollbar.set)
        
        # Pack treeview and scrollbar
        self.bulk_results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=10)
        
        # Status label for bulk operations
        self.bulk_status_var = tk.StringVar()
        self.bulk_status_var.set("Ready for bulk IP scanning")
        bulk_status_label = ttk.Label(bulk_main_frame, textvariable=self.bulk_status_var,
                                     relief=tk.SUNKEN, anchor=tk.W)
        bulk_status_label.pack(side=tk.BOTTOM, fill=tk.X, pady=(5, 0))

    def create_settings_content(self, parent_frame):
        # Create the Settings tab content for application configuration.
        # Includes API credentials, appearance settings, data management options,
        # and import/export functionality. Uses scrollable frame for all options.
        # Main settings frame with scrollbar support
        settings_canvas = tk.Canvas(parent_frame)
        settings_scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=settings_canvas.yview)
        settings_scrollable_frame = ttk.Frame(settings_canvas)
        
        # Configure scrolling behavior
        settings_scrollable_frame.bind(
            "<Configure>",
            lambda e: settings_canvas.configure(scrollregion=settings_canvas.bbox("all"))
        )
        
        # Create scrollable window
        settings_canvas.create_window((0, 0), window=settings_scrollable_frame, anchor="nw")
        settings_canvas.configure(yscrollcommand=settings_scrollbar.set)
        
        # Pack canvas and scrollbar
        settings_canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        settings_scrollbar.pack(side="right", fill="y")
        
        # API Settings Section
        api_frame = ttk.LabelFrame(settings_scrollable_frame, text="API Settings")
        api_frame.pack(fill=tk.X, pady=(0, 15), padx=10)
        
        # Load current API credentials
        credentials = self.settings_manager.load_api_credentials()
        
        # AbuseIPDB API Key
        ttk.Label(api_frame, text="AbuseIPDB API Key:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.abuseipdb_key_var = tk.StringVar(value=credentials.get("abuseipdb_api_key", ""))
        abuseipdb_entry = ttk.Entry(api_frame, textvariable=self.abuseipdb_key_var, width=50, show="*")
        abuseipdb_entry.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
        ttk.Button(api_frame, text="Show", command=lambda: self.toggle_api_key_visibility(abuseipdb_entry)).grid(row=0, column=2, padx=5)
        
        # VirusTotal API Key
        ttk.Label(api_frame, text="VirusTotal API Key:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.virustotal_key_var = tk.StringVar(value=credentials.get("virustotal_api_key", ""))
        virustotal_entry = ttk.Entry(api_frame, textvariable=self.virustotal_key_var, width=50, show="*")
        virustotal_entry.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=5)
        ttk.Button(api_frame, text="Show", command=lambda: self.toggle_api_key_visibility(virustotal_entry)).grid(row=1, column=2, padx=5)
        
        # API Timeout
        ttk.Label(api_frame, text="Request Timeout (seconds):").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        self.api_timeout_var = tk.StringVar(value=str(self.settings_manager.get_setting("api_settings", "request_timeout")))
        timeout_spinbox = ttk.Spinbox(api_frame, from_=5, to=120, textvariable=self.api_timeout_var, width=10)
        timeout_spinbox.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Configure grid weights
        api_frame.grid_columnconfigure(1, weight=1)
        
        # Case Management Settings Section
        case_mgmt_frame = ttk.LabelFrame(settings_scrollable_frame, text="Case Management Settings")
        case_mgmt_frame.pack(fill=tk.X, pady=(0, 15), padx=10)
        
        # Case Retention Limit
        ttk.Label(case_mgmt_frame, text="Case Retention Limit:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.retention_limit_var = tk.StringVar(value=str(self.settings_manager.get_setting("case_management", "case_retention_limit")))
        retention_spinbox = ttk.Spinbox(case_mgmt_frame, from_=50, to=1000, increment=50, textvariable=self.retention_limit_var, width=10)
        retention_spinbox.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(case_mgmt_frame, text="cases before creating new file").grid(row=0, column=2, sticky=tk.W, padx=5)
        
        # Date/Time Format
        ttk.Label(case_mgmt_frame, text="Date/Time Format:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.date_format_var = tk.StringVar(value=self.settings_manager.get_setting("case_management", "date_format"))
        date_format_combo = ttk.Combobox(case_mgmt_frame, textvariable=self.date_format_var, state='readonly', width=25)
        date_format_combo['values'] = ('YYYY-MM-DD_HH:MM:SS', 'YYYYMMDD_HHMMSS', 'DD-MM-YYYY_HH:MM:SS', 'MM-DD-YYYY_HH:MM:SS')
        date_format_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Configure grid weights
        case_mgmt_frame.grid_columnconfigure(1, weight=1)
        
        # Data and Export Settings Section
        data_export_frame = ttk.LabelFrame(settings_scrollable_frame, text="Data and Export Settings")
        data_export_frame.pack(fill=tk.X, pady=(0, 15), padx=10)
        
        # Save Location
        ttk.Label(data_export_frame, text="Case Files Location:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.save_location_var = tk.StringVar(value=self.settings_manager.get_setting("data_export", "save_location"))
        location_entry = ttk.Entry(data_export_frame, textvariable=self.save_location_var, width=50)
        location_entry.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
        ttk.Button(data_export_frame, text="Browse", command=self.browse_save_location).grid(row=0, column=2, padx=5)
        
        # Export Format
        ttk.Label(data_export_frame, text="Export Format:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.export_format_var = tk.StringVar(value=self.settings_manager.get_setting("data_export", "export_format"))
        export_format_combo = ttk.Combobox(data_export_frame, textvariable=self.export_format_var, state='readonly', width=15)
        export_format_combo['values'] = ('JSON', 'CSV', 'XML')
        export_format_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Compression option
        self.compress_files_var = tk.BooleanVar(value=self.settings_manager.get_setting("data_export", "compress_old_files"))
        compress_check = ttk.Checkbutton(data_export_frame, text="Compress old case files", variable=self.compress_files_var)
        compress_check.grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)
        
        # Backup settings
        self.backup_enabled_var = tk.BooleanVar(value=self.settings_manager.get_setting("data_export", "backup_enabled"))
        backup_check = ttk.Checkbutton(data_export_frame, text="Enable automatic backups", variable=self.backup_enabled_var)
        backup_check.grid(row=3, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)
        
        # Backup location
        ttk.Label(data_export_frame, text="Backup Location:").grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)
        self.backup_location_var = tk.StringVar(value=self.settings_manager.get_setting("data_export", "backup_location"))
        backup_entry = ttk.Entry(data_export_frame, textvariable=self.backup_location_var, width=50)
        backup_entry.grid(row=4, column=1, sticky=tk.EW, padx=5, pady=5)
        ttk.Button(data_export_frame, text="Browse", command=self.browse_backup_location).grid(row=4, column=2, padx=5)
        
        # Configure grid weights
        data_export_frame.grid_columnconfigure(1, weight=1)
        
        # Appearance Settings Section
        appearance_frame = ttk.LabelFrame(settings_scrollable_frame, text="Appearance Settings")
        appearance_frame.pack(fill=tk.X, pady=(0, 15), padx=10)

        # Notes Text Font Family
        ttk.Label(appearance_frame, text="Notes Font Family:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.notes_font_family_var = tk.StringVar(value=self.settings_manager.get_setting("appearance", "notes_font_family"))
        notes_font_combo = ttk.Combobox(appearance_frame, textvariable=self.notes_font_family_var, state='readonly', width=20)
        notes_font_combo['values'] = ('Segoe UI', 'Arial', 'Calibri', 'Consolas', 'Courier New', 'Times New Roman', 'Helvetica')
        notes_font_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        # Notes Text Font Size
        ttk.Label(appearance_frame, text="Notes Font Size:").grid(row=0, column=2, sticky=tk.W, padx=(20, 5), pady=5)
        self.notes_font_size_var = tk.StringVar(value=str(self.settings_manager.get_setting("appearance", "notes_font_size")))
        notes_size_spinbox = ttk.Spinbox(appearance_frame, from_=8, to=20, textvariable=self.notes_font_size_var, width=8)
        notes_size_spinbox.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Note about font changes
        ttk.Label(appearance_frame, text="Note: Font changes will be applied when you save settings.").grid(row=1, column=0, columnspan=4, pady=5, padx=10, sticky=tk.W)
        
        # Configure grid weights
        appearance_frame.grid_columnconfigure(1, weight=1)
        appearance_frame.grid_columnconfigure(3, weight=1)
        
        # Settings Control Buttons
        buttons_frame = ttk.Frame(settings_scrollable_frame)
        buttons_frame.pack(fill=tk.X, pady=15, padx=10)
        
        # Save Settings button
        save_settings_button = create_colored_button(buttons_frame, text="Save Settings", 
                                                   command=self.save_all_settings)
        save_settings_button.pack(side=tk.LEFT, padx=5)
        
        # Reset to Defaults button
        reset_button = create_colored_button(buttons_frame, text="Reset to Defaults", 
                                          command=self.reset_settings_to_defaults)
        reset_button.pack(side=tk.LEFT, padx=5)
        
        # Export Settings button
        ttk.Button(buttons_frame, text="Export Settings", command=self.export_settings).pack(side=tk.LEFT, padx=5)
        
        # Import Settings button
        ttk.Button(buttons_frame, text="Import Settings", command=self.import_settings).pack(side=tk.LEFT, padx=5)

    def update_notes_header(self):
        # Update the case notes header with user information while preserving existing content.
        # Automatically formats and organizes user details at the top of the notes section.
        # Maintains consistent header structure across all cases.
        # Get current notes content without trailing newlines
        current_content = self.notes_text.get('1.0', tk.END).rstrip('\n')

        # Parse content to separate header information from investigation notes
        lines = current_content.split('\n')
        other_lines = []
        
        # Find where the header ends (look for lines that don't start with our fields)
        header_fields = ['User:', 'Email:', 'Role:', 'Hostname:']
        in_header = True
        
        for line in lines:
            if in_header and any(line.startswith(field) for field in header_fields):
                continue  # Skip existing header lines - we'll rebuild them
            elif in_header and line.strip() == '':
                continue  # Skip empty lines in header area
            else:
                in_header = False
                other_lines.append(line)
        
        # Build new header in consistent order, including any existing values
        new_header = []
        
        # Always check all fields and include them if they have values
        user = self.user_var.get().strip()
        if user:
            new_header.append(f"User: {user}")
        
        email = self.email_var.get().strip()
        if email:
            new_header.append(f"Email: {email}")
        
        role = self.role_var.get().strip()
        if role:
            new_header.append(f"Role: {role}")
        
        hostname = self.host_var.get().strip()
        if hostname:
            new_header.append(f"Hostname: {hostname}")
        
        # Combine header with remaining content
        if new_header:
            if other_lines and any(line.strip() for line in other_lines):  # If there's other content
                new_content = '\n'.join(new_header) + '\n\n' + '\n'.join(other_lines)
            else:
                new_content = '\n'.join(new_header)
        else:
            new_content = '\n'.join(other_lines) if other_lines else ''

        # Update the notes text
        self.notes_text.delete('1.0', tk.END)
        self.notes_text.insert('1.0', new_content)

    def on_field_change(self, *args):
        # Callback when any field changes - updates header automatically
        # This gets called when any traced variable changes
        # We don't need to do anything here since the add buttons handle updates
        pass

    def add_details_to_notes(self):
                # Add/update all detail information in the notes header
        self.update_notes_header()

        # Collect non-empty fields to provide status feedback
        added_fields = []
        if self.user_var.get().strip():
            added_fields.append(f"User '{self.user_var.get().strip()}'")
        if self.email_var.get().strip():
            added_fields.append(f"Email '{self.email_var.get().strip()}'")
        if self.role_var.get().strip():
            added_fields.append(f"Role '{self.role_var.get().strip()}'")
        if self.host_var.get().strip():
            added_fields.append(f"Hostname '{self.host_var.get().strip()}'")
        
        if added_fields:
            self.status_var.set(f"Added to notes: {', '.join(added_fields)}")
        else:
            self.status_var.set("All detail fields cleared from notes")

    def add_outcome_to_notes(self):
        # Add the selected outcome to the bottom of the notes text
        classification = self.classification_var.get()
        outcome_type = self.outcome_type_var.get()
        
        # Format the outcome as "Verdict: Classification, Type"
        outcome_text = f"\nVerdict: {classification}, {outcome_type}"
        
        # Get current text and add the outcome to the bottom on a new line
        current_text = self.notes_text.get('1.0', tk.END).rstrip('\n')
        if current_text:
            new_text = current_text + "\n" + outcome_text
        else:
            new_text = outcome_text

        # Update the text area
        self.notes_text.delete('1.0', tk.END)
        self.notes_text.insert('1.0', new_text)        # Update status
        self.status_var.set(f"Added verdict: {classification}, {outcome_type}")
    
    def defang_url(self):
        # Defang the URL to make it non-clickable and safe
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Please enter a URL to defang")
            return
        
        # Defang the URL by:
        # 1. Adding brackets around dots
        # 2. Replacing http/https with hXXp/hXXps
        # 3. Adding brackets around common TLDs
        defanged = url
        
        # Replace protocols
        defanged = defanged.replace('http://', 'hxxp://')
        defanged = defanged.replace('https://', 'hxxps://')
        defanged = defanged.replace('ftp://', 'fXp://')
        
        # Add brackets around dots
        defanged = defanged.replace('.', '[.]')
        
        # Update the field with the defanged URL
        self.url_var.set(defanged)

        # Add defanged URL to notes
        current_text = self.notes_text.get('1.0', tk.END).rstrip('\n')
        defanged_text = f"\n{defanged}"
        
        if current_text:
            new_text = current_text + defanged_text
        else:
            new_text = defanged_text.lstrip('\n')

        self.notes_text.delete('1.0', tk.END)
        self.notes_text.insert('1.0', new_text)

        # Update status
        self.status_var.set(f"URL defanged and added to notes")

    def scan_hash_virustotal(self):
        # Scan a file hash using VirusTotal API and add results to case notes.
        # Validates API key, makes the request, and formats the response for display.
        file_hash = self.file_hash_var.get().strip()
        if not file_hash:
            messagebox.showwarning("Warning", "Please enter a file hash to scan")
            return
        
        try:
            # Load encrypted API key from settings
            credentials = self.settings_manager.load_api_credentials()
            api_key = credentials.get("virustotal_api_key", "").strip()
            
            if not api_key:
                messagebox.showerror("Error", "VirusTotal API key not found. Please configure it in Settings.")
                return
            
            # Update status to show scanning progress
            self.status_var.set(f"Scanning hash with VirusTotal: {file_hash[:16]}...")
            self.root.update()
            
            # Make API request to VirusTotal v3 API
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            headers = {
                'x-apikey': api_key
            }
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                
                if 'data' in data:
                    file_data = data['data']['attributes']
                    
                    # Format the output
                    result_text = f"\n\nVirusTotal Scan Results for: {file_hash}\n"
                    
                    # Basic file information
                    result_text += f"File Type: {file_data.get('type_notes', 'Unknown')}\n"
                    result_text += f"File Size: {file_data.get('size', 'Unknown')} bytes\n"
                    result_text += f"MD5: {file_data.get('md5', 'N/A')}\n"
                    result_text += f"SHA1: {file_data.get('sha1', 'N/A')}\n"
                    result_text += f"SHA256: {file_data.get('sha256', 'N/A')}\n"
                    
                    # Scan statistics
                    stats = file_data.get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    undetected = stats.get('undetected', 0)
                    harmless = stats.get('harmless', 0)
                    total_scans = malicious + suspicious + undetected + harmless
                    
                    result_text += f"\nScan Results:\n"
                    result_text += f"Malicious: {malicious}/{total_scans}\n"
                    result_text += f"Suspicious: {suspicious}/{total_scans}\n"
                    result_text += f"Harmless: {harmless}/{total_scans}\n"
                    result_text += f"Undetected: {undetected}/{total_scans}\n"
                    
                    # Get detection names from top AV vendors
                    results = file_data.get('last_analysis_results', {})
                    detections = []
                    for engine, result in results.items():
                        if result.get('category') == 'malicious':
                            detection = result.get('result', 'Malware')
                            detections.append(f"{engine}: {detection}")
                    
                    if detections:
                        result_text += f"\nTop Detections:\n"
                        # Show first 5 detections to avoid too much text
                        for detection in detections[:5]:
                            result_text += f"- {detection}\n"
                        if len(detections) > 5:
                            result_text += f"... and {len(detections) - 5} more detections\n"
                    
                    # Names if available
                    names = file_data.get('names', [])
                    if names:
                        result_text += f"\nKnown Filenames:\n"
                        for name in names[:3]:  # Show first 3 names
                            result_text += f"- {name}\n"
                        if len(names) > 3:
                            result_text += f"... and {len(names) - 3} more names\n"

                    # Add to notes
                    current_text = self.notes_text.get('1.0', tk.END).rstrip('\n')
                    if current_text:
                        new_text = current_text + result_text
                    else:
                        new_text = result_text.rstrip('\n')

                    self.notes_text.delete('1.0', tk.END)
                    self.notes_text.insert('1.0', new_text)

                    self.status_var.set(f"VirusTotal scan completed - {malicious}/{total_scans} detections")
                    
                else:
                    messagebox.showerror("Error", "Invalid response from VirusTotal API")
                    self.status_var.set("VirusTotal scan failed")
                    
            elif response.status_code == 404:
                # Hash not found in VirusTotal database
                result_text = f"\n\nVirusTotal Scan Results for: {file_hash}\n"
                result_text += "Status: File not found in VirusTotal database\n"
                result_text += "This hash has not been previously submitted to VirusTotal\n"

                current_text = self.notes_text.get('1.0', tk.END).rstrip('\n')
                if current_text:
                    new_text = current_text + result_text
                else:
                    new_text = result_text.rstrip('\n')

                self.notes_text.delete('1.0', tk.END)
                self.notes_text.insert('1.0', new_text)

                self.status_var.set("Hash not found in VirusTotal database")
                
            else:
                messagebox.showerror("Error", f"VirusTotal API error: {response.status_code}")
                self.status_var.set("VirusTotal scan failed")
                
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Network error: {str(e)}")
            self.status_var.set("VirusTotal scan failed - network error")
        except Exception as e:
            messagebox.showerror("Error", f"Error scanning with VirusTotal: {str(e)}")
            self.status_var.set("VirusTotal scan failed")
    
    def load_existing_cases(self):
        # Load existing cases on startup
        try:
            cases = self.case_manager.get_all_cases()
            self.status_var.set(f"Loaded {len(cases)} existing cases")
        except Exception as e:
            self.status_var.set("Ready - No existing cases")
    
    def search_ip_abuseipdb(self):
        # Search an IP address using AbuseIPDB API and add threat intelligence to notes.
        # Provides abuse confidence percentage, ISP information, and hostname details.
        ip_address = self.ip_var.get().strip()
        if not ip_address:
            messagebox.showwarning("Warning", "Please enter an IP address to search")
            return
        
        try:
            # Load encrypted API key from settings
            credentials = self.settings_manager.load_api_credentials()
            api_key = credentials.get("abuseipdb_api_key", "").strip()
            
            if not api_key:
                messagebox.showerror("Error", "AbuseIPDB API key not found. Please configure it in Settings.")
                return
            
            # Update status to show search progress
            self.status_var.set(f"Searching AbuseIPDB for {ip_address}...")
            self.root.update()
            
            # Make API request to AbuseIPDB
            url = 'https://api.abuseipdb.com/api/v2/check'
            querystring = {
                'ipAddress': ip_address,
                'maxAgeInDays': '90',
                'verbose': ''
            }
            headers = {
                'Accept': 'application/json',
                'Key': api_key
            }
            
            response = requests.get(url, headers=headers, params=querystring)
            response.raise_for_status()
            
            data = response.json()
            
            if 'data' in data:
                ip_data = data['data']
                
                # Format the output as requested
                result_text = f"\n\n{ip_address}\n"
                result_text += f"This IP was reported {ip_data.get('totalReports', 0)} times.\n"
                result_text += f"Confidence of Abuse is {ip_data.get('abuseConfidencePercentage', 0)}%\n\n"
                result_text += f"ISP: {ip_data.get('isp', 'Unknown')}\n"
                result_text += f"Usage Type: {ip_data.get('usageType', 'Unknown')}\n"
                result_text += f"ASN: {ip_data.get('asn', 'Unknown')}\n"
                
                # Handle multiple hostnames
                hostnames = ip_data.get('hostnames', [])
                if hostnames:
                    result_text += f"Hostname(s): {', '.join(hostnames)}\n"
                else:
                    result_text += "Hostname(s): None\n"
                
                result_text += f"Domain Name: {ip_data.get('domain', 'Unknown')}\n"
                
                # Format country without flag
                country_code = ip_data.get('countryCode', '')
                country_name = ip_data.get('countryName', 'Unknown')
                result_text += f"Country: {country_name}"
                
                # Add to notes
                current_text = self.notes_text.get('1.0', tk.END).rstrip('\n')
                if current_text:
                    new_text = current_text + result_text
                else:
                    new_text = result_text.rstrip('\n')

                self.notes_text.delete('1.0', tk.END)
                self.notes_text.insert('1.0', new_text)

                self.status_var.set(f"AbuseIPDB search completed for {ip_address}")
                
            else:
                messagebox.showerror("Error", "Invalid response from AbuseIPDB API")
                self.status_var.set("AbuseIPDB search failed")
                
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Network error: {str(e)}")
            self.status_var.set("AbuseIPDB search failed - network error")
        except Exception as e:
            messagebox.showerror("Error", f"Error searching AbuseIPDB: {str(e)}")
            self.status_var.set("AbuseIPDB search failed")
    
    def bulk_scan_ips(self):
        # Scan multiple IP addresses against AbuseIPDB and display results in a table.
        # Parses input text for IP addresses and performs batch scanning with progress indication.
        # Get the input text and parse IP addresses
        input_text = self.bulk_ip_text.get('1.0', tk.END).strip()
        if not input_text:
            messagebox.showwarning("Warning", "Please enter IP addresses to scan")
            return
        
        # Parse IP addresses from input (supports multiple formats)
        ip_addresses = self.parse_ip_addresses(input_text)
        if not ip_addresses:
            messagebox.showwarning("Warning", "No valid IP addresses found in input")
            return
        
        # Check for API key
        credentials = self.settings_manager.load_api_credentials()
        api_key = credentials.get("abuseipdb_api_key", "").strip()
        
        if not api_key:
            messagebox.showerror("Error", "AbuseIPDB API key not found. Please configure it in Settings.")
            return
        
        # Clear previous results
        for item in self.bulk_results_tree.get_children():
            self.bulk_results_tree.delete(item)
        
        # Initialize progress bar
        self.bulk_progress['maximum'] = len(ip_addresses)
        self.bulk_progress['value'] = 0
        
        # Update status
        self.bulk_status_var.set(f"Scanning {len(ip_addresses)} IP addresses...")
        self.root.update()
        
        # Scan each IP address
        successful_scans = 0
        failed_scans = 0
        
        for i, ip_address in enumerate(ip_addresses):
            try:
                # Update progress
                self.bulk_progress['value'] = i + 1
                self.bulk_status_var.set(f"Scanning {ip_address} ({i+1}/{len(ip_addresses)})...")
                self.root.update()
                
                # Perform the API call
                result = self.scan_single_ip(ip_address, api_key)
                
                if result:
                    # Add result to tree
                    self.bulk_results_tree.insert('', tk.END, values=result)
                    successful_scans += 1
                else:
                    # Add error entry
                    self.bulk_results_tree.insert('', tk.END, values=(
                        ip_address, 'Error', 'N/A', 'N/A', 'Failed to scan', 'N/A', 'N/A'
                    ))
                    failed_scans += 1
                
                # Small delay to respect rate limits
                import time
                time.sleep(1)  # 1 second delay between requests
                
            except Exception as e:
                # Add error entry for failed scan
                self.bulk_results_tree.insert('', tk.END, values=(
                    ip_address, 'Error', 'N/A', 'N/A', f'Error: {str(e)[:30]}...', 'N/A', 'N/A'
                ))
                failed_scans += 1
        
        # Update final status
        self.bulk_status_var.set(f"Scan complete: {successful_scans} successful, {failed_scans} failed")
        
        # Reset progress bar
        self.bulk_progress['value'] = 0
    
    def parse_ip_addresses(self, text):
        # Parse IP addresses from input text supporting multiple formats.
        import re
        
        # IP address regex pattern
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        # Find all potential IP addresses
        potential_ips = re.findall(ip_pattern, text)
        
        # Validate and deduplicate IP addresses
        valid_ips = []
        seen_ips = set()
        
        for ip in potential_ips:
            # Basic validation (check if octets are <= 255)
            try:
                octets = ip.split('.')
                if all(0 <= int(octet) <= 255 for octet in octets):
                    if ip not in seen_ips:
                        valid_ips.append(ip)
                        seen_ips.add(ip)
            except ValueError:
                continue  # Skip invalid IPs
        
        return valid_ips
    
    def scan_single_ip(self, ip_address, api_key):
        # Scan a single IP address against AbuseIPDB API.
        try:
            # Make API request to AbuseIPDB
            url = 'https://api.abuseipdb.com/api/v2/check'
            querystring = {
                'ipAddress': ip_address,
                'maxAgeInDays': '90',
                'verbose': ''
            }
            headers = {
                'Accept': 'application/json',
                'Key': api_key
            }
            
            response = requests.get(url, headers=headers, params=querystring, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if 'data' in data:
                ip_data = data['data']
                
                # Extract relevant information
                reports = ip_data.get('totalReports', 0)
                confidence = ip_data.get('abuseConfidencePercentage', 0)
                country = ip_data.get('countryCode', 'Unknown')
                isp = ip_data.get('isp', 'Unknown')
                usage_type = ip_data.get('usageType', 'Unknown')
                
                # Handle multiple hostnames
                hostnames = ip_data.get('hostnames', [])
                hostname_str = ', '.join(hostnames[:2])  # Show first 2 hostnames
                if len(hostnames) > 2:
                    hostname_str += f' (+{len(hostnames)-2} more)'
                if not hostname_str:
                    hostname_str = 'None'
                
                return (ip_address, str(reports), f"{confidence}%", country, 
                       isp[:30] + '...' if len(isp) > 30 else isp, 
                       usage_type, hostname_str)
            
            return None
            
        except Exception as e:
            print(f"Error scanning {ip_address}: {e}")
            return None
    
    def clear_bulk_input(self):
        # Clear the bulk IP input text area
        self.bulk_ip_text.delete('1.0', tk.END)
        self.bulk_status_var.set("Input cleared - ready for new IP addresses")
    
    def copy_bulk_results(self):
        # Copy bulk scan results to clipboard in a formatted table
        # Check if there are results to copy
        if not self.bulk_results_tree.get_children():
            messagebox.showwarning("Warning", "No results to copy")
            return
        
        # Prepare formatted results
        results_text = []
        
        # Add header
        header = f"{'IP Address':<15} {'Reports':<8} {'Confidence':<12} {'Country':<15} {'ISP':<20} {'Usage Type':<15}"
        results_text.append(header)
        results_text.append("-" * 80)
        
        # Add each result
        for item in self.bulk_results_tree.get_children():
            values = self.bulk_results_tree.item(item)['values']
            ip, reports, confidence, country, isp, usage_type, hostnames = values
            
            # Format row
            row = f"{ip:<15} {reports:<8} {confidence:<12} {country:<15} {isp[:18]:<20} {usage_type:<15}"
            results_text.append(row)
            
            # Add hostnames if available and not 'None'
            if hostnames and hostnames != 'None':
                results_text.append(f"{'':>16} Hostnames: {hostnames}")
        
        results_text.append("")
        results_text.append(f"Scan completed with {len(self.bulk_results_tree.get_children())} results")
        
        # Copy to clipboard
        formatted_results = '\n'.join(results_text)
        self.root.clipboard_clear()
        self.root.clipboard_append(formatted_results)
        self.root.update()
        
        # Update status
        self.bulk_status_var.set(f"Copied {len(self.bulk_results_tree.get_children())} results to clipboard")
        messagebox.showinfo("Copy Complete", "Bulk scan results copied to clipboard.\nYou can now paste them into the notes section.")

    def insert_bulk_results_into_notes(self):
        # Insert bulk scan results directly into the notes section.
        # Uses the same format as the "Copy Results" button.
        # Check if there are results to insert
        if not self.bulk_results_tree.get_children():
            messagebox.showwarning("Warning", "No results to insert")
            return
        
        # Prepare formatted results (same format as copy_bulk_results)
        results_text = []
        
        # Add header
        header = f"{'IP Address':<15} {'Reports':<8} {'Confidence':<12} {'Country':<15} {'ISP':<20} {'Usage Type':<15}"
        results_text.append(header)
        results_text.append("-" * 80)
        
        # Add each result
        for item in self.bulk_results_tree.get_children():
            values = self.bulk_results_tree.item(item)['values']
            ip, reports, confidence, country, isp, usage_type, hostnames = values
            
            # Format row
            row = f"{ip:<15} {reports:<8} {confidence:<12} {country:<15} {isp[:18]:<20} {usage_type:<15}"
            results_text.append(row)
            
            # Add hostnames if available and not 'None'
            if hostnames and hostnames != 'None':
                results_text.append(f"{'':>16} Hostnames: {hostnames}")
        
        results_text.append("")
        results_text.append(f"Scan completed with {len(self.bulk_results_tree.get_children())} results")
        
        # Insert into notes text area
        formatted_results = '\n'.join(results_text)
        
        # Get current notes content and add the results at the bottom
        current_text = self.notes_text.get('1.0', tk.END).rstrip('\n')
        if current_text:
            new_text = current_text + '\n\n' + formatted_results
        else:
            new_text = formatted_results

        self.notes_text.delete('1.0', tk.END)
        self.notes_text.insert('1.0', new_text)
        
        # Update status
        total_results = len(self.bulk_results_tree.get_children())
        self.bulk_status_var.set(f"Inserted {total_results} results into notes")
        messagebox.showinfo("Insert Complete", f"Bulk scan results inserted into notes section.\n{total_results} results added.")

    def toggle_api_key_visibility(self, entry_widget):
        # Toggle the visibility of API key in entry widget
        if entry_widget['show'] == '*':
            entry_widget['show'] = ''
        else:
            entry_widget['show'] = '*'
    
    def browse_save_location(self):
        # Browse for case files save location
        directory = filedialog.askdirectory(
            title="Select Case Files Directory",
            initialdir=self.save_location_var.get()
        )
        if directory:
            self.save_location_var.set(directory)
    
    def browse_backup_location(self):
        # Browse for backup location
        directory = filedialog.askdirectory(
            title="Select Backup Directory",
            initialdir=self.backup_location_var.get() or os.path.expanduser("~")
        )
        if directory:
            self.backup_location_var.set(directory)
    
    def save_all_settings(self):
        # Save all settings to files
        try:
            # Save API credentials
            credentials = {
                "abuseipdb_api_key": self.abuseipdb_key_var.get().strip(),
                "virustotal_api_key": self.virustotal_key_var.get().strip()
            }
            self.settings_manager.save_api_credentials(credentials)
            
            # Save application settings
            self.settings_manager.set_setting("api_settings", "request_timeout", int(self.api_timeout_var.get()))
            self.settings_manager.set_setting("case_management", "case_retention_limit", int(self.retention_limit_var.get()))
            self.settings_manager.set_setting("case_management", "date_format", self.date_format_var.get())
            
            self.settings_manager.set_setting("data_export", "save_location", self.save_location_var.get())
            self.settings_manager.set_setting("data_export", "export_format", self.export_format_var.get())
            self.settings_manager.set_setting("data_export", "compress_old_files", self.compress_files_var.get())
            self.settings_manager.set_setting("data_export", "backup_enabled", self.backup_enabled_var.get())
            self.settings_manager.set_setting("data_export", "backup_location", self.backup_location_var.get())
            
            # Save appearance settings
            self.settings_manager.set_setting("appearance", "notes_font_family", self.notes_font_family_var.get())
            self.settings_manager.set_setting("appearance", "notes_font_size", int(self.notes_font_size_var.get()))

            # Save settings to file
            if self.settings_manager.save_settings():
                # Reinitialize case manager with new data directory
                self.reinitialize_case_manager()
                
                # Apply font changes after successful save
                self.apply_font_settings()
                self.status_var.set("Settings saved successfully")
            else:
                self.status_var.set("Failed to save settings")
                
        except ValueError as e:
            self.status_var.set(f"Invalid input - please check your values: {str(e)}")
        except Exception as e:
            self.status_var.set(f"Error saving settings: {str(e)}")
    
    def reset_settings_to_defaults(self):
        # Reset all settings to defaults
        result = messagebox.askyesno("Reset Settings", 
                                   "Are you sure you want to reset all settings to defaults?\n\n"
                                   "This will not affect your saved API keys.")
        if result:
            # Reset to defaults (but keep API keys)
            self.settings_manager.settings = self.settings_manager.default_settings.copy()
            self.settings_manager.save_settings()
            
            # Update UI with default values
            self.api_timeout_var.set(str(self.settings_manager.get_setting("api_settings", "request_timeout")))
            self.retention_limit_var.set(str(self.settings_manager.get_setting("case_management", "case_retention_limit")))
            self.date_format_var.set(self.settings_manager.get_setting("case_management", "date_format"))
            self.save_location_var.set(self.settings_manager.get_setting("data_export", "save_location"))
            self.export_format_var.set(self.settings_manager.get_setting("data_export", "export_format"))
            self.compress_files_var.set(self.settings_manager.get_setting("data_export", "compress_old_files"))
            self.backup_enabled_var.set(self.settings_manager.get_setting("data_export", "backup_enabled"))
            self.backup_location_var.set(self.settings_manager.get_setting("data_export", "backup_location"))
            
            # Update appearance settings
            self.notes_font_family_var.set(self.settings_manager.get_setting("appearance", "notes_font_family"))
            self.notes_font_size_var.set(str(self.settings_manager.get_setting("appearance", "notes_font_size")))

            self.status_var.set("Settings reset to defaults")
    
    def export_settings(self):
        # Export settings to a file
        file_path = filedialog.asksaveasfilename(
            title="Export Settings",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            if self.settings_manager.export_settings(file_path):
                self.status_var.set(f"Settings exported to: {file_path}")
            else:
                self.status_var.set("Failed to export settings")
    
    def import_settings(self):
        # Import settings from a file
        file_path = filedialog.askopenfilename(
            title="Import Settings",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            result = messagebox.askyesno("Import Settings", 
                                       "Importing settings will overwrite your current settings.\n"
                                       "API keys will not be affected.\n\n"
                                       "Do you want to continue?")
            if result:
                if self.settings_manager.import_settings(file_path):
                    self.status_var.set("Settings imported successfully - restart application for full effect")
                else:
                    self.status_var.set("Failed to import settings")
    
    def copy_all_text(self):
        # Copy all text from the notes text area to the clipboard
        text_content = self.notes_text.get('1.0', tk.END).strip()
        if not text_content:
            self.status_var.set("No text to copy - text area is empty")
            return
        
        # Copy to clipboard
        self.root.clipboard_clear()
        self.root.clipboard_append(text_content)
        self.root.update()  # Ensure clipboard is updated
        
        # Update status
        char_count = len(text_content)
        self.status_var.set(f"Copied {char_count} characters to clipboard")
    
    def clear_all_text(self):
        # Clear all text from the notes text area and all input fields with confirmation
        text_content = self.notes_text.get('1.0', tk.END).strip()
        
        # Check if any input fields have content
        has_field_content = any([
            self.user_var.get().strip(),
            self.role_var.get().strip(),
            self.email_var.get().strip(),
            self.host_var.get().strip(),
            self.ip_var.get().strip(),
            self.file_hash_var.get().strip(),
            self.url_var.get().strip()
        ])
        
        # Check if notes or fields have content
        if not text_content and not has_field_content:
            self.status_var.set("All fields are already empty")
            return
        
        # Ask for confirmation
        result = messagebox.askyesno("Clear All Fields", 
                                   "Are you sure you want to clear all fields and notes?\n\n"
                                   "This will clear:\n"
                                   "• All input fields (User, Email, Role, Hostname, IP, File Hash, URL)\n"
                                   "• Classification and Outcome settings\n"
                                   "• Notes text area\n\n"
                                   "This action cannot be undone.")
        
        if result:
            # Clear all input fields
            self.user_var.set("")
            self.role_var.set("")
            self.email_var.set("")
            self.host_var.set("")
            self.ip_var.set("")
            self.file_hash_var.set("")
            self.url_var.set("")
            
            # Reset classification and outcome to defaults
            self.classification_var.set("Benign")
            self.outcome_type_var.set("False-Positive")
            
            # Clear notes text area
            self.notes_text.delete('1.0', tk.END)
            
            # Clear the current case ID to ensure we create a new case when saving
            self.current_case_id = None
            
            self.status_var.set("All fields and notes cleared")
        else:
            self.status_var.set("Clear operation cancelled")
    
    def save_case(self):
        # Save the current case information to JSON files in the configured data directory.
        # If a case ID is already set (from loading an existing case), update that case.
        # Otherwise, create a new case with a unique timestamp-based ID.
        try:
            timestamp = datetime.now()
            
            # Check if we're updating an existing case or creating a new one
            if hasattr(self, 'current_case_id') and self.current_case_id:
                # We're updating an existing case
                case_id = self.current_case_id
                is_update = True
                
                # Get the original case to preserve created_at timestamp
                original_case = self.case_manager.get_case(case_id)
                if original_case:
                    created_at = original_case.created_at
                else:
                    # Fallback if original case not found
                    created_at = timestamp.isoformat()
            else:
                # We're creating a new case
                date_format = self.settings_manager.get_case_id_format()
                case_id = f"SOC-{timestamp.strftime(date_format)}"
                created_at = timestamp.isoformat()
                is_update = False
            
            # Collect all case data into structured format compatible with Case class
            case_data = {
                "case_id": case_id,
                "title": "",  # Add title field for Case class compatibility
                "description": self.notes_text.get('1.0', tk.END).rstrip('\n'),  # Use notes as description
                "user": self.user_var.get().strip(),
                "role": self.role_var.get().strip(),
                "email": self.email_var.get().strip(),
                "host": self.host_var.get().strip(),  # Changed from hostname to host
                "ip_address": self.ip_var.get().strip(),
                "file_hash": self.file_hash_var.get().strip(),
                "outcome": f"{self.classification_var.get()}, {self.outcome_type_var.get()}",  # Combine classification and type
                "status": "completed",
                "created_at": created_at,  # Preserve original creation time for updates
                "updated_at": timestamp.isoformat(),  # Always update the modification time
                # Keep legacy fields for backward compatibility
                "timestamp": timestamp.isoformat(),
                "created_date": timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "details": {
                    "user": self.user_var.get().strip(),
                    "role": self.role_var.get().strip(),
                    "email": self.email_var.get().strip(),
                    "hostname": self.host_var.get().strip(),
                    "ip_address": self.ip_var.get().strip(),
                    "file_hash": self.file_hash_var.get().strip(),
                    "url": self.url_var.get().strip()
                },
                "outcome_details": {
                    "classification": self.classification_var.get(),
                    "outcome_type": self.outcome_type_var.get()
                },
                "notes": self.notes_text.get('1.0', tk.END).rstrip('\n')
            }
            
            # Determine data folder path from settings
            data_folder = self.settings_manager.get_data_directory()
            
            # Create individual case file
            case_filename = f"{case_id}.json"
            case_filepath = os.path.join(data_folder, case_filename)
            
            # Save individual case file
            with open(case_filepath, 'w', encoding='utf-8') as f:
                json.dump(case_data, f, indent=2, ensure_ascii=False)
            
            # Also update the main cases.json file for compatibility
            cases_filepath = os.path.join(data_folder, 'cases.json')
            
            # Read existing cases
            if os.path.exists(cases_filepath):
                with open(cases_filepath, 'r', encoding='utf-8') as f:
                    try:
                        all_cases = json.load(f)
                    except json.JSONDecodeError:
                        all_cases = []
            else:
                all_cases = []
            
            if is_update:
                # Find and update the existing case
                case_updated = False
                for i, existing_case in enumerate(all_cases):
                    if existing_case.get('case_id') == case_id:
                        all_cases[i] = case_data
                        case_updated = True
                        break
                
                # If case wasn't found in the list, add it (shouldn't happen but good fallback)
                if not case_updated:
                    all_cases.append(case_data)
            else:
                # Add new case to the list
                all_cases.append(case_data)
            
            # Save updated cases list
            with open(cases_filepath, 'w', encoding='utf-8') as f:
                json.dump(all_cases, f, indent=2, ensure_ascii=False)
            
            # Update the case manager's in-memory cache
            if is_update:
                # Use the case manager to update the case
                case_obj = Case.from_dict(case_data)
                self.case_manager.save_case(case_obj)
            else:
                # Reload cases to include the new case
                self.case_manager.load_cases()
            
            # Update status and show confirmation
            action = "updated" if is_update else "saved"
            self.status_var.set(f"Case {action} successfully: {case_id}")
            
            # Show success message with file location
            messagebox.showinfo("Case Saved", 
                              f"Case {action} successfully!\n\n"
                              f"Case ID: {case_id}\n"
                              f"File: {case_filename}\n"
                              f"Location: {data_folder}\n"
                              f"Action: {'Updated existing case' if is_update else 'Created new case'}")
            
        except Exception as e:
            # Handle any errors during save
            error_msg = f"Error saving case: {str(e)}"
            self.status_var.set("Failed to save case")
            messagebox.showerror("Save Error", error_msg)
            
            # Update status and show confirmation
            self.status_var.set(f"Case saved successfully: {case_id}")
            
            # Show success message with file location
            messagebox.showinfo("Case Saved", 
                              f"Case saved successfully!\n\n"
                              f"Case ID: {case_id}\n"
                              f"File: {case_filename}\n"
                              f"Location: {data_folder}")
            
        except Exception as e:
            # Handle any errors during save
            error_msg = f"Error saving case: {str(e)}"
            self.status_var.set("Failed to save case")
            messagebox.showerror("Save Error", error_msg)
    
    def perform_search(self):
        # Search through saved cases based on user input criteria.
        # Supports searching in specific fields or across all fields.
        # Displays results in a sortable table format.
        search_term = self.search_term_var.get().strip().lower()
        search_category = self.search_category_var.get()
        
        # Validate search input
        if not search_term and search_category == 'All Fields':
            messagebox.showwarning("Search", "Please enter a search term")
            return
        
        try:
            # Use CaseManager to get cases
            all_cases = self.case_manager.get_all_cases()
            
            if not all_cases:
                messagebox.showinfo("Search", "No saved cases found")
                return
            
            # Clear previous results
            self.clear_search_results()
            
            # Filter cases based on search criteria
            matching_cases = []
            for case in all_cases:
                if self.case_matches_search_obj(case, search_term, search_category):
                    matching_cases.append(case)
            
            # Populate treeview with results
            for case in matching_cases:
                # Format the data for display
                case_id = case.case_id or 'N/A'
                date = case.created_at[:10] if case.created_at else 'N/A'  # Just date part
                user = case.user or 'N/A'
                
                # Parse classification and outcome from combined outcome field
                outcome_parts = case.outcome.split(',') if case.outcome else ['N/A', 'N/A']
                classification = outcome_parts[0].strip() if len(outcome_parts) > 0 else 'N/A'
                outcome_type = outcome_parts[1].strip() if len(outcome_parts) > 1 else 'N/A'
                
                notes = case.notes or ''

                # Truncate notes for preview
                notes_preview = notes[:100] + "..." if len(notes) > 100 else notes
                notes_preview = notes_preview.replace('\n', ' ')  # Remove newlines for table display

                # Insert into treeview
                self.search_tree.insert('', tk.END, values=(
                    case_id, date, user, classification, outcome_type, notes_preview
                ), tags=(case_id,))  # Store case_id as tag for later retrieval
            
            # Update status
            count = len(matching_cases)
            self.status_var.set(f"Found {count} matching case{'s' if count != 1 else ''}")
            
            if count == 0:
                messagebox.showinfo("Search Results", "No cases found matching your search criteria")
            
        except Exception as e:
            messagebox.showerror("Search Error", f"Error searching cases: {str(e)}")
            self.status_var.set("Search failed")
    
    def case_matches_search_obj(self, case_obj, search_term, search_category):
        # Check if a Case object matches the search criteria
        if not search_term:  # If no search term, match all
            return True
        
        search_term = search_term.lower()
        
        if search_category == 'All Fields':
            # Search in all text fields of the Case object
            searchable_text = ' '.join([
                case_obj.case_id or '',
                case_obj.user or '',
                case_obj.email or '',
                case_obj.role or '',
                case_obj.host or '',
                case_obj.ip_address or '',
                case_obj.file_hash or '',
                case_obj.outcome or '',
                case_obj.notes or ''
            ]).lower()
            return search_term in searchable_text
        
        # Search in specific field
        field_mapping = {
            'Case ID': case_obj.case_id or '',
            'User': case_obj.user or '',
            'Email': case_obj.email or '',
            'Hostname': case_obj.host or '',
            'IP Address': case_obj.ip_address or '',
            'File Hash': case_obj.file_hash or '',
            'URL': '',  # URL not stored in Case object currently
            'Classification': case_obj.outcome.split(',')[0].strip() if case_obj.outcome else '',
            'Outcome Type': case_obj.outcome.split(',')[1].strip() if case_obj.outcome and ',' in case_obj.outcome else '',
            'Notes': case_obj.notes or ''
        }
        
        field_value = field_mapping.get(search_category, '').lower()
        return search_term in field_value

    def case_matches_search(self, case, search_term, search_category):
                # Check if a case matches the search criteria
        if not search_term:  # If no search term, match all
            return True
        
        search_term = search_term.lower()
        
        if search_category == 'All Fields':
            # Search in all text fields
            searchable_text = ' '.join([
                case.get('case_id', ''),
                case.get('details', {}).get('user', ''),
                case.get('details', {}).get('email', ''),
                case.get('details', {}).get('role', ''),
                case.get('details', {}).get('hostname', ''),
                case.get('details', {}).get('ip_address', ''),
                case.get('details', {}).get('file_hash', ''),
                case.get('details', {}).get('url', ''),
                case.get('outcome', {}).get('classification', ''),
                case.get('outcome', {}).get('outcome_type', ''),
                case.get('notes', '')
            ]).lower()
            return search_term in searchable_text
        
        # Search in specific field
        field_mapping = {
            'Case ID': case.get('case_id', ''),
            'User': case.get('details', {}).get('user', ''),
            'Email': case.get('details', {}).get('email', ''),
            'Hostname': case.get('details', {}).get('hostname', ''),
            'IP Address': case.get('details', {}).get('ip_address', ''),
            'File Hash': case.get('details', {}).get('file_hash', ''),
            'URL': case.get('details', {}).get('url', ''),
            'Classification': case.get('outcome', {}).get('classification', ''),
            'Outcome Type': case.get('outcome', {}).get('outcome_type', ''),
            'Notes': case.get('notes', '')
        }
        
        field_value = field_mapping.get(search_category, '').lower()
        return search_term in field_value
    
    def clear_search_results(self):
                # Clear search results and details
        for item in self.search_tree.get_children():
            self.search_tree.delete(item)
        self.search_details_text.delete('1.0', tk.END)
        self.status_var.set("Search results cleared")
    
    def load_all_cases(self):
        # Load and display all saved cases using CaseManager
        try:
            # Use CaseManager to get all cases
            all_cases = self.case_manager.get_all_cases()
            
            if not all_cases:
                messagebox.showinfo("Load Cases", "No saved cases found")
                return
            
            # Clear previous results
            self.clear_search_results()
            
            # Populate treeview with all cases
            for case in all_cases:
                case_id = case.case_id or 'N/A'
                date = case.created_at[:10] if case.created_at else 'N/A'
                user = case.user or 'N/A'
                
                # Parse classification and outcome from combined outcome field
                outcome_parts = case.outcome.split(',') if case.outcome else ['N/A', 'N/A']
                classification = outcome_parts[0].strip() if len(outcome_parts) > 0 else 'N/A'
                outcome_type = outcome_parts[1].strip() if len(outcome_parts) > 1 else 'N/A'
                
                notes = case.notes or ''

                notes_preview = notes[:100] + "..." if len(notes) > 100 else notes
                notes_preview = notes_preview.replace('\n', ' ')

                self.search_tree.insert('', tk.END, values=(
                    case_id, date, user, classification, outcome_type, notes_preview
                ), tags=(case_id,))
            
            count = len(all_cases)
            self.status_var.set(f"Loaded {count} case{'s' if count != 1 else ''}")
            
        except Exception as e:
            messagebox.showerror("Load Error", f"Error loading cases: {str(e)}")
            self.status_var.set("Failed to load cases")
    
    def load_selected_search_case(self, event):
        # Load the selected case details when clicked in search results
        selection = self.search_tree.selection()
        if not selection:
            return
        
        # Get the case ID from the selected item
        item = self.search_tree.item(selection[0])
        case_id = item['values'][0]
        
        try:
            # Use CaseManager to get the specific case
            selected_case = self.case_manager.get_case(case_id)
            
            if selected_case:
                # Store the selected case for potential loading to General tab
                self.selected_search_case = selected_case
                
                # Display case details
                self.display_case_details_obj(selected_case)
            else:
                messagebox.showerror("Error", f"Case {case_id} not found")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error loading case details: {str(e)}")
    
    def display_case_details_obj(self, case_obj):
        # Display full case details for a Case object in the details text area
        self.search_details_text.delete('1.0', tk.END)
        
        details = []
        details.append(f"Case ID: {case_obj.case_id or 'N/A'}")
        details.append(f"Date: {case_obj.created_at[:10] if case_obj.created_at else 'N/A'}")
        details.append("")
        
        # Case details
        details.append("=== CASE DETAILS ===")
        details.append(f"User: {case_obj.user or 'N/A'}")
        details.append(f"Role: {case_obj.role or 'N/A'}")
        details.append(f"Email: {case_obj.email or 'N/A'}")
        details.append(f"Hostname: {case_obj.host or 'N/A'}")
        details.append(f"IP Address: {case_obj.ip_address or 'N/A'}")
        details.append(f"File Hash: {case_obj.file_hash or 'N/A'}")
        details.append(f"URL: N/A")  # URL not stored in Case object currently
        details.append("")
        
        # Outcome
        details.append("=== OUTCOME ===")
        if case_obj.outcome and ',' in case_obj.outcome:
            outcome_parts = case_obj.outcome.split(',')
            classification = outcome_parts[0].strip()
            outcome_type = outcome_parts[1].strip() if len(outcome_parts) > 1 else 'N/A'
        else:
            classification = case_obj.outcome or 'N/A'
            outcome_type = 'N/A'
        
        details.append(f"Classification: {classification}")
        details.append(f"Outcome Type: {outcome_type}")
        details.append("")

        # Notes
        details.append("=== NOTES ===")
        details.append(case_obj.notes or 'No notes available')

        # Insert all details
        self.search_details_text.insert('1.0', '\n'.join(details))

    def display_case_details(self, case):
                # Display full case details in the details text area
        self.search_details_text.delete('1.0', tk.END)
        
        details = []
        details.append(f"Case ID: {case.get('case_id', 'N/A')}")
        details.append(f"Date: {case.get('created_date', 'N/A')}")
        details.append("")
        
        # Case details
        case_details = case.get('details', {})
        details.append("=== CASE DETAILS ===")
        details.append(f"User: {case_details.get('user', 'N/A')}")
        details.append(f"Role: {case_details.get('role', 'N/A')}")
        details.append(f"Email: {case_details.get('email', 'N/A')}")
        details.append(f"Hostname: {case_details.get('hostname', 'N/A')}")
        details.append(f"IP Address: {case_details.get('ip_address', 'N/A')}")
        details.append(f"File Hash: {case_details.get('file_hash', 'N/A')}")
        details.append(f"URL: {case_details.get('url', 'N/A')}")
        details.append("")
        
        # Outcome
        outcome = case.get('outcome', {})
        details.append("=== OUTCOME ===")
        details.append(f"Classification: {outcome.get('classification', 'N/A')}")
        details.append(f"Outcome Type: {outcome.get('outcome_type', 'N/A')}")
        details.append("")

        # Notes
        details.append("=== NOTES ===")
        details.append(case.get('notes', 'No notes available'))

        # Insert all details
        self.search_details_text.insert('1.0', '\n'.join(details))
    
    def load_case_to_general(self):
        # Load the selected case data to the General tab for editing
        if not hasattr(self, 'selected_search_case') or not self.selected_search_case:
            messagebox.showwarning("Load Case", "Please select a case from the search results first")
            return
        
        case = self.selected_search_case
        
        # Set the current case ID for future updates
        self.current_case_id = case.case_id
        
        # Load data into General tab fields from Case object
        self.user_var.set(case.user or '')
        self.role_var.set(case.role or '')
        self.email_var.set(case.email or '')
        self.host_var.set(case.host or '')
        self.ip_var.set(case.ip_address or '')
        self.file_hash_var.set(case.file_hash or '')
        self.url_var.set('')  # URL not stored in Case object currently
        
        # Parse outcome into classification and type
        if case.outcome and ',' in case.outcome:
            outcome_parts = case.outcome.split(',')
            classification = outcome_parts[0].strip()
            outcome_type = outcome_parts[1].strip() if len(outcome_parts) > 1 else 'False-Positive'
            self.classification_var.set(classification)
            self.outcome_type_var.set(outcome_type)
        else:
            self.classification_var.set(case.outcome or 'Benign')
            self.outcome_type_var.set('False-Positive')

        # Load notes
        self.notes_text.delete('1.0', tk.END)
        notes_content = case.notes or ''
        if notes_content:
            self.notes_text.insert('1.0', notes_content)

        # Switch to General tab
        self.notebook.select(0)
        
        # Update status
        case_id = case.case_id or 'Unknown'
        self.status_var.set(f"Loaded case {case_id} to General tab (Edit Mode)")
        messagebox.showinfo("Case Loaded", f"Case {case_id} has been loaded to the General tab.\nAny changes will update the existing case when saved.")
    
    def get_case_info_text(self):
                # Generate formatted text of all case information
        info = []
        info.append(f"User: {self.user_var.get()}")
        info.append(f"Role: {self.role_var.get()}")
        info.append(f"Email: {self.email_var.get()}")
        info.append(f"Hostname: {self.host_var.get()}")
        info.append(f"IP Address: {self.ip_var.get()}")
        info.append(f"File Hash: {self.file_hash_var.get()}")
        info.append(f"Classification: {self.classification_var.get()}")
        info.append(f"Outcome Type: {self.outcome_type_var.get()}")
        info.append(f"Notes: {self.notes_text.get('1.0', tk.END).strip()}")
        return "\n".join(info)
    
    def new_case(self):
        # Create a new case
        # Clear all fields
        self.user_var.set("")
        self.role_var.set("")
        self.email_var.set("")
        self.host_var.set("")
        self.ip_var.set("")
        self.file_hash_var.set("")
        self.url_var.set("")
        self.classification_var.set("Benign")
        self.outcome_type_var.set("False-Positive")
        self.notes_text.delete('1.0', tk.END)

        # Clear the current case ID to ensure we create a new case when saving
        self.current_case_id = None
        
        # Generate new case ID for display purposes (actual ID will be generated on save)
        new_id = f"SOC-{datetime.now().strftime('%Y-%m-%d_%H:%M:%S')}"
        
        self.current_case = Case()
        self.current_case.case_id = new_id
        self.status_var.set("New case created (Create Mode)")
        messagebox.showinfo("New Case", f"New case ready for creation.\nCase will be assigned a unique ID when saved.")
    
    def load_case_data(self, case):
                # Load case data into the form
        self.current_case = case
        self.user_var.set(case.user)
        self.role_var.set(case.role)
        self.email_var.set(case.email)
        self.host_var.set(case.host)
        self.ip_var.set(case.ip_address)
        self.file_hash_var.set(case.file_hash)
        # For backward compatibility, try to parse the old outcome format
        if hasattr(case, 'outcome') and case.outcome:
            # Try to split the outcome if it contains a comma
            if ',' in case.outcome:
                parts = [part.strip() for part in case.outcome.split(',')]
                if len(parts) >= 2:
                    self.classification_var.set(parts[0])
                    self.outcome_type_var.set(parts[1])
                else:
                    # Default values if parsing fails
                    self.classification_var.set("Benign")
                    self.outcome_type_var.set("False-Positive")
            else:
                # Map old values to new format
                if case.outcome == "Normal Activity":
                    self.classification_var.set("Benign")
                    self.outcome_type_var.set("Benign-True Positive")
                elif case.outcome == "Suspicious Activity":
                    self.classification_var.set("Suspicious")
                    self.outcome_type_var.set("Blocked-True Positive")
                elif case.outcome == "Incident Confirmed":
                    self.classification_var.set("Malicious")
                    self.outcome_type_var.set("Malicious-True Positive")
                elif case.outcome == "False Positive":
                    self.classification_var.set("Benign")
                    self.outcome_type_var.set("False-Positive")
                else:
                    self.classification_var.set("Benign")
                    self.outcome_type_var.set("False-Positive")
        else:
            self.classification_var.set("Benign")
            self.outcome_type_var.set("False-Positive")
        self.notes_text.delete('1.0', tk.END)
        if hasattr(case, 'notes') and case.notes:
            self.notes_text.insert('1.0', case.notes)

        self.status_var.set(f"Loaded case {case.case_id}")
    
    def search_cases(self):
                # Search for cases
        search_term = self.search_var.get().lower()
        if not search_term:
            messagebox.showwarning("Warning", "Please enter a search term")
            return
        
        # Clear previous results
        for item in self.search_tree.get_children():
            self.search_tree.delete(item)
        
        # Search cases
        cases = self.case_manager.search_cases(search_term)
        
        for case in cases:
            self.search_tree.insert('', tk.END, values=(
                case.case_id,
                case.title,
                case.status,
                case.user,
                case.created_at[:10]  # Just the date part
            ))
        
        self.status_var.set(f"Found {len(cases)} matching cases")
    
    def load_selected_case(self, event):
                # Load the selected case from search results
        selection = self.search_tree.selection()
        if selection:
            item = self.search_tree.item(selection[0])
            case_id = item['values'][0]
            case = self.case_manager.get_case(case_id)
            if case:
                self.load_case_data(case)
                self.notebook.select(0)  # Switch to General tab
    
    def load_existing_cases(self):
                # Load existing cases on startup
        try:
            cases = self.case_manager.get_all_cases()
            self.status_var.set(f"Loaded {len(cases)} existing cases")
        except Exception as e:
            self.status_var.set("Ready - No existing cases")
    
    def reinitialize_case_manager(self):
                # Reinitialize the case manager with the current data directory setting
        try:
            data_directory = self.settings_manager.get_data_directory()
            cases_file_path = os.path.join(data_directory, 'cases.json')
            self.case_manager = CaseManager(cases_file_path)
            self.status_var.set(f"Updated case data location to: {data_directory}")
        except Exception as e:
            self.status_var.set(f"Error updating case data location: {str(e)}")
    
    def apply_font_settings(self):
        # Apply font settings to all text widgets
        try:
            notes_font_family = self.settings_manager.get_setting("appearance", "notes_font_family")
            notes_font_size = self.settings_manager.get_setting("appearance", "notes_font_size")
            
            # Provide defaults if settings return None
            if notes_font_family is None:
                notes_font_family = "Arial"
            if notes_font_size is None:
                notes_font_size = 10
                
            font_tuple = (notes_font_family, notes_font_size)
            
            # Apply to main notes text widget
            if hasattr(self, 'notes_text'):
                self.notes_text.configure(font=font_tuple)
            
            # Apply to search details text widget
            if hasattr(self, 'search_details_text'):
                self.search_details_text.configure(font=font_tuple)
            
            # Apply to bulk IP text widget (use monospace font for IP addresses)
            if hasattr(self, 'bulk_ip_text'):
                # Use monospace font for better IP address readability
                self.bulk_ip_text.configure(font=("Consolas", notes_font_size))
                
        except Exception as e:
            print(f"Error applying font settings: {e}")
            # Apply default font as fallback
            default_font = ("Arial", 10)
            if hasattr(self, 'notes_text'):
                self.notes_text.configure(font=default_font)
            if hasattr(self, 'search_details_text'):
                self.search_details_text.configure(font=default_font)
            if hasattr(self, 'bulk_ip_text'):
                self.bulk_ip_text.configure(font=("Consolas", 10))

def main():
    # Initialize and run the SOC Case Logger application
    root = tk.Tk()
    app = SOCCaseLogger(root)
    root.mainloop()

if __name__ == "__main__":
    main()
