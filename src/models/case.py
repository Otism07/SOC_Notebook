# Standard library imports
from datetime import datetime
from typing import Optional

class Case:
    # Represents a single SOC (Security Operations Center) case
    # Contains all relevant information about a security incident or investigation,
    # including case details, user information, and timestamps
    
    def __init__(self, case_id: str = "", title: str = "", description: str = "", 
                 user: str = "", role: str = "", email: str = "", 
                 host: str = "", ip_address: str = "", file_hash: str = "",
                 outcome: str = "Normal Activity", status: str = "Open",
                 created_at: Optional[str] = None, updated_at: Optional[str] = None,
                 **kwargs):
        # Initialize a new Case instance
        # **kwargs allows for backward compatibility with old JSON format
        self.case_id = case_id
        self.title = title
        self.description = description
        
        # User/target information
        self.user = user
        self.role = role
        self.email = email
        
        # Technical details
        self.host = host
        self.ip_address = ip_address
        self.file_hash = file_hash
        
        # Case status and outcome
        self.outcome = outcome
        self.status = status
        
        # Timestamps - auto-generate if not provided
        self.created_at = created_at or datetime.now().isoformat()
        self.updated_at = updated_at or datetime.now().isoformat()
        
        # Store additional fields from old format for backward compatibility
        self.notes = kwargs.get('notes', '')
        
        # Ignore other fields like 'timestamp', 'created_date', 'details', 'outcome_details'
        # that might be present in legacy JSON data

    def update_timestamp(self):
        # Update the last modified timestamp to current time
        self.updated_at = datetime.now().isoformat()

    def to_dict(self):
        # Convert the Case object to a dictionary for JSON serialization
        return {
            'case_id': self.case_id,
            'title': self.title,
            'description': self.description,
            'user': self.user,
            'role': self.role,
            'email': self.email,
            'host': self.host,
            'ip_address': self.ip_address,
            'file_hash': self.file_hash,
            'outcome': self.outcome,
            'status': self.status,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'notes': getattr(self, 'notes', '')
        }

    @classmethod
    def from_dict(cls, data):
        # Create a Case instance from a dictionary (for JSON deserialization)
        # Handle backward compatibility with different JSON formats
        
        # Extract only the fields that the __init__ method expects
        init_fields = {
            'case_id': data.get('case_id', ''),
            'title': data.get('title', ''),
            'description': data.get('description', ''),
            'user': data.get('user', ''),
            'role': data.get('role', ''),
            'email': data.get('email', ''),
            'host': data.get('host', ''),
            'ip_address': data.get('ip_address', ''),
            'file_hash': data.get('file_hash', ''),
            'outcome': data.get('outcome', 'Normal Activity'),
            'status': data.get('status', 'Open'),
            'created_at': data.get('created_at'),
            'updated_at': data.get('updated_at'),
            'notes': data.get('notes', '')
        }
        
        # Remove None values to let __init__ handle defaults
        init_fields = {k: v for k, v in init_fields.items() if v is not None}
        
        return cls(**init_fields)

    def __str__(self):
        # String representation of the case for debugging and logging
        return f"Case {self.case_id}: {self.title} ({self.status})"