# Standard library imports
from datetime import datetime
from typing import Optional

class Case:
    """
    Represents a single SOC (Security Operations Center) case.
    Contains all relevant information about a security incident or investigation,
    including case details, user information, and timestamps.
    """
    
    def __init__(self, case_id: str = "", title: str = "", description: str = "", 
                 user: str = "", role: str = "", email: str = "", 
                 host: str = "", ip_address: str = "", file_hash: str = "",
                 outcome: str = "Normal Activity", status: str = "Open",
                 created_at: Optional[str] = None, updated_at: Optional[str] = None):
        """
        Initialize a new Case instance.
        
        Args:
            case_id: Unique identifier for the case
            title: Brief title/summary of the case
            description: Detailed description of the incident
            user: Username of the affected user
            role: Role/position of the affected user
            email: Email address of the affected user
            host: Hostname of the affected system
            ip_address: IP address involved in the incident
            file_hash: Hash of any suspicious files
            outcome: Investigation outcome (default: "Normal Activity")
            status: Current case status (default: "Open")
            created_at: Case creation timestamp (auto-generated if None)
            updated_at: Last update timestamp (auto-generated if None)
        """
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

    def update_timestamp(self):
        """Update the last modified timestamp to current time"""
        self.updated_at = datetime.now().isoformat()

    def to_dict(self):
        """
        Convert the Case object to a dictionary for JSON serialization.
        
        Returns:
            Dictionary representation of the case
        """
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
            'updated_at': self.updated_at
        }

    @classmethod
    def from_dict(cls, data):
        """
        Create a Case instance from a dictionary (for JSON deserialization).
        
        Args:
            data: Dictionary containing case data
            
        Returns:
            Case instance created from the dictionary data
        """
        return cls(**data)

    def __str__(self):
        """
        String representation of the case for debugging and logging.
        
        Returns:
            Human-readable string representation
        """
        return f"Case {self.case_id}: {self.title} ({self.status})"