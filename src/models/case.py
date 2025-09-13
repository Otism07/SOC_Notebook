from datetime import datetime
from typing import Optional

class Case:
    def __init__(self, case_id: str = "", title: str = "", description: str = "", 
                 user: str = "", role: str = "", email: str = "", 
                 host: str = "", ip_address: str = "", file_hash: str = "",
                 outcome: str = "Normal Activity", status: str = "Open",
                 created_at: Optional[str] = None, updated_at: Optional[str] = None):
        self.case_id = case_id
        self.title = title
        self.description = description
        self.user = user
        self.role = role
        self.email = email
        self.host = host
        self.ip_address = ip_address
        self.file_hash = file_hash
        self.outcome = outcome
        self.status = status
        self.created_at = created_at or datetime.now().isoformat()
        self.updated_at = updated_at or datetime.now().isoformat()

    def update_timestamp(self):
        """Update the last modified timestamp"""
        self.updated_at = datetime.now().isoformat()

    def to_dict(self):
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
        """Create a Case instance from a dictionary"""
        return cls(**data)

    def __str__(self):
        return f"Case {self.case_id}: {self.title} ({self.status})"