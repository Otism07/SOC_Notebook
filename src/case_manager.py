# Standard library imports
import json
import os
from typing import List, Optional

# Local imports
from models.case import Case

class CaseManager:
    # Manages SOC case data including CRUD operations, search functionality,
    # and JSON file persistence. Handles case storage and retrieval operations.
    
    def __init__(self, data_file: str = "data/cases.json"):
        # Initialize the CaseManager with a specified data file location
        self.data_file = data_file
        self.cases = {}  # Dictionary to store cases in memory (case_id -> Case object)
        self.ensure_data_directory()
        self.load_cases()

    def ensure_data_directory(self):
        # Create the data directory if it doesn't exist
        data_dir = os.path.dirname(self.data_file)
        if data_dir and not os.path.exists(data_dir):
            os.makedirs(data_dir)

    def load_cases(self):
        # Load all cases from the JSON file into memory
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as file:
                    data = json.load(file)
                    # Convert each JSON object back to Case object
                    for case_data in data:
                        case = Case.from_dict(case_data)
                        self.cases[case.case_id] = case
            except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
                print(f"Error loading cases: {e}")
                self.cases = {}

    def save_cases(self):
        # Save all cases from memory to the JSON file
        try:
            with open(self.data_file, 'w') as file:
                # Convert Case objects to dictionaries for JSON serialization
                cases_data = [case.to_dict() for case in self.cases.values()]
                json.dump(cases_data, file, indent=4)
        except Exception as e:
            print(f"Error saving cases: {e}")

    def create_case(self, case_id: str, title: str = "", description: str = "", **kwargs) -> Case:
        # Create a new case with the specified parameters
        case = Case(case_id=case_id, title=title, description=description, **kwargs)
        self.cases[case_id] = case
        self.save_cases()
        return case

    def save_case(self, case: Case):
        # Save or update an existing case
        case.update_timestamp()  # Update the last modified time
        self.cases[case.case_id] = case
        self.save_cases()

    def get_case(self, case_id: str) -> Optional[Case]:
        # Retrieve a specific case by its ID
        return self.cases.get(case_id)

    def get_all_cases(self) -> List[Case]:
        # Get all cases currently stored in the system
        return list(self.cases.values())

    def update_case(self, case_id: str, **updates):
        # Update specific fields of an existing case
        if case_id in self.cases:
            case = self.cases[case_id]
            # Update only the specified fields
            for key, value in updates.items():
                if hasattr(case, key):
                    setattr(case, key, value)
            case.update_timestamp()
            self.save_cases()
            return case
        return None

    def delete_case(self, case_id: str) -> bool:
        # Delete a case from the system
        if case_id in self.cases:
            del self.cases[case_id]
            self.save_cases()
            return True
        return False

    def search_cases(self, search_term: str) -> List[Case]:
        # Search for cases containing the specified term in any field
        search_term = search_term.lower()
        results = []
        
        for case in self.cases.values():
            # Search across multiple case fields
            searchable_fields = [
                case.case_id.lower(),
                case.title.lower(),
                case.description.lower(),
                case.user.lower(),
                case.email.lower(),
                case.host.lower(),
                case.ip_address.lower(),
                case.status.lower(),
                case.outcome.lower()
            ]
            
            # Check if search term appears in any field
            if any(search_term in field for field in searchable_fields):
                results.append(case)
        
        return results

    def get_cases_by_status(self, status: str) -> List[Case]:
        # Get all cases with a specific status
        return [case for case in self.cases.values() if case.status.lower() == status.lower()]

    def get_cases_by_user(self, user: str) -> List[Case]:
        # Get all cases associated with a specific user
        return [case for case in self.cases.values() if case.user.lower() == user.lower()]

    def export_cases(self, filename: str):
        # Export all cases to a specified JSON file
        try:
            with open(filename, 'w') as file:
                cases_data = [case.to_dict() for case in self.cases.values()]
                json.dump(cases_data, file, indent=4)
        except Exception as e:
            raise Exception(f"Error exporting cases: {e}")

    def import_cases(self, filename: str):
        # Import cases from a JSON file
        try:
            with open(filename, 'r') as file:
                data = json.load(file)
                # Convert imported data to Case objects
                for case_data in data:
                    case = Case.from_dict(case_data)
                    self.cases[case.case_id] = case
                self.save_cases()
        except Exception as e:
            raise Exception(f"Error importing cases: {e}")

    def get_case_statistics(self):
        # Generate statistics about the current cases
        total_cases = len(self.cases)
        status_counts = {}
        outcome_counts = {}
        
        # Count cases by status and outcome
        for case in self.cases.values():
            status_counts[case.status] = status_counts.get(case.status, 0) + 1
            outcome_counts[case.outcome] = outcome_counts.get(case.outcome, 0) + 1
        
        return {
            'total_cases': total_cases,
            'status_breakdown': status_counts,
            'outcome_breakdown': outcome_counts
        }