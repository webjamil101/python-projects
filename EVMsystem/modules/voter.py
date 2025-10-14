import hashlib
import secrets
from datetime import datetime
from .database import DatabaseManager

class VoterManager:
    def __init__(self):
        self.db = DatabaseManager()
    
    def register_voter(self, voter_data):
        """Register a new voter"""
        try:
            required_fields = ['voter_card_number', 'full_name', 'date_of_birth', 'address', 'constituency']
            for field in required_fields:
                if field not in voter_data or not voter_data[field]:
                    return False, f"Missing required field: {field}"
            
            # Check if voter already exists
            existing = self.db.get_single_record(
                "SELECT * FROM voters WHERE voter_card_number = ?",
                (voter_data['voter_card_number'],)
            )
            if existing:
                return False, "Voter card number already registered"
            
            # Generate verification code
            verification_code = secrets.token_hex(6).upper()
            
            self.db.execute_query('''
                INSERT INTO voters (voter_card_number, full_name, date_of_birth, address, 
                                  constituency, phone_number, email, verification_code)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                voter_data['voter_card_number'],
                voter_data['full_name'],
                voter_data['date_of_birth'],
                voter_data['address'],
                voter_data['constituency'],
                voter_data.get('phone_number', ''),
                voter_data.get('email', ''),
                verification_code
            ))
            
            # Log the registration
            voter_id = self.db.execute_query(
                "SELECT voter_id FROM voters WHERE voter_card_number = ?",
                (voter_data['voter_card_number'],)
            )[0]['voter_id']
            
            self.db.execute_query('''
                INSERT INTO audit_log (action_type, user_type, user_id, description)
                VALUES (?, ?, ?, ?)
            ''', ('voter_registration', 'admin', None, f"Voter {voter_data['voter_card_number']} registered"))
            
            return True, f"Voter registered successfully. Verification Code: {verification_code}"
            
        except Exception as e:
            return False, f"Error registering voter: {e}"
    
    def verify_voter(self, voter_card_number):
        """Verify a voter's eligibility"""
        try:
            voter = self.db.get_single_record(
                "SELECT * FROM voters WHERE voter_card_number = ?",
                (voter_card_number,)
            )
            
            if not voter:
                return False, "Voter not found"
            
            if not voter['is_verified']:
                return False, "Voter not verified"
            
            if voter['has_voted']:
                return False, "Voter has already voted"
            
            return True, "Voter is eligible to vote", dict(voter)
            
        except Exception as e:
            return False, f"Error verifying voter: {e}"
    
    def get_voter_stats(self):
        """Get voter statistics"""
        try:
            stats = self.db.get_single_record('''
                SELECT 
                    COUNT(*) as total_voters,
                    SUM(is_verified) as verified_voters,
                    SUM(has_voted) as voted_voters,
                    COUNT(DISTINCT constituency) as total_constituencies
                FROM voters
            ''')
            return dict(stats) if stats else {}
        except Exception as e:
            print(f"Error getting voter stats: {e}")
            return {}
    
    def search_voters(self, search_term=""):
        """Search voters by name or voter card number"""
        try:
            query = """
                SELECT * FROM voters 
                WHERE full_name LIKE ? OR voter_card_number LIKE ?
                ORDER BY full_name
            """
            search_pattern = f"%{search_term}%"
            voters = self.db.execute_query(query, (search_pattern, search_pattern))
            return [dict(voter) for voter in voters]
        except Exception as e:
            print(f"Error searching voters: {e}")
            return []
    
    def mark_voter_as_voted(self, voter_id):
        """Mark voter as having voted"""
        try:
            self.db.execute_query(
                "UPDATE voters SET has_voted = 1 WHERE voter_id = ?",
                (voter_id,)
            )
            return True
        except Exception as e:
            print(f"Error marking voter as voted: {e}")
            return False