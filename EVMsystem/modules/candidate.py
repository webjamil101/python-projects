from .database import DatabaseManager

class CandidateManager:
    def __init__(self):
        self.db = DatabaseManager()
    
    def add_candidate(self, candidate_data, admin_id):
        """Add a new candidate to election"""
        try:
            required_fields = ['election_id', 'candidate_number', 'full_name', 'party_name', 'constituency']
            for field in required_fields:
                if field not in candidate_data or not candidate_data[field]:
                    return False, f"Missing required field: {field}"
            
            # Check if candidate number already exists in this election
            existing = self.db.get_single_record(
                "SELECT * FROM candidates WHERE election_id = ? AND candidate_number = ?",
                (candidate_data['election_id'], candidate_data['candidate_number'])
            )
            if existing:
                return False, "Candidate number already exists in this election"
            
            self.db.execute_query('''
                INSERT INTO candidates (election_id, candidate_number, full_name, party_name, 
                                      party_symbol, constituency, photo_url, manifesto)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                candidate_data['election_id'],
                candidate_data['candidate_number'],
                candidate_data['full_name'],
                candidate_data['party_name'],
                candidate_data.get('party_symbol', ''),
                candidate_data['constituency'],
                candidate_data.get('photo_url', ''),
                candidate_data.get('manifesto', '')
            ))
            
            # Log the action
            self.db.execute_query('''
                INSERT INTO audit_log (action_type, user_type, user_id, description)
                VALUES (?, ?, ?, ?)
            ''', ('add_candidate', 'admin', admin_id, 
                  f"Added candidate {candidate_data['full_name']} to election {candidate_data['election_id']}"))
            
            return True, "Candidate added successfully"
            
        except Exception as e:
            return False, f"Error adding candidate: {e}"
    
    def get_election_candidates(self, election_id):
        """Get all candidates for an election"""
        try:
            candidates = self.db.execute_query('''
                SELECT c.*, e.election_name 
                FROM candidates c
                JOIN elections e ON c.election_id = e.election_id
                WHERE c.election_id = ? AND c.is_active = 1
                ORDER BY c.candidate_number
            ''', (election_id,))
            return [dict(candidate) for candidate in candidates]
        except Exception as e:
            print(f"Error fetching candidates: {e}")
            return []
    
    def get_candidate_by_number(self, election_id, candidate_number):
        """Get candidate by election ID and candidate number"""
        try:
            candidate = self.db.get_single_record(
                "SELECT * FROM candidates WHERE election_id = ? AND candidate_number = ? AND is_active = 1",
                (election_id, candidate_number)
            )
            return dict(candidate) if candidate else None
        except Exception as e:
            print(f"Error fetching candidate: {e}")
            return None
    
    def update_candidate(self, candidate_id, update_data, admin_id):
        """Update candidate information"""
        try:
            set_clause = ", ".join([f"{key} = ?" for key in update_data.keys()])
            query = f"UPDATE candidates SET {set_clause} WHERE candidate_id = ?"
            params = list(update_data.values()) + [candidate_id]
            
            self.db.execute_query(query, params)
            
            # Log the action
            self.db.execute_query('''
                INSERT INTO audit_log (action_type, user_type, user_id, description)
                VALUES (?, ?, ?, ?)
            ''', ('update_candidate', 'admin', admin_id, f"Updated candidate {candidate_id}"))
            
            return True, "Candidate updated successfully"
            
        except Exception as e:
            return False, f"Error updating candidate: {e}"