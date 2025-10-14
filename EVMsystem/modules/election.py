from datetime import datetime
from .database import DatabaseManager

class ElectionManager:
    def __init__(self):
        self.db = DatabaseManager()
    
    def create_election(self, election_data, admin_id):
        """Create a new election"""
        try:
            required_fields = ['election_name', 'election_type', 'constituency', 'start_date', 'end_date']
            for field in required_fields:
                if field not in election_data or not election_data[field]:
                    return False, f"Missing required field: {field}"
            
            # Validate dates
            start_date = datetime.strptime(election_data['start_date'], '%Y-%m-%d')
            end_date = datetime.strptime(election_data['end_date'], '%Y-%m-%d')
            
            if start_date >= end_date:
                return False, "End date must be after start date"
            
            self.db.execute_query('''
                INSERT INTO elections (election_name, election_type, constituency, start_date, 
                                     end_date, description, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                election_data['election_name'],
                election_data['election_type'],
                election_data['constituency'],
                election_data['start_date'],
                election_data['end_date'],
                election_data.get('description', ''),
                admin_id
            ))
            
            election_id = self.db.execute_query(
                "SELECT election_id FROM elections WHERE election_name = ? AND constituency = ?",
                (election_data['election_name'], election_data['constituency'])
            )[0]['election_id']
            
            # Log the action
            self.db.execute_query('''
                INSERT INTO audit_log (action_type, user_type, user_id, description)
                VALUES (?, ?, ?, ?)
            ''', ('create_election', 'admin', admin_id, 
                  f"Created election: {election_data['election_name']} in {election_data['constituency']}"))
            
            return True, f"Election created successfully. Election ID: {election_id}"
            
        except Exception as e:
            return False, f"Error creating election: {e}"
    
    def update_election_status(self, election_id, status, admin_id):
        """Update election status"""
        try:
            valid_statuses = ['scheduled', 'active', 'completed', 'cancelled']
            if status not in valid_statuses:
                return False, f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
            
            self.db.execute_query(
                "UPDATE elections SET status = ? WHERE election_id = ?",
                (status, election_id)
            )
            
            # Log the action
            self.db.execute_query('''
                INSERT INTO audit_log (action_type, user_type, user_id, description)
                VALUES (?, ?, ?, ?)
            ''', ('update_election_status', 'admin', admin_id, 
                  f"Updated election {election_id} status to {status}"))
            
            return True, f"Election status updated to {status}"
            
        except Exception as e:
            return False, f"Error updating election status: {e}"
    
    def get_active_elections(self):
        """Get all active elections"""
        try:
            elections = self.db.execute_query('''
                SELECT * FROM elections 
                WHERE status = 'active' AND date('now') BETWEEN start_date AND end_date
                ORDER BY start_date
            ''')
            return [dict(election) for election in elections]
        except Exception as e:
            print(f"Error fetching active elections: {e}")
            return []
    
    def get_election_by_id(self, election_id):
        """Get election by ID"""
        try:
            election = self.db.get_single_record(
                "SELECT * FROM elections WHERE election_id = ?",
                (election_id,)
            )
            return dict(election) if election else None
        except Exception as e:
            print(f"Error fetching election: {e}")
            return None
    
    def get_all_elections(self):
        """Get all elections"""
        try:
            elections = self.db.execute_query(
                "SELECT * FROM elections ORDER BY start_date DESC"
            )
            return [dict(election) for election in elections]
        except Exception as e:
            print(f"Error fetching elections: {e}")
            return []
    
    def get_election_stats(self, election_id):
        """Get election statistics"""
        try:
            stats = self.db.get_single_record('''
                SELECT 
                    e.election_name,
                    e.constituency,
                    COUNT(DISTINCT c.candidate_id) as total_candidates,
                    COUNT(DISTINCT v.vote_id) as total_votes,
                    COUNT(DISTINCT vt.voter_id) as total_voters,
                    (SELECT COUNT(*) FROM voters WHERE constituency = e.constituency AND is_verified = 1) as total_eligible_voters
                FROM elections e
                LEFT JOIN candidates c ON e.election_id = c.election_id AND c.is_active = 1
                LEFT JOIN votes v ON e.election_id = v.election_id
                LEFT JOIN voters vt ON v.voter_id = vt.voter_id
                WHERE e.election_id = ?
                GROUP BY e.election_id
            ''', (election_id,))
            return dict(stats) if stats else {}
        except Exception as e:
            print(f"Error getting election stats: {e}")
            return {}