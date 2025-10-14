import hashlib
import secrets
from datetime import datetime
from .database import DatabaseManager

class VotingMachine:
    def __init__(self, machine_id="EV001"):
        self.db = DatabaseManager()
        self.machine_id = machine_id
        self.current_voter = None
        self.current_election = None
    
    def start_voting_session(self, election_id, admin_id):
        """Start a new voting session"""
        try:
            # Check if election is active
            election = self.db.get_single_record(
                "SELECT * FROM elections WHERE election_id = ? AND status = 'active'",
                (election_id,)
            )
            
            if not election:
                return False, "Election is not active or not found"
            
            self.current_election = dict(election)
            
            # Create voting session
            self.db.execute_query('''
                INSERT INTO voting_sessions (election_id, machine_id, start_time, created_by)
                VALUES (?, ?, ?, ?)
            ''', (election_id, self.machine_id, datetime.now().isoformat(), admin_id))
            
            # Log the action
            self.db.execute_query('''
                INSERT INTO audit_log (action_type, user_type, user_id, description)
                VALUES (?, ?, ?, ?)
            ''', ('start_voting_session', 'admin', admin_id, 
                  f"Started voting session for election {election_id} on machine {self.machine_id}"))
            
            return True, f"Voting session started for {election['election_name']}"
            
        except Exception as e:
            return False, f"Error starting voting session: {e}"
    
    def authenticate_voter(self, voter_card_number):
        """Authenticate voter and check eligibility"""
        try:
            from .voter import VoterManager
            voter_manager = VoterManager()
            
            success, message, voter_data = voter_manager.verify_voter(voter_card_number)
            
            if success:
                self.current_voter = voter_data
                return True, "Voter authenticated successfully", voter_data
            else:
                return False, message, None
                
        except Exception as e:
            return False, f"Authentication error: {e}", None
    
    def cast_vote(self, candidate_number):
        """Cast a vote for a candidate"""
        try:
            if not self.current_voter or not self.current_election:
                return False, "Voting session not properly initialized"
            
            # Get candidate details
            from .candidate import CandidateManager
            candidate_manager = CandidateManager()
            candidate = candidate_manager.get_candidate_by_number(
                self.current_election['election_id'], candidate_number
            )
            
            if not candidate:
                return False, "Invalid candidate number"
            
            # Generate unique vote hash for verification
            vote_data = f"{self.current_voter['voter_id']}{self.current_election['election_id']}{candidate['candidate_id']}{datetime.now().isoformat()}{secrets.token_hex(8)}"
            vote_hash = hashlib.sha256(vote_data.encode()).hexdigest()
            
            # Record the vote
            self.db.execute_query('''
                INSERT INTO votes (election_id, voter_id, candidate_id, voting_machine_id, vote_hash)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                self.current_election['election_id'],
                self.current_voter['voter_id'],
                candidate['candidate_id'],
                self.machine_id,
                vote_hash
            ))
            
            # Mark voter as voted
            from .voter import VoterManager
            voter_manager = VoterManager()
            voter_manager.mark_voter_as_voted(self.current_voter['voter_id'])
            
            # Update voting session count
            self.db.execute_query('''
                UPDATE voting_sessions 
                SET total_votes = total_votes + 1 
                WHERE election_id = ? AND machine_id = ? AND status = 'active'
            ''', (self.current_election['election_id'], self.machine_id))
            
            # Log the vote
            self.db.execute_query('''
                INSERT INTO audit_log (action_type, user_type, user_id, description)
                VALUES (?, ?, ?, ?)
            ''', ('cast_vote', 'voter', self.current_voter['voter_id'], 
                  f"Voter {self.current_voter['voter_card_number']} voted for candidate {candidate_number}"))
            
            # Clear current voter
            self.current_voter = None
            
            return True, f"Vote cast successfully for {candidate['full_name']}. Vote Hash: {vote_hash[:16]}..."
            
        except Exception as e:
            return False, f"Error casting vote: {e}"
    
    def end_voting_session(self, admin_id):
        """End the current voting session"""
        try:
            if not self.current_election:
                return False, "No active voting session"
            
            self.db.execute_query('''
                UPDATE voting_sessions 
                SET end_time = ?, status = 'completed' 
                WHERE election_id = ? AND machine_id = ? AND status = 'active'
            ''', (datetime.now().isoformat(), self.current_election['election_id'], self.machine_id))
            
            # Log the action
            self.db.execute_query('''
                INSERT INTO audit_log (action_type, user_type, user_id, description)
                VALUES (?, ?, ?, ?)
            ''', ('end_voting_session', 'admin', admin_id, 
                  f"Ended voting session for election {self.current_election['election_id']} on machine {self.machine_id}"))
            
            session_stats = self.db.get_single_record('''
                SELECT total_votes FROM voting_sessions 
                WHERE election_id = ? AND machine_id = ? 
                ORDER BY session_id DESC LIMIT 1
            ''', (self.current_election['election_id'], self.machine_id))
            
            self.current_election = None
            self.current_voter = None
            
            total_votes = session_stats['total_votes'] if session_stats else 0
            return True, f"Voting session ended. Total votes cast: {total_votes}"
            
        except Exception as e:
            return False, f"Error ending voting session: {e}"
    
    def get_session_stats(self):
        """Get current session statistics"""
        try:
            if not self.current_election:
                return {}
            
            stats = self.db.get_single_record('''
                SELECT 
                    COUNT(*) as total_votes,
                    COUNT(DISTINCT voter_id) as unique_voters,
                    MIN(vote_timestamp) as first_vote,
                    MAX(vote_timestamp) as last_vote
                FROM votes 
                WHERE election_id = ? AND voting_machine_id = ?
            ''', (self.current_election['election_id'], self.machine_id))
            
            return dict(stats) if stats else {}
        except Exception as e:
            print(f"Error getting session stats: {e}")
            return {}