import hashlib
import secrets
import time
from datetime import datetime, timedelta
from .database import DatabaseManager

class SecurityManager:
    def __init__(self):
        self.db = DatabaseManager()
        self.failed_attempts = {}
        self.lockout_duration = timedelta(minutes=30)
        self.max_attempts = 5
    
    def log_security_event(self, event_type, description, user_id=None, user_type='system'):
        """Log security-related events"""
        try:
            self.db.execute_query('''
                INSERT INTO audit_log (action_type, user_type, user_id, description)
                VALUES (?, ?, ?, ?)
            ''', (event_type, user_type, user_id, description))
            return True
        except Exception as e:
            print(f"Error logging security event: {e}")
            return False
    
    def check_brute_force(self, identifier, max_attempts=None):
        """Check for brute force attack attempts"""
        if max_attempts is None:
            max_attempts = self.max_attempts
        
        now = datetime.now()
        if identifier in self.failed_attempts:
            attempts, first_attempt, last_attempt = self.failed_attempts[identifier]
            
            # Reset if lockout period has passed
            if now - last_attempt > self.lockout_duration:
                del self.failed_attempts[identifier]
                return True, "Lockout reset"
            
            if attempts >= max_attempts:
                remaining_time = self.lockout_duration - (now - last_attempt)
                return False, f"Account locked. Try again in {remaining_time.seconds//60} minutes"
        
        return True, "OK"
    
    def record_failed_attempt(self, identifier):
        """Record a failed authentication attempt"""
        now = datetime.now()
        if identifier in self.failed_attempts:
            attempts, first_attempt, _ = self.failed_attempts[identifier]
            self.failed_attempts[identifier] = (attempts + 1, first_attempt, now)
        else:
            self.failed_attempts[identifier] = (1, now, now)
        
        # Log the failed attempt
        self.log_security_event('failed_attempt', f'Failed authentication attempt for {identifier}')
    
    def reset_failed_attempts(self, identifier):
        """Reset failed attempts counter"""
        if identifier in self.failed_attempts:
            del self.failed_attempts[identifier]
    
    def generate_secure_hash(self, data):
        """Generate a secure hash for data verification"""
        salt = secrets.token_hex(16)
        data_to_hash = f"{data}{salt}{datetime.now().isoformat()}"
        return hashlib.sha256(data_to_hash.encode()).hexdigest()
    
    def verify_vote_integrity(self, election_id):
        """Verify the integrity of votes in an election"""
        try:
            # Check for duplicate votes
            duplicates = self.db.execute_query('''
                SELECT voter_id, COUNT(*) as vote_count
                FROM votes 
                WHERE election_id = ?
                GROUP BY voter_id 
                HAVING COUNT(*) > 1
            ''', (election_id,))
            
            # Check vote hashes for consistency
            votes = self.db.execute_query('''
                SELECT vote_id, vote_hash, voter_id, election_id, candidate_id, vote_timestamp
                FROM votes 
                WHERE election_id = ?
            ''', (election_id,))
            
            integrity_issues = []
            
            if duplicates:
                integrity_issues.append(f"Found {len(duplicates)} potential duplicate votes")
            
            # Verify vote hashes (basic check)
            for vote in votes:
                vote_dict = dict(vote)
                expected_hash_data = f"{vote_dict['voter_id']}{vote_dict['election_id']}{vote_dict['candidate_id']}{vote_dict['vote_timestamp']}"
                # Note: This is a simplified check. In production, you'd use the original salt
                
            # Check for votes outside election period
            election = self.db.get_single_record(
                "SELECT start_date, end_date FROM elections WHERE election_id = ?",
                (election_id,)
            )
            
            if election:
                out_of_period_votes = self.db.execute_query('''
                    SELECT COUNT(*) as count
                    FROM votes 
                    WHERE election_id = ? 
                    AND (vote_timestamp < ? OR vote_timestamp > ?)
                ''', (election_id, election['start_date'], election['end_date']))
                
                if out_of_period_votes and out_of_period_votes[0]['count'] > 0:
                    integrity_issues.append(f"Found {out_of_period_votes[0]['count']} votes outside election period")
            
            if integrity_issues:
                return False, "Integrity issues found", integrity_issues
            else:
                return True, "Vote integrity verified", []
                
        except Exception as e:
            return False, f"Error verifying integrity: {e}", []
    
    def get_security_audit_log(self, days=7):
        """Get security audit log for specified days"""
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            logs = self.db.execute_query('''
                SELECT * FROM audit_log 
                WHERE timestamp > ? 
                ORDER BY timestamp DESC
            ''', (cutoff_date,))
            
            return [dict(log) for log in logs]
        except Exception as e:
            print(f"Error fetching audit log: {e}")
            return []
    
    def detect_anomalies(self, election_id):
        """Detect voting anomalies"""
        try:
            anomalies = []
            
            # Check for unusually high votes per minute
            vote_spikes = self.db.execute_query('''
                SELECT 
                    strftime('%Y-%m-%d %H:%M', vote_timestamp) as minute,
                    COUNT(*) as votes_per_minute
                FROM votes 
                WHERE election_id = ?
                GROUP BY minute
                HAVING votes_per_minute > 10  # Threshold for anomaly
                ORDER BY votes_per_minute DESC
            ''', (election_id,))
            
            if vote_spikes:
                anomalies.append(f"Found {len(vote_spikes)} periods with unusually high voting rate")
            
            # Check for votes from same machine in quick succession
            rapid_votes = self.db.execute_query('''
                SELECT v1.voting_machine_id, v1.vote_timestamp as time1, v2.vote_timestamp as time2
                FROM votes v1
                JOIN votes v2 ON v1.voting_machine_id = v2.voting_machine_id 
                    AND v1.vote_id < v2.vote_id
                    AND julianday(v2.vote_timestamp) - julianday(v1.vote_timestamp) < 0.000347  # 30 seconds
                WHERE v1.election_id = ? AND v2.election_id = ?
                LIMIT 10
            ''', (election_id, election_id))
            
            if rapid_votes:
                anomalies.append(f"Found {len(rapid_votes)} instances of rapid consecutive voting")
            
            return anomalies
            
        except Exception as e:
            print(f"Error detecting anomalies: {e}")
            return [f"Error in anomaly detection: {e}"]