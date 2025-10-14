from .database import DatabaseManager

class ResultManager:
    def __init__(self):
        self.db = DatabaseManager()
    
    def get_election_results(self, election_id):
        """Get election results with candidate-wise vote count"""
        try:
            results = self.db.execute_query('''
                SELECT 
                    c.candidate_number,
                    c.full_name,
                    c.party_name,
                    c.party_symbol,
                    COUNT(v.vote_id) as vote_count,
                    ROUND(COUNT(v.vote_id) * 100.0 / (
                        SELECT COUNT(*) FROM votes WHERE election_id = ?
                    ), 2) as vote_percentage
                FROM candidates c
                LEFT JOIN votes v ON c.candidate_id = v.candidate_id AND v.election_id = ?
                WHERE c.election_id = ? AND c.is_active = 1
                GROUP BY c.candidate_id
                ORDER BY vote_count DESC
            ''', (election_id, election_id, election_id))
            
            return [dict(result) for result in results]
        except Exception as e:
            print(f"Error fetching election results: {e}")
            return []
    
    def get_constituency_results(self, constituency):
        """Get results for a specific constituency"""
        try:
            results = self.db.execute_query('''
                SELECT 
                    e.election_name,
                    c.candidate_number,
                    c.full_name,
                    c.party_name,
                    COUNT(v.vote_id) as vote_count
                FROM elections e
                JOIN candidates c ON e.election_id = c.election_id
                LEFT JOIN votes v ON c.candidate_id = v.candidate_id
                WHERE e.constituency = ? AND e.status = 'completed'
                GROUP BY e.election_id, c.candidate_id
                ORDER BY e.election_name, vote_count DESC
            ''', (constituency,))
            
            return [dict(result) for result in results]
        except Exception as e:
            print(f"Error fetching constituency results: {e}")
            return []
    
    def get_voter_turnout_stats(self, election_id):
        """Get voter turnout statistics"""
        try:
            stats = self.db.get_single_record('''
                SELECT 
                    COUNT(*) as total_eligible_voters,
                    COUNT(DISTINCT v.voter_id) as actual_voters,
                    ROUND(COUNT(DISTINCT v.voter_id) * 100.0 / COUNT(*), 2) as turnout_percentage
                FROM voters vt
                LEFT JOIN votes v ON vt.voter_id = v.voter_id AND v.election_id = ?
                WHERE vt.constituency = (
                    SELECT constituency FROM elections WHERE election_id = ?
                ) AND vt.is_verified = 1
            ''', (election_id, election_id))
            
            return dict(stats) if stats else {}
        except Exception as e:
            print(f"Error fetching turnout stats: {e}")
            return {}
    
    def get_machine_wise_results(self, election_id):
        """Get results by voting machine"""
        try:
            results = self.db.execute_query('''
                SELECT 
                    v.voting_machine_id,
                    COUNT(*) as vote_count,
                    MIN(v.vote_timestamp) as first_vote,
                    MAX(v.vote_timestamp) as last_vote
                FROM votes v
                WHERE v.election_id = ?
                GROUP BY v.voting_machine_id
                ORDER BY vote_count DESC
            ''', (election_id,))
            
            return [dict(result) for result in results]
        except Exception as e:
            print(f"Error fetching machine-wise results: {e}")
            return []
    
    def generate_results_report(self, election_id):
        """Generate comprehensive results report"""
        try:
            election = self.db.get_single_record(
                "SELECT * FROM elections WHERE election_id = ?",
                (election_id,)
            )
            
            if not election:
                return "Election not found"
            
            election_dict = dict(election)
            results = self.get_election_results(election_id)
            turnout_stats = self.get_voter_turnout_stats(election_id)
            machine_results = self.get_machine_wise_results(election_id)
            
            report = f"""
ELECTION RESULTS REPORT
{'='*60}
Election: {election_dict['election_name']}
Constituency: {election_dict['constituency']}
Type: {election_dict['election_type']}
Period: {election_dict['start_date']} to {election_dict['end_date']}
Status: {election_dict['status'].upper()}
{'='*60}

VOTER TURNOUT:
Total Eligible Voters: {turnout_stats.get('total_eligible_voters', 0)}
Actual Voters: {turnout_stats.get('actual_voters', 0)}
Turnout Percentage: {turnout_stats.get('turnout_percentage', 0)}%

{'='*60}
CANDIDATE RESULTS:
{'='*60}
{'No.':<4} {'Candidate':<20} {'Party':<15} {'Votes':<8} {'Percentage':<10}
{'-'*60}
"""
            
            for result in results:
                report += f"{result['candidate_number']:<4} {result['full_name']:<20} {result['party_name']:<15} {result['vote_count']:<8} {result['vote_percentage']:<10}%\n"
            
            report += f"\n{'='*60}"
            report += f"\nMACHINE-WISE VOTES:"
            report += f"\n{'='*60}"
            report += f"\n{'Machine ID':<12} {'Votes':<8} {'First Vote':<12} {'Last Vote':<12}"
            report += f"\n{'-'*60}"
            
            for machine in machine_results:
                first_vote = machine['first_vote'][:10] if machine['first_vote'] else 'N/A'
                last_vote = machine['last_vote'][:10] if machine['last_vote'] else 'N/A'
                report += f"\n{machine['voting_machine_id']:<12} {machine['vote_count']:<8} {first_vote:<12} {last_vote:<12}"
            
            # Determine winner
            if results and len(results) > 0:
                winner = results[0]
                report += f"\n\n{'='*60}"
                report += f"\nWINNER: {winner['full_name']} ({winner['party_name']})"
                report += f"\nVotes: {winner['vote_count']} ({winner['vote_percentage']}%)"
                report += f"\n{'='*60}"
            
            report += f"\n\nReport Generated: {election_dict.get('created_date', 'N/A')}"
            
            return report
            
        except Exception as e:
            return f"Error generating report: {e}"
    
    def export_results_to_file(self, election_id, filename=None):
        """Export results to a text file"""
        try:
            report = self.generate_results_report(election_id)
            
            if not filename:
                election = self.db.get_single_record(
                    "SELECT election_name, constituency FROM elections WHERE election_id = ?",
                    (election_id,)
                )
                if election:
                    filename = f"results_{election['election_name'].replace(' ', '_')}_{election['constituency']}.txt"
                else:
                    filename = f"results_election_{election_id}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)
            
            return True, f"Results exported to {filename}"
        except Exception as e:
            return False, f"Error exporting results: {e}"