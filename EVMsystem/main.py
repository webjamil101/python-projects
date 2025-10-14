
"""
Advanced Electronic Voting Machine (EVM) System
Main Application Entry Point
"""

import os
import sys
import importlib.util

# Add the modules directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
modules_path = os.path.join(current_dir, 'modules')
sys.path.insert(0, current_dir)  # Add project root
sys.path.insert(0, modules_path)  # Add modules directory

# Now import the modules
try:
    from modules.auth import Authentication
    from modules.voter import VoterManager
    from modules.candidate import CandidateManager
    from modules.election import ElectionManager
    from modules.voting import VotingMachine
    from modules.results import ResultManager
    from modules.security import SecurityManager
except ImportError as e:
    print(f"Import error: {e}")
    print("Trying alternative import method...")
    
    # Alternative import method
    import types
    def load_module(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    
    auth = load_module('auth', os.path.join(modules_path, 'auth.py'))
    voter = load_module('voter', os.path.join(modules_path, 'voter.py'))
    candidate = load_module('candidate', os.path.join(modules_path, 'candidate.py'))
    election = load_module('election', os.path.join(modules_path, 'election.py'))
    voting = load_module('voting', os.path.join(modules_path, 'voting.py'))
    results = load_module('results', os.path.join(modules_path, 'results.py'))
    security = load_module('security', os.path.join(modules_path, 'security.py'))
    
    Authentication = auth.Authentication
    VoterManager = voter.VoterManager
    CandidateManager = candidate.CandidateManager
    ElectionManager = election.ElectionManager
    VotingMachine = voting.VotingMachine
    ResultManager = results.ResultManager
    SecurityManager = security.SecurityManager

class EVMSystem:
    def __init__(self):
        self.auth = Authentication()
        self.voter_manager = VoterManager()
        self.candidate_manager = CandidateManager()
        self.election_manager = ElectionManager()
        self.voting_machine = VotingMachine()
        self.result_manager = ResultManager()
        self.security_manager = SecurityManager()
        
        self.current_election = None
        self.auth = Authentication()
        self.voter_manager = VoterManager()
        self.candidate_manager = CandidateManager()
        self.election_manager = ElectionManager()
        self.voting_machine = VotingMachine()
        self.result_manager = ResultManager()
        self.security_manager = SecurityManager()
        
        self.current_election = None
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_header(self, title):
        """Display application header"""
        self.clear_screen()
        print("=" * 70)
        print("            ADVANCED ELECTRONIC VOTING MACHINE SYSTEM")
        print("=" * 70)
        print(f"{title:^70}")
        print("-" * 70)
    
    def wait_for_enter(self):
        """Wait for user to press Enter"""
        input("\nPress Enter to continue...")
    
    def admin_login(self):
        """Admin login interface"""
        self.display_header("ADMINISTRATOR LOGIN")
        
        username = input("Username: ")
        password = input("Password: ")
        
        success, message = self.auth.login(username, password)
        print(f"\n{message}")
        
        if success:
            self.wait_for_enter()
            self.admin_dashboard()
        else:
            self.wait_for_enter()
            self.main_menu()
    
    def admin_dashboard(self):
        """Admin dashboard"""
        while True:
            self.display_header("ADMIN DASHBOARD")
            print(f"Welcome, {self.auth.current_user['full_name']}!")
            print(f"Role: {self.auth.current_user['role']}")
            print("\n1. Voter Management")
            print("2. Election Management")
            print("3. Candidate Management")
            print("4. Voting Session Control")
            print("5. Results & Reports")
            print("6. Security & Audit")
            print("7. Logout")
            
            choice = input("\nEnter your choice (1-7): ")
            
            if choice == '1':
                self.voter_management()
            elif choice == '2':
                self.election_management()
            elif choice == '3':
                self.candidate_management()
            elif choice == '4':
                self.voting_session_control()
            elif choice == '5':
                self.results_reports()
            elif choice == '6':
                self.security_audit()
            elif choice == '7':
                self.auth.logout()
                print("Logged out successfully!")
                self.wait_for_enter()
                break
            else:
                print("Invalid choice!")
                self.wait_for_enter()
    
    def voter_management(self):
        """Voter management interface"""
        while True:
            self.display_header("VOTER MANAGEMENT")
            print("1. Register New Voter")
            print("2. Search Voters")
            print("3. View Voter Statistics")
            print("4. Verify Voter")
            print("5. Back to Dashboard")
            
            choice = input("\nEnter your choice (1-5): ")
            
            if choice == '1':
                self.register_voter()
            elif choice == '2':
                self.search_voters()
            elif choice == '3':
                self.view_voter_stats()
            elif choice == '4':
                self.verify_voter()
            elif choice == '5':
                break
            else:
                print("Invalid choice!")
                self.wait_for_enter()
    
    def register_voter(self):
        """Register a new voter"""
        self.display_header("REGISTER NEW VOTER")
        
        voter_data = {}
        voter_data['voter_card_number'] = input("Voter Card Number: ")
        voter_data['full_name'] = input("Full Name: ")
        voter_data['date_of_birth'] = input("Date of Birth (YYYY-MM-DD): ")
        voter_data['address'] = input("Address: ")
        voter_data['constituency'] = input("Constituency: ")
        voter_data['phone_number'] = input("Phone Number (optional): ")
        voter_data['email'] = input("Email (optional): ")
        
        success, message = self.voter_manager.register_voter(voter_data)
        print(f"\n{message}")
        self.wait_for_enter()
    
    def search_voters(self):
        """Search voters"""
        self.display_header("SEARCH VOTERS")
        
        search_term = input("Enter search term (name or voter card number): ")
        voters = self.voter_manager.search_voters(search_term)
        
        if voters:
            print(f"\nFound {len(voters)} voter(s):")
            print("-" * 80)
            print(f"{'Card No':<12} {'Name':<20} {'Constituency':<15} {'Verified':<8} {'Voted':<6}")
            print("-" * 80)
            for voter in voters:
                verified = "Yes" if voter['is_verified'] else "No"
                voted = "Yes" if voter['has_voted'] else "No"
                print(f"{voter['voter_card_number']:<12} {voter['full_name']:<20} {voter['constituency']:<15} {verified:<8} {voted:<6}")
        else:
            print("No voters found.")
        
        self.wait_for_enter()
    
    def view_voter_stats(self):
        """View voter statistics"""
        self.display_header("VOTER STATISTICS")
        
        stats = self.voter_manager.get_voter_stats()
        
        if stats:
            print(f"Total Voters: {stats.get('total_voters', 0)}")
            print(f"Verified Voters: {stats.get('verified_voters', 0)}")
            print(f"Voted Voters: {stats.get('voted_voters', 0)}")
            print(f"Total Constituencies: {stats.get('total_constituencies', 0)}")
            
            if stats.get('total_voters', 0) > 0:
                verified_percentage = (stats.get('verified_voters', 0) / stats.get('total_voters', 0)) * 100
                voted_percentage = (stats.get('voted_voters', 0) / stats.get('total_voters', 0)) * 100
                print(f"Verified Percentage: {verified_percentage:.2f}%")
                print(f"Voted Percentage: {voted_percentage:.2f}%")
        else:
            print("No statistics available.")
        
        self.wait_for_enter()
    
    def verify_voter(self):
        """Verify a voter using verification code"""
        self.display_header("VERIFY VOTER")
        
        voter_card_number = input("Voter Card Number: ")
        verification_code = input("Verification Code: ")
        
        success, message = self.auth.verify_voter_code(voter_card_number, verification_code)
        print(f"\n{message}")
        self.wait_for_enter()
    
    def election_management(self):
        """Election management interface"""
        while True:
            self.display_header("ELECTION MANAGEMENT")
            print("1. Create New Election")
            print("2. View All Elections")
            print("3. View Active Elections")
            print("4. Update Election Status")
            print("5. View Election Statistics")
            print("6. Back to Dashboard")
            
            choice = input("\nEnter your choice (1-6): ")
            
            if choice == '1':
                self.create_election()
            elif choice == '2':
                self.view_all_elections()
            elif choice == '3':
                self.view_active_elections()
            elif choice == '4':
                self.update_election_status()
            elif choice == '5':
                self.view_election_stats()
            elif choice == '6':
                break
            else:
                print("Invalid choice!")
                self.wait_for_enter()
    
    def create_election(self):
        """Create a new election"""
        self.display_header("CREATE NEW ELECTION")
        
        election_data = {}
        election_data['election_name'] = input("Election Name: ")
        election_data['election_type'] = input("Election Type (e.g., National, State, Local): ")
        election_data['constituency'] = input("Constituency: ")
        election_data['start_date'] = input("Start Date (YYYY-MM-DD): ")
        election_data['end_date'] = input("End Date (YYYY-MM-DD): ")
        election_data['description'] = input("Description (optional): ")
        
        success, message = self.election_manager.create_election(election_data, self.auth.current_user['admin_id'])
        print(f"\n{message}")
        self.wait_for_enter()
    
    def view_all_elections(self):
        """View all elections"""
        self.display_header("ALL ELECTIONS")
        
        elections = self.election_manager.get_all_elections()
        
        if elections:
            print(f"{'ID':<4} {'Name':<20} {'Type':<12} {'Constituency':<15} {'Status':<12} {'Period':<23}")
            print("-" * 90)
            for election in elections:
                period = f"{election['start_date']} to {election['end_date']}"
                print(f"{election['election_id']:<4} {election['election_name']:<20} {election['election_type']:<12} {election['constituency']:<15} {election['status']:<12} {period:<23}")
        else:
            print("No elections found.")
        
        self.wait_for_enter()
    
    def view_active_elections(self):
        """View active elections"""
        self.display_header("ACTIVE ELECTIONS")
        
        elections = self.election_manager.get_active_elections()
        
        if elections:
            print(f"{'ID':<4} {'Name':<20} {'Type':<12} {'Constituency':<15} {'Period':<23}")
            print("-" * 80)
            for election in elections:
                period = f"{election['start_date']} to {election['end_date']}"
                print(f"{election['election_id']:<4} {election['election_name']:<20} {election['election_type']:<12} {election['constituency']:<15} {period:<23}")
        else:
            print("No active elections found.")
        
        self.wait_for_enter()
    
    def update_election_status(self):
        """Update election status"""
        self.display_header("UPDATE ELECTION STATUS")
        
        election_id = input("Election ID: ")
        if not election_id.isdigit():
            print("Invalid election ID!")
            self.wait_for_enter()
            return
        
        election = self.election_manager.get_election_by_id(int(election_id))
        if not election:
            print("Election not found!")
            self.wait_for_enter()
            return
        
        print(f"\nElection: {election['election_name']}")
        print(f"Current Status: {election['status']}")
        print("\nAvailable statuses: scheduled, active, completed, cancelled")
        
        new_status = input("\nNew Status: ").lower()
        
        success, message = self.election_manager.update_election_status(int(election_id), new_status, self.auth.current_user['admin_id'])
        print(f"\n{message}")
        self.wait_for_enter()
    
    def view_election_stats(self):
        """View election statistics"""
        self.display_header("ELECTION STATISTICS")
        
        election_id = input("Election ID: ")
        if not election_id.isdigit():
            print("Invalid election ID!")
            self.wait_for_enter()
            return
        
        stats = self.election_manager.get_election_stats(int(election_id))
        
        if stats:
            print(f"Election: {stats.get('election_name', 'N/A')}")
            print(f"Constituency: {stats.get('constituency', 'N/A')}")
            print(f"Total Candidates: {stats.get('total_candidates', 0)}")
            print(f"Total Votes: {stats.get('total_votes', 0)}")
            print(f"Total Voters: {stats.get('total_voters', 0)}")
            print(f"Total Eligible Voters: {stats.get('total_eligible_voters', 0)}")
            
            if stats.get('total_eligible_voters', 0) > 0:
                turnout = (stats.get('total_voters', 0) / stats.get('total_eligible_voters', 0)) * 100
                print(f"Voter Turnout: {turnout:.2f}%")
        else:
            print("No statistics available for this election.")
        
        self.wait_for_enter()
    
    def candidate_management(self):
        """Candidate management interface"""
        while True:
            self.display_header("CANDIDATE MANAGEMENT")
            print("1. Add Candidate")
            print("2. View Election Candidates")
            print("3. Back to Dashboard")
            
            choice = input("\nEnter your choice (1-3): ")
            
            if choice == '1':
                self.add_candidate()
            elif choice == '2':
                self.view_election_candidates()
            elif choice == '3':
                break
            else:
                print("Invalid choice!")
                self.wait_for_enter()
    
    def add_candidate(self):
        """Add a new candidate"""
        self.display_header("ADD CANDIDATE")
        
        candidate_data = {}
        candidate_data['election_id'] = input("Election ID: ")
        if not candidate_data['election_id'].isdigit():
            print("Invalid election ID!")
            self.wait_for_enter()
            return
        
        candidate_data['candidate_number'] = input("Candidate Number: ")
        if not candidate_data['candidate_number'].isdigit():
            print("Invalid candidate number!")
            self.wait_for_enter()
            return
        
        candidate_data['full_name'] = input("Full Name: ")
        candidate_data['party_name'] = input("Party Name: ")
        candidate_data['constituency'] = input("Constituency: ")
        candidate_data['party_symbol'] = input("Party Symbol (optional): ")
        candidate_data['photo_url'] = input("Photo URL (optional): ")
        candidate_data['manifesto'] = input("Manifesto (optional): ")
        
        success, message = self.candidate_manager.add_candidate(candidate_data, self.auth.current_user['admin_id'])
        print(f"\n{message}")
        self.wait_for_enter()
    
    def view_election_candidates(self):
        """View candidates for an election"""
        self.display_header("ELECTION CANDIDATES")
        
        election_id = input("Election ID: ")
        if not election_id.isdigit():
            print("Invalid election ID!")
            self.wait_for_enter()
            return
        
        candidates = self.candidate_manager.get_election_candidates(int(election_id))
        
        if candidates:
            election_name = candidates[0]['election_name'] if candidates else "Unknown"
            print(f"\nCandidates for: {election_name}")
            print("-" * 70)
            print(f"{'No.':<4} {'Name':<20} {'Party':<15} {'Constituency':<15}")
            print("-" * 70)
            for candidate in candidates:
                print(f"{candidate['candidate_number']:<4} {candidate['full_name']:<20} {candidate['party_name']:<15} {candidate['constituency']:<15}")
        else:
            print("No candidates found for this election.")
        
        self.wait_for_enter()
    
    def voting_session_control(self):
        """Voting session control interface"""
        while True:
            self.display_header("VOTING SESSION CONTROL")
            print("1. Start Voting Session")
            print("2. Cast Vote (Voter Interface)")
            print("3. End Voting Session")
            print("4. View Session Statistics")
            print("5. Back to Dashboard")
            
            choice = input("\nEnter your choice (1-5): ")
            
            if choice == '1':
                self.start_voting_session()
            elif choice == '2':
                self.cast_vote_interface()
            elif choice == '3':
                self.end_voting_session()
            elif choice == '4':
                self.view_session_stats()
            elif choice == '5':
                break
            else:
                print("Invalid choice!")
                self.wait_for_enter()
    
    def start_voting_session(self):
        """Start a voting session"""
        self.display_header("START VOTING SESSION")
        
        election_id = input("Election ID: ")
        if not election_id.isdigit():
            print("Invalid election ID!")
            self.wait_for_enter()
            return
        
        success, message = self.voting_machine.start_voting_session(int(election_id), self.auth.current_user['admin_id'])
        print(f"\n{message}")
        
        if success:
            self.current_election = self.election_manager.get_election_by_id(int(election_id))
        
        self.wait_for_enter()
    
    def cast_vote_interface(self):
        """Voter interface for casting votes"""
        self.display_header("VOTER INTERFACE - CAST VOTE")
        
        if not self.voting_machine.current_election:
            print("No active voting session. Please start a voting session first.")
            self.wait_for_enter()
            return
        
        voter_card_number = input("Enter Voter Card Number: ")
        
        success, message, voter_data = self.voting_machine.authenticate_voter(voter_card_number)
        print(f"\n{message}")
        
        if not success:
            self.wait_for_enter()
            return
        
        # Show candidates
        candidates = self.candidate_manager.get_election_candidates(self.voting_machine.current_election['election_id'])
        if candidates:
            print(f"\nCandidates for {self.voting_machine.current_election['election_name']}:")
            print("-" * 50)
            for candidate in candidates:
                print(f"{candidate['candidate_number']}. {candidate['full_name']} ({candidate['party_name']})")
            print("-" * 50)
            
            candidate_number = input("\nEnter candidate number to vote: ")
            if candidate_number.isdigit():
                success, message = self.voting_machine.cast_vote(int(candidate_number))
                print(f"\n{message}")
            else:
                print("Invalid candidate number!")
        else:
            print("No candidates available for this election.")
        
        self.wait_for_enter()
    
    def end_voting_session(self):
        """End the current voting session"""
        self.display_header("END VOTING SESSION")
        
        success, message = self.voting_machine.end_voting_session(self.auth.current_user['admin_id'])
        print(f"\n{message}")
        
        if success:
            self.current_election = None
        
        self.wait_for_enter()
    
    def view_session_stats(self):
        """View current session statistics"""
        self.display_header("VOTING SESSION STATISTICS")
        
        stats = self.voting_machine.get_session_stats()
        
        if stats:
            print(f"Total Votes: {stats.get('total_votes', 0)}")
            print(f"Unique Voters: {stats.get('unique_voters', 0)}")
            print(f"First Vote: {stats.get('first_vote', 'N/A')}")
            print(f"Last Vote: {stats.get('last_vote', 'N/A')}")
        else:
            print("No active voting session or no votes cast.")
        
        self.wait_for_enter()
    
    def results_reports(self):
        """Results and reports interface"""
        while True:
            self.display_header("RESULTS & REPORTS")
            print("1. View Election Results")
            print("2. Generate Results Report")
            print("3. Export Results to File")
            print("4. View Voter Turnout Statistics")
            print("5. Back to Dashboard")
            
            choice = input("\nEnter your choice (1-5): ")
            
            if choice == '1':
                self.view_election_results()
            elif choice == '2':
                self.generate_results_report()
            elif choice == '3':
                self.export_results()
            elif choice == '4':
                self.view_turnout_stats()
            elif choice == '5':
                break
            else:
                print("Invalid choice!")
                self.wait_for_enter()
    
    def view_election_results(self):
        """View election results"""
        self.display_header("ELECTION RESULTS")
        
        election_id = input("Election ID: ")
        if not election_id.isdigit():
            print("Invalid election ID!")
            self.wait_for_enter()
            return
        
        results = self.result_manager.get_election_results(int(election_id))
        
        if results:
            election = self.election_manager.get_election_by_id(int(election_id))
            print(f"\nResults for: {election['election_name']} ({election['constituency']})")
            print("=" * 60)
            print(f"{'No.':<4} {'Candidate':<20} {'Party':<15} {'Votes':<8} {'%':<8}")
            print("-" * 60)
            
            total_votes = sum(result['vote_count'] for result in results)
            
            for result in results:
                percentage = (result['vote_count'] / total_votes * 100) if total_votes > 0 else 0
                print(f"{result['candidate_number']:<4} {result['full_name']:<20} {result['party_name']:<15} {result['vote_count']:<8} {percentage:.1f}%")
            
            # Show winner
            if results:
                winner = results[0]
                print("-" * 60)
                print(f"WINNER: {winner['full_name']} ({winner['party_name']})")
                print(f"with {winner['vote_count']} votes ({winner['vote_percentage']}%)")
        else:
            print("No results available for this election.")
        
        self.wait_for_enter()
    
    def generate_results_report(self):
        """Generate results report"""
        self.display_header("GENERATE RESULTS REPORT")
        
        election_id = input("Election ID: ")
        if not election_id.isdigit():
            print("Invalid election ID!")
            self.wait_for_enter()
            return
        
        report = self.result_manager.generate_results_report(int(election_id))
        print("\n" + report)
        
        export = input("\nExport to file? (y/n): ").lower()
        if export == 'y':
            filename = input("Enter filename (or press Enter for auto-generated name): ")
            if not filename:
                filename = None
            success, message = self.result_manager.export_results_to_file(int(election_id), filename)
            print(message)
        
        self.wait_for_enter()
    
    def export_results(self):
        """Export results to file"""
        self.display_header("EXPORT RESULTS")
        
        election_id = input("Election ID: ")
        if not election_id.isdigit():
            print("Invalid election ID!")
            self.wait_for_enter()
            return
        
        filename = input("Enter filename (or press Enter for auto-generated name): ")
        if not filename:
            filename = None
        
        success, message = self.result_manager.export_results_to_file(int(election_id), filename)
        print(f"\n{message}")
        self.wait_for_enter()
    
    def view_turnout_stats(self):
        """View voter turnout statistics"""
        self.display_header("VOTER TURNOUT STATISTICS")
        
        election_id = input("Election ID: ")
        if not election_id.isdigit():
            print("Invalid election ID!")
            self.wait_for_enter()
            return
        
        stats = self.result_manager.get_voter_turnout_stats(int(election_id))
        
        if stats:
            print(f"Total Eligible Voters: {stats.get('total_eligible_voters', 0)}")
            print(f"Actual Voters: {stats.get('actual_voters', 0)}")
            print(f"Turnout Percentage: {stats.get('turnout_percentage', 0)}%")
            
            if stats.get('turnout_percentage', 0) > 0:
                non_voters = stats.get('total_eligible_voters', 0) - stats.get('actual_voters', 0)
                print(f"Non-voters: {non_voters}")
        else:
            print("No turnout statistics available for this election.")
        
        self.wait_for_enter()
    
    def security_audit(self):
        """Security and audit interface"""
        while True:
            self.display_header("SECURITY & AUDIT")
            print("1. View Security Audit Log")
            print("2. Verify Vote Integrity")
            print("3. Detect Anomalies")
            print("4. Back to Dashboard")
            
            choice = input("\nEnter your choice (1-4): ")
            
            if choice == '1':
                self.view_audit_log()
            elif choice == '2':
                self.verify_vote_integrity()
            elif choice == '3':
                self.detect_anomalies()
            elif choice == '4':
                break
            else:
                print("Invalid choice!")
                self.wait_for_enter()
    
    def view_audit_log(self):
        """View security audit log"""
        self.display_header("SECURITY AUDIT LOG")
        
        days = input("Enter number of days to view (default 7): ")
        if not days.isdigit():
            days = 7
        else:
            days = int(days)
        
        logs = self.security_manager.get_security_audit_log(days)
        
        if logs:
            print(f"\nAudit Log (last {days} days):")
            print("-" * 100)
            print(f"{'Timestamp':<20} {'Action':<20} {'User Type':<12} {'Description':<40}")
            print("-" * 100)
            for log in logs[:50]:  # Show last 50 entries
                timestamp = log['timestamp'][:19]  # Truncate microseconds
                print(f"{timestamp:<20} {log['action_type']:<20} {log['user_type']:<12} {log['description']:<40}")
            
            if len(logs) > 50:
                print(f"\n... and {len(logs) - 50} more entries")
        else:
            print("No audit log entries found.")
        
        self.wait_for_enter()
    
    def verify_vote_integrity(self):
        """Verify vote integrity for an election"""
        self.display_header("VERIFY VOTE INTEGRITY")
        
        election_id = input("Election ID: ")
        if not election_id.isdigit():
            print("Invalid election ID!")
            self.wait_for_enter()
            return
        
        success, message, issues = self.security_manager.verify_vote_integrity(int(election_id))
        
        print(f"\n{message}")
        
        if issues:
            print("\nIssues found:")
            for issue in issues:
                print(f"  - {issue}")
        else:
            print("No integrity issues detected.")
        
        self.wait_for_enter()
    
    def detect_anomalies(self):
        """Detect voting anomalies"""
        self.display_header("DETECT VOTING ANOMALIES")
        
        election_id = input("Election ID: ")
        if not election_id.isdigit():
            print("Invalid election ID!")
            self.wait_for_enter()
            return
        
        anomalies = self.security_manager.detect_anomalies(int(election_id))
        
        if anomalies:
            print("\nAnomalies detected:")
            for anomaly in anomalies:
                print(f"  - {anomaly}")
        else:
            print("No anomalies detected.")
        
        self.wait_for_enter()
    
    def main_menu(self):
        """Main application menu"""
        while True:
            self.display_header("MAIN MENU")
            print("1. Administrator Login")
            print("2. Exit")
            
            choice = input("\nEnter your choice (1-2): ")
            
            if choice == '1':
                self.admin_login()
            elif choice == '2':
                print("\nThank you for using the Electronic Voting Machine System!")
                break
            else:
                print("Invalid choice!")
                self.wait_for_enter()

def main():
    """Main application entry point"""
    try:
        evm_system = EVMSystem()
        evm_system.main_menu()
    except KeyboardInterrupt:
        print("\n\nApplication interrupted by user. Goodbye!")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        print("Please contact system administrator.")

if __name__ == "__main__":
    main()