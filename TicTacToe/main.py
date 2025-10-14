
"""
Tic Tac Toe Game - Main Application
"""

import sys
import os

# Add the current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

try:
    # Try importing from modules package
    from modules import Game, Database, clear_screen, display_header, validate_input
except ImportError as e:
    print(f"Import error: {e}")
    print("Trying direct imports...")
    
    # Fallback: try direct imports
    try:
        import importlib.util
        
        def load_module(module_name):
            """Dynamically load a module"""
            module_path = os.path.join(current_dir, 'modules', f'{module_name}.py')
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        
        # Load all required modules
        game_module = load_module('game')
        database_module = load_module('database')
        utils_module = load_module('utils')
        
        Game = game_module.Game
        Database = database_module.Database
        clear_screen = utils_module.clear_screen
        display_header = utils_module.display_header
        validate_input = utils_module.validate_input
        
    except Exception as e:
        print(f"Failed to load modules: {e}")
        print("Please make sure all module files exist in the 'modules' directory.")
        sys.exit(1)

class TicTacToeApp:
    def __init__(self):
        self.database = Database()
        self.game = Game(self.database)
    
    def main_menu(self):
        """Display main menu"""
        while True:
            display_header("MAIN MENU")
            print("1. Play Game")
            print("2. View Statistics")
            print("3. Leaderboard")
            print("4. Game History")
            print("5. Exit")
            
            choice = validate_input("\nEnter your choice (1-5): ", int, range(1, 6))
            
            if choice == 1:
                self.play_game_menu()
            elif choice == 2:
                self.view_statistics()
            elif choice == 3:
                self.view_leaderboard()
            elif choice == 4:
                self.view_game_history()
            elif choice == 5:
                print("\nThank you for playing Tic Tac Toe!")
                break
    
    def play_game_menu(self):
        """Display game setup menu"""
        display_header("GAME SETUP")
        
        print("Select Game Mode:")
        print("1. Human vs Human")
        print("2. Human vs Computer")
        print("3. Computer vs Computer")
        print("4. Back to Main Menu")
        
        mode_choice = validate_input("\nEnter your choice (1-4): ", int, range(1, 5))
        
        if mode_choice == 4:
            return
        
        game_modes = {
            1: "human_vs_human",
            2: "human_vs_ai", 
            3: "ai_vs_ai"
        }
        
        game_mode = game_modes[mode_choice]
        
        # Get player names and AI difficulty
        player1_name = "Player 1"
        player2_name = "Player 2"
        ai_difficulty = 'medium'
        
        if game_mode == "human_vs_human":
            player1_name = input("Enter name for Player 1 (X): ") or "Player 1"
            player2_name = input("Enter name for Player 2 (O): ") or "Player 2"
        elif game_mode == "human_vs_ai":
            player1_name = input("Enter your name: ") or "Human"
            print("\nSelect AI Difficulty:")
            print("1. Easy")
            print("2. Medium") 
            print("3. Hard")
            diff_choice = validate_input("Enter choice (1-3): ", int, range(1, 4))
            ai_difficulty = ['easy', 'medium', 'hard'][diff_choice - 1]
            player2_name = f"Computer ({ai_difficulty.title()})"
        elif game_mode == "ai_vs_ai":
            print("\nSelect AI Difficulty:")
            print("1. Easy")
            print("2. Medium")
            print("3. Hard")
            diff_choice = validate_input("Enter choice (1-3): ", int, range(1, 4))
            ai_difficulty = ['easy', 'medium', 'hard'][diff_choice - 1]
            player1_name = f"AI 1 ({ai_difficulty.title()})"
            player2_name = f"AI 2 ({'hard' if ai_difficulty == 'hard' else 'medium'})"
        
        # Board size
        print("\nSelect Board Size:")
        print("1. 3x3 (Classic)")
        print("2. 4x4")
        print("3. 5x5")
        size_choice = validate_input("Enter choice (1-3): ", int, range(1, 4))
        board_size = [3, 4, 5][size_choice - 1]
        
        # Start the game
        self.start_game(game_mode, player1_name, player2_name, ai_difficulty, board_size)
    
    def start_game(self, game_mode, player1_name, player2_name, ai_difficulty, board_size):
        """Start a new game"""
        try:
            # Re-initialize game with new settings
            self.game = Game(self.database)
            
            # Import Board here to avoid circular imports
            try:
                from modules.board import Board
            except ImportError:
                # Fallback import
                import importlib.util
                spec = importlib.util.spec_from_file_location('board', os.path.join(current_dir, 'modules', 'board.py'))
                board_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(board_module)
                Board = board_module.Board
            
            self.game.board = Board(board_size)
            self.game.setup_players(game_mode, player1_name, player2_name, ai_difficulty)
            self.game.start()
            
            # Game loop
            while True:
                result, winner = self.game.check_game_over()
                
                if result != 'continue':
                    self.game.end_game(result, winner)
                    break
                
                if not self.game.play_turn():
                    print("Invalid move! Game aborted.")
                    break
            
            input("\nPress Enter to continue...")
        
        except Exception as e:
            print(f"Error during game: {e}")
            import traceback
            traceback.print_exc()
            input("\nPress Enter to continue...")
    
    def view_statistics(self):
        """View player statistics"""
        display_header("PLAYER STATISTICS")
        
        username = input("Enter player name: ").strip()
        if not username:
            print("No username provided!")
            input("\nPress Enter to continue...")
            return
        
        stats = self.database.get_player_stats(username)
        
        if stats:
            print(f"\nStatistics for {username}:")
            print(f"Wins: {stats['wins']}")
            print(f"Losses: {stats['losses']}")
            print(f"Draws: {stats['draws']}")
            print(f"Total Games: {stats['total_games']}")
            
            if stats['total_games'] > 0:
                win_percentage = (stats['wins'] / stats['total_games']) * 100
                print(f"Win Percentage: {win_percentage:.2f}%")
            
            print(f"Last Played: {stats.get('last_played', 'Never')}")
        else:
            print(f"No statistics found for player '{username}'")
        
        input("\nPress Enter to continue...")
    
    def view_leaderboard(self):
        """View leaderboard"""
        display_header("LEADERBOARD - TOP PLAYERS")
        
        leaderboard = self.database.get_leaderboard(10)
        
        if leaderboard:
            print("\nRank  Player           Wins  Losses  Draws  Total  Win %")
            print("-" * 55)
            for i, player in enumerate(leaderboard, 1):
                print(f"{i:<5} {player['username']:<15} {player['wins']:<5} {player['losses']:<7} {player['draws']:<6} {player['total_games']:<6} {player['win_percentage']:<6}")
        else:
            print("No players found in the database.")
        
        input("\nPress Enter to continue...")
    
    def view_game_history(self):
        """View game history for a player"""
        display_header("GAME HISTORY")
        
        username = input("Enter player name: ").strip()
        if not username:
            print("No username provided!")
            input("\nPress Enter to continue...")
            return
        
        history = self.database.get_game_history(username, 10)
        
        if history:
            print(f"\nLast 10 games for {username}:")
            print("-" * 80)
            for game in history:
                result = "Draw"
                if game['winner_id']:
                    if game['winner_name'] == username:
                        result = "Win"
                    else:
                        result = "Loss"
                
                print(f"Game {game['game_id']}: {game['player1_name']} vs {game['player2_name']} | "
                      f"Result: {result} | Date: {game['end_time'][:10]}")
        else:
            print(f"No game history found for player '{username}'")
        
        input("\nPress Enter to continue...")

def main():
    """Main application entry point"""
    try:
        app = TicTacToeApp()
        app.main_menu()
    except KeyboardInterrupt:
        print("\n\nGame interrupted by user. Goodbye!")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
        print("Please check your installation and try again.")

if __name__ == "__main__":
    main()