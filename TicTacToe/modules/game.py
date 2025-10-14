import time
from datetime import datetime
from .board import Board
from .player import HumanPlayer, AIPlayer

class Game:
    def __init__(self, database=None):
        self.board = Board()
        self.players = []
        self.current_player_index = 0
        self.moves = []
        self.start_time = None
        self.database = database
        self.game_id = None
    
    def setup_players(self, game_mode, player1_name="Player 1", player2_name="Player 2", ai_difficulty='medium'):
        """Setup players based on game mode"""
        if game_mode == "human_vs_human":
            self.players = [
                HumanPlayer('X', player1_name),
                HumanPlayer('O', player2_name)
            ]
        elif game_mode == "human_vs_ai":
            self.players = [
                HumanPlayer('X', player1_name),
                AIPlayer('O', "Computer", ai_difficulty)
            ]
        elif game_mode == "ai_vs_ai":
            self.players = [
                AIPlayer('X', "AI Player 1", ai_difficulty),
                AIPlayer('O', "AI Player 2", 'hard' if ai_difficulty == 'hard' else 'medium')
            ]
    
    def start(self):
        """Start the game"""
        self.board.reset()
        self.moves = []
        self.current_player_index = 0
        self.start_time = time.time()
        
        # Save game to database if available
        if self.database and self.players:
            try:
                player1_id = self.database.save_player(self.players[0].name)
                player2_id = self.database.save_player(self.players[1].name)
                
                game_data = {
                    'player1_id': player1_id,
                    'player2_id': player2_id,
                    'game_type': ' vs '.join([p.name for p in self.players]),
                    'board_size': self.board.size,
                    'start_time': datetime.now().isoformat()
                }
                
                self.game_id = self.database.save_game(game_data)
                print(f"Game started with ID: {self.game_id}")  # Debug
            except Exception as e:
                print(f"Warning: Could not save game to database: {e}")
                self.database = None  # Disable database for this game
    
    def play_turn(self):
        """Play one turn of the game"""
        current_player = self.players[self.current_player_index]
        
        # Display board
        self.board.display()
        
        # Get move from current player
        move = current_player.get_move(self.board)
        
        if move:
            row, col = move
            
            # Make the move
            self.board.make_move(row, col, current_player.symbol)
            
            # Record move
            move_data = {
                'player': current_player.name,
                'symbol': current_player.symbol,
                'position': (row, col),
                'move_number': len(self.moves) + 1
            }
            self.moves.append(move_data)
            
            # Save move to database (if available and no errors)
            if self.database and self.game_id:
                try:
                    player_id = self.database.save_player(current_player.name)
                    self.database.save_move(
                        self.game_id, 
                        player_id, 
                        len(self.moves), 
                        row * self.board.size + col,
                        current_player.symbol
                    )
                except Exception as e:
                    print(f"Warning: Could not save move: {e}")
            
            # Switch to next player
            self.current_player_index = (self.current_player_index + 1) % len(self.players)
            
            return True
        return False
    
    def check_game_over(self):
        """Check if the game is over and return result"""
        winner_symbol = self.board.check_winner()
        
        if winner_symbol:
            winner = next((p for p in self.players if p.symbol == winner_symbol), None)
            return 'win', winner
        elif self.board.is_full():
            return 'draw', None
        else:
            return 'continue', None
    
    def end_game(self, result, winner=None):
        """End the game and handle results"""
        end_time = time.time()
        duration = int(end_time - self.start_time) if self.start_time else 0
        
        # Update player stats in memory
        if result == 'win' and winner:
            winner.record_win()
            loser = next((p for p in self.players if p != winner), None)
            if loser:
                loser.record_loss()
            print(f"\n🎉 {winner.name} wins! 🎉")
        elif result == 'draw':
            for player in self.players:
                player.record_draw()
            print("\n🤝 It's a draw! 🤝")
        
        # Display final board
        self.board.display()
        
        # Update database (if available and no errors)
        if self.database and self.game_id:
            try:
                winner_id = None
                if result == 'win' and winner:
                    winner_id = self.database.save_player(winner.name)
                    print(f"Winner ID: {winner_id}")  # Debug
                
                # Update game record
                self.database.update_game_result(
                    self.game_id, 
                    winner_id, 
                    str(self.moves)
                )
                print(f"Game result updated in database")  # Debug
                
                # Update player stats in database
                for player in self.players:
                    player_id = self.database.save_player(player.name)
                    if result == 'win':
                        if player == winner:
                            self.database.update_player_stats(player_id, 'win')
                            print(f"Updated {player.name} with WIN")  # Debug
                        else:
                            self.database.update_player_stats(player_id, 'loss')
                            print(f"Updated {player.name} with LOSS")  # Debug
                    elif result == 'draw':
                        self.database.update_player_stats(player_id, 'draw')
                        print(f"Updated {player.name} with DRAW")  # Debug
                        
            except Exception as e:
                print(f"Error updating database: {e}")
                import traceback
                traceback.print_exc()
        
        # Display game summary
        print(f"\nGame Summary:")
        print(f"Duration: {duration} seconds")
        print(f"Total moves: {len(self.moves)}")
        for player in self.players:
            stats = player.get_stats()
            print(f"{player.name}: {stats['wins']}W {stats['losses']}L {stats['draws']}D")
    
    def get_current_player(self):
        """Get current player"""
        return self.players[self.current_player_index]