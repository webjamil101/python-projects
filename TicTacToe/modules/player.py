from abc import ABC, abstractmethod

class Player(ABC):
    def __init__(self, symbol, name):
        self.symbol = symbol
        self.name = name
        self.wins = 0
        self.losses = 0
        self.draws = 0
    
    @abstractmethod
    def get_move(self, board):
        """Get player's move - to be implemented by subclasses"""
        pass
    
    def record_win(self):
        """Record a win"""
        self.wins += 1
    
    def record_loss(self):
        """Record a loss"""
        self.losses += 1
    
    def record_draw(self):
        """Record a draw"""
        self.draws += 1
    
    def get_stats(self):
        """Get player statistics"""
        total_games = self.wins + self.losses + self.draws
        win_percentage = (self.wins / total_games * 100) if total_games > 0 else 0
        return {
            'name': self.name,
            'wins': self.wins,
            'losses': self.losses,
            'draws': self.draws,
            'total_games': total_games,
            'win_percentage': round(win_percentage, 2)
        }

class HumanPlayer(Player):
    def get_move(self, board):
        """Get move from human player via input"""
        while True:
            try:
                move_input = input(f"\n{self.name}, enter your move (row,col): ")
                row, col = map(int, move_input.split(','))
                
                if board.is_valid_move(row, col):
                    return row, col
                else:
                    print("Invalid move! Please choose an empty cell.")
            except ValueError:
                print("Invalid input! Please enter row and column as numbers separated by comma (e.g., 1,2)")
            except Exception as e:
                print(f"Error: {e}. Please try again.")

class AIPlayer(Player):
    def __init__(self, symbol, name, difficulty='medium'):
        super().__init__(symbol, name)
        self.difficulty = difficulty
        from .ai import AI
        self.ai = AI(difficulty)
    
    def get_move(self, board):
        """Get move from AI player"""
        print(f"\n{self.name} is thinking...")
        return self.ai.get_move(board, self.symbol)