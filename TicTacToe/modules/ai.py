import random
import time

class AI:
    def __init__(self, difficulty='medium'):
        self.difficulty = difficulty
    
    def get_move(self, board, symbol):
        """Get AI move based on difficulty level"""
        time.sleep(1)  # Simulate thinking time
        
        if self.difficulty == 'easy':
            return self._get_random_move(board)
        elif self.difficulty == 'medium':
            return self._get_medium_move(board, symbol)
        elif self.difficulty == 'hard':
            return self._get_hard_move(board, symbol)
        else:
            return self._get_random_move(board)
    
    def _get_random_move(self, board):
        """Get a random valid move"""
        available_moves = board.get_available_moves()
        return random.choice(available_moves) if available_moves else None
    
    def _get_medium_move(self, board, symbol):
        """Get a smart move - tries to win or block opponent"""
        opponent = 'O' if symbol == 'X' else 'X'
        
        # Check for winning move
        winning_move = self._find_winning_move(board, symbol)
        if winning_move:
            return winning_move
        
        # Check for blocking move
        blocking_move = self._find_winning_move(board, opponent)
        if blocking_move:
            return blocking_move
        
        # Take center if available (for 3x3 board)
        if board.size == 3:
            center = (1, 1)
            if board.is_valid_move(*center):
                return center
        
        # Take corners
        corners = [(0, 0), (0, 2), (2, 0), (2, 2)]
        available_corners = [corner for corner in corners if board.is_valid_move(*corner)]
        if available_corners:
            return random.choice(available_corners)
        
        # Random move as fallback
        return self._get_random_move(board)
    
    def _get_hard_move(self, board, symbol):
        """Get optimal move using minimax algorithm for 3x3 board"""
        if board.size == 3:
            best_score = float('-inf')
            best_move = None
            opponent = 'O' if symbol == 'X' else 'X'
            
            for move in board.get_available_moves():
                # Make the move
                board.make_move(move[0], move[1], symbol)
                
                # Calculate score
                score = self._minimax(board, 0, False, symbol, opponent)
                
                # Undo the move
                board.make_move(move[0], move[1], ' ')
                
                if score > best_score:
                    best_score = score
                    best_move = move
            
            return best_move if best_move else self._get_medium_move(board, symbol)
        else:
            # For larger boards, use medium strategy
            return self._get_medium_move(board, symbol)
    
    def _minimax(self, board, depth, is_maximizing, player, opponent):
        """Minimax algorithm for optimal moves"""
        winner = board.check_winner()
        
        if winner == player:
            return 10 - depth
        elif winner == opponent:
            return depth - 10
        elif board.is_full():
            return 0
        
        if is_maximizing:
            best_score = float('-inf')
            for move in board.get_available_moves():
                board.make_move(move[0], move[1], player)
                score = self._minimax(board, depth + 1, False, player, opponent)
                board.make_move(move[0], move[1], ' ')
                best_score = max(score, best_score)
            return best_score
        else:
            best_score = float('inf')
            for move in board.get_available_moves():
                board.make_move(move[0], move[1], opponent)
                score = self._minimax(board, depth + 1, True, player, opponent)
                board.make_move(move[0], move[1], ' ')
                best_score = min(score, best_score)
            return best_score
    
    def _find_winning_move(self, board, symbol):
        """Find a move that would win the game"""
        for move in board.get_available_moves():
            # Try the move
            board.make_move(move[0], move[1], symbol)
            winner = board.check_winner()
            board.make_move(move[0], move[1], ' ')  # Undo move
            
            if winner == symbol:
                return move
        return None