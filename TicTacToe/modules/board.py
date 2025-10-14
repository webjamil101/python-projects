class Board:
    def __init__(self, size=3):
        self.size = size
        self.cells = [[' ' for _ in range(size)] for _ in range(size)]
        self.winning_combinations = self._generate_winning_combinations()
    
    def _generate_winning_combinations(self):
        """Generate all possible winning combinations"""
        combinations = []
        
        # Rows
        for i in range(self.size):
            combinations.append([(i, j) for j in range(self.size)])
        
        # Columns
        for j in range(self.size):
            combinations.append([(i, j) for i in range(self.size)])
        
        # Diagonals
        combinations.append([(i, i) for i in range(self.size)])
        combinations.append([(i, self.size - 1 - i) for i in range(self.size)])
        
        return combinations
    
    def display(self):
        """Display the current board state"""
        print("\n" + "   " + "   ".join(str(i) for i in range(self.size)))
        for i in range(self.size):
            row_display = f"{i}  "
            for j in range(self.size):
                row_display += self.cells[i][j]
                if j < self.size - 1:
                    row_display += " | "
            print(row_display)
            if i < self.size - 1:
                print("  " + "---" * (self.size * 2 - 1))
    
    def make_move(self, row, col, symbol):
        """Make a move on the board"""
        if self.is_valid_move(row, col):
            self.cells[row][col] = symbol
            return True
        return False
    
    def is_valid_move(self, row, col):
        """Check if a move is valid"""
        return (0 <= row < self.size and 
                0 <= col < self.size and 
                self.cells[row][col] == ' ')
    
    def is_full(self):
        """Check if the board is full"""
        for row in self.cells:
            if ' ' in row:
                return False
        return True
    
    def check_winner(self):
        """Check if there's a winner"""
        for combination in self.winning_combinations:
            symbols = [self.cells[i][j] for i, j in combination]
            if symbols[0] != ' ' and all(s == symbols[0] for s in symbols):
                return symbols[0]
        return None
    
    def get_available_moves(self):
        """Get all available moves"""
        moves = []
        for i in range(self.size):
            for j in range(self.size):
                if self.cells[i][j] == ' ':
                    moves.append((i, j))
        return moves
    
    def reset(self):
        """Reset the board"""
        self.cells = [[' ' for _ in range(self.size)] for _ in range(self.size)]
    
    def get_board_state(self):
        """Get current board state as string"""
        return '\n'.join(['|'.join(row) for row in self.cells])