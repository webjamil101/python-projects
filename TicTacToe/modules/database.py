import sqlite3
import os
from datetime import datetime
from contextlib import contextmanager

class Database:
    def __init__(self, db_path='data/tictactoe.db'):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def init_database(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            # Players table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS players (
                    player_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    wins INTEGER DEFAULT 0,
                    losses INTEGER DEFAULT 0,
                    draws INTEGER DEFAULT 0,
                    total_games INTEGER DEFAULT 0,
                    created_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_played TEXT
                )
            ''')
            
            # Games table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS games (
                    game_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    player1_id INTEGER,
                    player2_id INTEGER,
                    winner_id INTEGER,
                    game_type TEXT NOT NULL,
                    board_size INTEGER DEFAULT 3,
                    moves TEXT,
                    start_time TEXT DEFAULT CURRENT_TIMESTAMP,
                    end_time TEXT,
                    duration_seconds INTEGER DEFAULT 0,
                    FOREIGN KEY (player1_id) REFERENCES players (player_id),
                    FOREIGN KEY (player2_id) REFERENCES players (player_id),
                    FOREIGN KEY (winner_id) REFERENCES players (player_id)
                )
            ''')
            
            # Game moves table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS game_moves (
                    move_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    game_id INTEGER NOT NULL,
                    player_id INTEGER NOT NULL,
                    move_number INTEGER NOT NULL,
                    position INTEGER NOT NULL,
                    symbol TEXT NOT NULL,
                    move_time TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (game_id) REFERENCES games (game_id),
                    FOREIGN KEY (player_id) REFERENCES players (player_id)
                )
            ''')
    
    def save_player(self, username):
        """Save or update player statistics"""
        with self.get_connection() as conn:
            # Check if player exists
            player = conn.execute(
                "SELECT * FROM players WHERE username = ?", 
                (username,)
            ).fetchone()
            
            if player:
                # Update last_played
                conn.execute(
                    "UPDATE players SET last_played = ? WHERE username = ?",
                    (datetime.now().isoformat(), username)
                )
                return player['player_id']
            else:
                # Create new player
                cursor = conn.execute(
                    "INSERT INTO players (username, last_played) VALUES (?, ?)",
                    (username, datetime.now().isoformat())
                )
                return cursor.lastrowid
    
    def update_player_stats(self, player_id, result):
        """Update player statistics (win, loss, draw)"""
        with self.get_connection() as conn:
            if result == 'win':
                conn.execute(
                    "UPDATE players SET wins = wins + 1, total_games = total_games + 1 WHERE player_id = ?",
                    (player_id,)
                )
            elif result == 'loss':
                conn.execute(
                    "UPDATE players SET losses = losses + 1, total_games = total_games + 1 WHERE player_id = ?",
                    (player_id,)
                )
            elif result == 'draw':
                conn.execute(
                    "UPDATE players SET draws = draws + 1, total_games = total_games + 1 WHERE player_id = ?",
                    (player_id,)
                )
    
    def save_game(self, game_data):
        """Save complete game data"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO games (player1_id, player2_id, winner_id, game_type, board_size, moves, start_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                game_data['player1_id'],
                game_data['player2_id'],
                game_data.get('winner_id'),
                game_data['game_type'],
                game_data['board_size'],
                game_data.get('moves', ''),
                game_data.get('start_time', datetime.now().isoformat())
            ))
            
            return cursor.lastrowid
    
    def update_game_result(self, game_id, winner_id=None, moves=''):
        """Update game with final result"""
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE games 
                SET winner_id = ?, moves = ?, end_time = ?, duration_seconds = ?
                WHERE game_id = ?
            ''', (
                winner_id,
                moves,
                datetime.now().isoformat(),
                0,  # We're not calculating duration for now
                game_id
            ))
    
    def save_move(self, game_id, player_id, move_number, position, symbol):
        """Save individual move"""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO game_moves (game_id, player_id, move_number, position, symbol)
                VALUES (?, ?, ?, ?, ?)
            ''', (game_id, player_id, move_number, position, symbol))
    
    def get_player_stats(self, username):
        """Get player statistics"""
        with self.get_connection() as conn:
            player = conn.execute(
                "SELECT * FROM players WHERE username = ?", 
                (username,)
            ).fetchone()
            
            return dict(player) if player else None
    
    def get_leaderboard(self, limit=10):
        """Get top players by wins"""
        with self.get_connection() as conn:
            players = conn.execute('''
                SELECT username, wins, losses, draws, total_games,
                       CASE WHEN total_games > 0 THEN ROUND(wins * 100.0 / total_games, 2) ELSE 0 END as win_percentage
                FROM players 
                WHERE total_games > 0
                ORDER BY wins DESC, win_percentage DESC
                LIMIT ?
            ''', (limit,)).fetchall()
            
            return [dict(player) for player in players]
    
    def get_game_history(self, username, limit=10):
        """Get game history for a player"""
        with self.get_connection() as conn:
            player = conn.execute(
                "SELECT player_id FROM players WHERE username = ?", 
                (username,)
            ).fetchone()
            
            if not player:
                return []
            
            games = conn.execute('''
                SELECT g.*, 
                       p1.username as player1_name,
                       p2.username as player2_name,
                       w.username as winner_name
                FROM games g
                LEFT JOIN players p1 ON g.player1_id = p1.player_id
                LEFT JOIN players p2 ON g.player2_id = p2.player_id
                LEFT JOIN players w ON g.winner_id = w.player_id
                WHERE g.player1_id = ? OR g.player2_id = ?
                ORDER BY g.end_time DESC
                LIMIT ?
            ''', (player['player_id'], player['player_id'], limit)).fetchall()
            
            return [dict(game) for game in games]