import sqlite3
import os
from datetime import datetime
from contextlib import contextmanager

class HistoryManager:
    """Manage calculation history with database storage"""
    
    def __init__(self, db_path='data/calculator_history.db'):
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
            conn.execute('''
                CREATE TABLE IF NOT EXISTS calculation_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation TEXT NOT NULL,
                    expression TEXT NOT NULL,
                    result TEXT NOT NULL,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    category TEXT DEFAULT 'basic'
                )
            ''')
    
    def add_record(self, operation, expression, result, category='basic'):
        """Add a calculation record to history"""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO calculation_history (operation, expression, result, category)
                VALUES (?, ?, ?, ?)
            ''', (operation, expression, str(result), category))
    
    def get_history(self, limit=50, category=None):
        """Get calculation history"""
        with self.get_connection() as conn:
            if category:
                records = conn.execute('''
                    SELECT * FROM calculation_history 
                    WHERE category = ?
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (category, limit))
            else:
                records = conn.execute('''
                    SELECT * FROM calculation_history 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
            
            return [dict(record) for record in records]
    
    def clear_history(self):
        """Clear all calculation history"""
        with self.get_connection() as conn:
            conn.execute('DELETE FROM calculation_history')
    
    def get_statistics(self):
        """Get usage statistics"""
        with self.get_connection() as conn:
            stats = conn.execute('''
                SELECT 
                    COUNT(*) as total_calculations,
                    COUNT(DISTINCT operation) as unique_operations,
                    MIN(timestamp) as first_calculation,
                    MAX(timestamp) as last_calculation
                FROM calculation_history
            ''').fetchone()
            
            category_stats = conn.execute('''
                SELECT category, COUNT(*) as count
                FROM calculation_history
                GROUP BY category
                ORDER BY count DESC
            ''').fetchall()
            
            return {
                'total_calculations': stats['total_calculations'],
                'unique_operations': stats['unique_operations'],
                'first_calculation': stats['first_calculation'],
                'last_calculation': stats['last_calculation'],
                'category_stats': [dict(stat) for stat in category_stats]
            }
    
    def export_history(self, filename='calculator_history.txt'):
        """Export history to text file"""
        try:
            history = self.get_history(limit=1000)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("Calculator History Export\n")
                f.write("=" * 50 + "\n\n")
                
                for record in history:
                    f.write(f"Time: {record['timestamp']}\n")
                    f.write(f"Operation: {record['operation']}\n")
                    f.write(f"Expression: {record['expression']}\n")
                    f.write(f"Result: {record['result']}\n")
                    f.write(f"Category: {record['category']}\n")
                    f.write("-" * 30 + "\n")
            
            return True, f"History exported to {filename}"
        except Exception as e:
            return False, f"Error exporting history: {e}"