from .database import DatabaseManager
from datetime import datetime, timedelta

class InventoryManager:
    def __init__(self):
        self.db = DatabaseManager()
    
    def get_inventory_status(self):
        """Get complete inventory status"""
        try:
            inventory = self.db.execute_query('''
                SELECT m.*, 
                       CASE 
                         WHEN m.quantity <= m.reorder_level THEN 'Low Stock'
                         WHEN m.expiry_date <= date('now', '+30 days') THEN 'Near Expiry'
                         ELSE 'In Stock'
                       END as status
                FROM medicines m
                WHERE m.is_active = 1
                ORDER BY m.quantity ASC, m.expiry_date ASC
            ''')
            return [dict(item) for item in inventory]
        except Exception as e:
            print(f"Error fetching inventory: {e}")
            return []
    
    def get_stock_movements(self, medicine_id=None, days=30):
        """Get stock movement history"""
        try:
            query = '''
                SELECT sm.*, m.name as medicine_name
                FROM stock_movements sm
                JOIN medicines m ON sm.medicine_id = m.medicine_id
                WHERE sm.movement_date >= date('now', ?)
            '''
            params = [f'-{days} days']
            
            if medicine_id:
                query += " AND sm.medicine_id = ?"
                params.append(medicine_id)
            
            query += " ORDER BY sm.movement_date DESC"
            
            movements = self.db.execute_query(query, params)
            return [dict(mov) for mov in movements]
            
        except Exception as e:
            print(f"Error fetching stock movements: {e}")
            return []
    
    def get_inventory_valuation(self):
        """Get total inventory valuation"""
        try:
            result = self.db.get_single_record('''
                SELECT 
                    SUM(quantity * cost_price) as total_cost_value,
                    SUM(quantity * price) as total_retail_value,
                    COUNT(*) as total_items,
                    SUM(CASE WHEN quantity <= reorder_level THEN 1 ELSE 0 END) as low_stock_items
                FROM medicines 
                WHERE is_active = 1
            ''')
            return dict(result) if result else {
                'total_cost_value': 0,
                'total_retail_value': 0,
                'total_items': 0,
                'low_stock_items': 0
            }
        except Exception as e:
            print(f"Error calculating inventory valuation: {e}")
            return {
                'total_cost_value': 0,
                'total_retail_value': 0,
                'total_items': 0,
                'low_stock_items': 0
            }