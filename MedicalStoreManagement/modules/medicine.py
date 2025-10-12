from .database import DatabaseManager
from datetime import datetime, timedelta

class MedicineManager:
    def __init__(self):
        self.db = DatabaseManager()
    
    def add_medicine(self, medicine_data):
        """Add a new medicine to inventory"""
        try:
            # Validate required fields
            required_fields = ['name', 'batch_number', 'price', 'cost_price', 'expiry_date']
            for field in required_fields:
                if field not in medicine_data or not medicine_data[field]:
                    return False, f"Missing required field: {field}"
            
            # Check if batch number already exists
            existing = self.db.get_single_record(
                "SELECT * FROM medicines WHERE batch_number = ? AND is_active = 1",
                (medicine_data['batch_number'],)
            )
            if existing:
                return False, "Batch number already exists"
            
            # Insert medicine
            self.db.execute_query('''
                INSERT INTO medicines (name, generic_name, batch_number, manufacturer, 
                                    category, price, cost_price, quantity, reorder_level, 
                                    expiry_date, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                medicine_data['name'],
                medicine_data.get('generic_name', ''),
                medicine_data['batch_number'],
                medicine_data.get('manufacturer', ''),
                medicine_data.get('category', 'general'),
                float(medicine_data['price']),
                float(medicine_data['cost_price']),
                int(medicine_data.get('quantity', 0)),
                int(medicine_data.get('reorder_level', 10)),
                medicine_data['expiry_date'],
                medicine_data.get('description', '')
            ))
            
            return True, "Medicine added successfully"
            
        except Exception as e:
            return False, f"Error adding medicine: {e}"
    
    def update_medicine(self, medicine_id, update_data):
        """Update medicine information"""
        try:
            # Build update query dynamically
            set_clause = ", ".join([f"{key} = ?" for key in update_data.keys()])
            query = f"UPDATE medicines SET {set_clause} WHERE medicine_id = ? AND is_active = 1"
            params = list(update_data.values()) + [medicine_id]
            
            self.db.execute_query(query, params)
            return True, "Medicine updated successfully"
            
        except Exception as e:
            return False, f"Error updating medicine: {e}"
    
    def delete_medicine(self, medicine_id):
        """Soft delete a medicine"""
        try:
            self.db.execute_query(
                "UPDATE medicines SET is_active = 0 WHERE medicine_id = ?",
                (medicine_id,)
            )
            return True, "Medicine deleted successfully"
        except Exception as e:
            return False, f"Error deleting medicine: {e}"
    
    def get_medicine(self, medicine_id):
        """Get medicine by ID"""
        try:
            medicine = self.db.get_single_record(
                "SELECT * FROM medicines WHERE medicine_id = ? AND is_active = 1",
                (medicine_id,)
            )
            return dict(medicine) if medicine else None
        except Exception as e:
            print(f"Error fetching medicine: {e}")
            return None
    
    def search_medicines(self, search_term=""):
        """Search medicines by name or generic name"""
        try:
            query = """
                SELECT * FROM medicines 
                WHERE is_active = 1 AND (name LIKE ? OR generic_name LIKE ?)
                ORDER BY name
            """
            search_pattern = f"%{search_term}%"
            medicines = self.db.execute_query(query, (search_pattern, search_pattern))
            return [dict(med) for med in medicines]
        except Exception as e:
            print(f"Error searching medicines: {e}")
            return []
    
    def get_all_medicines(self):
        """Get all active medicines"""
        try:
            medicines = self.db.execute_query(
                "SELECT * FROM medicines WHERE is_active = 1 ORDER BY name"
            )
            return [dict(med) for med in medicines]
        except Exception as e:
            print(f"Error fetching medicines: {e}")
            return []
    
    def get_low_stock_medicines(self):
        """Get medicines with low stock"""
        try:
            medicines = self.db.execute_query('''
                SELECT * FROM medicines 
                WHERE quantity <= reorder_level AND is_active = 1
                ORDER BY quantity ASC
            ''')
            return [dict(med) for med in medicines]
        except Exception as e:
            print(f"Error fetching low stock medicines: {e}")
            return []
    
    def get_expired_medicines(self):
        """Get expired or near-expiry medicines"""
        try:
            # Get medicines expiring in next 30 days
            future_date = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')
            medicines = self.db.execute_query('''
                SELECT * FROM medicines 
                WHERE expiry_date <= ? AND is_active = 1
                ORDER BY expiry_date ASC
            ''', (future_date,))
            return [dict(med) for med in medicines]
        except Exception as e:
            print(f"Error fetching expired medicines: {e}")
            return []
    
    def update_stock(self, medicine_id, quantity_change, movement_type, reference_id=None, notes=""):
        """Update medicine stock and record movement"""
        try:
            # Update stock
            self.db.execute_query(
                "UPDATE medicines SET quantity = quantity + ? WHERE medicine_id = ?",
                (quantity_change, medicine_id)
            )
            
            # Record stock movement
            self.db.execute_query('''
                INSERT INTO stock_movements (medicine_id, movement_type, quantity, reference_id, notes)
                VALUES (?, ?, ?, ?, ?)
            ''', (medicine_id, movement_type, quantity_change, reference_id, notes))
            
            return True, "Stock updated successfully"
        except Exception as e:
            return False, f"Error updating stock: {e}"