from .database import DatabaseManager

class SupplierManager:
    def __init__(self):
        self.db = DatabaseManager()
    
    def add_supplier(self, supplier_data):
        """Add a new supplier"""
        try:
            required_fields = ['name', 'phone']
            for field in required_fields:
                if field not in supplier_data or not supplier_data[field]:
                    return False, f"Missing required field: {field}"
            
            self.db.execute_query('''
                INSERT INTO suppliers (name, contact_person, phone, email, address, tax_id, payment_terms)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                supplier_data['name'],
                supplier_data.get('contact_person', ''),
                supplier_data['phone'],
                supplier_data.get('email', ''),
                supplier_data.get('address', ''),
                supplier_data.get('tax_id', ''),
                supplier_data.get('payment_terms', '')
            ))
            
            return True, "Supplier added successfully"
            
        except Exception as e:
            return False, f"Error adding supplier: {e}"
    
    def update_supplier(self, supplier_id, update_data):
        """Update supplier information"""
        try:
            set_clause = ", ".join([f"{key} = ?" for key in update_data.keys()])
            query = f"UPDATE suppliers SET {set_clause} WHERE supplier_id = ? AND is_active = 1"
            params = list(update_data.values()) + [supplier_id]
            
            self.db.execute_query(query, params)
            return True, "Supplier updated successfully"
            
        except Exception as e:
            return False, f"Error updating supplier: {e}"
    
    def delete_supplier(self, supplier_id):
        """Soft delete a supplier"""
        try:
            self.db.execute_query(
                "UPDATE suppliers SET is_active = 0 WHERE supplier_id = ?",
                (supplier_id,)
            )
            return True, "Supplier deleted successfully"
        except Exception as e:
            return False, f"Error deleting supplier: {e}"
    
    def get_supplier(self, supplier_id):
        """Get supplier by ID"""
        try:
            supplier = self.db.get_single_record(
                "SELECT * FROM suppliers WHERE supplier_id = ? AND is_active = 1",
                (supplier_id,)
            )
            return dict(supplier) if supplier else None
        except Exception as e:
            print(f"Error fetching supplier: {e}")
            return None
    
    def get_all_suppliers(self):
        """Get all active suppliers"""
        try:
            suppliers = self.db.execute_query(
                "SELECT * FROM suppliers WHERE is_active = 1 ORDER BY name"
            )
            return [dict(supp) for supp in suppliers]
        except Exception as e:
            print(f"Error fetching suppliers: {e}")
            return []
    
    def search_suppliers(self, search_term=""):
        """Search suppliers by name"""
        try:
            query = """
                SELECT * FROM suppliers 
                WHERE is_active = 1 AND name LIKE ?
                ORDER BY name
            """
            search_pattern = f"%{search_term}%"
            suppliers = self.db.execute_query(query, (search_pattern,))
            return [dict(supp) for supp in suppliers]
        except Exception as e:
            print(f"Error searching suppliers: {e}")
            return []