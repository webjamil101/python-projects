from .database import DatabaseManager

class CustomerManager:
    def __init__(self):
        self.db = DatabaseManager()
    
    def add_customer(self, customer_data):
        """Add a new customer"""
        try:
            required_fields = ['name', 'phone']
            for field in required_fields:
                if field not in customer_data or not customer_data[field]:
                    return False, f"Missing required field: {field}"
            
            self.db.execute_query('''
                INSERT INTO customers (name, phone, email, address, customer_type)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                customer_data['name'],
                customer_data['phone'],
                customer_data.get('email', ''),
                customer_data.get('address', ''),
                customer_data.get('customer_type', 'regular')
            ))
            
            return True, "Customer added successfully"
            
        except Exception as e:
            return False, f"Error adding customer: {e}"
    
    def update_customer(self, customer_id, update_data):
        """Update customer information"""
        try:
            set_clause = ", ".join([f"{key} = ?" for key in update_data.keys()])
            query = f"UPDATE customers SET {set_clause} WHERE customer_id = ? AND is_active = 1"
            params = list(update_data.values()) + [customer_id]
            
            self.db.execute_query(query, params)
            return True, "Customer updated successfully"
            
        except Exception as e:
            return False, f"Error updating customer: {e}"
    
    def delete_customer(self, customer_id):
        """Soft delete a customer"""
        try:
            self.db.execute_query(
                "UPDATE customers SET is_active = 0 WHERE customer_id = ?",
                (customer_id,)
            )
            return True, "Customer deleted successfully"
        except Exception as e:
            return False, f"Error deleting customer: {e}"
    
    def get_customer(self, customer_id):
        """Get customer by ID"""
        try:
            customer = self.db.get_single_record(
                "SELECT * FROM customers WHERE customer_id = ? AND is_active = 1",
                (customer_id,)
            )
            return dict(customer) if customer else None
        except Exception as e:
            print(f"Error fetching customer: {e}")
            return None
    
    def get_all_customers(self):
        """Get all active customers"""
        try:
            customers = self.db.execute_query(
                "SELECT * FROM customers WHERE is_active = 1 ORDER BY name"
            )
            return [dict(cust) for cust in customers]
        except Exception as e:
            print(f"Error fetching customers: {e}")
            return []
    
    def search_customers(self, search_term=""):
        """Search customers by name or phone"""
        try:
            query = """
                SELECT * FROM customers 
                WHERE is_active = 1 AND (name LIKE ? OR phone LIKE ?)
                ORDER BY name
            """
            search_pattern = f"%{search_term}%"
            customers = self.db.execute_query(query, (search_pattern, search_pattern))
            return [dict(cust) for cust in customers]
        except Exception as e:
            print(f"Error searching customers: {e}")
            return []