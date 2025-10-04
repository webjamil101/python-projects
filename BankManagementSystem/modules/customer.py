from .database import DatabaseManager
from .utils import Utilities, ValidationError

class Customer:
    def __init__(self, customer_id=None, first_name="", last_name="", email="", phone="", 
                 address="", date_of_birth="", id_type="", id_number=""):
        self.customer_id = customer_id or Utilities.generate_id()
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.phone = phone
        self.address = address
        self.date_of_birth = date_of_birth
        self.id_type = id_type
        self.id_number = id_number
        self.created_date = Utilities.get_current_date()
        self.status = "active"
        
        self.db = DatabaseManager()
    
    def validate_customer(self):
        """Validate customer data"""
        try:
            Utilities.validate_email(self.email)
            Utilities.validate_phone(self.phone)
            if self.date_of_birth:
                Utilities.validate_age(self.date_of_birth)
            return True
        except ValidationError as e:
            raise e
    
    def save(self):
        """Save customer to database"""
        self.validate_customer()
        
        query = '''
            INSERT INTO customers 
            (customer_id, first_name, last_name, email, phone, address, 
             date_of_birth, id_type, id_number, created_date, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        params = (self.customer_id, self.first_name, self.last_name, self.email,
                 self.phone, self.address, self.date_of_birth, self.id_type,
                 self.id_number, self.created_date, self.status)
        
        self.db.execute_query(query, params)
        return self.customer_id
    
    def to_dict(self):
        """Convert customer object to dictionary"""
        return {
            'customer_id': self.customer_id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'phone': self.phone,
            'address': self.address,
            'date_of_birth': self.date_of_birth,
            'id_type': self.id_type,
            'id_number': self.id_number,
            'created_date': str(self.created_date),
            'status': self.status
        }

class CustomerManager:
    def __init__(self):
        self.db = DatabaseManager()
    
    def create_customer(self, customer_data):
        """Create a new customer"""
        customer = Customer(**customer_data)
        return customer.save()
    
    def get_customer(self, customer_id):
        """Get customer by ID"""
        query = "SELECT * FROM customers WHERE customer_id = ?"
        result = self.db.get_single_record(query, (customer_id,))
        return dict(result) if result else None
    
    def get_customer_by_email(self, email):
        """Get customer by email"""
        query = "SELECT * FROM customers WHERE email = ?"
        result = self.db.get_single_record(query, (email,))
        return dict(result) if result else None
    
    def update_customer(self, customer_id, update_data):
        """Update customer information"""
        set_clause = ", ".join([f"{key} = ?" for key in update_data.keys()])
        query = f"UPDATE customers SET {set_clause} WHERE customer_id = ?"
        params = list(update_data.values()) + [customer_id]
        
        self.db.execute_query(query, params)
        return True
    
    def deactivate_customer(self, customer_id):
        """Deactivate customer account"""
        query = "UPDATE customers SET status = 'inactive' WHERE customer_id = ?"
        self.db.execute_query(query, (customer_id,))
        return True
    
    def search_customers(self, **filters):
        """Search customers with filters"""
        base_query = "SELECT * FROM customers WHERE 1=1"
        params = []
        
        if 'name' in filters:
            base_query += " AND (first_name LIKE ? OR last_name LIKE ?)"
            params.extend([f"%{filters['name']}%", f"%{filters['name']}%"])
        
        if 'email' in filters:
            base_query += " AND email LIKE ?"
            params.append(f"%{filters['email']}%")
        
        if 'phone' in filters:
            base_query += " AND phone LIKE ?"
            params.append(f"%{filters['phone']}%")
        
        if 'status' in filters:
            base_query += " AND status = ?"
            params.append(filters['status'])
        
        base_query += " ORDER BY last_name, first_name"
        
        results = self.db.execute_query(base_query, params)
        return [dict(row) for row in results]
    
    def get_all_customers(self):
        """Get all customers"""
        query = "SELECT * FROM customers ORDER BY last_name, first_name"
        results = self.db.execute_query(query)
        return [dict(row) for row in results]