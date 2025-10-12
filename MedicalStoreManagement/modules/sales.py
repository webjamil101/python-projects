from .database import DatabaseManager
from datetime import datetime

class SalesManager:
    def __init__(self):
        self.db = DatabaseManager()
    
    def create_sale(self, sale_data, user_id):
        """Create a new sale transaction"""
        try:
            # Start transaction
            with self.db.get_connection() as conn:
                # Create sale record
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO sales (customer_id, total_amount, discount, tax_amount, 
                                    final_amount, payment_method, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    sale_data.get('customer_id'),
                    float(sale_data['total_amount']),
                    float(sale_data.get('discount', 0)),
                    float(sale_data.get('tax_amount', 0)),
                    float(sale_data['final_amount']),
                    sale_data.get('payment_method', 'cash'),
                    user_id
                ))
                
                sale_id = cursor.lastrowid
                
                # Add sale items and update stock
                for item in sale_data['items']:
                    # Add sale item
                    cursor.execute('''
                        INSERT INTO sale_items (sale_id, medicine_id, quantity, unit_price, total_price)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        sale_id,
                        item['medicine_id'],
                        int(item['quantity']),
                        float(item['unit_price']),
                        float(item['total_price'])
                    ))
                    
                    # Update stock
                    cursor.execute('''
                        UPDATE medicines 
                        SET quantity = quantity - ? 
                        WHERE medicine_id = ?
                    ''', (item['quantity'], item['medicine_id']))
                    
                    # Record stock movement
                    cursor.execute('''
                        INSERT INTO stock_movements (medicine_id, movement_type, quantity, reference_id, notes)
                        VALUES (?, 'sale', ?, ?, ?)
                    ''', (item['medicine_id'], -item['quantity'], sale_id, f"Sale #{sale_id}"))
                
                return True, f"Sale completed successfully. Sale ID: {sale_id}"
                
        except Exception as e:
            return False, f"Error creating sale: {e}"
    
    def get_sale(self, sale_id):
        """Get sale details by ID"""
        try:
            sale = self.db.get_single_record('''
                SELECT s.*, c.name as customer_name, u.full_name as created_by_name
                FROM sales s
                LEFT JOIN customers c ON s.customer_id = c.customer_id
                LEFT JOIN users u ON s.created_by = u.user_id
                WHERE s.sale_id = ?
            ''', (sale_id,))
            
            if not sale:
                return None
            
            # Get sale items
            items = self.db.execute_query('''
                SELECT si.*, m.name as medicine_name
                FROM sale_items si
                JOIN medicines m ON si.medicine_id = m.medicine_id
                WHERE si.sale_id = ?
            ''', (sale_id,))
            
            sale_dict = dict(sale)
            sale_dict['items'] = [dict(item) for item in items]
            return sale_dict
            
        except Exception as e:
            print(f"Error fetching sale: {e}")
            return None
    
    def get_sales_report(self, start_date=None, end_date=None):
        """Get sales report for a date range"""
        try:
            query = '''
                SELECT s.*, c.name as customer_name, u.full_name as created_by_name
                FROM sales s
                LEFT JOIN customers c ON s.customer_id = c.customer_id
                LEFT JOIN users u ON s.created_by = u.user_id
                WHERE 1=1
            '''
            params = []
            
            if start_date:
                query += " AND s.sale_date >= ?"
                params.append(start_date)
            if end_date:
                query += " AND s.sale_date <= ?"
                params.append(end_date)
            
            query += " ORDER BY s.sale_date DESC"
            
            sales = self.db.execute_query(query, params)
            return [dict(sale) for sale in sales]
            
        except Exception as e:
            print(f"Error fetching sales report: {e}")
            return []
    
    def get_daily_sales_summary(self, date=None):
        """Get daily sales summary"""
        try:
            if not date:
                date = datetime.now().strftime('%Y-%m-%d')
            
            summary = self.db.get_single_record('''
                SELECT 
                    COUNT(*) as total_sales,
                    SUM(final_amount) as total_revenue,
                    SUM(discount) as total_discount,
                    SUM(tax_amount) as total_tax
                FROM sales 
                WHERE DATE(sale_date) = ?
            ''', (date,))
            
            return dict(summary) if summary else {
                'total_sales': 0,
                'total_revenue': 0,
                'total_discount': 0,
                'total_tax': 0
            }
            
        except Exception as e:
            print(f"Error fetching daily summary: {e}")
            return {
                'total_sales': 0,
                'total_revenue': 0,
                'total_discount': 0,
                'total_tax': 0
            }