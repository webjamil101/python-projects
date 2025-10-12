from .database import DatabaseManager
from datetime import datetime, timedelta
import csv
import os

class ReportGenerator:
    def __init__(self):
        self.db = DatabaseManager()
    
    def generate_sales_report(self, start_date, end_date, report_type='summary'):
        """Generate sales report"""
        try:
            if report_type == 'summary':
                return self._generate_sales_summary(start_date, end_date)
            else:
                return self._generate_detailed_sales_report(start_date, end_date)
        except Exception as e:
            return f"Error generating sales report: {e}"
    
    def _generate_sales_summary(self, start_date, end_date):
        """Generate sales summary report"""
        try:
            summary = self.db.get_single_record('''
                SELECT 
                    COUNT(*) as total_sales,
                    SUM(final_amount) as total_revenue,
                    AVG(final_amount) as average_sale,
                    SUM(discount) as total_discount,
                    SUM(tax_amount) as total_tax,
                    MAX(final_amount) as highest_sale,
                    MIN(final_amount) as lowest_sale
                FROM sales 
                WHERE sale_date BETWEEN ? AND ?
            ''', (start_date, end_date))
            
            if not summary:
                return "No sales data for the selected period"
            
            summary_dict = dict(summary)
            report = f"""
SALES SUMMARY REPORT
Period: {start_date} to {end_date}
{'='*50}
Total Sales: {summary_dict['total_sales'] or 0}
Total Revenue: ${summary_dict['total_revenue'] or 0:,.2f}
Average Sale: ${summary_dict['average_sale'] or 0:,.2f}
Total Discount: ${summary_dict['total_discount'] or 0:,.2f}
Total Tax: ${summary_dict['total_tax'] or 0:,.2f}
Highest Sale: ${summary_dict['highest_sale'] or 0:,.2f}
Lowest Sale: ${summary_dict['lowest_sale'] or 0:,.2f}
{'='*50}
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
            return report
            
        except Exception as e:
            return f"Error generating summary: {e}"
    
    def _generate_detailed_sales_report(self, start_date, end_date):
        """Generate detailed sales report"""
        try:
            sales = self.db.execute_query('''
                SELECT s.sale_id, s.sale_date, c.name as customer_name, 
                       s.total_amount, s.discount, s.tax_amount, s.final_amount,
                       s.payment_method, u.full_name as created_by
                FROM sales s
                LEFT JOIN customers c ON s.customer_id = c.customer_id
                LEFT JOIN users u ON s.created_by = u.user_id
                WHERE s.sale_date BETWEEN ? AND ?
                ORDER BY s.sale_date DESC
            ''', (start_date, end_date))
            
            if not sales:
                return "No sales data for the selected period"
            
            report = f"""
DETAILED SALES REPORT
Period: {start_date} to {end_date}
{'='*80}
{'ID':<6} {'Date':<12} {'Customer':<20} {'Amount':<10} {'Discount':<10} {'Tax':<8} {'Final':<10} {'Method':<8}
{'-'*80}
            """
            
            for sale in sales:
                sale_dict = dict(sale)
                report += f"{sale_dict['sale_id']:<6} {sale_dict['sale_date'][:10]:<12} {sale_dict['customer_name'] or 'Walk-in':<20} ${sale_dict['total_amount']:<9.2f} ${sale_dict['discount']:<9.2f} ${sale_dict['tax_amount']:<7.2f} ${sale_dict['final_amount']:<9.2f} {sale_dict['payment_method']:<8}\n"
            
            report += f"{'='*80}\n"
            report += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            return report
            
        except Exception as e:
            return f"Error generating detailed report: {e}"
    
    def generate_inventory_report(self):
        """Generate inventory report"""
        try:
            inventory = self.db.execute_query('''
                SELECT name, batch_number, quantity, price, cost_price, 
                       (quantity * cost_price) as stock_value, expiry_date,
                       CASE 
                         WHEN quantity <= reorder_level THEN 'LOW'
                         WHEN expiry_date <= date('now', '+30 days') THEN 'EXPIRING'
                         ELSE 'OK'
                       END as status
                FROM medicines 
                WHERE is_active = 1
                ORDER BY status, quantity ASC
            ''')
            
            if not inventory:
                return "No inventory data available"
            
            report = f"""
INVENTORY STATUS REPORT
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*100}
{'Medicine':<20} {'Batch':<12} {'Qty':<6} {'Price':<8} {'Cost':<8} {'Value':<10} {'Expiry':<12} {'Status':<10}
{'-'*100}
            """
            
            for item in inventory:
                item_dict = dict(item)
                report += f"{item_dict['name']:<20} {item_dict['batch_number']:<12} {item_dict['quantity']:<6} ${item_dict['price']:<7.2f} ${item_dict['cost_price']:<7.2f} ${item_dict['stock_value']:<9.2f} {item_dict['expiry_date']:<12} {item_dict['status']:<10}\n"
            
            # Add summary
            valuation = self.db.get_single_record('''
                SELECT 
                    SUM(quantity * cost_price) as total_cost,
                    SUM(quantity * price) as total_retail,
                    COUNT(*) as total_items,
                    SUM(CASE WHEN quantity <= reorder_level THEN 1 ELSE 0 END) as low_stock,
                    SUM(CASE WHEN expiry_date <= date('now', '+30 days') THEN 1 ELSE 0 END) as expiring_soon
                FROM medicines WHERE is_active = 1
            ''')
            
            if valuation:
                val_dict = dict(valuation)
                report += f"{'='*100}\n"
                report += f"SUMMARY:\n"
                report += f"Total Items: {val_dict['total_items']}\n"
                report += f"Low Stock Items: {val_dict['low_stock']}\n"
                report += f"Expiring Soon: {val_dict['expiring_soon']}\n"
                report += f"Total Cost Value: ${val_dict['total_cost'] or 0:,.2f}\n"
                report += f"Total Retail Value: ${val_dict['total_retail'] or 0:,.2f}\n"
            
            return report
            
        except Exception as e:
            return f"Error generating inventory report: {e}"
    
    def export_report_to_csv(self, report_data, filename):
        """Export report data to CSV file"""
        try:
            os.makedirs('reports', exist_ok=True)
            filepath = f"reports/{filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            
            with open(filepath, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                
                if isinstance(report_data, list) and report_data:
                    # Write header
                    writer.writerow(report_data[0].keys())
                    # Write data
                    for row in report_data:
                        writer.writerow(row.values())
                else:
                    writer.writerow(['Report Data'])
                    writer.writerow([report_data])
            
            return f"Report exported to: {filepath}"
        except Exception as e:
            return f"Error exporting report: {e}"