import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import LabelEncoder
import json
import os

class PredictionEngine:
    def __init__(self, currency_converter):
        self.currency_converter = currency_converter
        self.occupation_patterns = {
            "Student": {
                "Food": 0.35,
                "Transport": 0.15,
                "Entertainment": 0.20,
                "Education": 0.25,
                "Shopping": 0.05
            },
            "Working Professional": {
                "Food": 0.25,
                "Transport": 0.15,
                "Entertainment": 0.15,
                "Shopping": 0.20,
                "Bills": 0.25
            },
            "Freelancer": {
                "Food": 0.30,
                "Transport": 0.10,
                "Entertainment": 0.15,
                "Shopping": 0.15,
                "Business": 0.30
            },
            "Family": {
                "Food": 0.40,
                "Transport": 0.10,
                "Entertainment": 0.10,
                "Shopping": 0.15,
                "Bills": 0.25
            }
        }
    
    def predict_monthly_expense(self, historical_data, occupation, base_currency, target_currency):
        """Predict monthly expenses based on historical data and occupation"""
        
        if not historical_data:
            return self.predict_from_occupation(occupation, base_currency, target_currency)
        
        # Convert data to DataFrame
        df = self.prepare_data(historical_data, base_currency, target_currency)
        
        if len(df) < 7:  # Not enough data for ML prediction
            return self.predict_from_occupation_and_history(df, occupation, target_currency)
        
        # Use machine learning for prediction
        return self.ml_prediction(df, target_currency)
    
    def prepare_data(self, historical_data, base_currency, target_currency):
        """Prepare data for analysis"""
        records = []
        
        for expense in historical_data:
            # Convert amount to target currency
            amount = self.currency_converter.convert(
                expense['amount'], 
                expense.get('currency', base_currency), 
                target_currency
            )
            
            records.append({
                'date': datetime.strptime(expense['date'], '%Y-%m-%d'),
                'amount': amount,
                'category': expense['category'],
                'day_of_week': datetime.strptime(expense['date'], '%Y-%m-%d').weekday(),
                'day_of_month': datetime.strptime(expense['date'], '%Y-%m-%d').day,
                'month': datetime.strptime(expense['date'], '%Y-%m-%d').month
            })
        
        return pd.DataFrame(records)
    
    def predict_from_occupation(self, occupation, base_currency, target_currency):
        """Predict expenses based on occupation patterns"""
        base_amounts = {
            "Student": 500,
            "Working Professional": 1500,
            "Freelancer": 1200,
            "Family": 2500
        }
        
        base_amount = base_amounts.get(occupation, 1000)
        converted_base = self.currency_converter.convert(base_amount, "USD", target_currency)
        
        pattern = self.occupation_patterns.get(occupation, self.occupation_patterns["Student"])
        prediction = {}
        
        for category, percentage in pattern.items():
            prediction[category] = round(converted_base * percentage, 2)
        
        return {
            'total': round(converted_base, 2),
            'breakdown': prediction,
            'confidence': 'low',
            'method': 'occupation_pattern'
        }
    
    def predict_from_occupation_and_history(self, df, occupation, target_currency):
        """Predict using occupation pattern and limited history"""
        if df.empty:
            return self.predict_from_occupation(occupation, "USD", target_currency)
        
        # Calculate average daily expense
        avg_daily = df['amount'].mean()
        monthly_estimate = avg_daily * 30
        
        # Adjust based on occupation pattern
        occupation_base = self.predict_from_occupation(occupation, "USD", target_currency)['total']
        adjusted_estimate = (monthly_estimate + occupation_base) / 2
        
        pattern = self.occupation_patterns.get(occupation, self.occupation_patterns["Student"])
        breakdown = {}
        
        for category, percentage in pattern.items():
            breakdown[category] = round(adjusted_estimate * percentage, 2)
        
        return {
            'total': round(adjusted_estimate, 2),
            'breakdown': breakdown,
            'confidence': 'medium',
            'method': 'hybrid'
        }
    
    def ml_prediction(self, df, target_currency):
        """Use machine learning for prediction"""
        try:
            # Prepare features
            df['days_from_start'] = (df['date'] - df['date'].min()).dt.days
            
            # Encode categories
            le = LabelEncoder()
            df['category_encoded'] = le.fit_transform(df['category'])
            
            # Train model
            X = df[['days_from_start', 'day_of_week', 'day_of_month', 'month', 'category_encoded']]
            y = df['amount']
            
            model = LinearRegression()
            model.fit(X, y)
            
            # Predict next 30 days
            last_date = df['date'].max()
            future_dates = [last_date + timedelta(days=i) for i in range(1, 31)]
            
            future_data = []
            total_prediction = 0
            
            for date in future_dates:
                for category in le.classes_:
                    features = [
                        (date - df['date'].min()).days,
                        date.weekday(),
                        date.day,
                        date.month,
                        le.transform([category])[0]
                    ]
                    
                    prediction = model.predict([features])[0]
                    if prediction > 0:
                        total_prediction += prediction
            
            # Calculate category breakdown from historical patterns
            category_totals = df.groupby('category')['amount'].sum()
            total_historical = category_totals.sum()
            breakdown = {}
            
            for category in category_totals.index:
                percentage = category_totals[category] / total_historical
                breakdown[category] = round(total_prediction * percentage, 2)
            
            return {
                'total': round(total_prediction, 2),
                'breakdown': breakdown,
                'confidence': 'high',
                'method': 'machine_learning'
            }
            
        except Exception as e:
            print(f"ML prediction failed: {e}")
            # Fallback to simple average
            avg_daily = df['amount'].mean()
            monthly_estimate = avg_daily * 30
            
            category_totals = df.groupby('category')['amount'].sum()
            total_historical = category_totals.sum()
            breakdown = {}
            
            for category in category_totals.index:
                percentage = category_totals[category] / total_historical
                breakdown[category] = round(monthly_estimate * percentage, 2)
            
            return {
                'total': round(monthly_estimate, 2),
                'breakdown': breakdown,
                'confidence': 'medium',
                'method': 'historical_average'
            }