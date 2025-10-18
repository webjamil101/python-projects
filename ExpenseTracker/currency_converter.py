import requests
import json
import os
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import messagebox

class CurrencyConverter:
    def __init__(self):
        self.rates = {}
        self.base_currency = "USD"
        self.load_exchange_rates()
        
        # Supported currencies with symbols
        self.currencies = {
            "USD": {"name": "US Dollar", "symbol": "$"},
            "EUR": {"name": "Euro", "symbol": "€"},
            "GBP": {"name": "British Pound", "symbol": "£"},
            "JPY": {"name": "Japanese Yen", "symbol": "¥"},
            "CAD": {"name": "Canadian Dollar", "symbol": "C$"},
            "AUD": {"name": "Australian Dollar", "symbol": "A$"},
            "INR": {"name": "Indian Rupee", "symbol": "₹"},
            "CNY": {"name": "Chinese Yuan", "symbol": "¥"},
            "SGD": {"name": "Singapore Dollar", "symbol": "S$"},
            "MYR": {"name": "Malaysian Ringgit", "symbol": "RM"},
            "IDR": {"name": "Indonesian Rupiah", "symbol": "Rp"},
            "PHP": {"name": "Philippine Peso", "symbol": "₱"},
            "KRW": {"name": "South Korean Won", "symbol": "₩"},
            "THB": {"name": "Thai Baht", "symbol": "฿"},
            "VND": {"name": "Vietnamese Dong", "symbol": "₫"}
        }
    
    def load_exchange_rates(self):
        """Load exchange rates from file or API"""
        try:
            if os.path.exists('data/exchange_rates.json'):
                with open('data/exchange_rates.json', 'r') as f:
                    data = json.load(f)
                    # Check if rates are less than 24 hours old
                    last_updated = datetime.fromisoformat(data['last_updated'])
                    if datetime.now() - last_updated < timedelta(hours=24):
                        self.rates = data['rates']
                        return
            
            # Fetch new rates if file doesn't exist or is outdated
            self.fetch_live_rates()
            
        except Exception as e:
            print(f"Error loading exchange rates: {e}")
            # Use default rates if loading fails
            self.set_default_rates()
    
    def set_default_rates(self):
        """Set default exchange rates as fallback"""
        self.rates = {
            "USD": 1.0,
            "EUR": 0.85,
            "GBP": 0.73,
            "JPY": 110.0,
            "CAD": 1.25,
            "AUD": 1.35,
            "INR": 74.0,
            "CNY": 6.45,
            "SGD": 1.35,
            "MYR": 4.20,
            "IDR": 14250.0,
            "PHP": 50.0,
            "KRW": 1180.0,
            "THB": 33.0,
            "VND": 23000.0
        }
    
    def fetch_live_rates(self):
        """Fetch live exchange rates from API"""
        try:
            # Using free exchange rate API
            response = requests.get('https://api.exchangerate-api.com/v4/latest/USD')
            if response.status_code == 200:
                data = response.json()
                self.rates = data['rates']
                
                # Save to file
                os.makedirs('data', exist_ok=True)
                with open('data/exchange_rates.json', 'w') as f:
                    json.dump({
                        'rates': self.rates,
                        'last_updated': datetime.now().isoformat()
                    }, f, indent=2)
            else:
                self.set_default_rates()
                
        except Exception as e:
            print(f"Error fetching live rates: {e}")
            self.set_default_rates()
    
    def convert(self, amount, from_currency, to_currency):
        """Convert amount from one currency to another"""
        if from_currency == to_currency:
            return amount
        
        if from_currency not in self.rates or to_currency not in self.rates:
            return amount
        
        # Convert to USD first, then to target currency
        usd_amount = amount / self.rates[from_currency]
        converted_amount = usd_amount * self.rates[to_currency]
        
        return round(converted_amount, 2)
    
    def get_currency_symbol(self, currency_code):
        """Get symbol for currency code"""
        return self.currencies.get(currency_code, {}).get('symbol', currency_code)
    
    def get_all_currencies(self):
        """Get list of all supported currencies"""
        return list(self.currencies.keys())