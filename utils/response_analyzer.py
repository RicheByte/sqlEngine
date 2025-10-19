"""
Response analysis utilities
"""

class ResponseAnalyzer:
    @staticmethod
    def calculate_similarity(text1, text2):
        """Calculate similarity between two texts"""
        if not text1 or not text2:
            return 0
            
        # Convert to sets of words for simple comparison
        try:
            words1 = set(text1.lower().split())
            words2 = set(text2.lower().split())
            
            if not words1 or not words2:
                return 0
                
            common_words = words1.intersection(words2)
            similarity = len(common_words) / max(len(words1), len(words2))
            
            return similarity
        except:
            return 0
    
    @staticmethod
    def detect_database_type(response):
        """Attempt to detect database type from response"""
        if not response:
            return "Unknown"
            
        response_lower = response.lower()
        
        database_indicators = {
            "MySQL": ["mysql", "mysqli_fetch", "mysql_"],
            "MSSQL": ["microsoft", "sql server", "odbc", "mssql"],
            "PostgreSQL": ["postgresql", "postgres", "pg_"],
            "Oracle": ["ora-", "oracle", "pl/sql"],
            "SQLite": ["sqlite", "sqlite3"]
        }
        
        for db_type, indicators in database_indicators.items():
            if any(indicator in response_lower for indicator in indicators):
                return db_type
        
        return "Unknown"
    
    @staticmethod
    def is_different_response(resp1, resp2, threshold=0.3):
        """Check if two responses are significantly different"""
        if not resp1 or not resp2:
            return False
            
        len1 = len(resp1)
        len2 = len(resp2)
        
        if len1 == 0 or len2 == 0:
            return False
        
        length_diff = abs(len1 - len2) / max(len1, len2)
        return length_diff > threshold