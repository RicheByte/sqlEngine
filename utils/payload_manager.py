"""
Payload Manager - Centralized payload handling and optimization
"""

import os
import re
from typing import List, Optional

class PayloadManager:
    """
    Manages payload loading, deduplication, normalization, and ordering.
    Makes it easy to work with new payloads without code changes.
    """
    
    @staticmethod
    def load_from_file(filepath: str, default_payloads: Optional[List[str]] = None) -> List[str]:
        """
        Load payloads from file with automatic cleaning and optimization.
        
        Args:
            filepath: Path to payload file
            default_payloads: Fallback payloads if file not found
            
        Returns:
            List of cleaned, deduplicated payloads
        """
        from config import (MAX_PAYLOADS_PER_TEST, SKIP_DUPLICATE_PAYLOADS, 
                           NORMALIZE_PAYLOADS, PAYLOAD_ENCODING)
        
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding=PAYLOAD_ENCODING) as f:
                    # Read and filter payloads
                    payloads = []
                    for line in f:
                        line = line.strip()
                        # Skip empty lines and comments
                        if not line or line.startswith('#') or line.startswith('//'):
                            continue
                        payloads.append(line)
                
                # Normalize whitespace if enabled
                if NORMALIZE_PAYLOADS:
                    payloads = [' '.join(p.split()) for p in payloads]
                
                # Remove duplicates while preserving order
                if SKIP_DUPLICATE_PAYLOADS:
                    payloads = list(dict.fromkeys(payloads))
                
                # Apply limit if specified
                if MAX_PAYLOADS_PER_TEST:
                    payloads = payloads[:MAX_PAYLOADS_PER_TEST]
                
                return payloads
            else:
                print(f"   Payload file not found: {filepath}, using defaults")
                return default_payloads or []
                
        except Exception as e:
            print(f"   Error loading payloads from {filepath}: {e}, using defaults")
            return default_payloads or []
    
    @staticmethod
    def deduplicate(payloads: List[str]) -> List[str]:
        """Remove duplicate payloads while preserving order"""
        return list(dict.fromkeys(payloads))
    
    @staticmethod
    def normalize(payloads: List[str]) -> List[str]:
        """Normalize whitespace in payloads"""
        return [' '.join(p.split()) for p in payloads]
    
    @staticmethod
    def filter_by_pattern(payloads: List[str], pattern: str) -> List[str]:
        """Filter payloads matching a regex pattern"""
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            return [p for p in payloads if regex.search(p)]
        except re.error:
            return payloads
    
    @staticmethod
    def sort_by_length(payloads: List[str], reverse: bool = False) -> List[str]:
        """Sort payloads by length (shortest first by default)"""
        return sorted(payloads, key=len, reverse=reverse)
    
    @staticmethod
    def sort_by_complexity(payloads: List[str]) -> List[str]:
        """Sort payloads by complexity (simple first)"""
        def complexity_score(payload):
            score = len(payload)
            score += payload.count('(') * 2
            score += payload.count('SELECT') * 5
            score += payload.count('UNION') * 5
            score += payload.count('FROM') * 3
            score += payload.count('WHERE') * 3
            return score
        
        return sorted(payloads, key=complexity_score)
    
    @staticmethod
    def categorize_by_database(payloads: List[str]) -> dict:
        """
        Categorize payloads by target database type.
        Useful for focused testing.
        """
        categories = {
            'mysql': [],
            'mssql': [],
            'postgresql': [],
            'oracle': [],
            'sqlite': [],
            'generic': []
        }
        
        for payload in payloads:
            payload_lower = payload.lower()
            
            if any(kw in payload_lower for kw in ['sleep(', 'benchmark', 'extractvalue', 'updatexml']):
                categories['mysql'].append(payload)
            elif any(kw in payload_lower for kw in ['waitfor', 'convert(int']):
                categories['mssql'].append(payload)
            elif any(kw in payload_lower for kw in ['pg_sleep', 'cast(', 'version()']):
                categories['postgresql'].append(payload)
            elif any(kw in payload_lower for kw in ['dbms_', 'utl_', 'ctxsys']):
                categories['oracle'].append(payload)
            elif 'randomblob' in payload_lower:
                categories['sqlite'].append(payload)
            else:
                categories['generic'].append(payload)
        
        return categories
    
    @staticmethod
    def add_custom_payloads(base_payloads: List[str], custom_payloads: List[str]) -> List[str]:
        """
        Add custom payloads to base list with automatic deduplication.
        Allows runtime payload extension.
        """
        combined = base_payloads + custom_payloads
        return PayloadManager.deduplicate(combined)
    
    @staticmethod
    def validate_payload(payload: str) -> bool:
        """
        Basic validation to ensure payload is safe to use.
        Prevents obviously malformed payloads.
        """
        if not payload or len(payload) > 1000:
            return False
        
        # Check for balanced quotes and parentheses
        quote_count = payload.count("'") + payload.count('"')
        paren_count = payload.count('(') - payload.count(')')
        
        # Allow unbalanced quotes (common in SQLi) but flag extreme cases
        if quote_count > 20 or abs(paren_count) > 10:
            return False
        
        return True
    
    @staticmethod
    def get_payload_stats(payloads: List[str]) -> dict:
        """Get statistics about a payload list"""
        if not payloads:
            return {
                'total': 0,
                'unique': 0,
                'avg_length': 0,
                'min_length': 0,
                'max_length': 0
            }
        
        lengths = [len(p) for p in payloads]
        
        return {
            'total': len(payloads),
            'unique': len(set(payloads)),
            'avg_length': sum(lengths) / len(lengths),
            'min_length': min(lengths),
            'max_length': max(lengths),
            'duplicates': len(payloads) - len(set(payloads))
        }
