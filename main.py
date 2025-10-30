#!/usr/bin/env python3
"""
SQL Injection Automator - Main Entry Point
"""

import time
import os
import sys
import json
from datetime import datetime

# Add current directory to path to ensure imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from engines.boolean_engine import BooleanEngine
from engines.time_engine import TimeEngine
from engines.union_engine import UnionEngine
from engines.error_engine import ErrorEngine
from utils.http_client import HttpClient
from utils.html_reporter import HTMLReporter
from config import TARGET_URL, TEST_PARAMS

class SQLiAutomator:
    def __init__(self):
        self.http_client = HttpClient()
        self.results = []
        self.scan_start_time = None
        self.scan_end_time = None
        
    def run_full_test(self):
        """Run all SQL injection tests"""
        self.scan_start_time = datetime.now()
        print("🔍 Starting SQL Injection Automation...")
        print(f"🎯 Target: {TARGET_URL}")
        print(f"📝 Testing Parameters: {', '.join(TEST_PARAMS)}")
        
        # Show configuration
        from config import MAX_PAYLOADS_PER_TEST, SKIP_DUPLICATE_PAYLOADS, SMART_PAYLOAD_ORDERING
        print(f"\n⚙️  Configuration:")
        print(f"   • Payload limit: {'Unlimited' if not MAX_PAYLOADS_PER_TEST else MAX_PAYLOADS_PER_TEST}")
        print(f"   • Remove duplicates: {'Yes' if SKIP_DUPLICATE_PAYLOADS else 'No'}")
        print(f"   • Smart ordering: {'Yes' if SMART_PAYLOAD_ORDERING else 'No'}")
        print()
        
        # Validate target is reachable first
        if not self.http_client.test_connection(TARGET_URL):
            print("❌ Target is not reachable. Check URL and network connection.")
            return False
        
        # Test each parameter
        for param in TEST_PARAMS:
            print(f"\n{'='*50}")
            print(f"Testing parameter: {param}")
            print(f"{'='*50}")
            
            self.test_parameter(param)
        
        self.scan_end_time = datetime.now()
        return True
    
    def test_parameter(self, param):
        """Test a specific parameter with all engines"""
        engines = [
            ("Boolean-Based", BooleanEngine()),
            ("Time-Based", TimeEngine()),
            ("Union-Based", UnionEngine()),
            ("Error-Based", ErrorEngine())
        ]
        
        for engine_name, engine in engines:
            print(f"\n⚡ Running {engine_name} SQLi...")
            try:
                result = engine.test(param, TARGET_URL)
                if result and result.get('vulnerable', False):
                    print(f"✅ {engine_name} - VULNERABLE")
                    self.results.append({
                        'parameter': param,
                        'engine': engine_name,
                        'status': 'VULNERABLE',
                        'payload': result['payload'],
                        'evidence': result.get('evidence', ''),
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                else:
                    print(f"❌ {engine_name} - Not vulnerable")
            except Exception as e:
                print(f"⚠️  {engine_name} - Error: {str(e)}")
    
    def generate_report(self):
        """Generate vulnerability reports"""
        print(f"\n{'='*60}")
        print("📊 SQL INJECTION TEST REPORT")
        print(f"{'='*60}")
        
        vulnerable_params = [r for r in self.results if r['status'] == 'VULNERABLE']
        
        if vulnerable_params:
            print(f"🚨 VULNERABILITIES FOUND: {len(vulnerable_params)}")
            for vuln in vulnerable_params:
                print(f"\n• Parameter: {vuln['parameter']}")
                print(f"  Type: {vuln['engine']}")
                print(f"  Payload: {vuln['payload']}")
                if vuln.get('evidence'):
                    print(f"  Evidence: {vuln['evidence']}")
        else:
            print("✅ No SQL injection vulnerabilities detected")
        
        # Generate HTML report
        html_report = HTMLReporter.generate_report(
            target_url=TARGET_URL,
            results=self.results,
            start_time=self.scan_start_time,
            end_time=self.scan_end_time
        )
        
        print(f"\n📈 Summary:")
        print(f"   Total tests executed: {len(self.results)}")
        print(f"   Vulnerabilities found: {len(vulnerable_params)}")
        print(f"   HTML Report: scan_report.html")
        
        return html_report

def main():
    """Main execution function"""
    automator = SQLiAutomator()
    
    try:
        success = automator.run_full_test()
        if success:
            automator.generate_report()
    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user")
    except Exception as e:
        print(f"\n💥 Error during scan: {str(e)}")

if __name__ == "__main__":
    main()