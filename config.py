"""
Configuration file for SQLi Automator
"""

# Target configuration
TARGET_URL = "http://testphp.vulnweb.com/listproducts.php"  # Example test site
TEST_PARAMS = ["cat", "artist", "category"]  # Parameters to test

# HTTP configuration
REQUEST_TIMEOUT = 10
USER_AGENT = "SQLi-Automator/2.0"
MAX_RETRIES = 2

# Engine configurations
TIME_DELAY_THRESHOLD = 3  # Seconds for time-based detection
BOOLEAN_DIFFERENCE_THRESHOLD = 0.3  # Content difference threshold

# Payload configurations
MAX_PAYLOADS_PER_TEST = 50  # Increased for comprehensive testing

# Report configuration
REPORT_TITLE = "SQL Injection Scan Report"
COMPANY_NAME = "Security Team"

# Security (for testing purposes only - understand the risks)
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')