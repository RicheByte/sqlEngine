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
BOOLEAN_DIFFERENCE_THRESHOLD = 0.2  # Content difference threshold (lowered for better detection)

# Payload configurations
MAX_PAYLOADS_PER_TEST = None  # None = no limit, use all payloads from file
SKIP_DUPLICATE_PAYLOADS = True  # Automatically remove duplicates
PAYLOAD_ENCODING = 'utf-8'  # Encoding for payload files
ALLOW_CUSTOM_PAYLOADS = True  # Allow inline payload definitions

# Advanced payload options
NORMALIZE_PAYLOADS = True  # Normalize whitespace and clean payloads
SMART_PAYLOAD_ORDERING = True  # Order payloads by effectiveness (simple first, complex later)

# Report configuration
REPORT_TITLE = "SQL Injection Scan Report"
COMPANY_NAME = "Security Team"

# Security (for testing purposes only - understand the risks)
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')