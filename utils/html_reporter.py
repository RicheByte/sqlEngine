"""
HTML Report Generator for SQL Injection Scan Results
"""

import os
import json
from datetime import datetime

class HTMLReporter:
    @staticmethod
    def generate_report(target_url, results, start_time, end_time, filename="scan_report.html"):
        """Generate comprehensive HTML report"""
        
        vulnerable_results = [r for r in results if r['status'] == 'VULNERABLE']
        scan_duration = end_time - start_time if end_time and start_time else None
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2.5em;
        }}
        
        .header .subtitle {{
            color: #7f8c8d;
            font-size: 1.2em;
        }}
        
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .card {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .card.vulnerable {{
            border-left: 5px solid #e74c3c;
        }}
        
        .card.safe {{
            border-left: 5px solid #2ecc71;
        }}
        
        .card.info {{
            border-left: 5px solid #3498db;
        }}
        
        .card h3 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        
        .card.vulnerable h3 {{
            color: #e74c3c;
        }}
        
        .card.safe h3 {{
            color: #2ecc71;
        }}
        
        .card.info h3 {{
            color: #3498db;
        }}
        
        .vulnerabilities {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            overflow: hidden;
            margin-bottom: 30px;
        }}
        
        .vulnerabilities h2 {{
            background: #2c3e50;
            color: white;
            padding: 20px;
            margin: 0;
        }}
        
        .vuln-list {{
            padding: 0;
        }}
        
        .vuln-item {{
            padding: 20px;
            border-bottom: 1px solid #ecf0f1;
            transition: background 0.3s;
        }}
        
        .vuln-item:hover {{
            background: #f8f9fa;
        }}
        
        .vuln-item:last-child {{
            border-bottom: none;
        }}
        
        .vuln-parameter {{
            font-weight: bold;
            color: #e74c3c;
            font-size: 1.1em;
        }}
        
        .vuln-type {{
            color: #3498db;
            margin: 5px 0;
        }}
        
        .vuln-payload {{
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            margin: 10px 0;
            border-left: 3px solid #e74c3c;
        }}
        
        .vuln-evidence {{
            color: #7f8c8d;
            font-style: italic;
        }}
        
        .no-vulns {{
            text-align: center;
            padding: 40px;
            color: #7f8c8d;
        }}
        
        .scan-info {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        
        .info-item {{
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        
        .info-label {{
            font-weight: bold;
            color: #2c3e50;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 30px;
            color: white;
            padding: 20px;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            
            .header h1 {{
                font-size: 2em;
            }}
            
            .summary-cards {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 SQL Injection Scan Report</h1>
            <div class="subtitle">Comprehensive Security Assessment Results</div>
        </div>
        
        <div class="summary-cards">
            <div class="card {'vulnerable' if vulnerable_results else 'safe'}">
                <h3>{len(vulnerable_results)}</h3>
                <p>Vulnerabilities Found</p>
            </div>
            <div class="card info">
                <h3>{len(results)}</h3>
                <p>Total Tests Executed</p>
            </div>
            <div class="card info">
                <h3>{scan_duration.total_seconds() if scan_duration else 0:.1f}s</h3>
                <p>Scan Duration</p>
            </div>
            <div class="card {'vulnerable' if vulnerable_results else 'safe'}">
                <h3>{'🚨' if vulnerable_results else '✅'}</h3>
                <p>{'Security Risk' if vulnerable_results else 'All Clear'}</p>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2>📋 Vulnerability Details</h2>
            <div class="vuln-list">
        """
        
        if vulnerable_results:
            for vuln in vulnerable_results:
                html_content += f"""
                <div class="vuln-item">
                    <div class="vuln-parameter">Parameter: {vuln['parameter']}</div>
                    <div class="vuln-type">Type: {vuln['engine']} SQL Injection</div>
                    <div class="vuln-payload">{vuln['payload']}</div>
                    <div class="vuln-evidence">{vuln.get('evidence', 'No additional evidence')}</div>
                    <div class="vuln-timestamp">Detected: {vuln.get('timestamp', 'Unknown')}</div>
                </div>
                """
        else:
            html_content += """
                <div class="no-vulns">
                    <h3>✅ No SQL Injection Vulnerabilities Detected</h3>
                    <p>All tested parameters appear to be secure against SQL injection attacks.</p>
                </div>
            """
        
        html_content += f"""
            </div>
        </div>
        
        <div class="scan-info">
            <h2>🔧 Scan Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Target URL</div>
                    <div>{target_url}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Scan Started</div>
                    <div>{start_time.strftime('%Y-%m-%d %H:%M:%S') if start_time else 'Unknown'}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Scan Completed</div>
                    <div>{end_time.strftime('%Y-%m-%d %H:%M:%S') if end_time else 'Unknown'}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Scan Duration</div>
                    <div>{scan_duration.total_seconds() if scan_duration else 0:.2f} seconds</div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by SQL Injection Automator • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>For educational and authorized testing purposes only</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Write HTML file
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filename