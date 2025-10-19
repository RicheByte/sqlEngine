"""
HTTP Client for making web requests
"""

import requests
import urllib3
from config import REQUEST_TIMEOUT, USER_AGENT, MAX_RETRIES

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HttpClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })
    
    def test_connection(self, url):
        """Test if target is reachable"""
        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT, verify=False)
            return response.status_code < 500
        except:
            return False
    
    def get(self, url, params=None, timeout=REQUEST_TIMEOUT):
        """Make GET request"""
        for attempt in range(MAX_RETRIES):
            try:
                response = self.session.get(
                    url, 
                    params=params, 
                    timeout=timeout,
                    verify=False  # For testing purposes only
                )
                return response.text
            except requests.exceptions.Timeout:
                if attempt == MAX_RETRIES - 1:
                    raise
                continue
            except requests.RequestException as e:
                if attempt == MAX_RETRIES - 1:
                    return None
                continue
        return None
    
    def post(self, url, data=None, timeout=REQUEST_TIMEOUT):
        """Make POST request"""
        for attempt in range(MAX_RETRIES):
            try:
                response = self.session.post(
                    url, 
                    data=data, 
                    timeout=timeout,
                    verify=False  # For testing purposes only
                )
                return response.text
            except requests.exceptions.Timeout:
                if attempt == MAX_RETRIES - 1:
                    raise
                continue
            except requests.RequestException as e:
                if attempt == MAX_RETRIES - 1:
                    return None
                continue
        return None