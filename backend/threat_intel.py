import os
import requests
from functools import lru_cache

ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')
ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'

@lru_cache(maxsize=1000)
def get_abuseipdb_score(ip_address):
    """
    Fetch threat score for an IP from AbuseIPDB.
    Returns a dictionary with risk_score (0-100) and threat_tags.
    """
    # Exclude private IPs
    if ip_address.startswith(('192.168.', '10.', '172.', '127.')):
        return {"risk_score": 0, "threat_tags": ""}

    if not ABUSEIPDB_API_KEY:
        # Mock behavior if no API key is provided
        # Some mock logic for demonstration
        if ip_address in ['192.168.1.100', '10.0.0.99', '203.0.113.45']:
            return {"risk_score": 85, "threat_tags": "Mocked Malicious"}
        return {"risk_score": 0, "threat_tags": ""}

    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }

    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=querystring, timeout=3)
        if response.status_code == 200:
            data = response.json()['data']
            score = data.get('abuseConfidenceScore', 0)
            tags = "Malicious" if score > 50 else ""
            return {"risk_score": score, "threat_tags": tags}
    except Exception as e:
        print(f"Error fetching AbuseIPDB data for {ip_address}: {e}")

    return {"risk_score": 0, "threat_tags": ""}
