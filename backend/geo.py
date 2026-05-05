import requests
from functools import lru_cache

@lru_cache(maxsize=1000)
def get_ip_geolocation(ip_address):
    """
    Fetch geolocation data for an IP address.
    Uses lru_cache to prevent repeated lookups for the same IP.
    """
    if ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("172.") or ip_address == "127.0.0.1":
        # Local IPs or test IPs can't be geolocated reliably, return mock data
        return {
            "country": "Local Network",
            "city": "Local",
            "lat": 0.0,
            "lon": 0.0
        }

    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=country,city,lat,lon,status", timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "lat": data.get("lat", 0.0),
                    "lon": data.get("lon", 0.0)
                }
    except Exception as e:
        print(f"Error fetching geolocation for {ip_address}: {e}")
        
    return {
        "country": "Unknown",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0
    }
