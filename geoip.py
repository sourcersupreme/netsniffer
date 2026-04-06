import geoip2.database
from config import GEOIP_DB

try:
    reader = geoip2.database.Reader(GEOIP_DB)
except FileNotFoundError:
    print("[ERROR] GeoIP database not found. Location tracking disabled.")
    reader = None

def get_location(ip):
    if reader is None:
        return "GeoIP Disabled"
    try:
        response = reader.city(ip)
        return f"{response.country.name}, {response.city.name}"
    except:
        return "Unknown"
