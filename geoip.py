import geoip2.database
from config import GEOIP_DB

reader = geoip2.database.Reader(GEOIP_DB)

def get_location(ip):
    try:
        response = reader.city(ip)
        return f"{response.country.name}, {response.city.name}"
    except:
        return "Unknown"
