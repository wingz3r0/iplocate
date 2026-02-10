#!/usr/bin/env python3
"""IP Geolocation & Ownership Lookup Tool.

Reads IPs from a CSV, enriches each with GeoLite2 geolocation + RDAP ownership
data, and writes results to an output CSV.
"""

import argparse
import csv
import ipaddress
import json
import os
import socket
import sys
import time
import xml.etree.ElementTree as ET

import geoip2.database
import geoip2.errors
import requests
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "data")

CITY_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb"
ASN_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb"

CITY_DB_FILE = "GeoLite2-City.mmdb"
ASN_DB_FILE = "GeoLite2-ASN.mmdb"

IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org"
IP_API_MIN_INTERVAL = 60.0 / 45  # 45 requests per minute

GEO_COLUMNS = [
    "geo_country_code",
    "geo_country",
    "geo_region",
    "geo_city",
    "geo_latitude",
    "geo_longitude",
    "geo_accuracy_radius_km",
    "geo_postal_code",
    "geo_asn",
    "geo_asn_org",
]

RDAP_COLUMNS = [
    "rdap_asn",
    "rdap_asn_description",
    "rdap_asn_cidr",
    "rdap_network_name",
    "rdap_network_cidr",
    "rdap_network_country",
    "rdap_org_name",
    "rdap_abuse_email",
    "rdap_abuse_phone",
    "rdap_registry",
]

RDNS_COLUMNS = ["rdns_hostname"]

ABUSE_COLUMNS = [
    "abuse_score",
    "abuse_reports",
    "abuse_usage_type",
    "abuse_is_tor",
    "abuse_domain",
]

# Usage types from AbuseIPDB that indicate residential/individual ISP customers
RESIDENTIAL_USAGE_TYPES = {
    "isp",
    "fixed line isp",
    "mobile isp",
}

# Usage types to exclude (datacenters, commercial, etc.)
NON_RESIDENTIAL_USAGE_TYPES = {
    "data center/web hosting/transit",
    "datacenter",
    "data center",
    "web hosting",
    "hosting",
    "content delivery network",
    "cdn",
    "commercial",
    "business",
    "corporate",
    "government",
    "military",
    "university/college/school",
    "library",
    "search engine spider",
    "reserved",
}

# Known datacenter/cloud/scanner/VPN ASNs to exclude
# These are ASNs commonly associated with automated scanning, cloud infrastructure, or VPNs
DATACENTER_ASNS = {
    # ==================== Major Cloud Providers ====================
    # Amazon/AWS
    16509, 14618, 7224, 8987, 10124, 38895, 58588, 62785, 39111,

    # Google Cloud / Google
    15169, 396982, 36039, 36040, 36384, 36385, 36411, 36412, 36561,
    36959, 37369, 39112, 39113, 41264, 43515, 55023, 139070, 139190,

    # Microsoft Azure / Microsoft
    8075, 8068, 8069, 8070, 8071, 8072, 8073, 8074, 12076, 23468,
    35106, 45139, 52985, 58862, 59067, 200517,

    # Oracle Cloud
    31898, 40627,

    # IBM Cloud / Softlayer
    36351, 11798,

    # Alibaba Cloud
    45102, 37963, 45096, 24429, 136907, 134963, 45094,

    # Tencent Cloud
    45090, 132203, 132591,

    # ==================== VPS / Hosting Providers ====================
    # DigitalOcean
    14061, 393406, 202109, 202425,

    # Linode / Akamai
    63949, 48337, 20940, 16625, 12222, 18717, 35994, 35993, 21342,
    21399, 22207, 23454, 23455, 24319, 30675, 31107, 31108, 31109,
    31110, 32787, 33905, 34164, 34850, 35204, 36183, 39836, 43639,
    55429, 55770, 133103, 136292, 200005, 200006, 393560,

    # Vultr / Choopa
    20473, 64515,

    # Hetzner
    24940, 213230, 212317,

    # OVH / OVHcloud
    16276, 35540, 44788,

    # Contabo
    51167, 40021,

    # Scaleway / Online.net
    12876, 62000,

    # UpCloud
    202053,

    # LeaseWeb
    60781, 28753, 16265, 30633, 38930, 59253, 131477, 394380,

    # Rackspace
    27357, 33070, 45187, 54527, 19994, 10532,

    # Equinix / Packet
    54825,

    # Hostinger
    47583, 59311,

    # DreamHost
    26347,

    # Liquid Web
    32244, 18978,

    # InMotion Hosting
    33182,

    # Bluehost / Endurance
    46606, 26496, 53831,

    # GoDaddy
    398101, 21501, 33182, 46606,

    # Namecheap
    22612,

    # HostGator
    21844,

    # SiteGround
    395978, 198605,

    # A2 Hosting
    55293,

    # Ionos / 1&1
    8560, 8972,

    # Fasthosts
    20738,

    # ==================== European / Global Hosting ====================
    # Serverius
    50673,

    # Leaseweb
    60781,

    # NFOrce
    43350,

    # WorldStream
    49981,

    # Selectel
    49505,

    # TimeWeb
    9123,

    # Reg.ru
    197695,

    # FirstByte
    203214,

    # ==================== CDN Providers ====================
    # Cloudflare
    13335, 209242, 394536, 132892,

    # Fastly
    54113,

    # KeyCDN
    200325,

    # StackPath / Highwinds
    33438, 12989,

    # BunnyCDN
    45102,

    # CDNetworks
    36408,

    # CacheFly
    30081,

    # jsDelivr (uses multiple)
    34164,

    # ==================== Known Scanners ====================
    # Censys
    398324, 398705,

    # Shodan
    20473,  # Uses Vultr primarily

    # Shadowserver
    25795, 54290,

    # Rapid7 / Project Sonar
    19905,

    # Stretchoid
    398722,

    # Bitsight / SecurityScorecard scanners
    395747, 40676,

    # Binary Edge
    206728,

    # GreyNoise
    396507,

    # Recyber
    210749,

    # Internet Census / Research scanners
    262287,

    # ==================== VPN Providers ====================
    # M247 (NordVPN, Surfshark, Atlas, etc.)
    9009, 208312,

    # Datacamp Limited (VPN infrastructure)
    212238, 60068,

    # Private Internet Access
    19437,

    # ExpressVPN
    394711, 206092,

    # IPVanish
    40156,

    # CyberGhost
    202422, 9009,

    # Mullvad
    198093,

    # ProtonVPN
    209103, 62371,

    # Windscribe
    395502,

    # HideMyAss
    196752,

    # TunnelBear
    52191,

    # VyprVPN / Golden Frog
    30668,

    # StrongVPN
    8100,

    # TorGuard
    52338,

    # AirVPN
    205851,

    # IVPN
    398435,

    # Astrill
    132779,

    # Hotspot Shield
    40034,

    # ZenMate
    62082,

    # Trust.Zone
    44477,

    # PureVPN
    138915,

    # Norton VPN / Symantec
    21345,

    # ==================== Tor / Anonymity ====================
    # Known Tor-friendly hosting
    51396, 60729, 200052, 213035,

    # ==================== Bot / Proxy Networks ====================
    # Bright Data (Luminati)
    42831,

    # Oxylabs
    44050,

    # Smartproxy
    209605,

    # ==================== Specialty Hosting / Bulletproof ====================
    # FranTech / BuyVM
    53667, 25820,

    # GTHost
    62563,

    # Njalla
    207942,

    # FlokiNET
    200651,

    # Shinjiru
    45815,

    # WebNX
    18450,

    # Psychz Networks
    40676,

    # ColoCrossing
    36352,

    # QuadraNet
    8100,

    # DataShack
    33387,

    # Secured Servers
    32475,

    # HostDime
    33182,

    # ==================== Enterprise / Corporate (often used for scanning) ====================
    # Palo Alto Networks
    27134,

    # Qualys
    36389,

    # Tenable
    393949,

    # Recorded Future
    395954,

    # ==================== Additional Data Centers ====================
    # Cogent
    174,

    # Hurricane Electric
    6939,

    # Zayo
    6461,

    # GTT
    3257,

    # NTT
    2914,

    # Telia
    1299,

    # PCCW
    3491,

    # Seabone / TIM
    6762,

    # Tata
    6453,

    # PacketFabric
    4556,

    # CoreSite
    19165,

    # CyrusOne
    395829,

    # QTS
    40913,

    # DataBank
    46562,

    # vXchnge
    40805,

    # ==================== Russian / Eastern European Hosting ====================
    # Rostelecom (hosting division)
    12389,

    # REG.RU
    197695,

    # TimeWeb
    9123,

    # Selectel
    49505,

    # RUVDS
    48282,

    # ==================== Asian Hosting ====================
    # SAKURA Internet
    7684,

    # GMO Internet
    7506,

    # NAVER Cloud
    23576,

    # Kakao (IDC)
    38099,

    # NHN Cloud
    38661,

    # ==================== Research / Academic (often scanning) ====================
    # RIPE NCC
    3333,

    # APNIC
    4608,

    # ARIN
    393225,

    # Various university research networks
    786, 2381, 11164,
}

IP_COLUMN_HINTS = {"ip", "ip_address", "ipaddress", "ip_addr", "ipaddr", "address", "src_ip", "dst_ip", "source_ip", "dest_ip"}


def download_db(url, dest_path):
    """Download a file from url to dest_path with progress output."""
    filename = os.path.basename(dest_path)
    print(f"Downloading {filename}...", file=sys.stderr)
    resp = requests.get(url, stream=True, timeout=120, allow_redirects=True)
    resp.raise_for_status()
    total = int(resp.headers.get("content-length", 0))
    downloaded = 0
    with open(dest_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)
            downloaded += len(chunk)
            if total:
                pct = downloaded * 100 // total
                print(f"\r  {filename}: {pct}% ({downloaded}/{total} bytes)", end="", file=sys.stderr)
    print(file=sys.stderr)
    print(f"  Saved to {dest_path}", file=sys.stderr)


def ensure_databases(city_db, asn_db, force_update):
    """Ensure GeoLite2 databases exist, downloading if needed.

    Returns (city_db_path, asn_db_path).
    """
    os.makedirs(DATA_DIR, exist_ok=True)

    if city_db is None:
        city_db = os.path.join(DATA_DIR, CITY_DB_FILE)
    if asn_db is None:
        asn_db = os.path.join(DATA_DIR, ASN_DB_FILE)

    if force_update or not os.path.isfile(city_db):
        download_db(CITY_DB_URL, city_db)
    if force_update or not os.path.isfile(asn_db):
        download_db(ASN_DB_URL, asn_db)

    return city_db, asn_db


def detect_ip_column(reader, fieldnames):
    """Auto-detect which column contains IP addresses.

    Samples up to 5 rows and tests each column with ipaddress.ip_address().
    Falls back to header name heuristics.
    """
    rows = []
    for i, row in enumerate(reader):
        rows.append(row)
        if i >= 4:
            break

    if not rows:
        print("Error: input CSV has no data rows.", file=sys.stderr)
        sys.exit(1)

    # Try each column: count how many sample values parse as IPs
    best_col = None
    best_count = 0
    for col in fieldnames:
        count = 0
        for row in rows:
            val = row.get(col, "").strip()
            if val:
                try:
                    ipaddress.ip_address(val)
                    count += 1
                except ValueError:
                    pass
        if count > best_count:
            best_count = count
            best_col = col

    if best_col and best_count > 0:
        return best_col, rows

    # Fallback: header name heuristics
    for col in fieldnames:
        if col.strip().lower() in IP_COLUMN_HINTS:
            return col, rows

    print("Error: could not auto-detect IP column. Use --ip-column to specify.", file=sys.stderr)
    sys.exit(1)


def is_private_ip(ip_str):
    """Check if an IP address is private or reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_reserved or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def is_residential_ip(row, abuse_threshold=25, check_asn=True, check_usage_type=True, check_tor=True):
    """Check if an IP appears to be from a residential ISP (individual user).

    Returns (is_residential, reason) tuple.
    - is_residential: True if IP appears residential, False otherwise
    - reason: String explaining why IP was filtered (empty if residential)
    """
    # Check abuse score
    abuse_score = row.get("abuse_score", "")
    if abuse_score != "" and abuse_score is not None:
        try:
            if int(abuse_score) > abuse_threshold:
                return False, f"high abuse score ({abuse_score})"
        except (ValueError, TypeError):
            pass

    # Check if Tor exit node
    if check_tor:
        is_tor = row.get("abuse_is_tor", "")
        if is_tor is True or str(is_tor).lower() == "true":
            return False, "Tor exit node"

    # Check usage type from AbuseIPDB
    if check_usage_type:
        usage_type = row.get("abuse_usage_type", "")
        if usage_type:
            usage_lower = usage_type.lower().strip()
            # Explicit residential types pass
            if usage_lower in RESIDENTIAL_USAGE_TYPES:
                pass  # OK, continue checks
            # Explicit non-residential types fail
            elif any(nrt in usage_lower for nrt in NON_RESIDENTIAL_USAGE_TYPES):
                return False, f"non-residential usage type ({usage_type})"

    # Check ASN against known datacenter/cloud/VPN ASNs
    if check_asn:
        for asn_field in ["geo_asn", "rdap_asn"]:
            asn_val = row.get(asn_field, "")
            if asn_val != "" and asn_val is not None:
                try:
                    asn_int = int(asn_val)
                    if asn_int in DATACENTER_ASNS:
                        return False, f"datacenter/cloud/VPN ASN ({asn_int})"
                except (ValueError, TypeError):
                    pass

    return True, ""


def geo_lookup(city_reader, asn_reader, ip_str):
    """Perform GeoLite2 City + ASN lookup. Returns a dict of geo columns."""
    result = {col: "" for col in GEO_COLUMNS}

    if is_private_ip(ip_str):
        result["geo_country"] = "PRIVATE/RESERVED"
        return result

    try:
        city = city_reader.city(ip_str)
        result["geo_country_code"] = city.country.iso_code or ""
        result["geo_country"] = city.country.name or ""
        if city.subdivisions.most_specific and city.subdivisions.most_specific.name:
            result["geo_region"] = city.subdivisions.most_specific.name
        result["geo_city"] = city.city.name or ""
        result["geo_latitude"] = city.location.latitude if city.location.latitude is not None else ""
        result["geo_longitude"] = city.location.longitude if city.location.longitude is not None else ""
        result["geo_accuracy_radius_km"] = city.location.accuracy_radius if city.location.accuracy_radius is not None else ""
        result["geo_postal_code"] = city.postal.code or ""
    except geoip2.errors.AddressNotFoundError:
        pass

    try:
        asn = asn_reader.asn(ip_str)
        result["geo_asn"] = asn.autonomous_system_number if asn.autonomous_system_number is not None else ""
        result["geo_asn_org"] = asn.autonomous_system_organization or ""
    except geoip2.errors.AddressNotFoundError:
        pass

    return result


def ip_api_refine(geo, ip_str, last_call_time):
    """Refine geo results using ip-api.com when GeoLite2 is too broad.

    Called when city is missing or accuracy_radius >= 100km.
    Returns (updated_geo, new_last_call_time).
    """
    # Enforce rate limit (45 req/min)
    now = time.time()
    elapsed = now - last_call_time
    if elapsed < IP_API_MIN_INTERVAL:
        time.sleep(IP_API_MIN_INTERVAL - elapsed)

    try:
        resp = requests.get(
            IP_API_URL.format(ip=ip_str),
            timeout=10,
        )
        last_call_time = time.time()
        data = resp.json()

        if data.get("status") != "success":
            return geo, last_call_time

        if not geo["geo_city"] and data.get("city"):
            geo["geo_city"] = data["city"]
        if not geo["geo_region"] and data.get("regionName"):
            geo["geo_region"] = data["regionName"]
        if not geo["geo_country"] and data.get("country"):
            geo["geo_country"] = data["country"]
        if not geo["geo_country_code"] and data.get("countryCode"):
            geo["geo_country_code"] = data["countryCode"]
        if not geo["geo_postal_code"] and data.get("zip"):
            geo["geo_postal_code"] = data["zip"]
        # Overwrite lat/lon when GeoLite2 was very broad
        if data.get("lat") is not None and data.get("lon") is not None:
            radius = geo["geo_accuracy_radius_km"]
            if (not geo["geo_city"]) or (radius and int(radius) >= 100):
                geo["geo_latitude"] = data["lat"]
                geo["geo_longitude"] = data["lon"]
                geo["geo_accuracy_radius_km"] = ""

    except Exception as e:
        print(f"  ip-api.com error for {ip_str}: {e}", file=sys.stderr)

    return geo, last_call_time


def rdap_lookup(ip_str, pause, max_retries=3):
    """Perform RDAP lookup via ipwhois. Returns a dict of RDAP columns."""
    result = {col: "" for col in RDAP_COLUMNS}

    if is_private_ip(ip_str):
        return result

    for attempt in range(max_retries):
        try:
            obj = IPWhois(ip_str)
            data = obj.lookup_rdap(depth=1)

            result["rdap_asn"] = data.get("asn", "") or ""
            result["rdap_asn_description"] = data.get("asn_description", "") or ""
            result["rdap_asn_cidr"] = data.get("asn_cidr", "") or ""
            result["rdap_registry"] = data.get("asn_registry", "") or ""

            network = data.get("network", {}) or {}
            result["rdap_network_name"] = network.get("name", "") or ""
            result["rdap_network_cidr"] = network.get("cidr", "") or ""
            result["rdap_network_country"] = network.get("country", "") or ""

            # Extract org and abuse contact from objects
            objects = data.get("objects", {}) or {}
            for handle, obj_data in objects.items():
                if not obj_data:
                    continue
                contact = obj_data.get("contact", {}) or {}

                # Org name
                if not result["rdap_org_name"] and contact.get("name"):
                    result["rdap_org_name"] = contact["name"]

                # Abuse email and phone
                roles = obj_data.get("roles", []) or []
                if "abuse" in roles:
                    for entry in contact.get("email", []) or []:
                        if entry.get("value") and not result["rdap_abuse_email"]:
                            result["rdap_abuse_email"] = entry["value"]
                    for entry in contact.get("phone", []) or []:
                        if entry.get("value") and not result["rdap_abuse_phone"]:
                            result["rdap_abuse_phone"] = entry["value"]

            return result

        except IPDefinedError:
            # Private/reserved IP — shouldn't reach here but handle gracefully
            return result
        except Exception as e:
            err_str = str(e).lower()
            if "429" in err_str or "rate" in err_str:
                wait = pause * (2 ** attempt)
                print(f"  Rate limited, retrying in {wait:.1f}s...", file=sys.stderr)
                time.sleep(wait)
                continue
            print(f"  RDAP error for {ip_str}: {e}", file=sys.stderr)
            return result

    print(f"  RDAP failed after {max_retries} retries for {ip_str}", file=sys.stderr)
    return result


def rdns_lookup(ip_str):
    """Perform reverse DNS lookup. Returns a dict with rdns_hostname."""
    result = {"rdns_hostname": ""}
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        result["rdns_hostname"] = hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        pass
    return result


def abuseipdb_lookup(ip_str, api_key, max_retries=3):
    """Query AbuseIPDB v2 API for abuse data. Returns a dict of abuse columns."""
    result = {col: "" for col in ABUSE_COLUMNS}

    if is_private_ip(ip_str):
        return result

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_str}&maxAgeInDays=90"
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }

    for attempt in range(max_retries):
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 429:
                wait = 2 ** (attempt + 1)
                print(f"  AbuseIPDB rate limited, retrying in {wait}s...", file=sys.stderr)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            data = resp.json().get("data", {})
            result["abuse_score"] = data.get("abuseConfidenceScore", "")
            result["abuse_reports"] = data.get("totalReports", "")
            result["abuse_usage_type"] = data.get("usageType", "") or ""
            result["abuse_is_tor"] = data.get("isTor", "")
            result["abuse_domain"] = data.get("domain", "") or ""
            return result
        except requests.exceptions.HTTPError as e:
            print(f"  AbuseIPDB error for {ip_str}: {e}", file=sys.stderr)
            return result
        except Exception as e:
            print(f"  AbuseIPDB error for {ip_str}: {e}", file=sys.stderr)
            return result

    print(f"  AbuseIPDB failed after {max_retries} retries for {ip_str}", file=sys.stderr)
    return result


def _clean_row(row):
    """Convert empty strings to None for JSON-based outputs."""
    return {k: (None if v == "" else v) for k, v in row.items()}


def write_csv(rows, out_fields, output_path):
    """Write results as CSV."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=out_fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_json(rows, output_path):
    """Write results as a JSON array."""
    cleaned = [_clean_row(r) for r in rows]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(cleaned, f, indent=2, ensure_ascii=False)
        f.write("\n")


def write_jsonl(rows, output_path):
    """Write results as JSON Lines (one JSON object per line)."""
    with open(output_path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(_clean_row(row), ensure_ascii=False) + "\n")


def write_geojson(rows, ip_col, output_path):
    """Write results as a GeoJSON FeatureCollection with Point geometries."""
    features = []
    for row in rows:
        props = _clean_row(row)
        lat = row.get("geo_latitude", "")
        lon = row.get("geo_longitude", "")
        if lat != "" and lon != "":
            try:
                geometry = {
                    "type": "Point",
                    "coordinates": [float(lon), float(lat)],
                }
            except (ValueError, TypeError):
                geometry = None
        else:
            geometry = None
        features.append({
            "type": "Feature",
            "geometry": geometry,
            "properties": props,
        })
    collection = {
        "type": "FeatureCollection",
        "features": features,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(collection, f, indent=2, ensure_ascii=False)
        f.write("\n")


def write_kml(rows, ip_col, output_path):
    """Write results as KML with Placemarks."""
    kml_ns = "http://www.opengis.net/kml/2.2"
    kml = ET.Element("kml", xmlns=kml_ns)
    doc = ET.SubElement(kml, "Document")
    name_el = ET.SubElement(doc, "name")
    name_el.text = "IP Geolocation Results"

    for row in rows:
        pm = ET.SubElement(doc, "Placemark")
        pm_name = ET.SubElement(pm, "name")
        pm_name.text = row.get(ip_col, "unknown")

        lat = row.get("geo_latitude", "")
        lon = row.get("geo_longitude", "")
        if lat != "" and lon != "":
            try:
                point = ET.SubElement(pm, "Point")
                coords = ET.SubElement(point, "coordinates")
                coords.text = f"{float(lon)},{float(lat)},0"
            except (ValueError, TypeError):
                pass

        ext = ET.SubElement(pm, "ExtendedData")
        for key, val in row.items():
            if key in (ip_col, "geo_latitude", "geo_longitude"):
                continue
            data_el = ET.SubElement(ext, "Data", name=key)
            val_el = ET.SubElement(data_el, "value")
            val_el.text = str(val) if val != "" else ""

    tree = ET.ElementTree(kml)
    ET.indent(tree, space="  ")
    tree.write(output_path, encoding="unicode", xml_declaration=True)


# Friendly display labels for record-block text output
_FIELD_LABELS = {
    "rdns_hostname": "rDNS Hostname",
    "geo_country_code": "Country Code",
    "geo_country": "Country",
    "geo_region": "Region",
    "geo_city": "City",
    "geo_latitude": "Latitude",
    "geo_longitude": "Longitude",
    "geo_accuracy_radius_km": "Accuracy Radius (km)",
    "geo_postal_code": "Postal Code",
    "geo_asn": "ASN",
    "geo_asn_org": "ASN Org",
    "rdap_asn": "RDAP ASN",
    "rdap_asn_description": "RDAP ASN Description",
    "rdap_asn_cidr": "RDAP ASN CIDR",
    "rdap_network_name": "Network Name",
    "rdap_network_cidr": "Network CIDR",
    "rdap_network_country": "Network Country",
    "rdap_org_name": "Org Name",
    "rdap_abuse_email": "Abuse Email",
    "rdap_abuse_phone": "Abuse Phone",
    "rdap_registry": "Registry",
    "abuse_score": "Abuse Score",
    "abuse_reports": "Abuse Reports",
    "abuse_usage_type": "Usage Type",
    "abuse_is_tor": "Is Tor",
    "abuse_domain": "Domain",
    "lookup_error": "Error",
}


def write_txt(rows, ip_col, output_path):
    """Write results as human-readable record blocks."""
    with open(output_path, "w", encoding="utf-8") as f:
        for idx, row in enumerate(rows):
            ip_str = row.get(ip_col, "unknown")
            f.write(f"{'=' * 60}\n")
            f.write(f"  {ip_str}\n")
            f.write(f"{'=' * 60}\n")

            # Original columns (excluding IP and enrichment columns)
            original_keys = [k for k in row if k not in GEO_COLUMNS
                             and k not in RDAP_COLUMNS and k not in RDNS_COLUMNS
                             and k not in ABUSE_COLUMNS and k != "lookup_error"
                             and k != ip_col]
            if original_keys:
                for key in original_keys:
                    val = row.get(key, "")
                    label = key.replace("_", " ").title()
                    if val != "":
                        f.write(f"  {label:<24} {val}\n")

            # rDNS section
            rdns_val = row.get("rdns_hostname", "")
            if rdns_val:
                f.write(f"\n  --- Reverse DNS ---\n")
                label = _FIELD_LABELS.get("rdns_hostname", "rDNS Hostname")
                f.write(f"  {label:<24} {rdns_val}\n")

            # Geo section
            geo_vals = {k: row.get(k, "") for k in GEO_COLUMNS}
            if any(v != "" for v in geo_vals.values()):
                f.write(f"\n  --- Geolocation ---\n")
                for key in GEO_COLUMNS:
                    val = row.get(key, "")
                    if val != "":
                        label = _FIELD_LABELS.get(key, key)
                        f.write(f"  {label:<24} {val}\n")

            # RDAP section
            rdap_vals = {k: row.get(k, "") for k in RDAP_COLUMNS}
            if any(v != "" for v in rdap_vals.values()):
                f.write(f"\n  --- RDAP Ownership ---\n")
                for key in RDAP_COLUMNS:
                    val = row.get(key, "")
                    if val != "":
                        label = _FIELD_LABELS.get(key, key)
                        f.write(f"  {label:<24} {val}\n")

            # Threat Intelligence section (AbuseIPDB)
            abuse_vals = {k: row.get(k, "") for k in ABUSE_COLUMNS}
            if any(v != "" for v in abuse_vals.values()):
                f.write(f"\n  --- Threat Intelligence ---\n")
                for key in ABUSE_COLUMNS:
                    val = row.get(key, "")
                    if val != "":
                        label = _FIELD_LABELS.get(key, key)
                        f.write(f"  {label:<24} {val}\n")

            # Error
            error = row.get("lookup_error", "")
            if error:
                f.write(f"\n  ** Error: {error}\n")

            f.write("\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="IP Geolocation & Ownership Lookup Tool. "
                    "Enriches IPs from a CSV with GeoLite2 geolocation and RDAP ownership data."
    )
    parser.add_argument("-i", "--input", required=True, help="Input CSV file with IP addresses")
    parser.add_argument("-o", "--output", required=True, help="Output file path")
    parser.add_argument("-f", "--format", default="csv", choices=["csv", "json", "jsonl", "geojson", "kml", "txt"],
                        help="Output format (default: csv)")
    parser.add_argument("-d", "--db", default=None, help="Path to GeoLite2-City.mmdb (auto-downloaded if omitted)")
    parser.add_argument("--asn-db", default=None, help="Path to GeoLite2-ASN.mmdb (auto-downloaded if omitted)")
    parser.add_argument("--ip-column", default=None, help="Name of IP column (auto-detected if omitted)")
    parser.add_argument("--rdap-pause", type=float, default=1.0, help="Seconds between RDAP lookups (default: 1.0)")
    parser.add_argument("--skip-rdap", action="store_true", help="Skip RDAP lookups (geo-only mode)")
    parser.add_argument("--skip-rdns", action="store_true", help="Skip reverse DNS hostname lookups")
    parser.add_argument("--abuseipdb-key", default=None, help="AbuseIPDB API key (enables threat checks)")
    parser.add_argument("--dedupe", action="store_true", help="Skip lookups for duplicate IPs (use cached results)")
    parser.add_argument("--no-refine", action="store_true", help="Skip ip-api.com fallback for broad geolocations")
    parser.add_argument("--update-db", action="store_true", help="Force re-download of GeoLite2 databases")

    # Residential/legitimacy filtering options
    parser.add_argument("--residential-only", action="store_true",
                        help="Only output IPs that appear to be from residential ISPs (requires --abuseipdb-key)")
    parser.add_argument("--abuse-threshold", type=int, default=25,
                        help="Abuse score threshold for filtering (default: 25, IPs above this are excluded)")
    parser.add_argument("--no-asn-filter", action="store_true",
                        help="Disable filtering by known datacenter/cloud/VPN ASNs")
    parser.add_argument("--no-usage-filter", action="store_true",
                        help="Disable filtering by AbuseIPDB usage type")
    parser.add_argument("--no-tor-filter", action="store_true",
                        help="Disable filtering of Tor exit nodes")
    parser.add_argument("--show-filtered", action="store_true",
                        help="Show filtered IPs in stderr output (for debugging)")
    return parser.parse_args()


def main():
    args = parse_args()

    # Validate residential-only requires abuseipdb-key for best results
    if args.residential_only and not args.abuseipdb_key:
        print("Warning: --residential-only works best with --abuseipdb-key for usage type filtering.", file=sys.stderr)
        print("         Without it, only ASN-based filtering will be applied.", file=sys.stderr)

    # Ensure databases exist
    city_db_path, asn_db_path = ensure_databases(args.db, args.asn_db, args.update_db)

    # Open database readers
    city_reader = geoip2.database.Reader(city_db_path)
    asn_reader = geoip2.database.Reader(asn_db_path)

    try:
        # Read input CSV
        with open(args.input, newline="", encoding="utf-8-sig") as infile:
            reader = csv.DictReader(infile)
            fieldnames = reader.fieldnames
            if not fieldnames:
                print("Error: input CSV has no headers.", file=sys.stderr)
                sys.exit(1)

            # Detect IP column
            if args.ip_column:
                ip_col = args.ip_column
                if ip_col not in fieldnames:
                    print(f"Error: column '{ip_col}' not found in CSV. Available: {fieldnames}", file=sys.stderr)
                    sys.exit(1)
                # Read all remaining rows
                rows = list(reader)
            else:
                ip_col, sampled_rows = detect_ip_column(reader, fieldnames)
                # Collect remaining rows after the sampled ones
                rows = sampled_rows + list(reader)

            print(f"Using IP column: '{ip_col}'", file=sys.stderr)
            total = len(rows)
            print(f"Processing {total} rows...", file=sys.stderr)

            # Build output fieldnames
            out_fields = list(fieldnames)
            if not args.skip_rdns:
                out_fields += RDNS_COLUMNS
            out_fields += GEO_COLUMNS
            if not args.skip_rdap:
                out_fields += RDAP_COLUMNS
            if args.abuseipdb_key:
                out_fields += ABUSE_COLUMNS
            out_fields.append("lookup_error")

            # Enrich all rows
            enriched = []
            filtered_count = 0
            last_api_call = 0.0
            cache = {}
            cache_hits = 0
            for i, row in enumerate(rows, 1):
                ip_str = row.get(ip_col, "").strip()
                error = ""

                # Validate IP
                valid_ip = True
                if not ip_str:
                    error = "empty IP"
                    valid_ip = False
                else:
                    try:
                        ipaddress.ip_address(ip_str)
                    except ValueError:
                        error = f"invalid IP: {ip_str}"
                        valid_ip = False

                # Check dedupe cache
                if valid_ip and args.dedupe and ip_str in cache:
                    row.update(cache[ip_str])
                    row["lookup_error"] = error

                    # Apply residential filter to cached results too
                    if args.residential_only:
                        is_res, filter_reason = is_residential_ip(
                            row,
                            abuse_threshold=args.abuse_threshold,
                            check_asn=not args.no_asn_filter,
                            check_usage_type=not args.no_usage_filter and args.abuseipdb_key,
                            check_tor=not args.no_tor_filter and args.abuseipdb_key,
                        )
                        if not is_res:
                            if args.show_filtered:
                                print(f"  [{i}/{total}] {ip_str} - FILTERED (cached): {filter_reason}", file=sys.stderr)
                            cache_hits += 1
                            continue

                    enriched.append(row)
                    cache_hits += 1
                    label = ip_str if ip_str else "(empty)"
                    print(f"  [{i}/{total}] {label} - OK (cached)", file=sys.stderr)
                    continue

                # Geo lookup
                if valid_ip:
                    geo = geo_lookup(city_reader, asn_reader, ip_str)
                else:
                    geo = {col: "" for col in GEO_COLUMNS}

                # Refine with ip-api.com if GeoLite2 result is broad
                if valid_ip and not args.no_refine and not is_private_ip(ip_str):
                    radius = geo["geo_accuracy_radius_km"]
                    needs_refine = (not geo["geo_city"]) or (radius and int(radius) >= 100)
                    if needs_refine:
                        geo, last_api_call = ip_api_refine(geo, ip_str, last_api_call)

                row.update(geo)

                # rDNS lookup
                if not args.skip_rdns:
                    if valid_ip:
                        rdns = rdns_lookup(ip_str)
                    else:
                        rdns = {col: "" for col in RDNS_COLUMNS}
                    row.update(rdns)

                # RDAP lookup
                if not args.skip_rdap:
                    if valid_ip:
                        rdap = rdap_lookup(ip_str, args.rdap_pause)
                        if i < total:
                            time.sleep(args.rdap_pause)
                    else:
                        rdap = {col: "" for col in RDAP_COLUMNS}
                    row.update(rdap)

                # AbuseIPDB lookup
                if args.abuseipdb_key:
                    if valid_ip:
                        abuse = abuseipdb_lookup(ip_str, args.abuseipdb_key)
                    else:
                        abuse = {col: "" for col in ABUSE_COLUMNS}
                    row.update(abuse)

                row["lookup_error"] = error

                # Store in dedupe cache
                if valid_ip and args.dedupe:
                    cached_fields = {}
                    for col in GEO_COLUMNS:
                        cached_fields[col] = row.get(col, "")
                    if not args.skip_rdns:
                        for col in RDNS_COLUMNS:
                            cached_fields[col] = row.get(col, "")
                    if not args.skip_rdap:
                        for col in RDAP_COLUMNS:
                            cached_fields[col] = row.get(col, "")
                    if args.abuseipdb_key:
                        for col in ABUSE_COLUMNS:
                            cached_fields[col] = row.get(col, "")
                    cache[ip_str] = cached_fields

                # Apply residential filter if enabled
                if args.residential_only and valid_ip and not is_private_ip(ip_str):
                    is_res, filter_reason = is_residential_ip(
                        row,
                        abuse_threshold=args.abuse_threshold,
                        check_asn=not args.no_asn_filter,
                        check_usage_type=not args.no_usage_filter and args.abuseipdb_key,
                        check_tor=not args.no_tor_filter and args.abuseipdb_key,
                    )
                    if not is_res:
                        filtered_count += 1
                        if args.show_filtered:
                            print(f"  [{i}/{total}] {ip_str} - FILTERED: {filter_reason}", file=sys.stderr)
                        else:
                            print(f"  [{i}/{total}] {ip_str} - filtered", file=sys.stderr)
                        continue

                enriched.append(row)

                status = "OK" if not error else error
                label = ip_str if ip_str else "(empty)"
                print(f"  [{i}/{total}] {label} - {status}", file=sys.stderr)

            # Write output in selected format
            fmt = args.format
            if fmt == "csv":
                write_csv(enriched, out_fields, args.output)
            elif fmt == "json":
                write_json(enriched, args.output)
            elif fmt == "jsonl":
                write_jsonl(enriched, args.output)
            elif fmt == "geojson":
                write_geojson(enriched, ip_col, args.output)
            elif fmt == "kml":
                write_kml(enriched, ip_col, args.output)
            elif fmt == "txt":
                write_txt(enriched, ip_col, args.output)

        done_msg = f"Done. Results written to {args.output} ({fmt})"
        if args.dedupe:
            unique_count = len(cache)
            done_msg += f" ({unique_count} unique IPs, {cache_hits} cached)"
        if args.residential_only:
            done_msg += f" [{len(enriched)} residential, {filtered_count} filtered]"
        print(done_msg, file=sys.stderr)

    finally:
        city_reader.close()
        asn_reader.close()


if __name__ == "__main__":
    main()
