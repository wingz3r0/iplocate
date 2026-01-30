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
    return parser.parse_args()


def main():
    args = parse_args()

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
        print(done_msg, file=sys.stderr)

    finally:
        city_reader.close()
        asn_reader.close()


if __name__ == "__main__":
    main()
