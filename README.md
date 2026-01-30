# iplocate

A Python CLI tool that reads IP addresses from a CSV file, enriches each one with geolocation and network ownership data, and writes the results in your choice of output format. No MaxMind account or API key signup required.

## Features

### Geolocation Lookup
- Uses GeoLite2 City and ASN databases for local, offline IP geolocation
- Returns country, region, city, latitude/longitude, postal code, accuracy radius, ASN, and ASN organization
- Databases are automatically downloaded on first run from [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb) into a local `data/` directory and reused on subsequent runs

### Location Refinement
- When GeoLite2 returns broad results (no city or accuracy radius >= 100km), the tool automatically queries [ip-api.com](http://ip-api.com) as a fallback to fill in city, region, and more precise coordinates
- Rate limited to 45 requests per minute to stay within ip-api.com's free tier
- Can be disabled with `--no-refine`

### RDAP Ownership Lookup
- Queries RDAP (Registration Data Access Protocol) via the `ipwhois` library for each IP
- Returns ASN, ASN description, network name, network CIDR, organization name, abuse contact email and phone, and regional registry
- Rate limited with configurable pause between lookups (default 1 second) and automatic retry on 429 responses
- Can be skipped entirely with `--skip-rdap` for geo-only mode

### Multiple Output Formats
Results can be written in six formats using the `-f` / `--format` flag:

| Format | Flag | Description |
|--------|------|-------------|
| CSV | `-f csv` | Default. Flat tabular format for spreadsheets and SIEM import |
| JSON | `-f json` | Pretty-printed JSON array. Empty fields become `null` |
| JSON Lines | `-f jsonl` | One JSON object per line. Streamable, works well with `jq` and CLI pipelines |
| GeoJSON | `-f geojson` | FeatureCollection with Point geometries. Viewable in geojson.io, QGIS, Leaflet |
| KML | `-f kml` | Google Earth compatible. Placemarks with coordinates and extended data fields |
| Text | `-f txt` | Human-readable record blocks with labeled sections for geolocation and ownership |

### Smart CSV Handling
- Auto-detects the IP column by sampling rows and testing values with Python's `ipaddress` module
- Falls back to header name heuristics (looks for columns named `ip`, `ip_address`, `src_ip`, etc.)
- All original columns from the input CSV are preserved in the output alongside the enrichment fields

### Error Handling
- Invalid IPs receive empty enrichment fields and a `lookup_error` value describing the problem
- Private and reserved IPs (RFC 1918, loopback, link-local) are labeled `PRIVATE/RESERVED` and skip external lookups
- RDAP failures are logged to stderr and never crash the tool
- Progress counter printed to stderr for each IP processed

## Installation

```
pip install -r requirements.txt
```

Dependencies: `geoip2`, `ipwhois`, `requests`

## Usage

```
python3 iplocate.py -i INPUT.csv -o OUTPUT -f FORMAT [options]
```

### Required Arguments

| Flag | Description |
|------|-------------|
| `-i`, `--input` | Input CSV file containing IP addresses |
| `-o`, `--output` | Output file path |

### Optional Arguments

| Flag | Description |
|------|-------------|
| `-f`, `--format` | Output format: `csv`, `json`, `jsonl`, `geojson`, `kml`, `txt` (default: `csv`) |
| `-d`, `--db` | Path to a custom GeoLite2-City.mmdb file |
| `--asn-db` | Path to a custom GeoLite2-ASN.mmdb file |
| `--ip-column` | Name of the column containing IPs (auto-detected if omitted) |
| `--rdap-pause` | Seconds between RDAP lookups (default: 1.0) |
| `--skip-rdap` | Skip RDAP lookups entirely |
| `--no-refine` | Skip ip-api.com fallback for broad geolocations |
| `--update-db` | Force re-download of GeoLite2 databases |

### Examples

Basic CSV-to-CSV enrichment:
```
python3 iplocate.py -i ips.csv -o results.csv
```

JSON output, geo-only (no RDAP):
```
python3 iplocate.py -i ips.csv -o results.json -f json --skip-rdap
```

GeoJSON for map visualization:
```
python3 iplocate.py -i ips.csv -o map.geojson -f geojson
```

Human-readable text report:
```
python3 iplocate.py -i ips.csv -o report.txt -f txt
```

KML for Google Earth:
```
python3 iplocate.py -i ips.csv -o locations.kml -f kml
```

## Output Fields

### Geolocation (prefixed `geo_`)

| Field | Description |
|-------|-------------|
| `geo_country_code` | ISO 3166-1 alpha-2 country code |
| `geo_country` | Country name |
| `geo_region` | State, province, or administrative region |
| `geo_city` | City name |
| `geo_latitude` | Latitude coordinate |
| `geo_longitude` | Longitude coordinate |
| `geo_accuracy_radius_km` | GeoLite2 accuracy radius in kilometers |
| `geo_postal_code` | Postal or ZIP code |
| `geo_asn` | Autonomous System Number |
| `geo_asn_org` | ASN organization name |

### RDAP Ownership (prefixed `rdap_`)

| Field | Description |
|-------|-------------|
| `rdap_asn` | Autonomous System Number |
| `rdap_asn_description` | ASN description |
| `rdap_asn_cidr` | ASN network CIDR |
| `rdap_network_name` | Registered network name |
| `rdap_network_cidr` | Network CIDR block |
| `rdap_network_country` | Country of network registration |
| `rdap_org_name` | Organization name |
| `rdap_abuse_email` | Abuse contact email |
| `rdap_abuse_phone` | Abuse contact phone |
| `rdap_registry` | Regional Internet Registry (arin, ripe, apnic, etc.) |

### Error

| Field | Description |
|-------|-------------|
| `lookup_error` | Error description if the IP was invalid or empty |

## Text Output Sample

```
============================================================
  8.8.8.8
============================================================
  Label                    Google DNS

  --- Geolocation ---
  Country Code             US
  Country                  United States
  Region                   Virginia
  City                     Ashburn
  Latitude                 39.03
  Longitude                -77.5
  Postal Code              20149
  ASN                      15169
  ASN Org                  Google LLC

  --- RDAP Ownership ---
  RDAP ASN                 15169
  RDAP ASN Description     GOOGLE - Google LLC, US
  RDAP ASN CIDR            8.8.8.0/24
  Network Name             GOGL
  Network CIDR             8.8.8.0/24
  Org Name                 Google LLC
  Abuse Email              network-abuse@google.com
  Abuse Phone              +1-650-253-0000
  Registry                 arin
```

## Data Sources

- **GeoLite2 databases**: Auto-downloaded from [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb) GitHub releases (redistributed MaxMind GeoLite2 data)
- **ip-api.com**: Free geolocation API used as a fallback for broad GeoLite2 results (45 requests/minute, non-commercial use)
- **RDAP**: Registration Data Access Protocol, queried via the `ipwhois` Python library

## License

GeoLite2 databases are provided under the [MaxMind GeoLite2 End User License Agreement](https://www.maxmind.com/en/geolite2/eula). The ip-api.com free tier is for non-commercial use.
