import re
import subprocess
import dns.name, dns.resolver, dns.reversename
import json
import sys
import time
import http.client
import socket
import maxminddb

PUBLIC_DNS_RESOLVERS = [
  "208.67.222.222",
  "1.1.1.1",
  "8.8.8.8",
  "8.26.56.26",
  "9.9.9.9",
  "64.6.65.6",
  "91.239.100.100",
  "185.228.168.168",
  "77.88.8.7",
  "156.154.70.1",
  "198.101.242.72",
  "176.103.130.130"
  ]

TLS_OPTIONS = [
  "SSLv2",
  "SSLv3",
  "TLSv1.0",
  "TLSv1.1",
  "TLSv1.2",
  "TLSv1.3"
]

maxmind_path = "GeoLite2-City.mmdb"

def ip_helper(info, key: str, record: str):
  resolver = dns.resolver.Resolver(configure=False)
  resolver.nameservers = PUBLIC_DNS_RESOLVERS
  for host in info:
    info[host][key] = []
    try:
      answer = resolver.resolve(host, record)
    except:
      continue
    for rr in answer:
      info[host][key].append(str(rr))

def scan_ipv4(info):
  ip_helper(info, "ipv4_addresses", 'A')

def scan_ipv6(info):
  ip_helper(info, "ipv6_addresses", 'AAAA')

def scan_http_server(info):
  for host in info:
    try:
      conn = http.client.HTTPConnection(host)
      conn.request("GET", "/")
      http_server = conn.getresponse().getheader("Server")
      info[host]["http_server"] = http_server if http_server else None
    except:
      info[host]["http_server"] = None

def scan_insecure_http(info):
  for host in info:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      if s.connect_ex((host, 80)):
        info[host]["insecure_http"] = False
      else:
        info[host]["insecure_http"] = True

def scan_redirect_to_https(info):
  for host in info:
    if info[host]["insecure_http"] == False:
      info[host]["redirect_to_https"] = False
      continue
    target = host
    count = 0
    while True:
      if count > 9:
        info[host]["redirect_to_https"] = False
        break
      count += 1
      try:
        conn = http.client.HTTPConnection(target, timeout=2)
        conn.request("GET", "/")
        response = conn.getresponse()
        http_code = response.getcode()

        if http_code >= 300 and http_code < 400:
          location = response.getheader("Location").strip("/")
          if "https" in location:
            info[host]["redirect_to_https"] = True
            break
          else:
            target = location[7:]
            continue
        elif http_code == 200:
          info[host]["redirect_to_https"] = False
        break
      except Exception as e:
        print(e)
        info[host]["redirect_to_https"] = False
        break

def scan_hsts(info):
  for host in info:
    info[host]["hsts"] = False
    target = host
    count = 0
    while True:
      if count > 9:
        info[host]["hsts"] = False
        break
      count += 1
      try:
        conn = http.client.HTTPConnection(target, timeout=2)
        conn.request("GET", "/")
        response = conn.getresponse()
        http_code = response.getcode()

        if http_code >= 300 and http_code < 400:
          location = response.getheader("Location").strip("/") if response.getheader("Location") else response.getheader("location").strip("/")
          if "https" in location:
            target = location[8:]
            conn2 = http.client.HTTPSConnection(target, 443, timeout=2)
            conn2.putrequest('GET', '/')
            conn2.endheaders()
            response2 = conn2.getresponse()
            info[host]["hsts"] = True if response2.getheader("Strict-Transport-Security") else False
            break
          else:    
            target = location[7:]
            continue
        elif http_code == 200:
          info[host]["hsts"] = True if response.getheader("Strict-Transport-Security") else False
        break
      except Exception as e:
        # print(e)
        break

def scan_tls_versions(info):
  for host in info:
    try:
      # may need to raise timeouts on these for some domains

      result = subprocess.check_output(["nmap", "--script", "ssl-enum-ciphers", "-p", "443", host],
          timeout=8, stderr=subprocess.STDOUT).decode("utf-8")
      info[host]["tls_versions"] = [option for option in TLS_OPTIONS if option in result]

      result = subprocess.check_output(["openssl", "s_client", "tls1_3", "-connect", host+":"+str(443)],
          timeout=2, stderr=subprocess.STDOUT, input=b'').decode("utf-8")
      if "error" not in result:
        info[host]["tls_versions"].append("TLSv1.3")

    except FileNotFoundError:
      print("needed program not found, skipping scan_tls_versions", file=sys.stderr)
      return
    except subprocess.TimeoutExpired:
      # print("scan_tls_versions timeout for " + host)
      continue
    except Exception:
      continue

def scan_root_ca(info):
  for host in info:
    try:
      result = subprocess.check_output(["openssl", "s_client", "-connect", host+":"+str(443)],
          timeout=2, stderr=subprocess.STDOUT, input=b'').decode("utf-8")
      if "error" not in result:

        result = result[:result.find("Server certificate")]
        print(result)
        ca = re.findall(r'O = (.*?), OU =', result.splitlines()[-2])[0]
        print(ca)

        # result = result[:result.find("Server certificate")]
        # print(result)
        # orgs = re.findall(r'O = (.*?),', result)
        # print(orgs)


        # beluga = result[(result.find("i:O = ")+len("i:O = ")):]
        # ca = beluga[:beluga.find("CN")-2]
        info[host]["scan_root_ca"] = ca

    except FileNotFoundError:
      print("needed program not found, skipping scan_root_ca", file=sys.stderr)
      return
    except subprocess.TimeoutExpired:
      # print("scan_root_ca timeout for " + host)
      continue
    except Exception as e:
      print(e)
      continue

def scan_rdns_names(info):
  resolver = dns.resolver.Resolver(configure=False)
  resolver.nameservers = PUBLIC_DNS_RESOLVERS
  for host in info:
    ips = info[host]["ipv4_addresses"]
    info[host]["rdns_names"] = []
    for ip in ips:
      try:
        n = dns.reversename.from_address(ip)
        answer = resolver.resolve(n, "PTR")
      except Exception as e:
        # print(e)
        continue
      for rr in answer:
        info[host]["rdns_names"].append(str(rr))
    info[host]["rdns_names"] = list(set(info[host]["rdns_names"]))

def scan_rtt_range(info):
  adjustment = 0
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    start = time.perf_counter_ns()          
    err = s.connect_ex(("127.0.0.1", 22))
    after = time.perf_counter_ns()
    adjustment = (after-start) / 1000000

  for host in info:
    mi = None
    ma = None
    for ip in info[host]["ipv4_addresses"]:
      for port in [80, 22, 443]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
          s.settimeout(1)
          start = time.perf_counter_ns()          
          err = s.connect_ex((ip, port))
          after = time.perf_counter_ns()
          if err:
            continue
          this_time = round((after-start) / 1000000 - adjustment)
          mi = min(this_time, mi) if mi else this_time
          ma = max(this_time, ma) if ma else this_time
    info[host]["rtt_range"] = [mi, ma]


def scan_geo_locations(info):
  with maxminddb.open_database(maxmind_path) as reader:
    for host in info:
      info[host]["geo_locations"] = []
      ips = info[host]["ipv4_addresses"]
      for ip in ips:
        record = reader.get(ip)
        if record is None:
          continue
        # print(record)
        # print("\n")
        country = city = province = ""
        if "country" in record:
          country = record["country"]["names"]["en"]
          # print(country)
        if "subdivisions" in record:
          province = record["subdivisions"][0]["names"]["en"]
          # print(province)
        if "city" in record:
          city = record["city"]["names"]["en"]
          # print(city)
        if not (country and city and province):
          continue
        location_record = ((city + ", ") if city else "") + ((province + ", ") if province else "") + (country if country else "")
        if location_record and location_record not in info[host]["geo_locations"]:
          info[host]["geo_locations"].append(location_record)



def scan(info):
  # scan_ipv4(info)
  # scan_ipv6(info)
  # scan_http_server(info)
  # scan_insecure_http(info)
  # scan_redirect_to_https(info)
  # scan_hsts(info)
  # scan_tls_versions(info)
  scan_root_ca(info)
  # scan_rdns_names(info)
  # scan_rtt_range(info)
  # scan_geo_locations(info)

def main():
    if len(sys.argv) != 3:
      print("Wrong input bruh")
      sys.exit(1)
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    hostnames = []
    with open(input_file, "r") as f:
      hostnames = [host.strip() for host in f.readlines()]
    
    info = {}
    for host in hostnames:
      info[host] = {"scan_time": str(time.time())}

    scan(info)

    with open(output_file, "w") as f:
      json.dump(info, f, sort_keys=True, indent=4)

    return 0

if __name__ == "__main__":
    main()
