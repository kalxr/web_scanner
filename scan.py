import re
import subprocess
import dns.name, dns.resolver, dns.reversename
import json
import sys
import time
import http.client
import socket
import maxminddb
import concurrent.futures

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

def scan_http_server_single(host, info):
  try:
    conn = http.client.HTTPConnection(host)
    conn.request("GET", "/")
    http_server = conn.getresponse().getheader("Server")
    info[host]["http_server"] = http_server if http_server else None
  except:
    info[host]["http_server"] = None

def scan_http_server(info):
  for host in info:
    scan_http_server_single(host, info)

def scan_insecure_http_single(host, info):
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    if s.connect_ex((host, 80)):
      info[host]["insecure_http"] = False
    else:
      info[host]["insecure_http"] = True

def scan_insecure_http(info):
  for host in info:
    scan_insecure_http_single(host, info)

def scan_redirect_to_https_single(host, info):
  if info[host]["insecure_http"] == False:
    info[host]["redirect_to_https"] = False
    return
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

def scan_redirect_to_https(info):
  for host in info:
    scan_redirect_to_https_single(host, info)

def scan_hsts_single(host, info):
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

def scan_hsts(info):
  for host in info:
    scan_hsts_single(host, info)

def scan_tls_versions_single(host, info):
  info[host]["tls_versions"] = []
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
    return
  except Exception:
    return

def scan_tls_versions(info):
  for host in info:
    scan_tls_versions_single(host, info)

def scan_root_ca_single(host, info):
  try:
    result = subprocess.check_output(["openssl", "s_client", "-connect", host+":"+str(443)],
        timeout=4, stderr=subprocess.STDOUT, input=b'').decode("utf-8")

    truncated_result = result[result.find("Certificate chain"):result.find("Server certificate")]
    truncated_result_lines = truncated_result.splitlines()
    relevant_line = truncated_result_lines[-2]
    truncated_relevant_line = relevant_line[relevant_line.find("O ="):]
    # print(truncated_relevant_line)

    ca = re.findall(r'O = (.*?), ', truncated_relevant_line)[0]
    if "\"" in ca:
      start = truncated_relevant_line.find("\"")
      end = truncated_relevant_line.find("\"", start+1)
      ca = truncated_relevant_line[start+1:end]

    info[host]["scan_root_ca"] = ca

  except FileNotFoundError:
    print("needed program not found, skipping scan_root_ca", file=sys.stderr)
    return
  except subprocess.TimeoutExpired:
    # print("scan_root_ca timeout for " + host)
    info[host]["scan_root_ca"] = None
    return
  except Exception as e:
    # print(e)
    info[host]["scan_root_ca"] = None
    return

def scan_root_ca(info):
  for host in info:
    scan_root_ca_single(host, info)

def scan_rdns_names_single(host, info):
  resolver = dns.resolver.Resolver(configure=False)
  resolver.nameservers = PUBLIC_DNS_RESOLVERS
  ips = info[host]["ipv4_addresses"]
  info[host]["rdns_names"] = []
  for ip in ips:
    try:
      n = dns.reversename.from_address(ip)
      answer = resolver.resolve(n, "PTR")
    except Exception as e:
      # print(e)
      return
    for rr in answer:
      info[host]["rdns_names"].append(str(rr))
  info[host]["rdns_names"] = list(set(info[host]["rdns_names"]))

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

def scan_rtt_range_single(host, info):
  mi = None
  ma = None
  for ip in info[host]["ipv4_addresses"]:
    for port in [80, 22, 443]:
      with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        start = time.perf_counter()          
        err = s.connect_ex((ip, port))
        after = time.perf_counter()
        if err:
          continue
        this_time = round((after-start) * 1000, 2)
        mi = min(this_time, mi) if mi else this_time
        ma = max(this_time, ma) if ma else this_time
  info[host]["rtt_range"] = [mi, ma]

def scan_rtt_range(info):
  for host in info:
    scan_rtt_range_single(host, info)

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
  try:
    scan_ipv4(info)
  except Exception:
    pass
  try:
    scan_ipv6(info)
  except Exception:
    pass
  try:
    scan_http_server(info)
  except Exception:
    pass
  try:
    scan_insecure_http(info)
  except Exception:
    pass
  try:
    scan_redirect_to_https(info)
  except Exception:
    pass
  try:
    scan_hsts(info)
  except Exception:
    pass
  try:
    scan_tls_versions(info)
  except Exception:
    pass
  try:
    scan_root_ca(info)
  except Exception:
    pass
  try:
    scan_rdns_names(info)
  except Exception:
    pass
  try:
    scan_rtt_range(info)
  except Exception:
    pass
  try:
    scan_geo_locations(info)
  except Exception:
    pass

def scan_single(host, info):
  try:
    scan_http_server_single(host, info)
  except Exception:
    pass
  try:
    scan_insecure_http_single(host, info)
  except Exception:
    pass
  try:
    scan_redirect_to_https_single(host, info)
  except Exception:
    pass
  try:
    scan_hsts_single(host, info)
  except Exception:
    pass
  try:
    scan_tls_versions_single(host, info)
  except Exception:
    pass
  try:
    scan_root_ca_single(host, info)
  except Exception:
    pass
  try:
    scan_rdns_names_single(host, info)
  except Exception:
    pass
  try:
    scan_rtt_range_single(host, info)
  except Exception:
    pass

def scan_fast(info):
  print("INITIATING SCAN_FAST")
  try:
    scan_ipv4(info)
    print("SCAN_IPv4 COMPLETE")
  except Exception:
    print("SCAN_IPv4 FAIL")
    pass
  try:
    scan_ipv6(info)
    print("SCAN_IPv6 COMPLETE")
  except Exception:
    print("SCAN_IPv6 FAIL")
    pass
  try:
    scan_geo_locations(info)
    print("SCAN_GEO_LOCATIONS COMPLETE")
  except Exception:
    print("SCAN_GEO_LOCATIONS FAIL")
    pass

  print("SEQUENTIAL SEGMENT COMPLETE")
  # ENGAGE SPEED
  print("ENGAGING SPEED")

  executor = concurrent.futures.ThreadPoolExecutor(max_workers=8)
  for host in info:
    executor.submit(scan_single, host, info)

  print("SCANS SUBMITTED TO THREADPOOL")

  executor.shutdown(wait=True)

  print("THREADPOOL SHUTDOWN")

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

    scan_fast(info)

    with open(output_file, "w") as f:
      json.dump(info, f, sort_keys=True, indent=4)

    return 0

if __name__ == "__main__":
    main()
