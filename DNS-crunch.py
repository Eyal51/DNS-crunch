import sys
from ipwhois import IPWhois


def crunch(dns_file):
    try:
        with open(dns_file) as f:
            dns_list = f.readlines()
    except:
        print(f"Could not open file:\n{dns_file}")

    for i, j in enumerate(dns_list):
        if j.startswith("[*] Scanning") and j.strip().endswith("for A records"):
            marker = i
            break
    segments = {}
    print(f"\tDomains and IP information:")
    for i in dns_list[marker + 1:]:
        ip, domain = i.strip().split(" - ")
        ip_segment = ip[:ip.rfind(".") + 1] + "0/24"
        if ip_segment in segments:
            segments[ip_segment] += 1
        else:
            segments[ip_segment] = 1
        try:
            obj = IPWhois(ip)
            results = obj.lookup_rdap(depth=1)
            orgName = results["objects"].get(results["entities"][0]).get("contact").get("name")
            print(f"{domain}, {ip}, {orgName}")
        except:
            print(f"{domain}, {ip}, ")

    print(f"\tPopulated segments:")
    sorted_segments = dict(sorted(segments.items(), key=lambda item: item[1]))
    for i in sorted_segments.keys():
        print(f"\n{i}: {sorted_segments[i]}")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"DNS cruncher\nUsage:\n\t{sys.argv[0]} <dns results file>")
    dns_file = sys.argv[1]
    crunch(dns_file)
