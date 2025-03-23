import dns.resolver
import argparse

def enumerate_dns(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        return [str(rdata.target) for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []

def main():
    parser = argparse.ArgumentParser(description="Enumerate CNAME records for a domain.")
    parser.add_argument("--domain", required=True, help="Domain to query (e.g., example.com)")
    parser.add_argument("--output", default="dns_records.txt", help="Output file")
    args = parser.parse_args()

    cnames = enumerate_dns(args.domain)
    with open(args.output, 'w') as f:
        for cname in cnames:
            f.write(f"{args.domain} -> {cname}\n")
    print(f"CNAME records saved to {args.output}")

if __name__ == "__main__":
    main()