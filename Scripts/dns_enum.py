import dns.resolver
import dns.zone
import dns.query
import argparse
import requests
from urllib.parse import urlparse
import sys
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Set, Optional, Dict
import time
import signal
import json
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# List of common third-party cloud domains to check for dangling records
THIRD_PARTY_DOMAINS = [
    "azurewebsites.net",
    "cloudapp.net",
    "s3.amazonaws.com",
    "herokuapp.com",
    "github.io",
    "appspot.com",
    "cloudflareworkers.com",
    "vercel.app",
]

class DNSScanner:
    def __init__(self, domain: str, timeout: int = 5, max_workers: int = 10, 
                 subdomain_list: Optional[str] = None, output_file: Optional[str] = None,
                 skip_enumeration: bool = False):
        self.domain = domain.lower().rstrip(".")
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.max_workers = max_workers
        self.subdomains: Set[str] = set()
        self.subdomain_list = subdomain_list
        self.output_file = output_file
        self.results: Dict[str, Dict] = {}
        self.skip_enumeration = skip_enumeration
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, signum, frame):
        logger.info("Scan interrupted by user. Saving results and exiting...")
        self.save_results()
        sys.exit(0)

    def load_subdomain_list(self) -> Set[str]:
        """Load subdomains from a provided list file."""
        if not self.subdomain_list or not Path(self.subdomain_list).is_file():
            return set()
        
        subdomains = set()
        try:
            with open(self.subdomain_list, 'r') as f:
                for line in f:
                    sub = line.strip().lower().rstrip(".")
                    if sub and (sub.endswith(f".{self.domain}") or sub == self.domain):
                        subdomains.add(sub)
            logger.info(f"Loaded {len(subdomains)} subdomains from list: {self.subdomain_list}")
        except Exception as e:
            logger.error(f"Failed to load subdomain list {self.subdomain_list}: {e}")
        return subdomains

    def get_subdomains_from_dns(self) -> Set[str]:
        """Enumerate subdomains using various DNS record types."""
        subdomains = set()
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]

        try:
            answers = self.resolver.resolve(self.domain, "NS")
            for ns in answers:
                ns_str = str(ns).rstrip(".")
                logger.info(f"Found NS: {ns_str}")
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_str, self.domain))
                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{self.domain}".lstrip(".")
                        subdomains.add(subdomain)
                except Exception as e:
                    logger.debug(f"Zone transfer failed for {ns_str}: {e}")
        except dns.resolver.NXDOMAIN:
            logger.error(f"Domain {self.domain} does not exist.")
            sys.exit(1)
        except Exception as e:
            logger.warning(f"Error querying NS records: {e}")

        for rtype in record_types:
            try:
                answers = self.resolver.resolve(self.domain, rtype)
                for rdata in answers:
                    if rtype == "MX":
                        target = str(rdata.exchange).rstrip(".")
                    elif rtype in ["CNAME", "NS"]:
                        target = str(rdata.target).rstrip(".")
                    else:
                        continue
                    if target.endswith(f".{self.domain}"):
                        subdomains.add(target)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception as e:
                logger.debug(f"Error querying {rtype} records: {e}")

        return subdomains

    def get_subdomains_from_ct(self) -> Set[str]:
        """Fetch subdomains from Certificate Transparency logs via crt.sh."""
        subdomains = set()
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            response = requests.get(url, timeout=self.resolver.timeout)
            response.raise_for_status()
            data = response.json()
            for entry in data:
                name = entry.get("name_value", "").lower().rstrip(".")
                if name.endswith(f".{self.domain}") or name == self.domain:
                    subdomains.add(name)
                for sub in name.split("\n"):
                    sub = sub.strip().lower().rstrip(".")
                    if sub.endswith(f".{self.domain}") or sub == self.domain:
                        subdomains.add(sub)
            logger.info(f"Found {len(subdomains)} subdomains from Certificate Transparency logs")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to fetch CT logs from crt.sh: {e}")
        return subdomains

    def get_subdomains(self) -> Set[str]:
        """Enumerate subdomains from multiple sources or use provided list."""
        if self.subdomain_list and self.skip_enumeration:
            logger.info("Skipping internal enumeration; using provided subdomain list.")
            self.subdomains = self.load_subdomain_list()
        else:
            logger.info("Enumerating subdomains from DNS records...")
            self.subdomains.update(self.get_subdomains_from_dns())

            logger.info("Enumerating subdomains from Certificate Transparency logs...")
            self.subdomains.update(self.get_subdomains_from_ct())

            # Default common subdomains
            common_subs = ["www", "mail", "app", "dev", "staging", "test", "api", "blog"]
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                executor.map(self._check_subdomain, 
                            [f"{sub}.{self.domain}" for sub in common_subs])

        if not self.subdomains:
            logger.warning("No subdomains found or provided. Exiting.")
            sys.exit(1)
        logger.info(f"Total unique subdomains: {len(self.subdomains)}")
        return self.subdomains

    def _check_subdomain(self, subdomain: str) -> None:
        """Helper method to check if a subdomain exists."""
        try:
            self.resolver.resolve(subdomain, "A")
            self.subdomains.add(subdomain)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except Exception as e:
            logger.debug(f"Error checking subdomain {subdomain}: {e}")

    def check_cname(self, subdomain: str) -> Optional[str]:
        """Check if a subdomain has a CNAME record."""
        try:
            answers = self.resolver.resolve(subdomain, "CNAME")
            for rdata in answers:
                return str(rdata.target).rstrip(".")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return None
        except Exception as e:
            logger.debug(f"Error checking CNAME for {subdomain}: {e}")
            return None

    def is_dangling(self, cname_target: str) -> bool:
        """Check if the CNAME target is potentially dangling."""
        parsed = urlparse(f"http://{cname_target}")
        target_domain = parsed.netloc or cname_target

        for third_party in THIRD_PARTY_DOMAINS:
            if third_party in target_domain:
                try:
                    response = requests.head(
                        f"http://{cname_target}",
                        timeout=self.resolver.timeout,
                        allow_redirects=True
                    )
                    status = response.status_code
                    if status in (404, 403, 410):
                        return True
                    elif status >= 500:
                        return True
                    return False
                except requests.exceptions.RequestException:
                    try:
                        self.resolver.resolve(target_domain, "A")
                        return False
                    except dns.resolver.NXDOMAIN:
                        return True
        return False

    def save_results(self) -> None:
        """Save scan results to a JSON file if output_file is specified."""
        if not self.output_file or not self.results:
            return
        
        try:
            with open(self.output_file, 'w') as f:
                json.dump(self.results, f, indent=4)
            logger.info(f"Results saved to {self.output_file}")
        except Exception as e:
            logger.error(f"Failed to save results to {self.output_file}: {e}")

    def scan(self) -> None:
        """Execute the full dangling DNS scan."""
        start_time = time.time()
        logger.info(f"Starting scan for {self.domain}")

        # Enumerate or load subdomains
        subdomains = self.get_subdomains()

        # Check CNAMEs and dangling records
        logger.info("Checking for CNAMEs and potential dangling records...")
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            results = executor.map(self._analyze_subdomain, subdomains)
        
        for subdomain, (cname, is_dang) in zip(subdomains, results):
            self.results[subdomain] = {"cname": cname, "dangling": is_dang}
            if cname:
                logger.info(f"{subdomain} has CNAME: {cname}")
                if is_dang:
                    logger.warning(f"Potential dangling DNS detected: {subdomain} -> {cname}")
                else:
                    logger.info(f"{subdomain} -> {cname} appears active")

        logger.info(f"Scan completed in {time.time() - start_time:.2f} seconds")
        self.save_results()

    def _analyze_subdomain(self, subdomain: str) -> tuple[Optional[str], bool]:
        """Helper method to analyze a single subdomain."""
        cname = self.check_cname(subdomain)
        return cname, self.is_dangling(cname) if cname else False

def main():
    parser = argparse.ArgumentParser(description="Hunt for dangling DNS records.")
    parser.add_argument("domain", help="Target domain to scan (e.g., example.com)")
    parser.add_argument("--timeout", type=int, default=5, help="DNS and HTTP timeout in seconds")
    parser.add_argument("--workers", type=int, default=10, help="Max concurrent workers")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--subdomains", type=str, help="Path to file with pre-enumerated subdomains")
    parser.add_argument("--skip-enumeration", action="store_true", 
                        help="Skip internal enumeration and use provided subdomain list only")
    parser.add_argument("--output", type=str, help="Path to output JSON file")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    scanner = DNSScanner(
        args.domain, 
        timeout=args.timeout, 
        max_workers=args.workers,
        subdomain_list=args.subdomains,
        output_file=args.output,
        skip_enumeration=args.skip_enumeration
    )
    scanner.scan()

if __name__ == "__main__":
    main()
