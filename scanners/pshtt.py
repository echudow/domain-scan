import codecs
import logging
import os
import re
from typing import Any, List

from pshtt import pshtt
from utils import utils

###
# Measure a site's HTTP behavior using DHS NCATS' pshtt tool.

# Network timeout for each internal pshtt HTTP request.
pshtt_timeout = 7

# Default to a custom user agent that can be overridden via an environment
# variable
user_agent = os.environ.get("PSHTT_USER_AGENT", "18F/domain-scan/pshtt.py")

# Keep here to get some best-effort container reuse in Lambda.
suffix_list = None

# In Lambda, we package a snapshot of the PSL with the environment.
lambda_support = True
lambda_suffix_path = "./cache/public-suffix-list.txt"


# Download third party data once, at the top of the scan.
def init(environment, options):
    logging.warning("[pshtt] Downloading third party data...")

    # Initialize the scanner:
    if hasattr(pshtt, "init"):
        pshtt.init(environment, options)

    return {
        'preload_list': pshtt.load_preload_list(),
        'preload_pending': pshtt.load_preload_pending(),
        'suffix_list': None
    }


# Finalize the scanner
def finalize(environment, options):
    if hasattr(pshtt, "finalize"):
        pshtt.finalize(environment, options)


# To save on bandwidth to Lambda, slice the preload and pending lists
# down to an array of just the domain and its base domain, if they
# exist.  Override the list in place, which should only modify it
# per-scan.
def init_domain(domain, environment, options):
    cache_dir = options.get("_", {}).get("cache_dir", "./cache")
    base_domain = utils.base_domain_for(domain, cache_dir=cache_dir)

    preload_list = []
    if domain in environment.get("preload_list", []):
        preload_list.append(domain)
    if base_domain != domain and base_domain in environment.get("preload_list", []):
        preload_list.append(base_domain)
    environment["preload_list"] = preload_list

    preload_pending = []
    if domain in environment.get("preload_pending", []):
        preload_pending.append(domain)
    if base_domain != domain and base_domain in environment.get("preload_pending", []):
        preload_pending.append(base_domain)
    environment["preload_pending"] = preload_pending

    return environment


def list_from_dict_key(d: dict, k: str, delim: str=',') -> List[str]:
    """Extract a list from a delimited string in a dictionary.
    Parameters
    ----------
    d : dict
        The dictionary containing the delimited string.
    k : str
        The key under which the delimited value is stored in the
        dictionary.
    delim : str
        The delimiter for the delimited string.
    Returns
    -------
    List[str]: The list extracted from the delimited string, or an
    empty list if the dictionary key is None or does not exist.
    """
    ans = []
    s = d.get(k, None)
    if s is not None:
        ans = s.split(',')

    return ans


# Run locally or in the cloud.
# Gets third-party data passed into the environment.
def scan(domain, environment, options):

    domain = format_domain(domain)

    if environment["scan_method"] == "lambda":
        suffix_list = codecs.open(lambda_suffix_path, encoding='utf-8')
    else:  # scan_method == "local"
        suffix_list = environment["suffix_list"]

    # This should cause no network calls, either locally or the cloud.
    pshtt.initialize_external_data(
        init_preload_list=environment.get('preload_list'),
        init_preload_pending=environment.get('preload_pending'),
        init_suffix_list=suffix_list
    )

    results = pshtt.inspect_domains(
        [domain],
        {
            'timeout': options.get("timeout", pshtt_timeout),
            'user_agent': user_agent,
            'adfs_hsts': options.get("adfs_hsts"),
            'debug': options.get("debug", False),
            'ca_file': options.get("ca_file"),
            'pt_int_ca_file': options.get("pt_int_ca_file"),
            'dns': list_from_dict_key(options, 'dns'),
            'preload_list': environment.get('preload_list'),
            'preload_pending': environment.get('preload_pending'),
        }
    )

    # Actually triggers the work.
    results = list(results)

    # pshtt returns array of results, but we always send in 1.
    return results[0]


# Given a response from pshtt, convert it to a CSV row.
def to_rows(data):
    row = []
    for field in headers:
        value = data[field]
        row.append(value)

    return [row]


headers = [
    "Canonical URL", "Live",
    "Redirect", "Redirect To",
    "Valid HTTPS", "Defaults to HTTPS", "Downgrades HTTPS",
    "Strictly Forces HTTPS", "HTTPS Bad Chain", "HTTPS Bad Hostname",
    "HTTPS Expired Cert", "HTTPS Self Signed Cert",
    "HSTS", "HSTS Header", "HSTS Max Age", "HSTS Entire Domain",
    "HSTS Preload Ready", "HSTS Preload Pending", "HSTS Preloaded",
    "Base Domain HSTS Preloaded", "Domain Supports HTTPS",
    "Domain Enforces HTTPS", "Domain Uses Strong HSTS",
    "HTTPS Live", "HTTPS Full Connection", "HTTPS Client Auth Required",
    "HTTPS Publicly Trusted", "HTTPS Custom Truststore Trusted",
    "IP", "Server Header", "Server Version", "Status Code", "HTTPS Cert Chain Length",
    "HTTPS Probably Missing Intermediate Cert", "Notes",
    "Unknown Error",
]


def format_domain(domain):
    return re.sub(r"^(https?://)?(www\.)?", "", domain)
