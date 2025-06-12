import pandas as pd
import time
import requests
import tldextract
from urllib.parse import urlparse
import whois

def extract_features_from_url(url):
    parsed = urlparse(url)
    path = parsed.path
    full = parsed.geturl()
    tld = tldextract.extract(url)

    try:
        domain = f"{tld.domain}.{tld.suffix}"
        domain_info = whois.whois(domain)

        creation = domain_info.creation_date
        updated = domain_info.updated_date
        expiration = domain_info.expiration_date

        if isinstance(creation, list): creation = creation[0]
        if isinstance(updated, list): updated = updated[0]
        if isinstance(expiration, list): expiration = expiration[0]

        if isinstance(creation, str): creation = pd.to_datetime(creation, errors='coerce')
        if isinstance(updated, str): updated = pd.to_datetime(updated, errors='coerce')
        if isinstance(expiration, str): expiration = pd.to_datetime(expiration, errors='coerce')

        activation_time = (creation - updated).days if pd.notnull(creation) and pd.notnull(updated) else 0
        expiration_time = (expiration - updated).days if pd.notnull(expiration) and pd.notnull(updated) else 0
    except:
        activation_time = 0
        expiration_time = 0

    try:
        start = time.time()
        r = requests.get(url, timeout=5)
        response_time = time.time() - start
    except:
        response_time = 0

    extracted_features = {
        'directory_length': len(path),
        'time_domain_activation': activation_time,
        'qty_comma_directory': path.count(','),
        'file_length': len(path.split('/')[-1]) if '/' in path else len(path),
        'qty_slash_directory': path.count('/'),
        'qty_asterisk_directory': path.count('*'),
        'length_url': len(full),
        'qty_underline_directory': path.count('_'),
        'qty_slash_url': full.count('/'),
        'qty_plus_file': path.split('/')[-1].count('+'),
        'qty_and_directory': path.count('&'),
        'qty_and_file': path.split('/')[-1].count('&'),
        'ttl_hostname': 0,
        'time_response': response_time,
        'asn_ip': 0,
        'time_domain_expiration': expiration_time,
        'qty_dot_directory': path.count('.'),
        'qty_asterisk_file': path.split('/')[-1].count('*'),
        'qty_exclamation_directory': path.count('!'),
        'qty_hyphen_file': path.split('/')[-1].count('-')
    }

    return extracted_features

