import regex as re
import chardet
from collections import OrderedDict


def extract_iocs(file):
    result = chardet.detect(file)
    encoding = result['encoding']
    
    for line in list(file.decode(encoding).splitlines()):
        ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)

        ips = [i for i in ip] if ip else []

        md5 = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])', line)

        md5_hashes = [i for i in md5] if md5 else []

        sha1 = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{40}(?![a-z0-9])', line)

        sha1_hashes = [i for i in sha1] if sha1 else []

        sha256 = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{64}(?![a-z0-9])', line)

        sha256_hashes = [i for i in sha256] if sha256 else []

        url = re.findall(r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b(?:[-a-zA-Z0-9@:%_\+.~#?&//=]*)', line)

        urls = [i for i in url] if url else []

        domain = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', line)

        domains = [i for i in domain] if domain else []

        email = re.findall(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', line)

        emails = [i for i in email] if email else []
    
    
    ips_unique = list(OrderedDict.fromkeys(ips))
    md5_unique = list(OrderedDict.fromkeys(md5_hashes))
    sha1_unique = list(OrderedDict.fromkeys(sha1_hashes))
    sha256_unique = list(OrderedDict.fromkeys(sha256_hashes))
    urls_unique = list(OrderedDict.fromkeys(urls))
    domains_unique = list(OrderedDict.fromkeys(domains))
    emails_unique = list(OrderedDict.fromkeys(emails))

    r = re.compile(r'[0-9]+(?:\.[0-9]+){3}')

    domains_filtered = [i for i in domains_unique if not r.match(i)]

    statistics = {
        'ips': len(ips_unique), 
        'ips_rem_dupl': len(ips) - len(ips_unique),
        'md5': len(md5_unique), 
        'md5_rem_dupl': len(md5_hashes) - len(md5_unique),
        'sha1': len(sha1_unique), 
        'sha1_rem_dupl': len(sha1_hashes) - len(sha1_unique),
        'sha256': len(sha256_unique), 
        'sha256_rem_dupl': len(sha256_hashes) - len(sha256_unique),
        'urls': len(urls_unique), 
        'urls_rem_dupl': len(urls) - len(urls_unique),
        'domains': len(domains_filtered), 
        'domains_rem_dupl': len(domains_unique) - len(domains_filtered),
        'emails': len(emails_unique),
        'emails_rem_dupl': len(emails) - len(emails_unique),
        'total': len(ips_unique) + len(md5_unique) + len(sha1_unique) + len(sha256_unique) + len(urls_unique) + len(domains_filtered) + len(emails_unique)
    }

    return {
        'ips': ips_unique, 
        'md5': md5_unique, 
        'sha1': sha1_unique, 
        'sha256': sha256_unique, 
        'urls': urls_unique, 
        'domains': domains_filtered,
        'emails': emails_unique,
        'statistics': statistics
    }
