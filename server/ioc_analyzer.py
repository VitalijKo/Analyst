import requests
import regex as re
import json
from collections import OrderedDict
from datetime import datetime
from time import sleep


def virustotal(ioc, type, apikey):
    if type == 'ip':
        endpoint = 'ip_addresses'

    elif type == 'domain':
        endpoint = 'domains'

    elif type == 'url':
        endpoint = 'urls'

    elif type == 'hash':
        endpoint = 'files'

    else:
        return {'error': 'unknown ioc type'}

    url = f'https://www.virustotal.com/api/v3/{endpoint}/{ioc}'

    if not apikey:
        apikey = ''

    headers = {
        'x-apikey': apikey
    }

    response = requests.get(url=url, headers=headers)

    response_json = json.loads(response.text)

    if response.status_code == 200:
        response_json = json.loads(response.text)

        return response_json
    
    return {'error': response.status_code}


def maltiverse_check(ip, endpoint, apikey):
    headers = {
        'Authorization': f'Bearer {apikey}'
    }

    url = f'https://api.maltiverse.com/{endpoint}/'

    response = requests.get(url=f'{url}{ip}', headers=headers)

    response_json = json.loads(response.text)

    if response.status_code == 200:
        response_json = json.loads(response.text)

        return response_json

    return {'error': response.status_code}


def crowdsec(ip, api_key):
    headers = {
        'x-api-key': api_key
    }

    url = f'https://cti.api.crowdsec.net/v2/smoke/{ip}'

    response = requests.get(url=url, headers=headers)

    if response.status_code == 200:

        response_json = response.json()

        return response_json

    return {'error': response.status_code}


def abuseipdb_ip_check(ip, apikey):
    if not apikey:
        apikey = ''

    url = 'https://api.abuseipdb.com/api/v2'

    endpoint = '/check'

    headers = {
        'Accept': 'application/json',
        'Key': apikey
    }

    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '365'
    }

    response = requests.get(
        url=url + endpoint,
        headers=headers,
        params=querystring
    )

    if response.status_code == 200:
        response_json = json.loads(response.text)

        return response_json

    return {'error': response.status_code}


def alienvaultotx(ioc, type, apikey):
    if type == 'ip':
        endpoint = 'IPv4'

    elif type == 'hash':
        endpoint = 'file'

    elif type == 'domain':
        endpoint = 'domain'

    else:
        return {'error': 'unknown ioc type'}

    url = f'https://otx.alienvault.com/api/v1/indicators/{endpoint}/{ioc}'

    if not apikey:
        apikey = ''

    headers = {
        'X-OTX-API-Key': apikey
    }

    response = requests.get(url=url, headers=headers)

    if response.status_code == 200:
        response_json = json.loads(response.text)

        return response_json
   
    return {'error': response.status_code}


def threatfox_ip_check(ip, apikey):
    url = 'https://threatfox-api.abuse.ch/api/v1/'

    headers = {
        'API-KEY': apikey
    }

    payload = {
        'query': 'search_ioc',
        'search_term': ip
    }

    payload_json = json.dumps(payload)

    response = requests.post(url=url, headers=headers, data=payload_json)

    response_json = json.loads(response.text)

    if response.status_code == 200:
        response_json = json.loads(response.text)

        return response_json
    
    return {'error': response.status_code}


def blocklist_de_ip_check(ip):
    url = 'http://api.blocklist.de/api.php?'

    endpoint = 'ip='

    response = requests.get(url=url + endpoint + ip)

    result = response.text.replace('<br />', ' ')

    attacks = re.search('attacks: (\d+)', result).group(1)
    reports = re.search('reports: (\d+)', result).group(1)

    result_dict = {
        'attacks': attacks,
        'reports': reports
    }

    if response.status_code in [401, 429]:
        result_dict = {'error': response.status_code}

    return result_dict


def check_pulsedive(ioc, apikey):
    url = f'https://pulsedive.com/api/'

    endpoint = f'explore.php?q=ioc%3D{ioc}&limit=10&pretty=1&key={apikey}'

    response = requests.get(url=url + endpoint)

    response_json = json.loads(response.text)

    if response.status_code == 200:
        response_json = json.loads(response.text)

        return response_json
    
    return {'error': response.status_code}


def check_bgpview(ip):
    url = f'https://api.bgpview.io/ip/{ip}'

    response = requests.get(url=url)

    response_json = json.loads(response.text)

    if response.status_code == 200:
        response_json = json.loads(response.text)

        return response_json
    
    return {'error': response.status_code}


def ipqualityscore_ip_check(ip, apikey):
    endpoint = f'https://ipqualityscore.com/api/json/ip/{apikey}/{ip}'

    response = requests.get(url=endpoint)

    response_json = json.loads(response.text)

    if response.status_code == 200:
        response_json = json.loads(response.text)

        return response_json
    
    return {'error': response.status_code}


def urlscanio(domain):
    url = f'https://urlscan.io/api/v1/search/?q=domain:{domain}'

    response = requests.get(url=url)

    response_json = [dict(item, expanded=False) for item in response.json()['results']]

    if response.status_code == 200:
        response_json = json.loads(response.text)

        return response_json
    
    return {'error': response.status_code}


def urlhaus_url_check(url):
    import urllib.parse

    url = 'https://urlhaus-api.abuse.ch/v1/url/'

    data = {
        'url': urllib.parse.quote_plus(url)
    }

    response = requests.post(url=url, data=data)

    response_json = json.loads(response.text)

    if response.status_code == 200:
        response_json = json.loads(response.text)

        return response_json
    
    return {'error': response.status_code}


def checkphish_ai(ioc, apikey):
    scan_url = 'https://developers.checkphish.ai/api/neo/scan'

    scan_data = {
        'apiKey': apikey,
        'urlInfo': {
            'url': ioc
        }
    }

    headers = {
        'Content-Type':'application/json'
    }

    scan_response = requests.post(url=scan_url, headers=headers, data=json.dumps(scan_data))

    if response.status_code in [401, 429]:
        result_dict = {'error': response.status_code}

    status_url = 'https://developers.checkphish.ai/api/neo/scan/status'

    status_data = {
        'apiKey': apikey,
        'jobID': scan_response.json()['jobID'],
        'insights': True
    }

    if scan_response.json()['jobID'] == 'none':
        if scan_response.json()['errorMessage']:
            return {'error': scan_response.json()['errorMessage']}

        return {'error': 404}

    for i in range(5):
        status_response = requests.post(url=status_url, headers=headers, json=status_data)

        if response.status_code in [401, 429]:
            result_dict = {'error': response.status_code}

        status_response_json = status_response.json()

        if status_response_json['status'] == 'DONE':
            return status_response_json

        sleep(5)


def safebrowsing_url_check(ioc, apikey):
    url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={apikey}'

    headers = {
        'Content-type': 'application/json'
    }

    data = {
        'client': {
            'clientId': 'VitOSINT',
            'clientVersion': '0.1'
        },
        'threatInfo': {
            'threatTypes':      ['MALWARE',
                                 'SOCIAL_ENGINEERING',
                                 'THREAT_TYPE_UNSPECIFIED',
                                 'UNWANTED_SOFTWARE',
                                 'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes':    ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [
                {'url': f'{ioc}'}
            ]
        }
    }
    response = requests.post(url=url, headers=headers, data=json.dumps(data))

    response_json = json.loads(response.text)

    if response.status_code == 200:
        response_json = json.loads(response.text)

        return response_json
    
    return {'error': response.status_code}


def hunter_email_check(email, apikey):
    url = f'https://api.hunter.io/v2/email-verifier?email={email}&api_key={apikey}'

    response = requests.get(url=url)

    response_json = json.loads(response.text)

    if response.status_code == 200:
        response_json = json.loads(response.text)

        return response_json
    
    return {'error': response.status_code}


def emailrep_email_check(email, apikey):
    url = f'https://emailrep.io/{email}'

    headers = {
        'key': apikey,
        'User-Agent': 'VitOSINT'
    }

    response = requests.get(url=url, headers=headers)

    response_json = json.loads(response.text)

    if response.status_code == 200:
        response_json = json.loads(response.text)

        return response_json
    
    return {'error': response.status_code}


def haveibeenpwnd_email_check(email, apikey):
    services = ['pasteaccount', 'breachedaccount']

    headers = {
        'hibp-api-key': apikey,
        'User-Agent': 'VitOSINT'
    }

    result = {}

    for service in services:
        response = requests.get(url=f'https://haveibeenpwned.com/api/v3/{service}/{email}', headers=headers)

        if response.status_code in [401, 429]:
            result_dict = {'error': response.status_code}

        sleep(6)

        result[service] = json.loads(response.content) if response.content else None

    return result


def malwarebazaar_hash_check(hash):
    url = 'https://mb-api.abuse.ch/api/v1/'

    data = {
        'query': 'get_info',
        'hash': hash
    }

    response = requests.post(url=url, data=data)

    response_json = json.loads(response.text)

    if response.status_code == 200:
        response_json = json.loads(response.text)

        return response_json
    
    return {'error': response.status_code}


def check_shodan(ioc, method, apikey):
    url = 'https://api.shodan.io'

    endpoint = {
        'ip': '/shodan/host/',
        'domain': '/dns/domain/'
    }

    if method == 'ip':
        response = requests.get(url=url + endpoint[method] + ioc + '?key=' + apikey)

        response_json = json.loads(response.text)

        if response.status_code == 200:
            response_json = json.loads(response.text)

            return response_json

        elif response.status_code == 404 and response_json['error'] == 'No information available for that IP.':
            return response_json

        return {'shodan_error': response.status_code}

    elif method == 'domain':
        response = requests.get(url=url + endpoint[method] + ioc + '?key=' + apikey)

        response_json = json.loads(response.text)

        if response.status_code == 200:
            response_json = json.loads(response.text)

            return response_json
        
        return {'shodan_error': response.status_code}


def search_reddit(ioc, client_secret, client_id):
    url = f'https://www.reddit.com/search.json'

    headers = {
        'User-Agent': 'VitOSINT 0.1'
    }

    params = {
        'q': ioc,
        'sort': 'new',
        'limit': 25,
        'syntax': 'plain',
        't': 'all'
    }

    response = requests.get(url, headers=headers, params=params, auth=(client_id, client_secret))

    result = []

    if response.ok:
        data = response.json()

        for post in data['data']['children']:
            post_data = post['data']

            result.append({
                'id': post_data['id'],
                'author': post_data['author'],
                'created_utc': datetime.fromtimestamp(int(post_data['created_utc'])).strftime('%Y-%m-%d %H:%M:%S'),
                'title': post_data['title'],
                'message': post_data['selftext'],
                'score': post_data['score'],
                'url': post_data['url']
            })

    if response.status_code in [401, 429]:
        result_dict = {'error': response.status_code}

    return result


def mastodon(keyword):
    url = f'https://ioc.exchange/api/v2/search?q={keyword}'

    response = requests.get(url=url)

    if response.status_code == 200:
        response_json = json.loads(response.text)['statuses']

        return response_json
    
    return {'error': response.status_code}



def search_nist_nvd(cve, api_key):
    headers = {
        'apiKey': api_key
    }

    pattern = r'^CVE-\d{4}-\d{4,}$'

    match_cve = re.match(pattern, cve)

    if match_cve:
        url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}'

        response = requests.get(url=url, headers=headers)

        if response.status_code == 200:
            response_json = json.loads(response.text)

            return response_json
        
        return {'error': response.status_code}
    
    response_json = {'error': 'Invalid input '}

    return response_json


def search_github(ioc, access_token):
    url = f'https://api.github.com/search/code?q={ioc}'

    headers = {
        'Authorization': f'Token {access_token}'
    }

    response = requests.get(url=url, headers=headers)

    if response.status_code == 200:
        response_json = response.json()

        return response_json
    
    return {'error': response.status_code}
