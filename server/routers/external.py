import ioc_analyzer
import domain_monitoring
import newsfeed
from fastapi import APIRouter, Body
from database import crud, models
from database.database import SessionLocal, engine

router = APIRouter()
models.Base.metadata.create_all(bind=engine)


@router.get('/api/ip/abuseipdb/{ip}', tags=['IP addresses'])
async def abuseipdb(ip):
    apikey = crud.get_apikey(name='abuseipdb', db=SessionLocal())

    return ioc_analyzer.abuseipdb_ip_check(ip, apikey['key'])


@router.get('/api/ip/alienvault', tags=['IP addresses'])
async def alienvault_ip(ioc=''):
    apikey = crud.get_apikey(name='alienvault', db=SessionLocal())

    return ioc_analyzer.alienvaultotx(ioc, 'ip', apikey['key'])


@router.get('/api/hash/alienvault', tags=['Hashes'])
async def alienvault_hash(ioc=''):
    apikey = crud.get_apikey(name='alienvault', db=SessionLocal())

    return ioc_analyzer.alienvaultotx(ioc, 'hash', apikey['key'])


@router.get('/api/domain/alienvault', tags=['Domains'])
async def alienvault_domain(ioc=''):
    apikey = crud.get_apikey(name='alienvault', db=SessionLocal())

    return ioc_analyzer.alienvaultotx(ioc, 'domain', apikey['key'])


@router.get('/api/ip/bgpview/{ip}', tags=['IP addresses'])
async def bgpview(ip):
    return ioc_analyzer.check_bgpview(ip)


@router.get('/api/ip/blocklist_de/{ip}', tags=['IP addresses'])
async def blocklistde(ip):
    return ioc_analyzer.blocklist_de_ip_check(ip)


@router.get('/api/ip/crowdsec/{ip}', tags=['IP addresses'])
async def crowdsec(ip):
    apikey = crud.get_apikey(name='crowdsec', db=SessionLocal())

    return ioc_analyzer.crowdsec(ip, apikey['key'])


@router.get('/api/ip/ipqualityscore/{ip}', tags=['IP addresses'])
async def ipqualityscore(ip):
    apikey = crud.get_apikey(name='ipqualityscore', db=SessionLocal())

    return ioc_analyzer.ipqualityscore_ip_check(ip, apikey['key'])


@router.get('/api/ip/maltiverse/{ip}', tags=['IP addresses'])
async def maltiverse_ip(ip):
    apikey = crud.get_apikey(name='maltiverse', db=SessionLocal())

    return ioc_analyzer.maltiverse_check(ip, 'ip', apikey['key'])


@router.get('/api/domain/maltiverse/{hostname}', tags=['Domains'])
async def maltiverse_domain(hostname):
    apikey = crud.get_apikey(name='maltiverse', db=SessionLocal())

    return ioc_analyzer.maltiverse_check(hostname, 'hostname', apikey['key'])


@router.get('/api/url/checkphish/{url}', tags=['URLs'])
async def checkphish_url(url):
    apikey = crud.get_apikey(name='checkphishai', db=SessionLocal())

    return ioc_analyzer.checkphish_ai(url, apikey['key'])


@router.get('/api/domain/checkphish/{domain}', tags=['Domains'])
async def checkphish_domain(domain):
    apikey = crud.get_apikey(name='checkphishai', db=SessionLocal())

    return ioc_analyzer.checkphish_ai(domain, apikey['key'])


@router.get('/api/ip/checkphish/{ip}', tags=['IP addresses'])
async def checkphish_ip(ip):
    apikey = crud.get_apikey(name='checkphishai', db=SessionLocal())

    return ioc_analyzer.checkphish_ai(ip, apikey['key'])


@router.get('/api/url/maltiverse/{url}', tags=['URLs'])
async def maltiverse_url(url):
    apikey = crud.get_apikey(name='maltiverse', db=SessionLocal())

    return ioc_analyzer.maltiverse_check(url, 'url', apikey['key'])


@router.get('/api/hash/maltiverse/{hash}', tags=['Hashes'])
async def maltiverse_hash(hash):
    apikey = crud.get_apikey(name='maltiverse', db=SessionLocal())

    return ioc_analyzer.maltiverse_check(hash, 'sample', apikey['key'])


@router.get('/api/hash/malwarebazaar/{hash}', tags=['Hashes'])
async def malwarebazaar(hash):
    return ioc_analyzer.malwarebazaar_hash_check(hash)


@router.get('/api/newsfeed', tags=['VitOSINT modules'])
async def news():
    return newsfeed.get_news()


@router.get('/api/ip/pulsedive', tags=['IP addresses'])
async def pulsedive_ip(ioc=''):
    apikey = crud.get_apikey(name='pulsedive', db=SessionLocal())

    return ioc_analyzer.check_pulsedive(ioc, apikey['key'])


@router.get('/api/domain/pulsedive', tags=['Domains'])
async def pulsedive_domain(ioc=''):
    apikey = crud.get_apikey(name='pulsedive', db=SessionLocal())

    return ioc_analyzer.check_pulsedive(ioc, apikey['key'])


@router.get('/api/hash/pulsedive', tags=['Hashes'])
async def pulsedive_hash(ioc=''):
    apikey = crud.get_apikey(name='pulsedive', db=SessionLocal())

    return ioc_analyzer.check_pulsedive(ioc, apikey['key'])


@router.get('/api/domain/safebrowsing', tags=['Domains'])
async def safebrowsing_domain(ioc=''):
    apikey = crud.get_apikey(name='safebrowsing', db=SessionLocal())

    return ioc_analyzer.safebrowsing_url_check(ioc, apikey['key'])


@router.get('/api/url/safebrowsing', tags=['URLs'])
async def safebrowsing_url(ioc=''):
    apikey = crud.get_apikey(name='safebrowsing', db=SessionLocal())

    return ioc_analyzer.safebrowsing_url_check(ioc, apikey['key'])


@router.get('/api/ip/shodan', tags=['IP addresses'])
async def shodan_ip(ioc=''):
    apikey = crud.get_apikey(name='shodan', db=SessionLocal())

    return ioc_analyzer.check_shodan(ioc, 'ip', apikey['key'])


@router.get('/api/domain/shodan', tags=['Domains'])
async def shodan_domain(ioc=''):
    apikey = crud.get_apikey(name='shodan', db=SessionLocal())

    return ioc_analyzer.check_shodan(ioc, 'domain', apikey['key'])


@router.get('/api/ip/threatfox/{ip}', tags=['IP addresses'])
async def theatfox(ip):
    apikey = crud.get_apikey(name='threatfox', db=SessionLocal())

    return ioc_analyzer.threatfox_ip_check(ip, apikey['key'])


@router.get('/api/email/hunterio/{email}', tags=['Emails'])
async def hunterio(email):
    apikey = crud.get_apikey(name='hunterio', db=SessionLocal())

    return ioc_analyzer.hunter_email_check(email, apikey['key'])


@router.get('/api/email/emailrepio/{email}', tags=['Emails'])
async def emailrepio(email):
    apikey = crud.get_apikey(name='emailrepio', db=SessionLocal())

    return ioc_analyzer.emailrep_email_check(email, apikey['key'])


@router.get('/api/email/haveibeenpwnd/{email}', tags=['Emails'])
async def haveibeenpwnd(email):
    apikey = crud.get_apikey(name='hibp', db=SessionLocal())

    return ioc_analyzer.haveibeenpwnd_email_check(email, apikey['key'])


@router.get('/api/cve/nist_nvd/{cve}', tags=['CVEs'])
async def nistnvd(cve):
    if not hasattr(crud.get_apikey(name='nist_nvd', db=SessionLocal()), 'key'):
        return {'error': 'No API key found for NIST NVD'}
    
    apikey = crud.get_apikey(name='nist_nvd', db=SessionLocal())

    return ioc_analyzer.search_nist_nvd(cve, apikey['key'])


@router.get('/api/socialmedia/reddit/{ioc}', tags=['Social Media'])
async def reddit(ioc):
    reddit_cs = crud.get_apikey(name='reddit_cs', db=SessionLocal())
    reddit_cid = crud.get_apikey(name='reddit_cid', db=SessionLocal())

    return ioc_analyzer.search_reddit(ioc=ioc, client_secret=reddit_cs['key'], client_id=reddit_cid['key'])


@router.get('/api/socialmedia/mastodon/{ioc}', tags=['Social Media'])
async def mastodon(ioc):
    return ioc_analyzer.mastodon(ioc)


@router.get('/api/url/urlhaus/{url}', tags=['URLs'])
async def urlhaus(url):
    return ioc_analyzer.urlhaus_url_check(url)


@router.get('/api/url/urlscanio/{domain}', tags=['URLs'])
async def urlscanio(domain):
    return domain_monitoring.urlscanio(domain)


@router.get('/api/ip/virustotal', tags=['IP addresses'])
async def virustotal_ip(ioc=''):
    apikey = crud.get_apikey(name='virustotal', db=SessionLocal())

    return ioc_analyzer.virustotal(ioc, 'ip', apikey['key'])


@router.get('/api/domain/virustotal', tags=['Domains'])
async def virustotal_domain(ioc=''):
    apikey = crud.get_apikey(name='virustotal', db=SessionLocal())

    return ioc_analyzer.virustotal(ioc, 'domain', apikey['key'])


@router.get('/api/url/virustotal', tags=['URLs'])
async def virustotal_url(ioc=''):
    apikey = crud.get_apikey(name='virustotal', db=SessionLocal())
    
    return ioc_analyzer.virustotal(ioc, 'url', apikey['key'])


@router.get('/api/hash/virustotal', tags=['Hashes'])
async def virustotal_hash(ioc=''):
    apikey = crud.get_apikey(name='virustotal', db=SessionLocal())

    return ioc_analyzer.virustotal(ioc, 'hash', apikey['key'])


@router.get('/api/multi/github', tags=['Multi'])
async def github(ioc=''):
    apikey = crud.get_apikey(name='github', db=SessionLocal())

    return ioc_analyzer.search_github(ioc=ioc, access_token=apikey['key'])
