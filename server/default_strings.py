domain_monitoring = {
    'description': '''### Domain Monitoring is a module that helps you protect your organization from phishing attacks by allowing you to search for recently registered domains that match a specific pattern. This can help you identify potential threats before they occur. Using the URLScan.io API, the module allows you to view screenshots of websites to see what is behind a domain without the need to visit the site and potentially expose yourself to danger. Additionally, with just a single click, you can check each domain and the IP it resolves to against multiple threat intelligence services to further protect your organization.

```bash
For example, you can use the module to search for domains that start with "google-" by using the search pattern "google-*". 
```
    '''
}

email_analyzer = {
    'description': '### Email Analyzer is a module that allows you to analyze .eml files for potential threats. To use the module, simply drag an .eml file into it. The module will then parse the file and perform basic security checks to identify any potential risks. It also extracts all indicators of compromise (IOCs) from the file and makes it possible to analyze them using various open source intelligence (OSINT) services. In addition, Email Analyzer generates hash values for every attachment in the file, allowing you to perform a privacy-friendly analysis of these files. This can help you protect your organization from cyber attacks and other threats that may come through email.'
}

ioc_analyzer = {
    'description': '''### IOC Analyzer is a module that helps you analyze various types of indicators of compromise (IOCs), including IP addresses, hashes, email addresses, domains, and URLs. It uses a variety of services, such as VirusTotal, AlienVault, and AbuseIPDB, as well as social media platforms, to gather information about the IOCs you are interested in. The tool is able to automatically detect the type of IOC you are analyzing and uses the appropriate services to gather the most relevant information. This can help you identify potential threats and take the necessary steps to protect your organization from cyber attacks.

**Available IOCs you can analyze:**
    - IP addresses -
    - Domains -
    - URLs -
    - Email addresses -
    - Hashes (md5, sha1, sha256) -
    - CVEs -
    '''
}

ioc_extractor = {
    'description': '### IOC Extractor is a module that allows you to extract and organize indicators of compromise (IOCs) from unstructured files using regular expressions (Regex). The module automatically removes any duplicates, so you dont have to worry about sorting through the same IOCs multiple times. There are no complicated settings or features to worry about – just drop your file containing the IOCs into the tool and let it do the work for you. With a single click, you can analyze every detected IOC, saving you the time and effort of building Excel sheets to extract IOCs from files manually. Whether you are an experienced security professional or new to the field, IOC Extractor can help you quickly and easily identify potential threats to your organization.'
}
