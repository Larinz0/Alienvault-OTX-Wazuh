#!/usr/bin/env python3
import requests

url = "https://otx.alienvault.com/otxapi/indicators/"
params = {
    'type': 'domain',
    'include_inactive': 0,
    'sort': '-modified',
    'q': '',
    'limit': 10
}

headers = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'X-OTX-API-KEY': 'APIKEY_HERE'
}

output_file = "domains.txt"  # Nome del file di output

with open(output_file, 'w') as file:
    for page in range(1, 100000):  # cicla attraverso le prime 10 pagine
        params['page'] = page
        response = requests.get(url, params=params, headers=headers)

        if response.status_code == 200:
            data = response.json()
            domain_list = [entry['indicator'] for entry in data['results'] if entry['type'] == 'domain']
            
            for domain in domain_list:
                file.write(f"{domain}:\n")  
                print(f"Scritto su file: {domain}")
        else:
            print(f"Errore nella richiesta per la pagina {page}: {response.status_code}")
            print(response.text)

print(f"I domini sono stati scritti su {output_file}")
