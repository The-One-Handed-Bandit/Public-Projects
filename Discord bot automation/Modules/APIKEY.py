from dotenv import load_dotenv
import os
import requests 
import json
import base64


load_dotenv()


ip = os.getenv("abused_ip")
links = os.getenv("virus_total")

    
search = 'https://api.abuseipdb.com/api/v2/check'
VT_API_URL = 'https://www.virustotal.com/api/v3/urls'

def checker(address):
    header = {
            'Accept': 'application/json',
            'Key':ip
        }


    querystring = {
            'ipAddress': address,
            'maxAgeInDays': '90'
        }

    try:
        request = requests.get(search,headers=header, params=querystring )
        stats = request.json()
        attribute = stats.get('data', {})
        return attribute 
    except Exception as e:
            return print(e)
            
    
def string(url):


    headers = {
        'x-apikey':links
    }

    submit = requests.post(VT_API_URL, headers=headers, data={"url": url})
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    returning = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    report = requests.get(returning, headers=headers)
    response = report.json()

    hi = response.get('data', {})
    data = hi.get('attributes', {})
    stats = data.get('last_analysis_stats', {})
    got = data.get("last_http_response_headers", {})

    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    undetected = stats.get('undetected', 0)
    typel = hi.get('type')
    Content= got.get("Content-Type")
    total = malicious + suspicious + undetected + stats.get('harmless', 0)
    return{ 
        'malicious': malicious,
        'total': total,
        'typel': typel,
        'Content': Content,
        'data': hi
    }
