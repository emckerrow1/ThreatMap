# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from ThreatMap import settings
from django.http import JsonResponse
from django.shortcuts import render

import json
import requests

# Create your views here.
def AbuseIPDBLookup(ip, days=30):
    url = 'https://www.abuseipdb.com/check/{0}/json?key={1}&days={2}'.format(ip, settings.Abuse_DB_API, days)
    result = requests.get(url).json()
    categories_id = []
    categories = []
    for report in result:
        for category_id in report['category']:
            if category_id not in categories_id:
                categories_id.append(category_id)
                categories.append(abuse_category_lookup(category_id))
    results = {'ip':ip, 'count':len(result), 'categories':categories}
    return results

def GeoIPLookup(ip, fields='ip,country_name,latitude,longitude'):
    url = 'http://api.ipstack.com/{0}?access_key={1}&fields={2}'.format(ip, settings.IPStackAPI, fields)
    result = requests.get(url).json()
    return result

def abuse_category_lookup(category):
    categories = {
      '3': 'Fraud orders',
      '4': 'DDoS Attack',
      '5': 'FTP Brute-Force',
      '6': 'Ping of Death',
      '7': 'Phishing',
      '8': 'Fraud VoIP',
      '9': 'Open Proxy',
      '10': 'Web Spam',
      '11': 'Email Spam',
      '12': 'Blog Spam',
      '13': 'VPN IP',
      '14': 'Port Scan',
      '15': 'Hacking',
      '16': 'SQL Injection',
      '17': 'Spoofing',
      '18': 'Brute-Force',
      '19': 'Bad Web Bot',
      '20': 'Exploited Host',
      '21': 'Web App Attack',
      '22': 'SSH',
      '23': 'IoT Targeted'
    }
    return categories[str(category)]

def threat_map(request):
    # took 1 min 22 secs - to process two IPs
    ips = ['31.184.192.185','196.52.43.113']
    results = []
    for ip in ips:
        # implement celery worker here
        abuse = AbuseIPDBLookup(ip)
        if abuse['count'] > 0:
            geo = GeoIPLookup(ip)
            results.append({'abuse':abuse, 'geo':geo})
    #results = [{'geo': {'longitude': 30.2642, 'ip': '31.184.192.185', 'latitude': 59.8944, 'country_name': 'Russia'}, 'abuse': {'count': 61, 'ip': '31.184.192.185', 'categories': ['Brute-Force', 'Web App Attack', 'DDoS Attack', 'Hacking', 'Ping of Death', 'Port Scan', 'Spoofing', 'Web Spam', 'Exploited Host', 'SQL Injection']}}, {'geo': {'longitude': -74.3499, 'ip': '196.52.43.113', 'latitude': 40.5186, 'country_name': 'United States'}, 'abuse': {'count': 98, 'ip': '196.52.43.113', 'categories': ['Port Scan', 'Hacking', 'Brute-Force', 'DDoS Attack', 'Web App Attack', 'FTP Brute-Force', 'SSH', 'Exploited Host']}}]
    print(results)
    return JsonResponse({'results':results})