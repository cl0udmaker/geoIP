# -*- coding: utf-8 -*-
"""
Geolocate IP
Micorosft Interflow GeoIP Service [beta]
Input: ipaddress[<ipaddress>...]
Optional Params: --vt [Virus total ipaddress api]
                 --iflow [ip address]

Created on Tue Jul 12 10:48:19 2016

@author: edgarasm
"""
import sys
import httplib, json, requests, xmltodict #urllib, base64

# method to parse JSON object from VT ipaddress api
def vtIP(ip):
    try: 
        params = {'ip': ip, 'apikey': 'APIKEY' }
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        response = requests.get(url, params = params)
        response_json = response.json()
        return response_json
    except Exception as e:
        print('[-Errno {0}] {1}'.format(e.errno, e.strerror))
 
# method to parse string returned from VT and format display
def format_vtIP(out_vt):
    print 'Historic Passive DNS resolutions [last_resolved] [hostname]'
    for resolution in sorted(out_vt['resolutions'], key = lambda key:key['last_resolved'], reverse = True):
        print resolution['last_resolved'], resolution['hostname']
    print 
    print 'Detected URLs [scan_date] [url]'
    for url in sorted(out_vt['detected_urls'], key = lambda key:key['scan_date'], reverse = True):
        print url['scan_date'], url['url']
    return

# method to parse JSON object from interflow geoIP api
def geoIP(ip):
    headers = {'Ocp-Apim-Subscription-Key': 'AzureKey'}
    try:
        conn = httplib.HTTPSConnection('interflowinternal.azure-api.net')
        conn.request('GET', '/geoip/ipinfo/%s' % ip, '{body}', headers)
        response = conn.getresponse()
        response_interflow = response.read()
        return response_interflow
    except Exception as e:
        print('[-Errno {0}] {1}'.format(e.errno, e.strerror))

#TODO: method to parse string and format display [xmltodict]
def format_geoIP(doc):
    print 'IP adress: ' + str(doc['ipinfo']['ip_address'])
    print 'Internet Carrier: ' + doc['ipinfo']['Network']['carrier']
    print 'Domain: ' + doc['ipinfo']['Network']['Domain']['tld']
    print 'Type: ' + str(doc['ipinfo']['Network']['OrganizationData']['organization_type'])
    print 'Description: ' + doc['ipinfo']['Network']['organization']
    print 'Geo Location'
    print 'Region: ' + doc['ipinfo']['Location']['region']
    print 'City: ' + doc['ipinfo']['Location']['CityData']['city']
    print 'County: ' + doc['ipinfo']['Location']['CountryData']['country']
    print 'Country code: ' + doc['ipinfo']['Location']['CountryData']['country_code']
    print 'Continent: ' + doc['ipinfo']['Location']['continent']
    print 'Location: ' + doc['ipinfo']['Location']['latitude'], doc['ipinfo']['Location']['longitude']
    return
#TODO: method to process file input/output

def main():
    if not sys.argv[1:]:
        print 'usage: .geoIP.py [--vt] <ip_address>'
        sys.exit(1)
    if sys.argv[1] =='--vt': 
        ip_address = sys.argv[2]
        out_vt = vtIP(ip_address)
        format_vtIP(out_vt)
    elif sys.argv[1] == '--iflow':
        ip_address = sys.argv[2]
        out_iflow_xml = geoIP(ip_address)
        parsed_xml = xmltodict.parse(out_iflow_xml)
        format_geoIP(parsed_xml)
    
if __name__ == '__main__':
    main()

