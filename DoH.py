
import requests
from urllib.parse import urlencode

"dns over https client. this code uses free unauthenticated public doh server to resolve dns query"

def build_doh_url(domain, record_type, doh_server):
    query_params = {
        'name': domain,
        'type': record_type
    }
    query_string = urlencode(query_params)
    return f"{doh_server}?{query_string}"

def resolve_dns_over_https(domain, record_type='A', doh_server='https://cloudflare-dns.com/dns-query'):
    jsondata = {}
    headers = {
        'Accept': 'application/dns-json',
    }
    url = build_doh_url(domain, record_type, doh_server)
    print(f"Request URL: {url}")

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Ensure HTTP status code is 200
        print(f" Response Status Code: {response.status_code} ,\n raw data =\n   {response.text}")

        json_response = response.json()
        if 'Answer' in json_response:
            jsondata = json_response['Answer']
        else:
            print( f"No answer found for domain {domain}" )
    except requests.RequestException as e:
        print (f"HTTP request failed: {e}")
    finally:
        return jsondata


def get_ip_list(json_responce):
    ips = []
    for one_server in json_responce:
        try:
            ips.append(one_server["data"])
        except e:
            print("doh json responce contain no data field . this domain may not exists ,",e)
    return  ips

def get_ips(domain):
    ips = []
    json_data = resolve_dns_over_https(domain)

    for one_server in json_data:
        try:
               ips.append(one_server["data"])
        except :
            print("doh json responce contain no data field .because this  domain may not exists")

    return  ips

if __name__ == "__main__":
    domain = 'localhost'
    answers = resolve_dns_over_https(domain)
    ips = get_ip_list(answers)
    if ips:
        for ip in ips:
            print ("# A record reading success")
            print("domain = ",domain," ip = ",ip)
    else:
        print("no ips found")