import dns.query
import dns.message
import dns.rdatatype
import DoH as doh


"""
this module contains dnscache poison detection
this code used ttl based detection of spoofing from this research paper 
    https://cvr.ac.in/ojs/index.php/cvracin/article/download/537/427
another method used is cross checing using multiple dns servers ( dns over https is used for doing it) 

"""

def get_query_and_responce(domain,resolver ='8.8.8.8'):
    query = dns.message.make_query(domain, dns.rdatatype.A)
    response = dns.query.udp(query, resolver)
    return query,response

def is_id_of_req_and_responce_equal(req,res):
    if req == res:
        return True

def is_ttl_long(ttl ,threashold = 24 ):
    minutes = ttl/60
    hour = minutes/60
    print(f" ttl in hours = {hour}")
    if hour > threashold:
        return True

def get_ips(domain):
    ips = []
    query, response = get_query_and_responce(domain)
    if response.answer:
        for rrset in response.answer:
            for rdata in rrset:
                ip = rdata.to_text()
                ips.append(ip)
    return ips

def get_ips_from_doh_and_normal(domain):
    "returns normal dns responce and dnsover http responce"
    normal_ips = get_ips(domain)
    doh_ips = doh.get_ips(domain)
    print(f" normal ips = {normal_ips}")
    print(f" doh ips = {doh_ips}")
    return normal_ips,doh_ips

def is_normal_and_doh_iplist_different(domain):
    "normal dns responce and dnsover http responce willbe compared and if both ips list contain non common ip then it returns it"

    normalips , doh_ips = get_ips_from_doh_and_normal(domain)
    normalips_set = set(normalips)
    doh_ips_set = set(doh_ips)
    result = []
    #normalips_set,doh_ips_set = set([ '185.26.182.103']),set(['185.26.182.10', '185.26.182.103']) # for debugging

    if not normalips_set.issubset(doh_ips_set) or not doh_ips_set.issubset(normalips_set):
        print("two ip's list compared and non matching item is found =",normalips_set - doh_ips_set , doh_ips_set - normalips_set )
        result = list(normalips_set - doh_ips_set | doh_ips_set - normalips_set)
    else:
        print("two items compared. both are equal contents")
    return result


def is_ttl_long_and_it_is_spoofed(domain):
    spoofed_ips = []
    query,response = get_query_and_responce(domain)
    print(f"Request ID: {query.id} Response ID: {response.id}")

    if is_id_of_req_and_responce_equal(query.id,response.id):
        print("req id and resp id mathes so check ttl ")

        if response.answer:
            for rrset in response.answer:
                for rdata in rrset:
                    ttl = rrset.ttl
                    print(f"Record: {rdata}, TTL: {ttl}")
                    if is_ttl_long(ttl):
                        print (" ttl is > one day so probably it is spoofing ")
                        spoofed_ips.append (rdata.address)
                    else:
                        print(" ttl is short < 24 hrs ")
    else:
        print("No answer records found.")
    return spoofed_ips


def is_dns_query_spoofed(domain):
    ips_list = []
    ttl_long_found = is_ttl_long_and_it_is_spoofed(domain)
    responce_difference_found =  is_normal_and_doh_iplist_different(domain)

    if ttl_long_found or responce_difference_found :
        ips_list = ttl_long_found + responce_difference_found
    return ips_list

def get_comandline_args():
    parser = argparse.ArgumentParser(description=" to check cachepoision input domain name ")
    parser.add_argument("-d", "--domain", help = "which domain you want to check. like google.com")
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    import argparse
    args = get_comandline_args()

    if args.domain:
        domain = args.domain
    else:
        domain = input("enter a domain name >")

    result = is_dns_query_spoofed(domain)
    if result:
        print("### this domain is probably spoofed. below is spoofed ip list ###")
        for ip in result:
            print(" [+] ",ip)
    else:
        print("### spoofing not detected ###")