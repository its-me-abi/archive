import dns.query
import dns.message
import dns.rdatatype

"""
this code is based on this research paper
    https://cvr.ac.in/ojs/index.php/cvracin/article/download/537/427

it compares reqest and responce ids and if matches then check ttl,if ttl is > 1 day then it is dns cache poison

"""
def get_query_and_responce(domain,resolver ='8.8.8.8'):
    query = dns.message.make_query(domain, dns.rdatatype.A)
    response = dns.query.udp(query, resolver)
    return query,response

def is_id_of_req_and_responce_equal(req,res):
    if req == res:
        return True

def is_ttl_long(ttl):
    minutes = ttl/60
    hour = minutes/60
    if hour > 24:
        return True

def is_it_spoofed(domain):
    query,response = get_query_and_responce(domain)

    print(f"Request ID: {query.id}")
    print(f"Response ID: {response.id}")
    if is_id_of_req_and_responce_equal(query.id,response.id):
        print("req id and resp id mathes so check ttl ")

    if response.answer:
        for rrset in response.answer:
            for rdata in rrset:
                ttl = rrset.ttl
                print(f"Record: {rdata}, TTL: {ttl}")
                print(f"TTL is {ttl}")
                if is_ttl_long(ttl):
                    print ("ttl is > one day so probably it is spoofing ")
                    return True
                else:
                    print("ttl is short < 24 hrs ")
    else:
        print("No answer records found.")

if __name__ == "__main__":
    domain = 'google.com'
    result = is_it_spoofed(domain)
    if result :
        print("this domain is spoofed")
    else:
        print("spoofing not detected ")