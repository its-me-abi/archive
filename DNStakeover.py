
import sys
try:
    import dns
    import dns.resolver
except:
    print ("### error dnspython is not installed .try installing it . 'pip install dnspython' ###")
    sys.exit()

#author : abilash /6/2024  part of swiftsafe internship

vulnerable_dns_services = [

    "ns1.000domains.com",
    "ns2.000domains.com",
    "fwns1.000domains.com",
    "fwns2.000domains.com"

    #Digital Ocean
    "ns1.digitalocean.com",
    "ns2.digitalocean.com",
    "ns3.digitalocean.com",

    #ns**.
    ".dnsmadeeasy.com",

    #Domain.com
    "ns1.domain.com",
    "ns2.domain.com",

    #dotser
    "ns1.dotster.com",
    "ns2.dotster.com",
    "ns1.nameresolve.com",
    "ns2.nameresolve.com",

    #easydns
    "dns1.easydns.com",
    "dns2.easydns.net",
    "dns3.easydns.org",
    "dns4.easydns.info",

    #ns-cloud-**.googledomains.com

    ".googledomains.com",

    #Hurricane Electric
    "ns1.he.net",
    "ns2.he.net",
    "ns3.he.net",
    "ns4.he.net",
    "ns5.he.net",

    #Linode
    "ns1.linode.com",
    "ns2.linode.com",

    #mydomain
    "ns1.mydomain.com",
    "ns2.mydomain.com",

    #name.com ns1***.name.com
    ".name.com",

    #tierranet
    "ns1.domaindiscover.com",
    "ns2.domaindiscover.com",

    #reg.ru
    "ns1.reg.ru",
    "ns2.reg.ru",

    #yahoo small business
    "yns1.yahoo.com",
    "yns2.yahoo.com",

    ]



def get_all_ip_of_nameserver(nameserver):
    "returns  all ips of nameserver from A record"
    try:

        all_ips = []
        a_records = dns.resolver.resolve(nameserver, 'A')

        if a_records:
            for ip in a_records:
                ip_text = ip.to_text()
                print(f"\n ip address found for nameserver {nameserver} is {ip_text} ")
                all_ips.append (ip_text)
            return all_ips
        else:
           print(f"no ip  found in NS records for this nameserver {nameserver}")

    except dns.resolver.NoNameservers:
        print(f"No nameservers found for {nameserver}")
    except dns.resolver.NXDOMAIN:
        print(f"Domain {nameserver} does not exist")
    except dns.exception.DNSException as e:
        print(f"DNS lookup failed: {e}")
    finally:
        return []


def get_first_ip_of_nameserver(nameserver):
    "returns a first ip of nameserver from A record"
    ips = get_all_ip_of_nameserver(nameserver)
    if ips:
        return ips[0]


def get_all_nameservers_of_domain(domain):
    "query resolover for authorititaive ns records for a domain"

    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        all_nameservers = []

        if ns_records:
            print(f"ns records found for domain {domain}")
            for one_ns_records in ns_records:
                print(f"   {one_ns_records.to_text()}")
                all_nameservers.append(one_ns_records.to_text().rstrip("."))

            return all_nameservers

        else:
           print(f"ns records not found for domain {domain}")

    except dns.resolver.NoNameservers:
        print(f"No nameservers found for {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"Domain {domain} does not exist")
    except dns.exception.DNSException as e:
        print(f"DNS lookup failed: {e}")


def get_vulnerable_nameservers(domain = []):
    nameservers = domain
    vulnerable_servers = []
    for one_dns_server in nameservers:
        for one in vulnerable_dns_services:
           if one in one_dns_server  :
               print(f"   yes vulnerable dns providers detected {one_dns_server} ")
               vulnerable_servers.append(one_dns_server)
    return vulnerable_servers


def is_nameserver_returns_refused_or_serverfail(domain,nameserver):
    try:
        resolver = dns.resolver.Resolver()
        nameserver_ip = get_first_ip_of_nameserver(nameserver)
        if nameserver_ip:
           print (f" checking {nameserver} for noerror. sended this domain in query = {domain}")
           resolver.nameservers = [nameserver_ip]
           a_records = resolver.resolve(domain, 'A')
           if a_records:
               status_code = a_records.response.rcode()
               if status_code == dns.rcode.NOERROR:
                    print(f" DNS takeover not possible because noerror returned from {nameserver}")

               elif status_code == dns.rcode.REFUSED or dns.rcode.SERVFAIL:
                    print(f" dns takeover possible on {nameserver} because code is {status_code}")
                    return True
           else:
               print(f" no A record found in {nameserver} for the domain = {domain}")

    except dns.resolver.NoNameservers:
        print(f"No nameservers found for {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"Domain {domain} does not exist")
    except dns.exception.DNSException as e:
        print(f"DNS lookup failed: {e}")


def is_takeover_possible (domain):

    all_nameservers   = get_all_nameservers_of_domain(domain)

    if all_nameservers:
        all_vulnerable_nameservers = get_vulnerable_nameservers(all_nameservers)
        if all_vulnerable_nameservers:
            print ("\n# we got vulnerable dns provider servers so next ask it about domain")
            takeover_possibel_nameservers = []

            for one_server in  all_vulnerable_nameservers :
                is_it_vulnerable = is_nameserver_returns_refused_or_serverfail(domain ,one_server)
                if is_it_vulnerable:
                    print (f" ### found a vulnerable nameserver {one_server}")
                    takeover_possibel_nameservers.append( one_server )
                else:
                    print (f" checked it is not vulnerable {one_server}")
            return takeover_possibel_nameservers

        else:
            print ("# this nameserver is not from vulnerable dns provider ")
    else:
        print("no nameservers available for this domain (no NS record)")


def check_domains_from_file(input='domains.txt' ,out = 'result.txt' ,failed = 'result_failed.txt'):
    with open(input, 'r') as infile:
       for line in infile:
           print ("\n# checking following line",line)
           result = is_takeover_possible(line.strip())
           if result:
               with open(out, 'a+') as outfile:
                   outfile.write ( str(result))
           else:
               with open(failed, 'a+') as failed:
                   failed.write ( line)

def ask_by_cli():
    domain = input("enter a domain name to check dns takeover possible or not >")
    possible = is_takeover_possible(domain)
    return possible


def get_comandline_args():
    parser = argparse.ArgumentParser(description=" it can check possibility of dns takeover. you can give domain name as input")
    parser.add_argument("-d", "--domain", help = "which domain you want to check like google.com")
    parser.add_argument("-in", "--input", help = "path to domain.txt contains a domain list ")
    parser.add_argument("-out", "--output", help="to which file it should write successfull takeover details")
    args = parser.parse_args() 
    return args


if __name__ == "__main__":
    import argparse
    
    args = get_comandline_args()
    possible = []
    
    if args.domain  :
        possible = is_takeover_possible(args.domain)
    else:
        if args.input and args.output:
            check_domains_from_file(input = args.input,out = args.output )
        else:
            possible = ask_by_cli()

    if  possible:
        print ("############   YES. DNS takeover  possible  ############")
        for servers in possible:
            print ("[+] ",servers)
    else:
        print ("############ NO. DNS takeover  impossible ############")

