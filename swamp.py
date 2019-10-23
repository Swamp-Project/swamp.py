import json
import requests
import sys
import argparse
import re
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import init
from colorama import Fore, Back, Style
from datetime import datetime
# disable warning HTTPS
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# USER API KEYS
SPY_ON_WEB_API_KEY=""

class Swamp(object):

    def __init__(self, cli=False, outfile=None, api="urlscan", token=None): 
        self.cli = cli
        self.outfile = outfile
        self.urlscan = False
        self.spyonweb = False
        if isinstance(api,list):
            api_list = api
        elif isinstance(api,str):
            api_list = api.split(',')
        else:
            raise ValueError('api must be either a string or list of strings')

        if api_list[0] == "all":
            self.urlscan = True
            self.spyonweb = True
        if "spyonweb" in api_list:
            self.spyonweb = True
        if "urlscan" in api_list:
            self.urlscan = True

        # ensure api_key is given if needed
        if self.spyonweb:
            # if a token is passed in, use it (allows me to test without putting my key on the internet)
            if token != None:
                self.api_key = token
            # if not, and the api key is not defined, warn the user and disable spyoneweb
            elif SPY_ON_WEB_API_KEY == "":
                print(Fore.RED + "SpyOnWeb API is enabled and an API Key has not been supplied. Set 'SPY_ON_WEB_API_KEY' at the top of swamp.py")
                self.spyonweb = False
            # otherwise, use the API key
            else:
                self.api_key = SPY_ON_WEB_API_KEY
            
    def run(self,id=None,url=None):
        gid = id
        if self.outfile != None:
            # write date and time to file to initialize
            with open(self.outfile,'w') as fObj:
                dt = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
                fObj.write("{}\n".format(dt))

        if gid != None:
            urls = self.scan_gid(gid)
            if not self.cli:
                return urls

        elif url != None:
            gids = self.get_gids_from_url(self.handle_url_protocol(url))
            urls = self.scan_gids(gids)
            if not self.cli:
                return urls

        else:
            if self.cli:
                print(Fore.RED + "You must pass in either '-url <webpage url>' or '-id <google tracking id>'")
                print(Style.RESET_ALL)
            else:
                assert False, "You must pass in either url=<webpage url string> or id=<google tracking id string>"

    def show_banner(self):
        if self.cli:
            print()
            print(Fore.YELLOW + 
            """
            .d8888b.  888       888       d8888888b     d8888888888b.
            d88P  Y88b888   o   888      d888888888b   d8888888   Y88b
            Y88b.     888  d8b  888     d88P88888888b.d88888888    888
            "Y888b.   888 d888b 888    d88P 888888Y88888P888888   d88P
                "Y88b.888d88888b888   d88P  888888 Y888P 8888888888P"
                  "88888888P Y88888  d88P   888888  Y8P  888888
            Y88b  d88P8888P   Y8888 d8888888888888   "   888888
             "Y8888P" 888P     Y888d88P     888888       888888          
            """)
    
            print()
            print(Fore.GREEN + "An OSINT tool for Google Analytics ID Reverse lookup")
            print(Fore.RED + "By Jake Creps | With help from Francesco Poldi, WebBreacher and Mark Ditsworth")
            print(Fore.WHITE)

    def handle_url_protocol(self,url):
        pattern = re.compile('^http[s]?\://')
        if pattern.match(url):
            # input string is okay, but make sure it is valid  url
            validated_url = self.validate_url(url)
            if not validated_url:
                raise ValueError("{} is not a valid URL.".format(url))
            else:
                return validated_url
        else:
            if self.cli:
                print(Fore.YELLOW + "Protocol not given. Will try HTTPS and then HTTP.")
            # test if https will work
            https_url = 'https://' + url
            validated_https_url = self.validate_url(https_url)
            if not validated_https_url:
                # try http
                if self.cli:
                    print(Fore.RED + "Failed.")
                http_url = 'http://' + url
                validated_http_url = self.validate_url(http_url)
                if not validated_http_url:
                    raise ValueError("{} is not a valid URL".format(url))
                else:
                    return validated_http_url
            else:
                return validated_https_url
    
    def validate_url(self,url):
        if self.cli:
            print(Fore.GREEN + "Validating {}".format(url))
        try:
            check = requests.head(url)
        except requests.exceptions.ConnectionError:
            print(Fore.RED + "Unable to access {}".format(url) + Style.RESET_ALL)
            return False

        if check.status_code < 400:
            # if redirected, return the redirected url
            if check.status_code // 100 == 3:
                if self.cli:
                    print(Fore.YELLOW + "Redirected to " + Fore.WHITE + "{}".format(check.headers['Location']))
                return check.headers['Location']
            else:
                return url
        else:
            return False
    
    def get_gids_from_url(self,url):
        if self.cli:
            print(Fore.GREEN + "Analyzing {}...".format(url) + Style.RESET_ALL)

        if self.outfile != None:
            with open(self.outfile,'a') as fObj:
                fObj.write("Anlaysis for {}\n".format(url))

        urlresponse = requests.get(url,verify=False)
        gids_list = re.findall('UA\-[0-9]+\-[0-9]+',urlresponse.text)
        # drop duplicate ids
        gids_list = set(gids_list)

        for gid in gids_list:
            if self.cli:
                print(Fore.GREEN + "Discovered " + Fore.YELLOW + "{}".format(gid) + Fore.GREEN + " Google Tracking ID in " + Fore.WHITE + "{}".format(url))
        return gids_list

    def scan_gids(self, ids):
        if self.cli:
            for _id in ids:
                self.scan_gid(_id)
        else:
            urls = {}
            for _id in ids:
                urls[_id] = self.scan_gid(_id)
            return urls
    
    def query_api(self,url):
        try:
            # Make web request for that URL and don't verify SSL/TLS certs
            response = requests.get(url, verify=False)
        except Exception as e:
            print(Fore.RED + "[ !!! ]   ERROR - {}".format(str(e)))
            sys.exit(1)

        if self.cli:
            print(Fore.YELLOW + "[+] " + Fore.RED + "Searching for associated URLs...")

        return response

    def query_urlscan(self, id):
        url = 'https://urlscan.io/api/v1/search/?q={}'.format(id)

        response = self.query_api(url)

        # Output is already JSON so we just need to load and parse it
        j = json.loads(response.text)

        # Create an empty set to store the URLs so we only get unique ones
        uniqueurls = set([])

        # Extract every URL and add to the set
        for entry in j['results']:
            uniqueurls.add((entry['page']['url']))
        return uniqueurls
    
    # Returns a limit of 100 results
    # ToD0: Support setting the limit
    # ToDo: Support getting more results with iterative requests
    # ToDo: de-duplicate results (e.g. example.com and www.example.com will be returned
    def query_spyonweb(self,id,api_key):
        url = 'https://api.spyonweb.com/v1/analytics/{}?access_token={}'.format(id,api_key)
        
        # the id, less the last set of numbers, is used to get the results from the returned json
        id_key = '-'.join(id.split('-')[:2])
        
        response = self.query_api(url)

        j = json.loads(response.text)
        if j['status'] != "found":
            print(Fore.RED + "Error accessing API." + Style.RESET_ALL)
            sys.exit(1)
        else:
            urls = j['result']['analytics'][id_key]['items'].keys()
            return set(urls)

    def output_api_results(self, id, urls):
        if self.cli:
            print(Fore.YELLOW + "[+] " + Fore.RED + "Outputting discovered URLs associate to {}...".format(id))

        if self.outfile != None:
            with open(self.outfile,'a') as fObj:
                fObj.write("Outputting discovered URLs associate to {}\n".format(id))
        
        # Sort the set and print
        for url in sorted(urls):
            if self.cli:
                print(Fore.YELLOW + '[!]' + Fore.GREEN + " URL: " + Fore.WHITE + url)
            if self.outfile != None:
                with open(self.outfile,'a') as fObj:
                    fObj.write("URL: {}\n".format(url))

        print(Style.RESET_ALL)
        return list(urls)

    def scan_gid(self, id):
        if self.cli:
            print()
            print(Fore.GREEN + "Using {} for Reverse Lookup".format(id))
        
        URLs = {}
        if self.spyonweb:
            if self.cli:
                print(Fore.GREEN + "Querying SpyOnWeb")
            uniqueurls = self.query_spyonweb(id,self.api_key)
            URLs['spyonweb'] = self.output_api_results(id,uniqueurls)
        
        if self.urlscan:
            if self.cli:
                print(Fore.GREEN + "Querying urlscan")
            uniqueurls = self.query_urlscan(id)
            URLs['urlscan'] = self.output_api_results(id,uniqueurls)

        return URLs


    def url_to_domain(self,url):
        pattern = re.compile("^http[s]?\://[^/]+")
        domain = pattern.match(url)
        return domain[0]

    def urls_to_domains(self,url_iter):
        domain_set = set([])
        for url in url_iter:
            domain_set.add((self.url_to_domain(url)))
        return list(domain_set)

if __name__ == '__main__':
    ap = argparse.ArgumentParser(prog="swamp", usage="python %(prog)s [options]")
    ap.add_argument('-id', help="Google Analytics ID", action="store")
    ap.add_argument('-url', help="Website URL", action="store")
    ap.add_argument('-o', help="Output file for results", action="store")
    ap.add_argument('-urlscan',help="Use the urlscan API for reverse lookup", action="store_true")
    ap.add_argument('-spyonweb',help="Use the SpyOnWeb API for reverse lookup", action="store_true")
    ap.add_argument('-token',help="API key or token", action="store")
    args = ap.parse_args()
    
    # set api based on user input. defaults to urlscan
    api_choice = []
    if args.urlscan:
        api_choice.append('urlscan')
    if args.spyonweb:
        api_choice.append('spyonweb')
    if not args.spyonweb and not args.urlscan:
        api_choice = "all"

    SwampApp = Swamp(cli=True, outfile=args.o, api=api_choice, token=args.token)
    SwampApp.show_banner()
    SwampApp.run(id=args.id,url=args.url)
