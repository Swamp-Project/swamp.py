import json
import requests
import sys
import argparse
import re
import networkx as nx

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import init
from colorama import Fore, Back, Style
from datetime import datetime
# disable warning HTTPS
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# USER API KEYS
SPY_ON_WEB_API_KEY=""

class Swamp(object):
    def __init__(self, cli=False, outfile=None, api="urlscan", token=None, depth=1):
        self.VALIDATION_FAIL_FLAG = False
        self.cli = cli
        self.outfile = outfile
        # limiting depth to 2
        assert type(depth) == int and depth >= 1, "depth argument must be an int >= 1"
        
        if depth > 2:
            self.depth = 2
            print(Fore.YELLOW + "Depth is limited to 2." + Style.RESET_ALL)
        else:
            self.depth = depth
            
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
        
        if self.urlscan:
            self.urlscan_graph = nx.DiGraph()

        # ensure api_key is given if needed
        if self.spyonweb:
            self.spyonweb_graph = nx.DiGraph()
            # if a token is passed in, use it (allows me to test without putting my key on the internet)
            if token != None:
                self.api_key = token
            # if not, and the api key is not defined, warn the user and disable spyoneweb
            elif SPY_ON_WEB_API_KEY == "":
                print(Fore.YELLOW + "                  [!][!][!] WARNING [!][!][!]")
                print(Fore.YELLOW + "SpyOnWeb API is enabled and an API Key has not been supplied.")
                print(Fore.YELLOW + "Set 'SPY_ON_WEB_API_KEY' at the top of swamp.py" + Style.RESET_ALL)
                # if only spyonweb was selected, quit the program
                if not self.urlscan:
                    sys.exit(1)

                self.spyonweb = False
            # otherwise, use the API key
            else:
                self.api_key = SPY_ON_WEB_API_KEY
            
    def run(self,id=None,url=None):
        gid = id
        validated_input = self.build_graph(url=url,_id=gid)
        
        if gid:
            if self.spyonweb and self.cli:
                self.output_single_api_results(validated_input,'spyonweb')
            
            if self.urlscan  and self.cli:
                self.output_single_api_results(validated_input,'urlscan')
            
            if self.outfile:
                self.output_to_file(_id=validated_input)
        
        elif url:
            if self.spyonweb and self.cli:
                self.output_api_results_from_url(validated_input, 'spyonweb')
            
            if self.urlscan and self.cli:
                self.output_api_results_from_url(validated_input, 'urlscan')
                
            if self.outfile:
                self.output_to_file(url=validated_input)
                
        else:
            if self.cli:
                print(Fore.RED + "You must pass in either '-url <webpage url>' or '-id <google tracking id>'")
                print(Style.RESET_ALL)
            else:
                assert False, "You must pass in either url=<webpage url string> or id=<google tracking id string>"
        
        if not self.cli:
            Graphs = {}
            if self.urlscan:
                Graphs['urlscan'] = self.urlscan_graph
            if self.spyonweb:
                Graphs['spyonweb'] = self.spyoneweb_graph
            
            return Graphs

    def build_graph(self,url=None,_id=None):
        assert (url == None or _id == None) and url != _id, "only one of url and _id can be passed in"
        if _id == None:
            validated_url = self.handle_url_protocol(url)
            validated_domain = self.url_to_domain(validated_url)
            gids = self.get_gids_from_url(validated_url)
            if self.urlscan:
                self.scan_gids(gids, calling_url=validated_domain, api='urlscan')
            if self.spyonweb:
                self.scan_gids(gids, calling_url=validated_domain, api='spyonweb')
            root = validated_domain
            
        elif url == None:
            if self.urlscan:
                self.scan_gids([_id], api='urlscan')
            if self.spyonweb:
                self.scan_gids([_id], api='spyonweb')
            root = _id
        
        if self.depth == 2 and _id == None:
            if self.urlscan:
                for n in self.urlscan_graph.successors(root):
                    valid_url = self.handle_url_protocol(n)
                    if self.VALIDATION_FAIL_FLAG:
                        self.VALIDATION_FAIL_FLAG = False
                        continue
                    valid_domain = self.url_to_domain(valid_url)
                    gids = self.get_gids_from_url(valid_url)
                    self.scan_gids(gids, calling_url=valid_domain, api='urlscan')
            if self.spyonweb:
                for n in self.spyonweb_graph.successors(root):
                    valid_url = self.handle_url_protocol(n)
                    if self.VALIDATION_FAIL_FLAG:
                        self.VALIDATION_FAIL_FLAG = False
                        continue
                    valid_domain = self.url_to_domain(valid_url)
                    gids = self.get_gids_from_url(valid_url)
                    self.scan_gids(gids, calling_url=valid_domain, api='spyonweb')
        
        return root
            
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
                    print(Fore.RED + "{} is not a valid URL".format(url) + Style.RESET_ALL)
                    self.VALIDATION_FAIL_FLAG = True
                else:
                    return validated_http_url
            else:
                return validated_https_url
    
    def validate_url(self,url):
        if self.cli:
            print(Fore.GREEN + "Validating {}".format(url) + Fore.WHITE)
        try:
            check = requests.head(url)
        except requests.exceptions.ConnectionError:
            if self.cli:
                print(Fore.RED + "Unable to access {}".format(url) + Style.RESET_ALL)
            return False

        if check.status_code < 400:
            # if redirected, return the redirected url
            if check.status_code // 100 == 3:
                if self.cli:
                    print(Fore.YELLOW + "Redirected to " + Fore.WHITE + "{}".format(check.headers['Location']))
                return url
            else:
                return url
        else:
            return False
    
    def query_api(self,url):
        try:
            # Make web request for that URL and don't verify SSL/TLS certs
            response = requests.get(url, verify=False)
        except Exception as e:
            print(Fore.RED + "[ !!! ]   ERROR - {}".format(str(e)))
            sys.exit(1)

        return response

    def query_urlscan(self, id, calling_url=None):
        url = 'https://urlscan.io/api/v1/search/?q={}'.format(id)

        response = self.query_api(url)

        # Output is already JSON so we just need to load and parse it
        j = json.loads(response.text)

        # Create an empty set to store the URLs so we only get unique ones
        uniqueurls = set([])
        
        #if calling_url != None:
        #    uniqueurls.add(calling_url)
        
        # Extract every URL and add to the set
        for entry in j['results']:
            uniqueurls.add((entry['page']['url']))
        
        if len(uniqueurls) == 0:
            if self.cli:
                print(Fore.YELLOW + "No results found for {}.".format(id) + Style.RESET_ALL)
        else:
            if calling_url != None:
                edges_to_add = [(calling_url, x) for x in self.urls_to_domains(uniqueurls)]
                #self.urlscan_graph.add_edges_from(list(itertools.combinations(self.urls_to_domains(uniqueurls),2)), tracking_id=id)
                self.urlscan_graph.add_edges_from(edges_to_add, tracking_id=id)
            else:
                self.urlscan_graph.add_nodes_from(self.urls_to_domains(uniqueurls))
    
    # Returns a limit of 100 results
    # ToD0: Support setting the limit
    # ToDo: Support getting more results with iterative requests
    # ToDo: de-duplicate results (e.g. example.com and www.example.com will be returned
    def query_spyonweb(self, id, api_key, calling_url=None):
        url = 'https://api.spyonweb.com/v1/analytics/{}?access_token={}'.format(id,api_key)
        
        # the id, less the last set of numbers, is used to get the results from the returned json
        id_key = '-'.join(id.split('-')[:2])
        
        response = self.query_api(url)

        j = json.loads(response.text)
        if j['status'] != "found":
            if self.cli:
                print(Fore.RED + "No results found for {}.".format(id) + Style.RESET_ALL)
        else:
            uniqueurls = set(j['result']['analytics'][id_key]['items'].keys())
            
            #if calling_url != None:
            #    uniqueurls.add(calling_url)
            if calling_url != None:
                edges_to_add = [(calling_url, x) for x in self.urls_to_domains(self.dedupe_urls(uniqueurls))]
                self.spyonweb_graph.add_edges_from(edges_to_add, tracking_id=id)
            else:
                self.spyonweb_graph.add_nodes_from(self.urls_to_domains(self.dedupe_urls(uniqueurls)))
                
    def get_gids_from_url(self,url):
        if self.cli:
            print(Fore.GREEN + "Analyzing {}...".format(url) + Style.RESET_ALL)

#        if self.outfile != None:
#            with open(self.outfile,'a') as fObj:
#                fObj.write("Anlaysis for {}\n".format(url))

        urlresponse = requests.get(url,verify=False)
        gids_list = re.findall('UA\-[0-9]+\-[0-9]+',urlresponse.text)
        # drop duplicate ids
        gids_list = set(gids_list)

        for gid in gids_list:
            if self.cli:
                print(Fore.GREEN + "Discovered " + Fore.YELLOW + "{}".format(gid) + Fore.GREEN + " Google Tracking ID in " + Fore.WHITE + "{}".format(url))
        return gids_list

    def scan_gids(self, ids, calling_url=None, api='urlscan'):
        if len(ids) == 0:
            print(Fore.YELLOW + "No Tacking IDs found in {}".format(calling_url) + Style.RESET_ALL)
            
        for _id in ids:
            self.scan_gid(_id, calling_url=calling_url, api=api)
            

    def scan_gid(self, id, calling_url=None, api='urlscan'):
        if self.cli:
            print()
            print(Fore.GREEN + "Using {} for Reverse Lookup".format(id))
        
        if api == 'spyonweb':
            if self.cli:
                print(Fore.GREEN + "Querying SpyOnWeb")
                
            self.query_spyonweb(id,self.api_key,calling_url=calling_url)
        
        else:
            if self.cli:
                print(Fore.GREEN + "Querying urlscan")
                
            self.query_urlscan(id,calling_url=calling_url)
    
    def output_single_api_results(self,id,api):
        print(Fore.YELLOW + "[+] " + Fore.RED + "Outputting discovered URLs associate with {}...".format(id))
        
#        if self.outfile != None:
#            with open(self.outfile,'a') as fObj:
#                fObj.write("Outputting discovered URLs associate with {}\n".format(id))
        
        if api == 'spyonweb':
            Graph = self.spyonweb_graph.copy()
        else:
            Graph = self.urlscan_graph.copy()
        
        for url in Graph.nodes():
            print(Fore.YELLOW + '[!]' + Fore.GREEN + " URL: " + Fore.WHITE + url)
#            if self.outfile != None:
#                with open(self.outfile,'a') as fObj:
#                    fObj.write("URL: {}\n".format(url))
        
    def output_api_results_from_url(self, url, api):
        
        print(Fore.YELLOW + "[+] " + Fore.RED + "Outputting {} discovered URLs associate with {}...".format(api,url))

#        if self.outfile != None:
#            with open(self.outfile,'a') as fObj:
#                fObj.write("Outputting {} discovered URLs associate with {}\n".format(api,url))
        
        if api == 'spyonweb':
            Graph = self.spyonweb_graph.copy()
        else:
            Graph = self.urlscan_graph.copy()
        
        # Sort the set and print
        #extended_list = [[u,v] for u,v,x in list(Graph.edges.data('tracking_id')) if x == id]
        #reduced_set = set([i for sublist in extended_list for i in sublist])
        try:
            for neighbor in Graph.successors(url):
                print(Fore.YELLOW + '[!]' + Fore.GREEN + " URL: " + Fore.WHITE + neighbor)
                if self.depth == 2:
                    for next_neighbor in Graph.successors(neighbor):
                        print(Fore.YELLOW + '   [!]' + Fore.GREEN + " URL: " + Fore.WHITE + next_neighbor)
        except nx.exception.NetworkXError:
            print(Fore.WHITE + "None found." + Style.RESET_ALL)
        
        print(Style.RESET_ALL)
    
    def _output_to_file(self, api, graph, url=None, _id=None):
        if _id:
            with open(self.outfile, 'a') as fObj:
                fObj.write("Using {} for Reverse Lookup with {}.\n".format(_id, api))
                fObj.write("[+] Discovered URLs associated with {}:\n".format(_id))
                for x in graph.nodes():
                    fObj.write("[!] URL: {}\n".format(x))
        
        elif url:
            with open(self.outfile, 'a') as fObj:
                fObj.write("Analyzing tracking IDs on {} for Reverse Lookup with {}.\n".format(url, api))
                fObj.write("[+] Discovered URLs associated with {}:\n".format(url))
                for neighbor in graph.successors(url):
                    fObj.write("[!] URL: {}\n".format(neighbor))
                    if self.depth == 2:
                        for next_neighbor in graph.successors(neighbor):
                            fObj.write("   [!] URL: {}\n".format(next_neighbor))
    
    def output_to_file(self, url=None, _id=None):
        with open(self.outfile,'w') as fObj:
            dt = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
            fObj.write("File created {} UTC\n".format(dt))
        
        if self.urlscan:
            self._output_to_file('urlscan.io', self.urlscan_graph, url=url, _id=_id)
        
        if self.spyonweb:
            self._output_to_file('SpyOnWeb', self.spyonweb_graph, url=url, _id=_id)
        

    def url_to_domain(self,url):
        pattern = re.compile('(^http[s]?\://w?w?w?\.?|/$)')
        prefix_stripped_url = pattern.sub('',url)
        domain = re.match('[^/]+', prefix_stripped_url)
        return domain[0]

    def urls_to_domains(self,url_iter):
        domain_set = set([])
        for url in url_iter:
            domain_set.add((self.url_to_domain(url)))
        return list(domain_set)
    
    def dedupe_urls(self,url_set):
        deduped_url_set = set([])
        for x in url_set:
            for y in url_set:
                if x != y and x in y:
                    deduped_url_set.add(x)
        return deduped_url_set

if __name__ == '__main__':
    ap = argparse.ArgumentParser(prog="swamp", usage="python %(prog)s [options]")
    ap.add_argument('-id', help="Google Analytics ID", action="store")
    ap.add_argument('-url', help="Website URL", action="store")
    ap.add_argument('-o', help="Output file for results", action="store")
    ap.add_argument('-urlscan',help="Use the urlscan API for reverse lookup", action="store_true")
    ap.add_argument('-spyonweb',help="Use the SpyOnWeb API for reverse lookup", action="store_true")
    ap.add_argument('-token',help="API key or token", action="store")
    ap.add_argument('-depth',help="Depth of search", action="store", default=1, type=int)
    args = ap.parse_args()
    
    # set api based on user input. defaults to urlscan
    api_choice = []
    if args.urlscan:
        api_choice.append('urlscan')
    if args.spyonweb:
        api_choice.append('spyonweb')
    if not args.spyonweb and not args.urlscan:
        api_choice = "all"
        
    SwampApp = Swamp(cli=True, outfile=args.o, api=api_choice, token=args.token, depth=args.depth)
    SwampApp.show_banner()
    SwampApp.run(id=args.id,url=args.url)
