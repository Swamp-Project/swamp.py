import json
import requests
import sys
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import init
from colorama import Fore, Back, Style

# disable warning HTTPS
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Swamp(object):

    def __init__(self, *args, **kwargs):
        self.show_banner()

        ap = argparse.ArgumentParser(prog="swamp", usage="python %(prog)s [options]")
        ap.add_argument('-id', help="Google Analytics ID", action="store")
        args = ap.parse_args()

        self.gid = args.id
        
        self.scan_gid(self.gid)
        

    def show_banner(self):

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
        print(Fore.RED + "By Jake Creps | With help from Francesco Poldi and WebBreacher")
        print(Fore.WHITE)

    def scan_gid(self, id):

        print(Fore.GREEN + "Using {} for Google Analytic Lookup".format(id))

        url = 'https://urlscan.io/api/v1/search/?q={}'.format(id) # UA-6888464-2

        try:
            # Make web request for that URL and don't verify SSL/TLS certs
            response = requests.get(url, verify=False)
        except Exception as e:
            print(Fore.RED + "[ !!! ]   ERROR - {}".format(str(e)))
            sys.exit(1)
        print(Fore.YELLOW + "[+] " + Fore.RED + "Searching for associated URLs...")

        # Output is already JSON so we just need to load and parse it
        j = json.loads(response.text)

        # Create an empty set to store the URLs so we only get unique ones
        uniqueurls = set([])

        # Extract every URL and add to the set
        for entry in j['results']:
            uniqueurls.add((entry['page']['url']))
        print(Fore.YELLOW + "[+] " + Fore.RED + "Outputting discovered URLs associate to {}...".format(id))

        # Sort the set and print
        for url in sorted(uniqueurls):
            print(Fore.YELLOW + '[!]' + Fore.GREEN + " URL: " + Fore.WHITE + url)

if __name__ == '__main__':
    SwampApp = Swamp()