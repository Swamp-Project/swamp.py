# Swamp
An OSINT tool for discovering associated sites through Google Analytics Tracking IDs
using a selection of APIs.

### Supported APIs
- [urlscan.io](https://urlscan.io/about-api/#search) (Free)
- [SpyOnWeb](https://api.spyonweb.com/v1/docs_) (Requires Account)

### Enter your Google Analytics Tracking ID or URL and let Swamp take care of the rest.

Example using a specific tracking ID: 
```bash
python3 swamp.py -id UA-6888464-2
```

Example using a url:
```bash
python3 swamp.py -url https://www.medium.com
```
Note that if the URL protocol is not given (e.g. `-url medium.com`), Swamp will default to HTTPS, and try HTTP if HTTPS fails.

Full results are printed to screen, and can be written to file with the `-o` flag.
```bash
python3 swamp.py -id UA-6888464-2 -o myOutputFile.txt
```

You can control what API(s) Swamp will use by suppliying the `-urlscan` and/or `-spyonweb` flags, such as
```bash
python3 swamp.py -id UA-6888464-2 -urlscan -spyonweb
```

By default, Swamp will attempt to use both urlscan.io and SpyOnWeb.

To use SpyOnWeb, first edit line 14 of `swamp.py` to provide your SpyOnWeb API Key:
```python
# USER API KEYS
SPY_ON_WEB_API_KEY="Your API Key Here"
```
Without this, Swamp will skip any query of SpyOnWeb.

Additionally, you can use swamp.py in your own python script.
```python
>>> import swamp
>>> Swamp = swamp.Swamp() # init Swamp object (by default uses urlscan.io)
>>> Swamp = swamp.Swamp(api="spyonweb") # init Swamp object to use SpyOnWeb
>>> Swamp = swamp.Swamp(api=["urlscan","spyonweb"]) # init Swamp object to use SpyOnWeb and urlscan.io
>>> Swamp = swamp.Swamp(api="all") # init Swamp object to use all available APIs
>>> results = Swamp.run(id="UA-12345-1")
>>> results
{"urlscan":["url1", "url2", "url3"], "spyonweb":["url1", "url2", "url3"]}
>>> results = Swamp.run(url="infowars.com")
>>> results
{"UA-12345-1":{"urlscan":["url1", "url2", "url3"], "spyonweb":["url1", "url2", "url3"]}, "UA-67789-1":{"urlscan":["url1", "url2", "url3"], "spyonweb":["url1", "url2", "url3"]}

>>> associated_domains = Swamp.urls_to_domains(associated_urls) # reduces the list of urls to a list of unique domains
```

Test scripts are included.

To verify the CLI functionality: `./test.sh [<your_SpyOnWeb_Token>]`

To verify the python module functionality: `python test.py [-spyonweb_token <your_SpyOnWeb_Token>]`
