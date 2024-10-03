#!/usr/bin/env python3
from multiprocessing.pool import ThreadPool
from time import time as timer
from urllib.request import urlopen
import mmh3
import codecs
import sys
import ssl
import argparse
import os


def main():
    urls = []
    a = {}
    
    # Reading the URLs
    for line in sys.stdin:
        if line.strip()[-1] == "/":
            urls.append(line.strip() + "favicon.ico")
        else:
            urls.append(line.strip() + "/favicon.ico")
    
    def fetch_url(url):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            response = urlopen(url, timeout=5, context=ctx)
            favicon = codecs.encode(response.read(), "base64")
            hash = mmh3.hash(favicon)
            key = hash
            a.setdefault(key, [])
            a[key].append(url)
            return url, hash, None
        except Exception as e:
            return url, None, e

    # Running the fetch URL task with ThreadPool
    results = ThreadPool(20).imap_unordered(fetch_url, urls)
    
    # Collecting and printing results
    print("\u001b[32m[Unified Results] - \u001b[0m\n")
    
    fingerprint = {
        99395752: "slack-instance",
        116323821: "spring-boot",
        81586312: "Jenkins",
        -235701012: "Cnservers LLC",
        743365239: "Atlassian",
        # (Add more fingerprints here as needed...)
    }

    for url, hash, error in results:
        if error is None:
            print(f"\u001b[32m[INFO]\u001b[0m Fetched {url[:-12]}")
        else:
            print(f"\u001b[31m[ERR]\u001b[0m Not Fetched {url[:-12]}")
    
    print("\n-------------------------------------------------------------------")
    
    for hash_key, associated_urls in a.items():
        # Printing the hash and associated URLs
        print(f"\u001b[33m[Hash]\u001b[0m \u001b[32;1m{hash_key}\u001b[0m")
        for url in associated_urls:
            print(f"     {url[:-12]}")
        
        # If the hash matches a fingerprint
        if hash_key in fingerprint:
            print(f"\u001b[31m[Fingerprint Match]\u001b[0m {fingerprint[hash_key]}")
        
        # Printing the Shodan dork link
        print(f"\u001b[34m[Shodan Dork]\u001b[0m https://www.shodan.io/search?query=http.favicon.hash:{hash_key}")
        print("-------------------------------------------------------------------")
    
    print("\nSummary:")
    print(" \u001b[36mcount      \u001b[35mHash\u001b[0m         ")
    for i in a.keys():
        print(f"~ \u001b[36m[{len(a[i])}]  : \u001b[35m[{i}]\u001b[0m ")
    
    print("\n[End of Results]\n")


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description='FavFreak - a Favicon Hash based asset mapper')
        parser.add_argument('-o', '--output', help='Output file name')
        parser.add_argument('--shodan', help='Prints Shodan Dorks', action='store_true')
        args = parser.parse_args()
        
        # Running the main process
        a, urls = main()

    except KeyboardInterrupt:
        print("\n\u001b[31m[EXIT] Keyboard Interrupt Encountered \u001b[0m")
