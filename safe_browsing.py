#!/usr/bin/python
"""

Name: safe_browsing.py
Description: Analyze urlsnarf log for malware and phishing sites.

Author: Roy Firestein (roy__AT__firestein.net)
Date: October 9 2012

Version: 0.3.4 (Nov 20, 2012)


TO DO:

1. Compile parts to C++ as python module with ShedSkin (http://code.google.com/p/shedskin)

"""



""" API KEY """
API_KEY = ""
""" API KEY """


import urllib2
import re
import sys
from optparse import OptionParser

if len(API_KEY) == 0:
    print "No API key"
    print "Register for one at: https://developers.google.com/safe-browsing/key_signup"
    sys.exit(0)

print "\n\tSafe Browsing Analyzer v0.3.4\n"

def usage():
    print "Usage: %s [options]" %sys.argv[0]
    print "Options:"
    print "\t-f --file \tLog file to read"
    print "\t-c --csv \tFile name to save CSV results to"
    print
    sys.exit(0)
    
def chunks(l, n=500):
    '''
    Create array of URL lists with 500 item in each
    '''
    return [l[i:i+n] for i in range(0, len(l), n)]
    
parser = OptionParser("Usage: %prog [options]")
parser.add_option("-f", "--file", dest="filename", help="Log file to read")
parser.add_option("-c", "--csv", dest="save_csv", default="output.csv", help="File name to save CSV results to")
(options, args) = parser.parse_args()

LOG_FILE = options.filename
SAVE_CSV = options.save_csv
API_URL = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=firefox&apikey=%s&appver=1.5.2&pver=3.0" %API_KEY
#rx = re.compile('^([^.]*\.[^ ]*) [^"]*"[^ ]* (https?://[^/:]*)[/:]')
rx = re.compile('^([^.]*\.[^ ]*) [^:]*\[([^ ]*) [^"]*"[^ ]* (https?://[^/:]*)[/:]')
LOGS = {}
output = []
csv = ["URL,Status,Clients\n"]
IS_TTY = sys.stdin.isatty()

# Check we have all needed arguments
if (IS_TTY and not LOG_FILE):
    usage()

# Determine if data is piped or file was specified
if IS_TTY:
    INPUT = open(LOG_FILE, 'r')
else:
    INPUT = sys.stdin
# Read line by line so we can handle large inputs
counter = 0
for line in INPUT:
    counter = counter + 1
    #text = "[+] Analyzing line # %s" %(counter)
    #print text,
    try:
        re_result = rx.match(line)
        client = re_result.group(1)
        date = re_result.group(2)
        url = re_result.group(3)
        
        # Collect unique URLs
        if not url in LOGS.keys():
            LOGS.update({url: [client]})
        else:
            # if URL already exists, add only unique clients
            if not client in LOGS[url]:
                LOGS[url].append(client)
    except:
        print "Regex failed on line: %s" %line

# close file
if IS_TTY:
    INPUT.close()

# Prepare and send the API request
if len(LOGS) > 0:
    
    # split into chunks of 500 URLs per request
    URLS = LOGS.keys()
    url_chunks = chunks(URLS)
    print "Total URLs to analyze: %s (in %s chunks)\n" %(len(URLS), len(url_chunks))
    
    for chunk in url_chunks:
        lines = [ "%s\n" %line for line in chunk ]
        lines.insert(0, "%s\n" %(len(chunk)))
        post_data = "".join(lines)
        # send chunk for analysis
        request = urllib2.Request(API_URL, post_data)
        response = urllib2.urlopen(request)
        results = response.readlines()
        
        # Process results
        if response.getcode() == 200:
            
            # Match URLs with results
            for i in range(0,len(chunk)):
                output.append((chunk[i], results[i].strip(), LOGS[chunk[i]]))

# Print results
if len(output) > 0:
    for url in output:
        if url[1] != 'ok':
            print "BAD: %s (%s)" %(url[0], (url[1]))
            lines = [ "%s," %client for client in url[2] ]
            clients = "".join(lines)
            if SAVE_CSV:
                csv_line = '"%s","%s","%s"\n' %(url[0], url[1], clients)
                csv.append(csv_line)
else:
    print "All URLs are clean."
    
# Save results to CSV file
if len(csv) > 0 and SAVE_CSV:
    fh = open(SAVE_CSV, 'w')
    for line in csv:
        fh.write(line)
    fh.close()
    print "\nResults saved to CSV"
#EOF
