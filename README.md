safe_browsing
=============

Analyze urlsnarf and other HTTP connection logs for malware and phishing sites using Google's SafeBrowsing API


API Key
-------

Get an API key from Google by vising:
https://developers.google.com/safe-browsing/key_signup

Enter the key in the script.


Usage
-----

	cat urlsnarf.log | ./safe_browsing.py -c report.csv
or
	./safe_browsing.py -f urlsnarf.log -c report.csv
	

