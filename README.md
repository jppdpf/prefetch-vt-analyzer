# Prefetch Resources Analyzer

Checks if prefetch files are loading known malicious items by querying VirusTotal with the items hash.

## As is
It queries the first three prefetch resources found. 
And queries a hash of a malicious dll to mock a encountered dangerous resource.

## Limitations
They are marked in the code, you can remove or just comment them, to experience the full power.

## Need
You need to get a VirusTotal API KEY.
Also, you might need to run this script with Administrator privileges.
