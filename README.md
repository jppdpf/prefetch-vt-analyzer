# Prefetch Resources Analyzer

Checks if prefetch files are loading known malicious items by querying VirusTotal with the items hash.

## Proof Of Concept Mode
PoC is good for PoC or a trial VirusTotal API key.

This queries the first three resources from the prefetch files.
Plus one already known malicious dll hash value to mock a malicious finding.



## Run

### Needs 
- A VirusTotal API KEY.

### Insert VirusTotal API Key
Open the run_prefetch_vt_analyzer.py file.
Search the file for the following pattern and replace it.
```bash
"<your-api-key>"
```
Save the file.

### Install the requirements.
```bash
python setup.py install
```
### Open a console with Administrator Privilege

```bash
python run_prefetch_vt_analyzer.py
```

## Future work: 
- add command line arguments
- performing concurrent requests
