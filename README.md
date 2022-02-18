# Prefetch Resources Analyzer

Checks if prefetch files are loading known malicious items by querying VirusTotal with the items hash.

## Proof Of Concept Mode
PoC is good for PoC or a trial VirusTotal API key.

This queries the first three resources from the prefetch files.
Plus one already known malicious dll hash value to mock a malicious finding.

## Need
You need to get a VirusTotal API KEY.


## Run

Clone this repository.

Open the run_prefetch_vt_analyzer.py file.
Replace <your-api-key> with (you guessed it) your VirusTotal API KEY
```python
import vt
VT_CLIENT = vt.Client("<your-api-key>")
```
Save the file.

Open a command line with Administrator privileges, you mostly likely will need them.

First install its requirements.
```bash
python setup.py install
```

Now you can execute the script.

```bash
python run_prefetch_vt_analyzer.py
```

## Future work: 
- add command line arguments
- performing concurrent requests
