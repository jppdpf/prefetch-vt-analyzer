# Prefetch Resources Analyzer

Checks if prefetch files are loading known malicious items by querying VirusTotal with the items hash.

## As is
It queries the first three prefetch resources found. 
Plus, queries a hash of a malicious dll to mock a encountered dangerous resource.

## Limitations
They are marked in the code, you can remove or just comment them, to experience the full power.

## Need
You need to get a VirusTotal API KEY.


## Run

Clone this repository.

Open the run_prefetch_vt_analyzer.py file.
Replace <your-api-key> with (you guessed it) your VirusTotal API KEY
```python
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
