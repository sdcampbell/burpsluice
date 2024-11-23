# burpsluice

In Burp's Target tab, right click on one or many domains and "Save selected items". Burpsluice parses the XML output file and saves all unique cookie and parameter names to file.

## Usage

```
python3 burpsluice.py -h
usage: burpsluice.py [-h] [--output OUTPUT] xml_file

Parse Burp Suite XML output for parameters

positional arguments:
  xml_file              Burp Suite XML file to parse

options:
  -h, --help            show this help message and exit
  --output OUTPUT, -o OUTPUT
                        Base filename for output files (default: burp_params)
```
