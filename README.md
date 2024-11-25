# burpsluice

Burpsluice is a Python script that extracts all cookie and parameter names from Burp exports to file, and saves them to plain text files for examination. I find this useful when I'm pentesting a large web application with an overwhelming number of cookies and parameters. Run `less` with the output files to look for interesting cookie/parameter names, then search your scope to find where they're used.

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
