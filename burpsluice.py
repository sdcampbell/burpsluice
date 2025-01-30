#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import argparse
from urllib.parse import parse_qs, urlparse
import json
import base64
import sys
from collections import defaultdict

class BurpParser:
    def __init__(self):
        self.cookies = set()
        self.params = set()
        # Add dictionaries to store key-value pairs
        self.cookie_values = defaultdict(set)
        self.param_values = defaultdict(set)

    def parse_cookies(self, headers: str) -> None:
        """Extract cookie names and values from header string."""
        for line in headers.split('\n'):
            if line.lower().startswith('cookie:'):
                cookies = line[7:].strip().split(';')
                for cookie in cookies:
                    if '=' in cookie:
                        cookie_name, cookie_value = cookie.split('=', 1)
                        cookie_name = cookie_name.strip()
                        self.cookies.add(cookie_name)
                        self.cookie_values[cookie_name].add(cookie_value.strip())
            elif line.lower().startswith('set-cookie:'):
                cookie = line[11:].strip()
                if '=' in cookie:
                    cookie_name, cookie_value = cookie.split('=', 1)
                    cookie_name = cookie_name.strip()
                    self.cookies.add(cookie_name)
                    # Extract value before any cookie attributes
                    value = cookie_value.split(';')[0].strip()
                    self.cookie_values[cookie_name].add(value)

    def parse_query_params(self, query: str) -> None:
        """Extract parameter names and values from URL query string."""
        if not query:
            return
            
        params = query.split('&')
        for param in params:
            if '=' in param:
                param_name, param_value = param.split('=', 1)
                if param_name:
                    self.params.add(param_name)
                    self.param_values[param_name].add(param_value)

    def parse_post_data(self, data: str, content_type: str = '') -> None:
        """Extract parameter names and values from POST data."""
        if not data:
            return

        if 'form' in content_type.lower():
            params = data.split('&')
            for param in params:
                if '=' in param:
                    param_name, param_value = param.split('=', 1)
                    if param_name:
                        self.params.add(param_name)
                        self.param_values[param_name].add(param_value)
            return

        if ('json' in content_type.lower() or 
            data.strip().startswith('{') or 
            data.strip().startswith('[')):
            try:
                json_data = json.loads(data)
                self._extract_json_pairs(json_data)
            except json.JSONDecodeError:
                pass

    def _extract_json_pairs(self, obj, prefix='') -> None:
        """Recursively extract parameter names and values from JSON object."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(key, str):
                    self.params.add(key)
                    if isinstance(value, (str, int, float, bool)):
                        self.param_values[key].add(str(value))
                    elif isinstance(value, (dict, list)):
                        self._extract_json_pairs(value, f"{prefix}{key}.")
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    self._extract_json_pairs(item, prefix)

    def get_content_type(self, headers: str) -> str:
        """Extract content-type from headers."""
        for line in headers.split('\n'):
            if line.lower().startswith('content-type:'):
                return line[13:].strip()
        return ''

    def parse_burp_xml(self, xml_file: str) -> None:
        """Parse Burp Suite XML file and extract parameters."""
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for item in root.findall('.//item'):
            # Parse request
            request = item.find('request')
            if request is not None and request.text:
                request_text = base64.b64decode(request.text).decode('utf-8', errors='replace')
                
                if '\r\n\r\n' in request_text:
                    headers, body = request_text.split('\r\n\r\n', 1)
                else:
                    headers, body = request_text, ""

                self.parse_cookies(headers)
                content_type = self.get_content_type(headers)

                first_line = headers.split('\n')[0]
                if first_line:
                    parts = first_line.split(' ')
                    if len(parts) >= 2:
                        method = parts[0].upper()
                        url = parts[1]
                        
                        parsed_url = urlparse(url)
                        self.parse_query_params(parsed_url.query)

                        if method == 'POST' and body:
                            self.parse_post_data(body, content_type)

            # Parse response
            response = item.find('response')
            if response is not None and response.text:
                response_text = base64.b64decode(response.text).decode('utf-8', errors='replace')
                if '\r\n\r\n' in response_text:
                    headers, body = response_text.split('\r\n\r\n', 1)
                    content_type = self.get_content_type(headers)
                    self.parse_cookies(headers)
                    if 'json' in content_type.lower():
                        self.parse_post_data(body, content_type)

    def search_key(self, key: str) -> list:
        """Search for values associated with a specific key."""
        values = set()
        if key in self.cookie_values:
            values.update(self.cookie_values[key])
        if key in self.param_values:
            values.update(self.param_values[key])
        return sorted(values)

    def save_results(self, base_filename: str) -> None:
        """Save extracted parameters to files."""
        with open(f"{base_filename}_cookies.txt", 'w') as f:
            for cookie in sorted(self.cookies):
                f.write(f"{cookie}\n")

        with open(f"{base_filename}_parameters.txt", 'w') as f:
            for param in sorted(self.params):
                f.write(f"{param}\n")

def main():
    parser = argparse.ArgumentParser(description='Parse Burp Suite XML output for parameters')
    parser.add_argument('xml_file', help='Burp Suite XML file to parse')
    parser.add_argument('--output', '-o', default='burp_params',
                      help='Base filename for output files (default: burp_params)')
    parser.add_argument('--key', '-k', help='Search for values of a specific key')
    args = parser.parse_args()

    try:
        burp_parser = BurpParser()
        burp_parser.parse_burp_xml(args.xml_file)
        
        if args.key:
            # If key is specified, search and print values
            values = burp_parser.search_key(args.key)
            if values:
                for value in values:
                    print(value)
            else:
                print(f"\nNo values found for key '{args.key}'")
        else:
            # Original functionality
            burp_parser.save_results(args.output)
            print(f"Successfully parsed {args.xml_file}")
            print(f"Found:")
            print(f"  {len(burp_parser.cookies)} unique cookies")
            print(f"  {len(burp_parser.params)} unique parameters")
            print(f"\nResults saved with base filename: {args.output}")
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()