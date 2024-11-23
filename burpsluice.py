#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import argparse
from urllib.parse import parse_qs, urlparse
import json
import base64
import sys

class BurpParser:
    def __init__(self):
        self.cookies = set()
        self.params = set()

    def parse_cookies(self, headers: str) -> None:
        """Extract cookie names from header string."""
        for line in headers.split('\n'):
            if line.lower().startswith('cookie:'):
                cookies = line[7:].strip().split(';')
                for cookie in cookies:
                    if '=' in cookie:
                        cookie_name = cookie.split('=')[0].strip()
                        self.cookies.add(cookie_name)
            elif line.lower().startswith('set-cookie:'):
                cookie = line[11:].strip()
                if '=' in cookie:
                    cookie_name = cookie.split('=')[0].strip()
                    self.cookies.add(cookie_name)

    def parse_query_params(self, query: str) -> None:
        """Extract parameter names from URL query string."""
        if not query:
            return
            
        # Split on & and take only the part before = for each parameter
        params = query.split('&')
        for param in params:
            if '=' in param:
                param_name = param.split('=')[0]
                if param_name:
                    self.params.add(param_name)

    def parse_post_data(self, data: str, content_type: str = '') -> None:
        """Extract parameter names from POST data."""
        if not data:
            return

        # Handle application/x-www-form-urlencoded
        if 'form' in content_type.lower():
            params = data.split('&')
            for param in params:
                if '=' in param:
                    param_name = param.split('=')[0]
                    if param_name:
                        self.params.add(param_name)
            return

        # Handle JSON content
        if ('json' in content_type.lower() or 
            data.strip().startswith('{') or 
            data.strip().startswith('[')):
            try:
                json_data = json.loads(data)
                self._extract_json_keys(json_data)
            except json.JSONDecodeError:
                pass

    def _extract_json_keys(self, obj) -> None:
        """Recursively extract parameter names from JSON object."""
        if isinstance(obj, dict):
            # Only add keys that are strings and contain only printable characters
            for key in obj.keys():
                if isinstance(key, str):
                    self.params.add(key)
            # Recurse into nested structures
            for value in obj.values():
                if isinstance(value, (dict, list)):
                    self._extract_json_keys(value)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    self._extract_json_keys(item)

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

                # Get method and URL from first line
                first_line = headers.split('\n')[0]
                if first_line:
                    parts = first_line.split(' ')
                    if len(parts) >= 2:
                        method = parts[0].upper()
                        url = parts[1]
                        
                        # Parse URL parameters
                        parsed_url = urlparse(url)
                        self.parse_query_params(parsed_url.query)

                        # Parse POST data if present
                        if method == 'POST' and body:
                            self.parse_post_data(body, content_type)

            # Parse response
            response = item.find('response')
            if response is not None and response.text:
                response_text = base64.b64decode(response.text).decode('utf-8', errors='replace')
                if '\r\n\r\n' in response_text:
                    headers, body = response_text.split('\r\n\r\n', 1)
                    content_type = self.get_content_type(headers)
                    self.parse_cookies(headers)  # Check for Set-Cookie headers
                    if 'json' in content_type.lower():
                        self.parse_post_data(body, content_type)  # Reuse post_data parser for JSON responses

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
    args = parser.parse_args()

    try:
        burp_parser = BurpParser()
        burp_parser.parse_burp_xml(args.xml_file)
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
