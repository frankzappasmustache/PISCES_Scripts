#!/usr/bin/env python3

import os
import sys
import json
import base64
import subprocess
import tkinter as tk
from tkinter import filedialog
import requests
import math
import re
import ipaddress
import platform # Used to determine the OS for file paths

# --- ANSI COLOR CODES (Vim Airline Inspired) ---
class Colors:
    """A class to hold ANSI color codes for terminal output."""
    # Using names inspired by a terminal color palette
    PURPLE = '\033[95m'      # For main headers
    BLUE = '\033[94m'        # For user input prompts
    CYAN = '\033[96m'        # For informational messages (Connecting, etc.)
    GREEN = '\033[92m'       # For success messages
    ORANGE = '\033[93m'      # For section prompts and warnings
    RED = '\033[91m'         # For errors
    ENDC = '\033[0m'         # Resets the color
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- CONFIGURATION (Loaded from Environment Variables) ---
KIBANA_URL = os.getenv("KIBANA_URL")
KIBANA_COOKIE = os.getenv("KIBANA_COOKIE")
# --- END CONFIGURATION ---

def check_env_variables():
    """Checks if all required environment variables are set and exits if not."""
    required_vars = ["KIBANA_URL", "KIBANA_COOKIE"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        print(f"{Colors.RED}!!! CONFIGURATION ERROR !!!{Colors.ENDC}")
        print(f"{Colors.RED}The following required environment variables are not set:{Colors.ENDC}")
        for var in missing_vars:
            print(f"{Colors.RED}   - {var}{Colors.ENDC}")
        print(f"{Colors.ORANGE}\nPlease set them before running the script.{Colors.ENDC}")
        sys.exit(1)
    return True

def fetch_kibana_data(hit_id, index_pattern):
    """
    Fetches a document using the Kibana Console Proxy API. Includes a retry
    mechanism for recoverable network errors.
    """
    while True: # Loop to allow for retries on network errors
        print(f"\n{Colors.CYAN}Connecting to Kibana to fetch data for hit ID: {hit_id} (Index: {index_pattern})...{Colors.ENDC}")
        
        proxy_path = f"/api/console/proxy?path={index_pattern}/_search&method=POST"
        kibana_api_endpoint = KIBANA_URL.rstrip('/') + proxy_path
        
        headers = {
            "Content-Type": "application/json",
            "kbn-xsrf": "true",
            "Cookie": KIBANA_COOKIE
        }

        es_query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"_id": hit_id}},
                        # This query will ensure we only get actual Suricata alerts
                        {"term": {"suricata.eve.event_type": "alert"}}
                    ]
                }
            },
            "size": 1
        }

        try:
            response = requests.post(kibana_api_endpoint, headers=headers, json=es_query, timeout=90)
            response.raise_for_status()
            data = response.json()
            
            if isinstance(data, dict) and "responses" in data:
                es_response = data["responses"][0]
            else:
                es_response = data

            hits = es_response.get("hits", {}).get("hits", [])
            
            if not hits:
                print(f"{Colors.RED}Error: No document found with ID '{hit_id}' that matches the required log format in the selected index.{Colors.ENDC}")
                print(f"{Colors.ORANGE}Check your hit ID and ensure it corresponds to a valid Suricata alert.{Colors.ENDC}")
                return None
            
            print(f"{Colors.GREEN}Successfully fetched data from Kibana.{Colors.ENDC}")
            return hits[0]['_source']

        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}A network error occurred while contacting Kibana: {e}{Colors.ENDC}")
            retry_choice = input(f"{Colors.ORANGE}Would you like to try again? (y/n): {Colors.ENDC}").lower()
            if retry_choice != 'y':
                return None # Exit if user says no

        except requests.exceptions.HTTPError as e:
            print(f"{Colors.RED}HTTP Error fetching data from Kibana: {e.response.status_code} {e.response.reason}{Colors.ENDC}")
            if e.response.status_code in [401, 403]:
                print(f"{Colors.RED}Authentication failed. Your KIBANA_COOKIE may be invalid or expired.{Colors.ENDC}")
            print(f"{Colors.RED}Response body: {e.response.text}{Colors.ENDC}")
            return None
        
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            print(f"{Colors.RED}Could not parse the response from Kibana. Unexpected format: {e}{Colors.ENDC}")
            return None

def format_dict_for_ticket(data, indent=0):
    """Recursively formats a dictionary for clean, indented ticket display."""
    lines = []
    indent_str = ' ' * indent
    if not isinstance(data, dict):
        lines.append(f"{indent_str}{data}")
        return lines

    for key, value in data.items():
        if value is None:
            continue
        if isinstance(value, dict):
            lines.append(f"{indent_str}{key}:")
            lines.extend(format_dict_for_ticket(value, indent + 4))
        elif isinstance(value, list):
            lines.append(f"{indent_str}{key}:")
            for item in value:
                formatted_item_lines = format_dict_for_ticket(item, 0)
                lines.append(f"{' ' * (indent + 4)}- {formatted_item_lines[0].lstrip()}")
                if len(formatted_item_lines) > 1:
                    for line in formatted_item_lines[1:]:
                         lines.append(f"{' ' * (indent + 6)}{line.lstrip()}")
        else:
            lines.append(f"{indent_str}{key}: {value}")
    return lines

def is_public_ip(ip_string):
    """Checks if a given IP address string is a public IP (is_global)."""
    if not ip_string:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        return ip_obj.is_global
    except ValueError:
        return False

def run_threat_intel_script(ip_addresses):
    """Runs the advanced threat intel script and returns its formatted output."""
    if not ip_addresses:
        return ""
    
    print(f"\n{Colors.CYAN}Running advanced threat intelligence lookup...{Colors.ENDC}")
    command = ["python", "advanced-threat-intel-v3.py", "--format", "ticket"] + ip_addresses
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8')
        print(f"{Colors.GREEN}Threat intelligence script executed successfully.{Colors.ENDC}")
        return result.stdout
    except FileNotFoundError:
        return f"{Colors.RED}ERROR: 'advanced-threat-intel-v3.py' not found. Make sure it's in the same directory or in your system's PATH.{Colors.ENDC}"
    except subprocess.CalledProcessError as e:
        stderr_sanitized = re.sub(r'key=[a-zA-Z0-9]+', 'key={api-key-redacted}', e.stderr)
        return f"{Colors.RED}ERROR: Threat intel script failed with exit code {e.returncode}:\n{stderr_sanitized}{Colors.ENDC}"

def select_files():
    """Opens a file dialog to select one or more files and returns their paths."""
    print(f"{Colors.CYAN}Opening file selection dialog...{Colors.ENDC}")
    root = tk.Tk()
    root.withdraw()
    filepaths = filedialog.askopenfilenames()
    return filepaths

# --- HELPER FUNCTIONS FOR SUB-FIELD SELECTION ---
def _flatten_dict_gen(d, parent_key, sep):
    """Generator to flatten a nested dictionary into paths and values."""
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, dict):
            yield (new_key, v)
            yield from _flatten_dict_gen(v, new_key, sep=sep)
        else:
            yield (new_key, v)

def parse_selection(selection_str):
    """Parses a selection string with spaces and hyphens into a set of indices."""
    indices = set()
    parts = selection_str.split()
    for part in parts:
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                indices.update(range(start - 1, end))
            except ValueError:
                print(f"{Colors.RED}Invalid range '{part}'. Skipping.{Colors.ENDC}")
        else:
            try:
                indices.add(int(part) - 1)
            except ValueError:
                print(f"{Colors.RED}Invalid number '{part}'. Skipping.{Colors.ENDC}")
    return indices

def display_in_columns(field_list):
    """Displays a list of fields in a multi-column format."""
    try:
        terminal_width = os.get_terminal_size().columns
    except OSError:
        terminal_width = 80 # Default width

    display_list = []
    for i, (path, value) in enumerate(field_list):
        is_parent = isinstance(value, dict)
        display_list.append(f"   {i+1:<3}: {path}{' (Parent)' if is_parent else ''}")

    max_len = max(len(s) for s in display_list) if display_list else 0
    col_width = max_len + 4
    num_cols = max(1, terminal_width // col_width)
    num_rows = math.ceil(len(display_list) / num_cols)

    for r in range(num_rows):
        line = ""
        for c in range(num_cols):
            index = r + c * num_rows
            if index < len(display_list):
                line += f"{display_list[index]:<{col_width}}"
        print(line)
# --- END HELPER FUNCTIONS ---

def main():
    """Main function to gather information and create a formatted issue file."""
    check_env_variables()
    print(f"{Colors.PURPLE}{Colors.BOLD}--- Issue Formatter ---{Colors.ENDC}")

    summary = input(f"\n{Colors.ORANGE}Enter Issue Summary (Title): {Colors.ENDC}")
    kibana_hit_id = input(f"{Colors.ORANGE}Enter the Kibana Hit ID to pull data from: {Colors.ENDC}")
    
    # --- ADDED: Index Selection ---
    print(f"\n{Colors.ORANGE}Select an Index Pattern to Search:{Colors.ENDC}")
    index_options = {"1": "*", "2": "suricata*"}
    print("   1: * (All indices - might be slower)")
    print("   2: suricata* (Suricata indices - recommended)")
    
    selected_index = ""
    while True:
        choice = input(f"{Colors.BLUE}Enter your choice (default: 2): {Colors.ENDC}") or "2"
        if choice in index_options:
            selected_index = index_options[choice]
            break
        else:
            print(f"{Colors.RED}Invalid selection. Please try again.{Colors.ENDC}")
    # --- END: Index Selection ---
    
    hit_data = fetch_kibana_data(kibana_hit_id, selected_index)
    if not hit_data:
        sys.exit(1)

    platform_info = hit_data.get('host', {}).get('os', {})
    platform_val = platform_info.get('type', 'N/A')
    os_name = platform_info.get('name', 'N/A')
    os_version = platform_info.get('version', 'N/A')

    print(f"\n{Colors.CYAN}--- System Profile Information (from Kibana) ---{Colors.ENDC}")
    print(f"   {Colors.GREEN}Platform: {platform_val}{Colors.ENDC}")
    print(f"   {Colors.GREEN}OS: {os_name}{Colors.ENDC}")
    print(f"   {Colors.GREEN}OS Version: {os_version}{Colors.ENDC}")
    
    flow_data = hit_data.get('suricata', {}).get('eve', {}).get('flow', {})
    flow_details = {
        "packets_to_server": flow_data.get('pkts_toserver'),
        "packets_to_client": flow_data.get('pkts_toclient'),
        "bytes_to_server": flow_data.get('bytes_toserver'),
        "bytes_to_client": flow_data.get('bytes_toclient')
    }
    flow_details_filtered = {k: v for k, v in flow_details.items() if v is not None}

    primary_details = {
        "timestamp": hit_data.get('@timestamp'),
        "destination": hit_data.get('destination'),
        "source": hit_data.get('source'),
        "network": hit_data.get('network'),
        "clientID": hit_data.get('clientID')
    }
    if flow_details_filtered:
        primary_details['flow_details'] = flow_details_filtered
    
    primary_details_filtered = {k: v for k, v in primary_details.items() if v is not None}

    description = "== ELK Log Details ==\n"
    description += "\n".join(format_dict_for_ticket(primary_details_filtered))
    description += "\n"

    print(f"\n{Colors.PURPLE}--- Additional Fields Found in Kibana Hit ---{Colors.ENDC}")
    all_keys = set(hit_data.keys())
    pulled_top_level_keys = set(primary_details_filtered.keys()) | {'host', 'suricata'}
    
    additional_fields_data = {k: v for k in sorted(list(all_keys - pulled_top_level_keys)) if hit_data.get(k)}
    
    selectable_fields = list(_flatten_dict_gen(additional_fields_data, '', '.'))

    if selectable_fields:
        print(f"{Colors.CYAN}You can select individual fields (e.g., 5 8), ranges (e.g., 10-15), or a parent field to include all its children.{Colors.ENDC}")
        display_in_columns(selectable_fields)
        
        extra_fields_choice = input(f"\n{Colors.BLUE}Enter numbers of fields/sub-fields to include, or press Enter to skip: {Colors.ENDC}")
        if extra_fields_choice:
            description += "\n== Additional Log Fields ==\n"
            
            initial_indices = parse_selection(extra_fields_choice)
            final_indices = set(initial_indices)

            for index in initial_indices:
                if 0 <= index < len(selectable_fields):
                    path, value = selectable_fields[index]
                    if isinstance(value, dict): # If it's a parent
                        for i, (child_path, child_value) in enumerate(selectable_fields):
                            if child_path.startswith(path + '.') and not isinstance(child_value, dict):
                                final_indices.add(i)

            grouped_fields = {}
            for index in sorted(list(final_indices)):
                if 0 <= index < len(selectable_fields):
                    path, value = selectable_fields[index]
                    if isinstance(value, dict): continue

                    top_level_key = path.split('.')[0]
                    if top_level_key not in grouped_fields:
                        grouped_fields[top_level_key] = []
                    grouped_fields[top_level_key].append((path, value))
            
            for top_level_key in sorted(grouped_fields.keys()):
                for path, value in grouped_fields[top_level_key]:
                    description += f"{path}:\n"
                    if isinstance(value, list):
                        for item in value:
                            description += f"    - {item}\n"
                    else:
                        description += f"    - {value}\n"
                description += "\n"

    steps_to_reproduce = input(f"\n{Colors.ORANGE}Enter Steps to Reproduce (typically the short URL to the Kibana search): {Colors.ENDC}")

    additional_info = ""
    user_commentary = input(f"\n{Colors.ORANGE}Enter any additional commentary (or press Enter to skip):\n{Colors.ENDC}")
    if user_commentary: additional_info += f"== Analyst Commentary ==\n{user_commentary}\n\n"

    run_intel_choice = input(f"{Colors.ORANGE}Run advanced threat intel script? (y/n): {Colors.ENDC}").lower()
    if run_intel_choice == 'y':
        suggested_ips = []
        src_ip = hit_data.get('source', {}).get('ip')
        dst_ip = hit_data.get('destination', {}).get('ip')

        if src_ip and is_public_ip(src_ip):
            suggested_ips.append(src_ip)
        if dst_ip and dst_ip != src_ip and is_public_ip(dst_ip):
            suggested_ips.append(dst_ip)
            
        suggested_input = " ".join(suggested_ips)

        prompt_message = f"{Colors.BLUE}Enter IPs/domains to check (e.g., 8.8.8.8 badsite.com)"
        if suggested_input:
            prompt_message += f"\n[Press Enter to use: {suggested_input}]: {Colors.ENDC}"
        else:
            prompt_message += f": {Colors.ENDC}"
        user_input = input(prompt_message)

        targets_to_check = user_input.split() if user_input else suggested_input.split()

        if targets_to_check:
            intel_output = run_threat_intel_script(targets_to_check)
            additional_info += f"== Threat Intelligence Lookup ==\n{intel_output}"
        else:
            print(f"{Colors.ORANGE}No public IPs or domains provided. Skipping threat intel lookup.{Colors.ENDC}")

    ticket_content = f"""== SUMMARY ==
{summary}

== SYSTEM PROFILE ==
Platform: {platform_val}
OS: {os_name}
OS Version: {os_version}

{description.strip()}

== STEPS TO REPRODUCE ==
{steps_to_reproduce}

{additional_info.strip()}
"""

    sanitized_summary = re.sub(r'[<>:"/\\|?*]', '_', summary).strip()
    if not sanitized_summary:
        sanitized_summary = "Untitled Issue"

    if platform.system() == "Windows":
        base_path = r"C:\Users\dusti\OneDrive - WCC\OneDrive - Whatcom Community College\Documents\PISCES\Issues"
    else:
        base_path = "/home/mayibroot/onedrive_wcc/Documents/PISCES/Issues"
    
    issue_folder = os.path.join(base_path, sanitized_summary)
    os.makedirs(issue_folder, exist_ok=True)
    
    file_name = f"{sanitized_summary}.txt"
    file_path = os.path.join(issue_folder, file_name)

    print(f"\n{Colors.CYAN}--- Writing Issue to File ---{Colors.ENDC}")
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(ticket_content)
        print(f"{Colors.GREEN}Successfully saved issue to:{Colors.ENDC} {file_path}")
    except IOError as e:
        print(f"{Colors.RED}Error writing to file: {e}{Colors.ENDC}")
        sys.exit(1)

    print(f"\n{Colors.CYAN}Opening file in Sublime Text...{Colors.ENDC}")
    try:
        subprocess.run(['subl', file_path], check=True)
    except FileNotFoundError:
        print(f"{Colors.RED}Error: 'subl' command not found. Is Sublime Text installed and in your system's PATH?{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}Error opening file with Sublime Text: {e}{Colors.ENDC}")


if __name__ == "__main__":
    main()

