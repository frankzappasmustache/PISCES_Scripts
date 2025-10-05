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

def fetch_kibana_data(search_id, index_pattern, search_type):
    """
    Fetches a document using the Kibana Console Proxy API.
    """
    emulate_browser = False # Start in normal mode
    while True: # Loop to allow for retries on network errors
        print(f"\n{Colors.CYAN}Connecting to Kibana to fetch data for {search_type}: {search_id} (Index: {index_pattern})...{Colors.ENDC}")

        proxy_path = f"/api/console/proxy?path={index_pattern}/_search&method=POST"
        kibana_api_endpoint = KIBANA_URL.rstrip('/') + proxy_path

        headers = {
            "Content-Type": "application/json",
            "kbn-xsrf": "true",
            "Cookie": KIBANA_COOKIE
        }

        if emulate_browser:
            print(f"{Colors.CYAN}Attempting connection in Browser Emulation Mode...{Colors.ENDC}")
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"

        if search_type == "Document ID":
            search_clause = {"term": {"_id": search_id}}
        else: # Flow ID
            search_clause = {"term": {"suricata.eve.flow_id": search_id}}

        es_query = {
            "query": search_clause,
            "size": 1
        }
        
        try:
            response = requests.post(kibana_api_endpoint, headers=headers, json=es_query, timeout=90)
            response.raise_for_status()
            data = response.json()

            hits = data.get("hits", {}).get("hits", [])

            if not hits:
                print(f"{Colors.RED}Error: No document found for {search_type} '{search_id}' in the specified index.{Colors.ENDC}")
                return None

            print(f"{Colors.GREEN}Successfully fetched data from Kibana.{Colors.ENDC}")
            return hits[0]['_source']

        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}A network error occurred while contacting Kibana: {e}{Colors.ENDC}")
            
            while True: # Loop for user choice
                print(f"{Colors.ORANGE}What would you like to do?{Colors.ENDC}")
                print("   1: Retry in Normal Mode")
                print("   2: Retry in Browser Emulation Mode")
                print("   3: Abort")
                choice = input(f"{Colors.BLUE}Enter your choice (default: 3): {Colors.ENDC}") or "3"

                if choice == '1':
                    emulate_browser = False
                    break 
                elif choice == '2':
                    emulate_browser = True
                    break
                elif choice == '3':
                    return None
                else:
                    print(f"{Colors.RED}Invalid choice. Please try again.{Colors.ENDC}")
        
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

    # --- Search Type Selection ---
    print(f"\n{Colors.ORANGE}Select a search method:{Colors.ENDC}")
    search_options = {"1": "Document ID", "2": "Flow ID"}
    print("   1: Search by Document ID")
    print("   2: Search by Suricata Flow ID")

    selected_search_type = ""
    while True:
        choice = input(f"{Colors.BLUE}Enter your choice (default: 1): {Colors.ENDC}") or "1"
        if choice in search_options:
            selected_search_type = search_options[choice]
            break
        else:
            print(f"{Colors.RED}Invalid selection. Please try again.{Colors.ENDC}")

    id_to_search = input(f"{Colors.ORANGE}Enter the {selected_search_type} to pull data from: {Colors.ENDC}")
    # --- END: Search Type Selection ---

    # --- Index Selection ---
    print(f"\n{Colors.ORANGE}Select an Index Pattern to Search:{Colors.ENDC}")
    index_options = {"1": "*", "2": "suricata*", "3": "Specify custom index..."}
    print("   1: * (All indices - might be slower)")
    print("   2: suricata* (Suricata indices - recommended)")
    print("   3: Specify custom index (e.g., suricata-2025.10.04)")

    selected_index = ""
    while True:
        choice = input(f"{Colors.BLUE}Enter your choice (default: 2): {Colors.ENDC}") or "2"
        if choice in index_options:
            if choice == '3':
                custom_index = input(f"{Colors.ORANGE}Enter the custom index pattern: {Colors.ENDC}")
                if custom_index.strip():
                    selected_index = custom_index.strip()
                    break
                else:
                    print(f"{Colors.RED}Custom index cannot be empty. Please choose from the menu again.{Colors.ENDC}")
                    continue
            else:
                selected_index = index_options[choice]
                break
        else:
            print(f"{Colors.RED}Invalid selection. Please try again.{Colors.ENDC}")
    # --- END: Index Selection ---

    hit_data = fetch_kibana_data(id_to_search, selected_index, selected_search_type)
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

    # --- START OF MODIFIED SECTION ---
    # The 'suricata.eve.flow' path may not exist in all logs, so we get it safely
    flow_data = hit_data.get('suricata', {}).get('eve', {}).get('flow', {})
    if not flow_data:
        flow_data = {} # Ensure flow_data is a dictionary even if not found
    
    flow_details = {
        "packets_to_server": flow_data.get('pkts_toserver'),
        "packets_to_client": flow_data.get('pkts_toclient'),
        "bytes_to_server": flow_data.get('bytes_toserver'),
        "bytes_to_client": flow_data.get('bytes_toclient')
    }
    # --- END OF MODIFIED SECTION ---

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
    
    # --- START OF MODIFIED SECTION ---
    # Only filter out fields that are always present or too complex to be useful at the top level.
    # This ensures source, destination, etc., are available for selection.
    pulled_top_level_keys = {'@timestamp', 'host', 'suricata'}
    # --- END OF MODIFIED SECTION ---

    additional_fields_data = {k: hit_data[k] for k in sorted(list(all_keys - pulled_top_level_keys)) if hit_data.get(k)}

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
        
        potential_indicators = set()
        ip_paths_to_check = [
            hit_data.get('src_ip'),
            hit_data.get('dest_ip'),
            hit_data.get('source', {}).get('ip'),
            hit_data.get('destination', {}).get('ip'),
            hit_data.get('alert', {}).get('source', {}).get('ip'),
            hit_data.get('alert', {}).get('target', {}).get('ip')
        ]
        for ip in ip_paths_to_check:
            if is_public_ip(ip):
                potential_indicators.add(ip)

        dns_rrname = hit_data.get('dns', {}).get('rrname')
        if dns_rrname:
            potential_indicators.add(dns_rrname)

        http_hostname = hit_data.get('http', {}).get('hostname')
        if http_hostname and not is_ip(http_hostname):
             potential_indicators.add(http_hostname)

        suggested_input = " ".join(sorted(list(potential_indicators)))

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

    # Sanitize the summary to create a valid folder/file name
    sanitized_summary = re.sub(r'[<>:"/\\|?*]', '_', summary).strip()
    if not sanitized_summary:
        sanitized_summary = "Untitled Issue"

    file_name = f"{sanitized_summary}.txt"

    # --- User Prompt for Save Location ---
    print(f"\n{Colors.PURPLE}{Colors.BOLD}--- Save Options ---{Colors.ENDC}")
    print(f"   1: Save to a new folder in the PISCES directory in your home folder (e.g., ~/PISCES/{sanitized_summary}/)")
    print(f"   2: Save to the current directory ({os.getcwd()}/)")
    print(f"   3: Save to the OneDrive PISCES/Issues directory (default)")

    save_choice = ""
    while save_choice not in ["1", "2", "3"]:
        save_choice = input(f"{Colors.BLUE}Enter your choice (default: 3): {Colors.ENDC}") or "3"
        if save_choice not in ["1", "2", "3"]:
            print(f"{Colors.RED}Invalid selection. Please enter 1, 2, or 3.{Colors.ENDC}")

    file_path = ""
    if save_choice == '1':
        home_dir = os.path.expanduser('~')
        pisces_base_path = os.path.join(home_dir, 'PISCES')
        issue_folder = os.path.join(pisces_base_path, sanitized_summary)
        os.makedirs(issue_folder, exist_ok=True)
        file_path = os.path.join(issue_folder, file_name)
    elif save_choice == '2':
        file_path = os.path.join(os.getcwd(), file_name)
    elif save_choice == '3':
        base_path = os.getenv("ISSUES_SAVE_PATH")
        if not base_path:
            print(f"{Colors.RED}ERROR: The 'ISSUES_SAVE_PATH' environment variable is not set.{Colors.ENDC}")
            print(f"{Colors.ORANGE}Please set it on your system to use this option.{Colors.ENDC}")
            sys.exit(1)
        
        issue_folder = os.path.join(base_path, sanitized_summary)
        os.makedirs(issue_folder, exist_ok=True)
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
        # Use 'subl' for Sublime Text. This is platform-agnostic if subl is in the system's PATH.
        subprocess.run(['subl', file_path], check=True)
    except FileNotFoundError:
        print(f"{Colors.RED}Error: 'subl' command not found. Is Sublime Text installed and in your system's PATH?{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}Error opening file with Sublime Text: {e}{Colors.ENDC}")


if __name__ == "__main__":
    main()