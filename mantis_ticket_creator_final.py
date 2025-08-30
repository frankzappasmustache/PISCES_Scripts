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

# --- ANSI COLOR CODES (Vim Airline Inspired) ---
class Colors:
    """A class to hold ANSI color codes for terminal output."""
    # Using names inspired by a terminal color palette
    PURPLE = '\033[95m'    # For main headers
    BLUE = '\033[94m'      # For user input prompts
    CYAN = '\033[96m'      # For informational messages (Connecting, etc.)
    GREEN = '\033[92m'     # For success messages
    ORANGE = '\033[93m'    # For section prompts and warnings
    RED = '\033[91m'       # For errors
    ENDC = '\033[0m'       # Resets the color
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- CONFIGURATION (Loaded from Environment Variables) ---
MANTIS_URL = os.getenv("MANTIS_URL")
MANTIS_API_TOKEN = os.getenv("MANTIS_API_TOKEN")
KIBANA_URL = os.getenv("KIBANA_URL")
KIBANA_COOKIE = os.getenv("KIBANA_COOKIE")
KIBANA_INDEX_PATTERN = os.getenv("KIBANA_INDEX_PATTERN")
# --- END CONFIGURATION ---

# --- MANTISBT OPTIONS (Static) ---
REPRODUCIBILITY = {'10': 'always', '30': 'sometimes', '50': 'random', '70': 'have not tried', '90': 'unable to reproduce', '100': 'N/A'}
SEVERITY = {'10': 'feature', '20': 'trivial', '30': 'text', '40': 'tweak', '50': 'minor', '60': 'major', '70': 'crash', '80': 'block'}
PRIORITY = {'10': 'none', '20': 'low', '30': 'normal', '40': 'high', '50': 'urgent', '60': 'immediate'}
# --- END MANTISBT OPTIONS ---


def check_env_variables():
    """Checks if all required environment variables are set and exits if not."""
    required_vars = [
        "MANTIS_URL", "MANTIS_API_TOKEN", "KIBANA_URL",
        "KIBANA_COOKIE", "KIBANA_INDEX_PATTERN"
    ]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        print(f"{Colors.RED}!!! CONFIGURATION ERROR !!!{Colors.ENDC}")
        print(f"{Colors.RED}The following required environment variables are not set:{Colors.ENDC}")
        for var in missing_vars:
            print(f"{Colors.RED}  - {var}{Colors.ENDC}")
        print(f"{Colors.ORANGE}\nPlease set them before running the script.{Colors.ENDC}")
        sys.exit(1)
    return True

def fetch_mantis_project_data():
    """Fetches all project data, including nested categories, from the MantisBT API."""
    print(f"\n{Colors.CYAN}Fetching projects and categories from MantisBT...{Colors.ENDC}")
    api_endpoint = f"{MANTIS_URL.rstrip('/')}/api/rest/projects"
    headers = {"Authorization": MANTIS_API_TOKEN}
    try:
        response = requests.get(api_endpoint, headers=headers, timeout=30)
        response.raise_for_status()
        projects_data = response.json().get('projects', [])
        if not projects_data:
            print(f"{Colors.RED}Error: No projects found or could not parse projects from MantisBT.{Colors.ENDC}")
            return None
        print(f"{Colors.GREEN}Successfully fetched data for {len(projects_data)} projects.{Colors.ENDC}")
        return projects_data
    except requests.exceptions.RequestException as e:
        print(f"{Colors.RED}Error fetching projects from MantisBT: {e}{Colors.ENDC}")
        return None

def fetch_kibana_data(hit_id):
    """
    Fetches a document using the Kibana Console Proxy API. Includes a retry
    mechanism for recoverable network errors.
    """
    while True: # Loop to allow for retries on network errors
        print(f"\n{Colors.CYAN}Connecting to Kibana to fetch data for hit ID: {hit_id}...{Colors.ENDC}")
        
        proxy_path = f"/api/console/proxy?path={KIBANA_INDEX_PATTERN}/_search&method=POST"
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
                        {"exists": {"field": "suricata"}}
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
                print(f"{Colors.RED}Error: No document found with ID '{hit_id}' that matches the required log format.{Colors.ENDC}")
                print(f"{Colors.ORANGE}Check your hit ID and ensure your KIBANA_INDEX_PATTERN is correct.{Colors.ENDC}")
                return None
            
            print(f"{Colors.GREEN}Successfully fetched data from Kibana.{Colors.ENDC}")
            return hits[0]['_source']

        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}A network error occurred while contacting Kibana: {e}{Colors.ENDC}")
            retry_choice = input(f"{Colors.ORANGE}Would you like to try again? (y/n): {Colors.ENDC}").lower()
            if retry_choice != 'y':
                return None # Exit if user says no
            # If user says 'y', the loop will continue automatically

        except requests.exceptions.HTTPError as e:
            print(f"{Colors.RED}HTTP Error fetching data from Kibana: {e.response.status_code} {e.response.reason}{Colors.ENDC}")
            if e.response.status_code in [401, 403]:
                print(f"{Colors.RED}Authentication failed. Your KIBANA_COOKIE may be invalid or expired.{Colors.ENDC}")
            print(f"{Colors.RED}Response body: {e.response.text}{Colors.ENDC}")
            return None # Non-recoverable error, so we don't retry
        
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            print(f"{Colors.RED}Could not parse the response from Kibana. Unexpected format: {e}{Colors.ENDC}")
            return None # Non-recoverable error

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

def get_user_selection(prompt, options, default=None):
    """Generic function to get a valid selection from a dictionary of options."""
    if not options:
        print(f"\n{Colors.ORANGE}No options available for '{prompt}'.{Colors.ENDC}")
        return None
        
    print(f"\n{Colors.ORANGE}{prompt}{Colors.ENDC}")
    for key, value in options.items():
        print(f"  {key}: {value}")
    
    while True:
        choice = input(f"{Colors.BLUE}Enter the number for your choice{f' (default: {default})' if default else ''}: {Colors.ENDC}")
        if not choice and default:
            return default
        if choice in options:
            return choice
        print(f"{Colors.RED}Invalid selection. Please try again.{Colors.ENDC}")

def is_public_ip(ip_string):
    """Checks if a given IP address string is a public IP (is_global)."""
    if not ip_string:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        return ip_obj.is_global
    except ValueError:
        # The string was not a valid IP address
        return False

def run_threat_intel_script(ip_addresses):
    """Runs the advanced threat intel script and returns its formatted output."""
    if not ip_addresses:
        return ""
    
    print(f"\n{Colors.CYAN}Running advanced threat intelligence lookup...{Colors.ENDC}")
    command = ["python", "advanced-threat-intel-v3.py", "--format", "ticket"] + ip_addresses
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"{Colors.GREEN}Threat intelligence script executed successfully.{Colors.ENDC}")
        return result.stdout
    except FileNotFoundError:
        return f"{Colors.RED}ERROR: 'advanced-threat-intel-v3.py' not found. Make sure it's in the same directory.{Colors.ENDC}"
    except subprocess.CalledProcessError as e:
        # Sanitize the stderr from the external script to remove any exposed API keys.
        # This is a security measure to prevent keys from being posted into a public ticket.
        stderr_sanitized = re.sub(r'key=[a-zA-Z0-9]+', 'key={api-key-redacted}', e.stderr)
        return f"{Colors.RED}ERROR: Threat intel script failed with exit code {e.returncode}:\n{stderr_sanitized}{Colors.ENDC}"

def select_file():
    """Opens a file dialog to select ONE file and returns its path."""
    print(f"{Colors.CYAN}Opening file selection dialog...{Colors.ENDC}")
    root = tk.Tk()
    root.withdraw()
    filepath = filedialog.askopenfilename()
    return filepath

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

def reconstruct_dict_from_path(path, value):
    """Rebuilds a nested dictionary from a path string and a value."""
    keys = path.split('.')
    res = current = {}
    for part in keys[:-1]:
        current[part] = {}
        current = current[part]
    current[keys[-1]] = value
    return res

def display_in_columns(field_list):
    """Displays a list of fields in a multi-column format."""
    try:
        terminal_width = os.get_terminal_size().columns
    except OSError:
        terminal_width = 80 # Default width if terminal size can't be determined

    display_list = []
    for i, (path, value) in enumerate(field_list):
        is_parent = isinstance(value, dict)
        display_list.append(f"  {i+1:<3}: {path}{' (Parent)' if is_parent else ''}")

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

# --- MAIN SCRIPT LOGIC ---

def main():
    """Main function to gather information and create a MantisBT ticket."""
    check_env_variables()
    print(f"{Colors.PURPLE}{Colors.BOLD}--- MantisBT Ticket Creator ---{Colors.ENDC}")

    all_project_data = fetch_mantis_project_data()
    if not all_project_data:
        sys.exit(1)
    
    # Sort projects alphabetically by name for display
    sorted_projects = sorted(all_project_data, key=lambda p: p['name'].lower())
    projects_for_selection = {str(p['id']): p['name'] for p in sorted_projects}
    
    project_id = get_user_selection("Select a Project ID:", projects_for_selection)
    if not project_id:
        sys.exit(1)

    # Find the full data for the selected project
    selected_project = next((p for p in all_project_data if str(p['id']) == project_id), None)
    
    categories_data = selected_project.get('categories', []) if selected_project else []
    # Sort categories alphabetically by name for display
    sorted_categories = sorted(categories_data, key=lambda c: c['name'].lower())
    categories = {str(c['id']): c['name'] for c in sorted_categories}
    
    category_id = "1" # Default to "[General]"
    if categories:
        category_id = get_user_selection("Select a Category:", categories)
        if not category_id:
            print(f"{Colors.ORANGE}No category selected, defaulting to '[General]'.{Colors.ENDC}")
            category_id = "1"
    else:
        print(f"{Colors.ORANGE}No specific categories found for this project, defaulting to '[General]'.{Colors.ENDC}")


    reproducibility_id = get_user_selection("Select Reproducibility:", REPRODUCIBILITY, default='70')
    severity_id = get_user_selection("Select Severity:", SEVERITY, default='50')
    priority_id = get_user_selection("Select Priority:", PRIORITY, default='30')

    print(f"\n{Colors.ORANGE}Enter System Profile Information:{Colors.ENDC}")
    platform = input(f"  {Colors.BLUE}Platform (e.g., Linux, Windows, macOS): {Colors.ENDC}")
    os_name = input(f"  {Colors.BLUE}Operating System (e.g., Ubuntu, CentOS, Windows 10): {Colors.ENDC}")
    os_version = input(f"  {Colors.BLUE}OS Version (e.g., 20.04 Focal Fossa, 21H2): {Colors.ENDC}")

    summary = input(f"\n{Colors.ORANGE}Enter Issue Summary (Title): {Colors.ENDC}")
    kibana_hit_id = input(f"{Colors.ORANGE}Enter the Kibana Hit ID to pull data from: {Colors.ENDC}")
    
    hit_data = fetch_kibana_data(kibana_hit_id)
    if not hit_data:
        sys.exit(1)

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
    pulled_top_level_keys = set(primary_details_filtered.keys())
    
    additional_fields_data = {k: hit_data[k] for k in sorted(list(all_keys - pulled_top_level_keys))}
    
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
                        for i, (child_path, _) in enumerate(selectable_fields):
                            if child_path.startswith(path + '.') and not isinstance(selectable_fields[i][1], dict):
                                final_indices.add(i)

            for index in sorted(list(final_indices)):
                if 0 <= index < len(selectable_fields):
                    path, value = selectable_fields[index]
                    if isinstance(value, dict):
                        continue
                    reconstructed_item = reconstruct_dict_from_path(path, value)
                    formatted_lines = format_dict_for_ticket(reconstructed_item)
                    description += "\n".join(formatted_lines) + "\n\n"

    steps_to_reproduce = input(f"\n{Colors.ORANGE}Enter Steps to Reproduce (typically the short URL to the Kibana search): {Colors.ENDC}")

    additional_info = ""
    user_commentary = input(f"\n{Colors.ORANGE}Enter any additional commentary for the ticket (or press Enter to skip):\n{Colors.ENDC}")
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
            print(f"{Colors.ORANGE}No public IPs or domains provided to check. Skipping.{Colors.ENDC}")

    attachments = []
    attach_files_choice = input(f"\n{Colors.ORANGE}Attach any files (e.g., screenshots)? (y/n): {Colors.ENDC}").lower()
    if attach_files_choice == 'y':
        while True:
            filepath = select_file()
            if not filepath:
                print(f"{Colors.ORANGE}File selection cancelled.{Colors.ENDC}")
                break
            
            print(f"{Colors.CYAN}Preparing file: {os.path.basename(filepath)}...{Colors.ENDC}")
            try:
                with open(filepath, "rb") as f:
                    file_content = base64.b64encode(f.read()).decode('utf-8')
                    attachments.append({"name": os.path.basename(filepath), "content": file_content})
                    print(f"{Colors.GREEN}Successfully added {os.path.basename(filepath)}. Total attachments: {len(attachments)}{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.RED}Could not read or encode file {filepath}: {e}{Colors.ENDC}")

            add_another = input(f"{Colors.ORANGE}Attach another file? (y/n): {Colors.ENDC}").lower()
            if add_another != 'y':
                break

    issue_payload = {
        "summary": summary, "description": description, "project": {"id": int(project_id)},
        "category": {"id": int(category_id)}, "reproducibility": {"id": int(reproducibility_id)},
        "severity": {"id": int(severity_id)}, "priority": {"id": int(priority_id)},
        "platform": platform, "os": os_name, "os_version": os_version,
        "steps_to_reproduce": steps_to_reproduce, "additional_information": additional_info,
        "tags": [{"name": "SOC"}, {"name": "auto-generated"}]
    }
    if attachments: issue_payload["files"] = attachments

    headers = {"Authorization": MANTIS_API_TOKEN, "Content-Type": "application/json"}
    print(f"\n{Colors.CYAN}--- Submitting Ticket to MantisBT ---{Colors.ENDC}")
    try:
        api_endpoint = f"{MANTIS_URL.rstrip('/')}/api/rest/issues"
        response = requests.post(api_endpoint, headers=headers, data=json.dumps(issue_payload))
        response.raise_for_status()
        response_data = response.json()
        new_issue_id = response_data['issue']['id']
        print(f"\n{Colors.GREEN}{Colors.BOLD}✅ SUCCESS! Ticket created successfully.{Colors.ENDC}")
        print(f"   {Colors.BOLD}Issue ID: {new_issue_id}{Colors.ENDC}")
        print(f"   {Colors.BOLD}View it here: {Colors.UNDERLINE}{MANTIS_URL.rstrip('/')}/view.php?id={new_issue_id}{Colors.ENDC}")
    except requests.exceptions.HTTPError as err:
        print(f"\n{Colors.RED}❌ ERROR! Failed to create ticket. Status Code: {err.response.status_code}{Colors.ENDC}")
        print(f"   {Colors.RED}Response: {err.response.text}{Colors.ENDC}")
    except requests.exceptions.RequestException as err:
        print(f"\n{Colors.RED}❌ ERROR! A network error occurred: {err}{Colors.ENDC}")

if __name__ == "__main__":
    main()

