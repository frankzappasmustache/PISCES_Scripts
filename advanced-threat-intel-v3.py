#!/usr/bin/env python3

import argparse
import os
import re
import sys
import time
from datetime import datetime

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from selenium import webdriver
from selenium.common.exceptions import SessionNotCreatedException, TimeoutException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

# --- CONFIGURATION ---
# Securely retrieve API keys from environment variables.
API_KEYS = {
    "virustotal": os.getenv("VT_API_KEY"),
    "otx": os.getenv("OTX_API_KEY"),
    "greynoise": os.getenv("GREYNOISE_API_KEY"),
    "abuseipdb": os.getenv("ABUSEIPDB_API_KEY"),
    "shodan": os.getenv("SHODAN_API_KEY"),
    "urlscan": os.getenv("URLSCAN_API_KEY"),
}

# Initialize Rich Console for beautiful printing
console = Console()


def setup_selenium_driver():
    """Sets up a headless Chrome browser instance using Selenium's built-in SeleniumManager."""
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36")
        
        driver = webdriver.Chrome(options=chrome_options)
        return driver
    except SessionNotCreatedException:
        print_error(
            "Selenium session could not be created due to a driver/browser mismatch.\n\n"
            "Please ensure you have the latest version of Selenium which includes automatic driver management:\n\n"
            "[bold cyan]pip install --upgrade selenium[/bold cyan]"
        )
        sys.exit(1)
    except Exception as e:
        print_error(f"An unexpected error occurred while setting up Selenium: {e}")
        sys.exit(1)


def is_ipv4(indicator):
    """Checks if the given string is a valid IPv4 address."""
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return ip_pattern.match(indicator)


def print_error(message):
    """Prints an error message in a styled panel."""
    console.print(Panel(f"[bold red]ERROR:[/bold red] {message}", title="Error", border_style="red"))

def handle_api_error(e, service_name, indicator):
    """Sanitizes and prints API request errors to avoid exposing keys."""
    try:
        if isinstance(e, requests.exceptions.HTTPError):
            url = e.request.url
            # Replace API key in URL with a placeholder for safe logging
            sanitized_url = re.sub(r'(key|apikey|api_key)=[^&]+', r'\1={API_KEY}', url, flags=re.IGNORECASE)
            
            # Try to get a specific error detail from the JSON response
            try:
                error_detail = e.response.json().get('errors', [{}])[0].get('detail', e.response.text)
            except requests.exceptions.JSONDecodeError:
                error_detail = e.response.text

            print_error(f"{service_name} API request for {indicator} failed.\nURL: {sanitized_url}\nDetail: {error_detail}")
        else:
            print_error(f"An unexpected error occurred with {service_name} for {indicator}: {e}")
    except Exception as final_e:
        # Fallback for errors during the error handling itself
        print_error(f"An unexpected error occurred during error handling for {service_name}: {final_e}")


# --- Data Gathering Functions ---

def scrape_talos(indicator, driver):
    """Scrapes the Cisco Talos Intelligence page by mimicking the user's search workflow."""
    console.print(f"[cyan]Querying Cisco Talos for {indicator}...[/cyan]")
    report_data = []
    try:
        driver.get("https://talosintelligence.com/")
        search_box = WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.ID, "new-search-form-input"))
        )
        search_box.send_keys(indicator)
        search_box.send_keys(Keys.RETURN)
        WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.CLASS_NAME, "reputation-details-container"))
        )
        soup = BeautifulSoup(driver.page_source, 'lxml')
        
        if web_rep_element := soup.find('span', class_='web-rep-label'):
            report_data.append(("Web Reputation", web_rep_element.text.strip()))
        if email_rep_element := soup.find('div', class_='email-rep-details'):
            if rep_label := email_rep_element.find('div', class_='rep-label'):
                report_data.append(("Email Reputation", rep_label.text.strip()))
        if owner_div := soup.find('div', class_='whois-data'):
            if len(owner_info := owner_div.find_all('div')) > 1:
                report_data.append(("Network Owner", owner_info[1].text.strip()))
        
        return report_data if report_data else []
    except Exception as e:
        print_error(f"Failed to scrape Cisco Talos for {indicator}. Error: {e}")
        return None

def scrape_xforce(indicator, driver):
    """Scrapes the IBM X-Force Exchange page by mimicking the user's search workflow."""
    console.print(f"[cyan]Querying IBM X-Force for {indicator}...[/cyan]")
    report_data = []
    try:
        driver.get("https://exchange.xforce.ibmcloud.com/")
        try:
            cookie_button = WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.ID, "onetrust-accept-btn-handler")))
            cookie_button.click()
            time.sleep(1)
        except TimeoutException:
            pass  # No cookie banner
        search_box = WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.XPATH, "//input[contains(@placeholder, 'Search by')]"))
        )
        search_box.send_keys(indicator)
        search_box.send_keys(Keys.RETURN)
        WebDriverWait(driver, 20).until(EC.visibility_of_element_located((By.CLASS_NAME, "details-table")))
        soup = BeautifulSoup(driver.page_source, 'lxml')
        if risk_element := soup.find('span', {'data-test-id': 'risk-score-value'}):
            report_data.append(("Risk Score", risk_element.text.strip()))
        if cat_heading := soup.find('h5', string='Categorization'):
            if cat_container := cat_heading.find_parent('div').find_next_sibling('div'):
                categories = [a.text.strip() for a in cat_container.find_all('a')]
                report_data.append(("Categorization", ", ".join(categories)))
        if details_table := soup.find('table', class_='details-table'):
            for row in details_table.find_all('tr'):
                cells = row.find_all('td')
                if len(cells) == 2:
                    key, value = cells[0].text.strip(), cells[1].text.strip()
                    if "Location" in key: report_data.append(("Location", value))
                    elif "ASN" in key: report_data.append(("ASN", value))
        return report_data if report_data else []
    except Exception as e:
        print_error(f"Failed to scrape IBM X-Force for {indicator}. Error: {e}")
        return None

def query_virustotal(indicator):
    """Queries the VirusTotal API and returns main data and vendor data."""
    if not API_KEYS["virustotal"]: return None, None
    console.print(f"[cyan]Querying VirusTotal for {indicator}...[/cyan]")
    indicator_type = "ip_addresses" if is_ipv4(indicator) else "domains"
    url = f"https://www.virustotal.com/api/v3/{indicator_type}/{indicator}"
    headers = {"x-apikey": API_KEYS["virustotal"]}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            return [], [] # Not found
        response.raise_for_status()
        data = response.json().get("data", {}).get("attributes", {})
        if not data:
            return [], [] # Empty response
        stats = data.get("last_analysis_stats", {})
        malicious_vendors = stats.get("malicious", 0)
        main_data = [
            ("Malicious Vendors", f"[red]{malicious_vendors}[/red]" if malicious_vendors > 0 else "[green]0[/green]"),
            ("Country", data.get("country", "N/A")),
            ("Last Analysis", datetime.fromtimestamp(data.get("last_analysis_date", 0)).strftime('%Y-%m-%d %H:%M:%S')),
            ("AS Owner", data.get("as_owner", "N/A")),
            ("ASN", str(data.get("asn", "N/A")))
        ]
        vendor_data = []
        analysis_results = data.get("last_analysis_results", {})
        for vendor, result in analysis_results.items():
            category = result.get("category", "N/A")
            if category not in ["harmless", "undetected"]:
                vendor_data.append((vendor, result.get("result"), f"[yellow]{category}[/yellow]"))
        return main_data, vendor_data
    except Exception as e:
        handle_api_error(e, "VirusTotal", indicator)
        return None, None

def query_otx(indicator):
    """Queries AlienVault OTX and returns data as a list of tuples."""
    if not API_KEYS["otx"]: return None
    console.print(f"[cyan]Querying AlienVault OTX for {indicator}...[/cyan]")
    indicator_type = "IPv4" if is_ipv4(indicator) else "domain"
    url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
    headers = {"X-OTX-API-KEY": API_KEYS["otx"]}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            return [] # Not found
        response.raise_for_status()
        data = response.json()
        if not data:
            return [] # Empty response
        related_pulses = data.get("pulse_info", {}).get("pulses", [])
        all_tags = {tag for pulse in related_pulses for tag in pulse.get("tags", [])}
        return [
            ("Pulse Count", str(data.get("pulse_info", {}).get("count", 0))),
            ("Location", f"{data.get('city', 'N/A')}, {data.get('country_name', 'N/A')}"),
            ("ASN", data.get("asn", "N/A")),
            ("Related Tags", ", ".join(sorted(list(all_tags))) if all_tags else "N/A")
        ]
    except Exception as e:
        handle_api_error(e, "AlienVault OTX", indicator)
        return None

def query_greynoise(indicator):
    """Queries the GreyNoise Enterprise API and returns data as a dictionary."""
    if not is_ipv4(indicator): return None
    if not API_KEYS["greynoise"]: return None
    console.print(f"[cyan]Querying GreyNoise for {indicator}...[/cyan]")
    url = f"https://api.greynoise.io/v3/ip/{indicator}"
    headers = {"key": API_KEYS["greynoise"]}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            return {} # Not found
        response.raise_for_status()
        return response.json()
    except Exception as e:
        handle_api_error(e, "GreyNoise", indicator)
        return None

def query_abuseipdb(indicator):
    """Queries the AbuseIPDB API and returns data as a list of tuples."""
    if not is_ipv4(indicator): return None
    if not API_KEYS["abuseipdb"]: return None
    console.print(f"[cyan]Querying AbuseIPDB for {indicator}...[/cyan]")
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": indicator, "maxAgeInDays": "90", "verbose": True}
    headers = {"Key": API_KEYS["abuseipdb"], "Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json().get("data", {})
        if not data or not data.get("ipAddress"):
            return [] # Not found or empty data
        abuse_score = data.get("abuseConfidenceScore", 0)
        return [
            ("Abuse Confidence", f"[red]{abuse_score}%[/red]" if abuse_score > 0 else "[green]0%[/green]"),
            ("Total Reports", str(data.get("totalReports", "N/A"))),
            ("Country", data.get("countryName", "N/A")),
            ("City", data.get("city", "N/A")),
            ("ISP", data.get("isp", "N/A")),
            ("Usage Type", data.get("usageType", "N/A")),
            ("Domain Name", data.get("domain", "N/A")),
            ("Hostname(s)", ", ".join(data.get("hostnames", [])) if data.get("hostnames") else "N/A"),
        ]
    except Exception as e:
        handle_api_error(e, "AbuseIPDB", indicator)
        return None

def query_shodan(indicator):
    """Queries the Shodan API for IP information."""
    if not is_ipv4(indicator): return None, None, None
    if not API_KEYS["shodan"]: return None, None, None
    console.print(f"[cyan]Querying Shodan for {indicator}...[/cyan]")
    url = f"https://api.shodan.io/shodan/host/{indicator}?key={API_KEYS['shodan']}"
    try:
        response = requests.get(url)
        if response.status_code == 404:
            return [], [], [] # Not found
        response.raise_for_status()
        data = response.json()
        main_details = [
            ("Organization", data.get("org", "N/A")),
            ("ISP", data.get("isp", "N/A")),
            ("ASN", data.get("asn", "N/A")),
            ("Hostnames", ", ".join(data.get("hostnames", [])) if data.get("hostnames") else "N/A"),
            ("Location", f"{data.get('city', 'N/A')}, {data.get('country_name', 'N/A')}")
        ]
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        return main_details, ports, vulns
    except Exception as e:
        handle_api_error(e, "Shodan", indicator)
        return None, None, None

def query_urlscan(indicator):
    """Searches URLScan for recent scans of an IP or domain."""
    if not API_KEYS["urlscan"]: return None
    console.print(f"[cyan]Querying URLScan for {indicator}...[/cyan]")
    query_type = "ip" if is_ipv4(indicator) else "domain"
    url = f"https://urlscan.io/api/v1/search/?q={query_type}:{indicator}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        results = response.json().get("results", [])
        if not results:
            return [] # No scans found
        latest_scan = results[0]
        scan_id = latest_scan.get("task", {}).get("uuid")
        result_url = f"https://urlscan.io/api/v1/result/{scan_id}/"
        result_response = requests.get(result_url)
        result_response.raise_for_status()
        result_data = result_response.json()
        verdict = result_data.get("verdicts", {}).get("overall", {})
        malicious = verdict.get("malicious", False)
        return [
            ("Status", "[red]Malicious[/red]" if malicious else "[green]Clean[/green]"),
            ("Scan Date", latest_scan.get("task", {}).get("time", "N/A")),
            ("Scanned URL", latest_scan.get("page", {}).get("url", "N/A")),
            ("Result URL", result_data.get("task", {}).get("reportURL", "N/A"))
        ]
    except Exception as e:
        handle_api_error(e, "URLScan", indicator)
        return None

# --- Formatting Functions ---

def get_search_url(service_key, indicator):
    """Generates a direct search URL for a given service and indicator."""
    is_ip = is_ipv4(indicator)
    urls = {
        "virustotal": f"https://www.virustotal.com/gui/{'ip-address' if is_ip else 'domain'}/{indicator}",
        "otx": f"https://otx.alienvault.com/indicator/{'ip' if is_ip else 'domain'}/{indicator}",
        "greynoise": f"https://viz.greynoise.io/ip/{indicator}" if is_ip else None,
        "abuseipdb": f"https://www.abuseipdb.com/check/{indicator}" if is_ip else None,
        "shodan": f"https://www.shodan.io/host/{indicator}" if is_ip else None,
        "urlscan": f"https://urlscan.io/search/#{indicator}",
        "xforce": f"https://exchange.xforce.ibmcloud.com/search/{indicator}",
        "talos": f"https://talosintelligence.com/reputation_center/lookup?search={indicator}"
    }
    return urls.get(service_key)


def format_for_ticket(indicator, all_data):
    """Formats the collected data into a clean, copy-paste friendly string with rich markup."""
    output = [
        "\n" + "="*60,
        f"[bold]Threat Intelligence Report for: {indicator}[/bold]",
        "="*60
    ]
    
    service_order = [
        ("virustotal", "VirusTotal"), ("abuseipdb", "AbuseIPDB"), ("otx", "AlienVault OTX"),
        ("greynoise", "GreyNoise"), ("shodan", "Shodan"), ("urlscan", "URLScan"),
        ("xforce", "IBM X-Force"), ("talos", "Cisco Talos")
    ]

    for service_key, service_name in service_order:
        output.append(f"\n[bold underline]---------- {service_name} ----------[/bold underline]")
        
        search_url = get_search_url(service_key, indicator)
        if search_url:
            output.append(f"Search URL: {search_url}")

        data = all_data.get(service_key)
        
        is_empty = (
            data is None or
            (isinstance(data, (list, tuple)) and not any(data)) or
            (isinstance(data, dict) and not data)
        )

        if is_empty:
            output.append("  [yellow]No record found for this indicator.[/yellow]")
            continue

        if service_key == "virustotal":
            main_data, vendor_data = data
            if main_data:
                for key, value in main_data:
                    output.append(f"  [dim]{key:<25}:[/dim] {value}")
            if vendor_data:
                output.append("\n  [bold]Vendor Analysis Breakdown:[/bold]")
                for vendor, result, category in vendor_data:
                    output.append(f"    - {vendor:<25}: {result} ({category})")
        
        elif service_key == "shodan":
            main_details, ports, vulns = data
            if main_details:
                for key, value in main_details:
                    output.append(f"  [dim]{key:<25}:[/dim] {value}")
            if ports:
                output.append(f"  [dim]{'Open Ports':<25}:[/dim] {', '.join(map(str, ports))}")
            if vulns:
                output.append("\n  [bold]Vulnerabilities:[/bold]")
                for vuln in vulns:
                    output.append(f"    - [red]{vuln}[/red]")
        
        elif isinstance(data, list):
            for key, value in data:
                output.append(f"  [dim]{key:<25}:[/dim] {value}")
        
        elif isinstance(data, dict) and service_key == "greynoise":
            if bsi := data.get("business_service_intelligence", {}):
                if bsi.get("found"):
                    output.append("\n  [bold]Business Service Intelligence:[/bold]")
                    for key, val in bsi.items():
                        if key != "found": output.append(f"    [dim]{key.replace('_', ' ').title():<23}:[/dim] {val}")
            if isi := data.get("internet_scanner_intelligence", {}):
                if isi.get("found"):
                    output.append("\n  [bold]Internet Scanner Intelligence:[/bold]")
                    metadata = isi.pop("metadata", {}); tags = isi.pop("tags", [])
                    for key, val in isi.items():
                        if key not in ["found", "raw_data"]:
                            output.append(f"    [dim]{key.replace('_', ' ').title():<23}:[/dim] {val}")
                    for key, val in metadata.items():
                        output.append(f"    [dim]{key.replace('_', ' ').title():<23}:[/dim] {val}")
                    if tags:
                        output.append(f"    [dim]{'Tags':<23}:[/dim] {', '.join(t['name'] for t in tags)}")
    return "\n".join(output)

def display_as_tables(indicator, all_data):
    """Displays the collected data in rich tables."""
    console.rule(f"[bold]Threat Intelligence Report for: {indicator}[/bold]")
    
    service_order = [
        ("virustotal", "VirusTotal"), ("abuseipdb", "AbuseIPDB"), ("otx", "AlienVault OTX"),
        ("greynoise", "GreyNoise"), ("shodan", "Shodan"), ("urlscan", "URLScan"),
        ("xforce", "IBM X-Force"), ("talos", "Cisco Talos")
    ]

    for service_key, service_name in service_order:
        data = all_data.get(service_key)
        is_empty = (
            data is None or
            (isinstance(data, (list, tuple)) and not any(data)) or
            (isinstance(data, dict) and not data)
        )

        search_url = get_search_url(service_key, indicator)
        title = f"[link={search_url}]{service_name}[/link]" if search_url else service_name

        if is_empty:
            console.print(Panel("[yellow]No record found for this indicator.[/yellow]", title=title, border_style="dim"))
            continue

        if service_key == "virustotal":
            vt_main, vt_vendor = data
            vt_table = Table(title=title, show_header=True, header_style="bold magenta", row_styles=["", "on #202020"])
            vt_table.add_column("Attribute", style="dim"); vt_table.add_column("Value")
            for key, val in vt_main: vt_table.add_row(key, val)
            console.print(vt_table)
            if vt_vendor:
                vendor_table = Table(title="Vendor Analysis Breakdown", show_header=True, header_style="bold blue", row_styles=["", "on #202020"])
                vendor_table.add_column("Vendor Name"); vendor_table.add_column("Result"); vendor_table.add_column("Category")
                for vendor, result, category in vt_vendor: vendor_table.add_row(vendor, result, category)
                console.print(vendor_table)
        
        elif service_key == "otx" or service_key == "abuseipdb" or service_key == "urlscan" or service_key == "xforce" or service_key == "talos":
            table = Table(title=title, show_header=True, header_style="bold green", row_styles=["", "on #202020"])
            table.add_column("Attribute", style="dim"); table.add_column("Value")
            for key, val in data: table.add_row(key, str(val))
            console.print(table)
        
        elif service_key == "greynoise":
             console.print(Panel(f"[bold yellow]{title}[/bold yellow]"))
             if bsi := data.get("business_service_intelligence", {}):
                 if bsi.get("found"):
                     bsi_table = Table(title="Business Service Intelligence", show_header=True, header_style="bold cyan", row_styles=["", "on #202020"])
                     bsi_table.add_column("Attribute", style="dim"); bsi_table.add_column("Value")
                     for key, val in bsi.items():
                         if key != "found": bsi_table.add_row(key.replace('_', ' ').title(), str(val))
                     console.print(bsi_table)
             if isi := data.get("internet_scanner_intelligence", {}):
                 if isi.get("found"):
                     isi_table = Table(title="Internet Scanner Intelligence", show_header=True, header_style="bold green", row_styles=["", "on #202020"])
                     isi_table.add_column("Attribute", style="dim"); isi_table.add_column("Value")
                     metadata = isi.pop("metadata", {}); tags = isi.pop("tags", [])
                     for key, val in isi.items():
                         if key not in ["found", "raw_data"]: isi_table.add_row(key.replace('_', ' ').title(), str(val))
                     for key, val in metadata.items(): isi_table.add_row(key.replace('_', ' ').title(), str(val))
                     if tags: isi_table.add_row("Tags", ", ".join(t['name'] for t in tags))
                     console.print(isi_table)

        elif service_key == "shodan":
             shodan_main, shodan_ports, shodan_vulns = data
             shodan_table = Table(title=title, show_header=True, header_style="bold purple", row_styles=["", "on #202020"])
             shodan_table.add_column("Attribute", style="dim"); shodan_table.add_column("Value")
             for key, val in shodan_main: shodan_table.add_row(key, val)
             shodan_table.add_row("Open Ports", ", ".join(map(str, shodan_ports)))
             console.print(shodan_table)
             if shodan_vulns:
                 vuln_table = Table(title="Shodan Vulnerabilities", show_header=True, header_style="bold red", row_styles=["", "on #202020"])
                 vuln_table.add_column("CVE")
                 for vuln in shodan_vulns:
                     vuln_table.add_row(f"[red]{vuln}[/red]")
                 console.print(vuln_table)

def main():
    """Main function to parse arguments and run the queries."""
    parser = argparse.ArgumentParser(
        description="A powerful threat intelligence tool to query multiple services via API and web scraping.",
        epilog="Example: python advanced-threat-intel-v3.py --format ticket 8.8.8.8 example.com"
    )
    parser.add_argument("indicators", nargs='+', help="One or more IP addresses or domains to look up.")
    parser.add_argument("--format", choices=['table', 'ticket'], default='table', help="Output format (default: table).")
    
    args = parser.parse_args()
    if not args.indicators:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    driver = setup_selenium_driver()
    
    try:
        if args.format == 'ticket':
            full_report_text = []
            for indicator in args.indicators:
                console.rule(f"[bold]Processing: {indicator}[/bold]")
                vt_main, vt_vendor = query_virustotal(indicator)
                shodan_main, shodan_ports, shodan_vulns = query_shodan(indicator)
                report_data = {
                    "virustotal": (vt_main, vt_vendor),
                    "otx": query_otx(indicator),
                    "greynoise": query_greynoise(indicator),
                    "abuseipdb": query_abuseipdb(indicator),
                    "shodan": (shodan_main, shodan_ports, shodan_vulns),
                    "urlscan": query_urlscan(indicator),
                    # "xforce": scrape_xforce(indicator, driver),
                    # "talos": scrape_talos(indicator, driver)
                }
                full_report_text.append(format_for_ticket(indicator, report_data))
            console.rule("[bold green]Report Complete[/bold green]")
            for report in full_report_text:
                console.print(report)
        else: # Table format
            for indicator in args.indicators:
                report_data = {
                    "virustotal": query_virustotal(indicator),
                    "otx": query_otx(indicator),
                    "greynoise": query_greynoise(indicator),
                    "abuseipdb": query_abuseipdb(indicator),
                    "shodan": query_shodan(indicator),
                    "urlscan": query_urlscan(indicator),
                    # "xforce": scrape_xforce(indicator, driver),
                    # "talos": scrape_talos(indicator, driver)
                }
                display_as_tables(indicator, report_data)

    finally:
        if driver:
            driver.quit()
    
    console.rule("[bold green]Report Complete[/bold green]")


if __name__ == "__main__":
    main()

