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


# --- Data Gathering Functions ---

def scrape_talos(indicator, driver):
    """Scrapes the Cisco Talos Intelligence page by mimicking the user's search workflow."""
    console.print(f"[cyan]Querying Cisco Talos for {indicator}...[/cyan]")
    
    try:
        # Navigate to the main page
        driver.get("https://talosintelligence.com/")
        
        # Wait for the search box to be ready and enter the indicator
        search_box = WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.ID, "new-search-form-input"))
        )
        search_box.send_keys(indicator)
        search_box.send_keys(Keys.RETURN)

        # Wait for the results page to load by looking for a key element
        WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.CLASS_NAME, "reputation-details-container"))
        )
        soup = BeautifulSoup(driver.page_source, 'lxml')

        table = Table(title="Cisco Talos Intelligence", show_header=True, header_style="bold blue", row_styles=["", "on #202020"])
        table.add_column("Attribute", style="dim")
        table.add_column("Value")

        table.add_row("IP Address / Domain", indicator)
        
        web_rep_element = soup.find('span', class_='web-rep-label')
        if web_rep_element:
            table.add_row("Web Reputation", web_rep_element.text.strip())
            
        email_rep_element = soup.find('div', class_='email-rep-details')
        if email_rep_element:
            rep_label = email_rep_element.find('div', class_='rep-label')
            if rep_label:
                table.add_row("Email Reputation", rep_label.text.strip())

        details = soup.find_all('div', class_='rep-details-stats-item')
        for item in details:
            label_element = item.find('div', class_='reputation-details-stats-item-label')
            value_element = item.find('div', class_='reputation-details-stats-item-value')
            if label_element and value_element:
                label = label_element.text.strip()
                value = value_element.text.strip()
                if "Hostname" in label:
                    table.add_row("Hostname", value)
                elif "Domain" in label:
                    table.add_row("Domain", value)
        
        owner_div = soup.find('div', class_='whois-data')
        if owner_div:
            owner_info = owner_div.find_all('div')
            if len(owner_info) > 1:
                 table.add_row("Network Owner", owner_info[1].text.strip())

        console.print(table)

    except TimeoutException:
        print_error("Failed to scrape Cisco Talos: The page timed out or the key content did not load.")
    except Exception as e:
        print_error(f"Failed to scrape Cisco Talos. The website structure may have changed. Error: {e}")


def scrape_xforce(indicator, driver):
    """Scrapes the IBM X-Force Exchange page by mimicking the user's search workflow."""
    console.print(f"[cyan]Querying IBM X-Force for {indicator}...[/cyan]")
    
    try:
        # Navigate to the main page
        driver.get("https://exchange.xforce.ibmcloud.com/")

        # Handle cookie banner
        try:
            cookie_button = WebDriverWait(driver, 5).until(
                EC.element_to_be_clickable((By.ID, "onetrust-accept-btn-handler"))
            )
            cookie_button.click()
            time.sleep(1)
        except TimeoutException:
            console.print("[dim]No cookie banner found on IBM X-Force, proceeding...[/dim]")

        # Handle tutorial pop-up
        try:
            skip_button = WebDriverWait(driver, 5).until(
                EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Skip tutorial')]"))
            )
            skip_button.click()
            time.sleep(1)
        except TimeoutException:
            console.print("[dim]No tutorial pop-up found on IBM X-Force, proceeding...[/dim]")

        # Find the search box, enter indicator, and submit
        search_box = WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.XPATH, "//input[@placeholder='Search by Application name, IP address, URL, Vulnerability, MD5, #Tag...']"))
        )
        search_box.send_keys(indicator)
        search_box.send_keys(Keys.RETURN)

        # Wait for the details table on the results page to be visible
        WebDriverWait(driver, 20).until(
            EC.visibility_of_element_located((By.CLASS_NAME, "details-table"))
        )
        soup = BeautifulSoup(driver.page_source, 'lxml')

        table = Table(title="IBM X-Force Exchange", show_header=True, header_style="bold cyan", row_styles=["", "on #202020"])
        table.add_column("Attribute", style="dim")
        table.add_column("Value")

        risk_element = soup.find('span', {'data-test-id': 'risk-score-value'})
        if risk_element:
            table.add_row("Risk Score", risk_element.text.strip())
        
        cat_heading = soup.find('h5', string='Categorization')
        if cat_heading:
            cat_container = cat_heading.find_parent('div').find_next_sibling('div')
            if cat_container:
                categories = [a.text.strip() for a in cat_container.find_all('a')]
                table.add_row("Categorization", ", ".join(categories))

        details_table = soup.find('table', class_='details-table')
        if details_table:
            rows = details_table.find_all('tr')
            for row in rows:
                cells = row.find_all('td')
                if len(cells) == 2:
                    key = cells[0].text.strip()
                    value = cells[1].text.strip()
                    if "Location" in key:
                        table.add_row("Location", value)
                    elif "ASN" in key:
                        table.add_row("ASN", value)

        console.print(table)

    except TimeoutException:
        print_error("Failed to scrape IBM X-Force: The page timed out or the key content did not load.")
    except Exception as e:
        print_error(f"Failed to scrape IBM X-Force. Error: {e}")


# --- API Query Functions ---

def query_virustotal(indicator):
    """Queries the VirusTotal API for IP or domain information."""
    if not API_KEYS["virustotal"]:
        print_error("VirusTotal API key (VT_API_KEY) is not set. Skipping.")
        return None, None
    console.print(f"[cyan]Querying VirusTotal for {indicator}...[/cyan]")
    
    indicator_type = "ip_addresses" if is_ipv4(indicator) else "domains"
    url = f"https://www.virustotal.com/api/v3/{indicator_type}/{indicator}"
    headers = {"x-apikey": API_KEYS["virustotal"]}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json().get("data", {}).get("attributes", {})

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
        print_error(f"VirusTotal API request for {indicator} failed: {e}")
        return None, None


def query_otx(indicator):
    """Queries AlienVault OTX for IP or domain information."""
    if not API_KEYS["otx"]:
        print_error("AlienVault OTX API key is not set. Skipping.")
        return None

    indicator_type = "IPv4" if is_ipv4(indicator) else "domain"
    url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
    headers = {"X-OTX-API-KEY": API_KEYS["otx"]}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        related_pulses = data.get("pulse_info", {}).get("pulses", [])
        all_tags = set()
        for pulse in related_pulses:
            for tag in pulse.get("tags", []):
                all_tags.add(tag)

        cves = set()
        for pulse in related_pulses:
            for indicator_data in pulse.get("indicators", []):
                if 'cve' in indicator_data.get('indicator', '').lower():
                    cves.add(indicator_data.get('indicator'))
        
        return [
            ("Indicator", data.get("indicator", "N/A")),
            ("Pulse Count", str(data.get("pulse_info", {}).get("count", 0))),
            ("Location", f"{data.get('city', 'N/A')}, {data.get('country_name', 'N/A')}"),
            ("ASN", data.get("asn", "N/A")),
            ("Related Tags", ", ".join(sorted(list(all_tags))) if all_tags else "N/A"),
            ("Exploited CVEs", ", ".join(cves) if cves else "None found in recent pulses")
        ]

    except requests.exceptions.HTTPError as e:
        print_error(f"AlienVault OTX API request failed: {e}")
        return None
    except Exception as e:
        print_error(f"An unexpected error occurred with AlienVault OTX: {e}")
        return None


def query_greynoise(indicator):
    """Queries the GreyNoise Enterprise API for IP information."""
    if not is_ipv4(indicator):
        return None
    if not API_KEYS["greynoise"]:
        print_error("GreyNoise API key is not set. Skipping.")
        return None

    url = f"https://api.greynoise.io/v3/ip/{indicator}"
    headers = {"key": API_KEYS["greynoise"]}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
             print_error(f"IP '{indicator}' not found in GreyNoise.")
        else:
             print_error(f"GreyNoise API request failed: {e}")
        return None
    except Exception as e:
        print_error(f"An unexpected error occurred with GreyNoise: {e}")
        return None


def query_abuseipdb(indicator):
    """Queries the AbuseIPDB API for all available information."""
    if not is_ipv4(indicator):
        return None
    if not API_KEYS["abuseipdb"]:
        print_error("AbuseIPDB API key is not set. Skipping.")
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": indicator, "maxAgeInDays": "90", "verbose": True}
    headers = {"Key": API_KEYS["abuseipdb"], "Accept": "application/json"}
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json().get("data", {})
        
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
            ("Is Whitelisted", str(data.get("isWhitelisted", "N/A"))),
            ("Last Reported", data.get("lastReportedAt", "N/A"))
        ]

    except requests.exceptions.HTTPError as e:
        print_error(f"AbuseIPDB API request failed: {e.response.json().get('errors', [{}])[0].get('detail')}")
        return None
    except Exception as e:
        print_error(f"An unexpected error occurred with AbuseIPDB: {e}")
        return None

def query_shodan(indicator):
    """Queries the Shodan API for IP information."""
    if not is_ipv4(indicator): return None, None, None
    if not API_KEYS["shodan"]:
        print_error("Shodan API key is not set. Skipping.")
        return None, None, None
    
    console.print(f"[cyan]Querying Shodan for {indicator}...[/cyan]")
    url = f"https://api.shodan.io/shodan/host/{indicator}?key={API_KEYS['shodan']}"
    
    try:
        response = requests.get(url)
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
        print_error(f"Shodan API request for {indicator} failed: {e}")
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
            return [("Status", "No recent scans found")]

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
        print_error(f"URLScan API request for {indicator} failed: {e}")
        return None

# --- Formatting Functions ---

def format_for_ticket(indicator, all_data):
    """Formats the collected data into a clean, copy-paste friendly string with rich markup."""
    output = [
        "\n" + "="*60,
        f"[bold]Threat Intelligence Report for: {indicator}[/bold]",
        "="*60
    ]

    service_map = {
        "virustotal": "VirusTotal", "xforce": "IBM X-Force", "otx": "AlienVault OTX",
        "greynoise": "GreyNoise", "abuseipdb": "AbuseIPDB", "talos": "Cisco Talos",
        "shodan": "Shodan", "urlscan": "URLScan"
    }

    for service_key, data in all_data.items():
        if not data or (isinstance(data, tuple) and all(v is None for v in data)):
            continue
        
        output.append(f"\n[bold underline]---------- {service_map.get(service_key, service_key.title())} ----------[/bold underline]")
        
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
                output.append(f"\n  [bold]Open Ports:[/bold] {', '.join(map(str, ports))}")
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
                    metadata = isi.pop("metadata", {})
                    tags = isi.pop("tags", [])
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
    
    # Unpack all data
    vt_main, vt_vendor = all_data.get("virustotal", (None, None))
    otx_data = all_data.get("otx")
    greynoise_data = all_data.get("greynoise")
    abuseipdb_data = all_data.get("abuseipdb")
    shodan_main, shodan_ports, shodan_vulns = all_data.get("shodan", (None, None, None))
    urlscan_data = all_data.get("urlscan")
    
    # --- Print Tables ---
    if vt_main:
        vt_table = Table(title="VirusTotal Intelligence", show_header=True, header_style="bold magenta", row_styles=["", "on #202020"])
        vt_table.add_column("Attribute", style="dim")
        vt_table.add_column("Value")
        for key, val in vt_main: vt_table.add_row(key, val)
        console.print(vt_table)
        if vt_vendor:
            vendor_table = Table(title="Vendor Analysis Breakdown", show_header=True, header_style="bold blue", row_styles=["", "on #202020"])
            vendor_table.add_column("Vendor Name"); vendor_table.add_column("Result"); vendor_table.add_column("Category")
            for vendor, result, category in vt_vendor: vendor_table.add_row(vendor, result, category)
            console.print(vendor_table)

    if otx_data:
        otx_table = Table(title="AlienVault OTX", show_header=True, header_style="bold green", row_styles=["", "on #202020"])
        otx_table.add_column("Attribute", style="dim"); otx_table.add_column("Value")
        for key, val in otx_data: otx_table.add_row(key, val)
        console.print(otx_table)

    if greynoise_data:
        console.print(Panel("[bold yellow]GreyNoise Intelligence[/bold yellow]"))
        if bsi := greynoise_data.get("business_service_intelligence", {}):
            if bsi.get("found"):
                bsi_table = Table(title="Business Service Intelligence", show_header=True, header_style="bold cyan", row_styles=["", "on #202020"])
                bsi_table.add_column("Attribute", style="dim"); bsi_table.add_column("Value")
                for key, val in bsi.items():
                    if key != "found": bsi_table.add_row(key.replace('_', ' ').title(), str(val))
                console.print(bsi_table)
        if isi := greynoise_data.get("internet_scanner_intelligence", {}):
            if isi.get("found"):
                isi_table = Table(title="Internet Scanner Intelligence", show_header=True, header_style="bold green", row_styles=["", "on #202020"])
                isi_table.add_column("Attribute", style="dim"); isi_table.add_column("Value")
                metadata = isi.pop("metadata", {}); tags = isi.pop("tags", [])
                for key, val in isi.items():
                    if key not in ["found", "raw_data"]: isi_table.add_row(key.replace('_', ' ').title(), str(val))
                for key, val in metadata.items(): isi_table.add_row(key.replace('_', ' ').title(), str(val))
                if tags: isi_table.add_row("Tags", ", ".join(t['name'] for t in tags))
                console.print(isi_table)

    if abuseipdb_data:
        abuse_table = Table(title="AbuseIPDB", show_header=True, header_style="bold red", row_styles=["", "on #202020"])
        abuse_table.add_column("Attribute", style="dim"); abuse_table.add_column("Value")
        for key, val in abuseipdb_data: abuse_table.add_row(key, val)
        console.print(abuse_table)

    if shodan_main:
        shodan_table = Table(title="Shodan", show_header=True, header_style="bold purple", row_styles=["", "on #202020"])
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
            
    if urlscan_data:
        urlscan_table = Table(title="URLScan", show_header=True, header_style="bold blue", row_styles=["", "on #202020"])
        urlscan_table.add_column("Attribute", style="dim"); urlscan_table.add_column("Value")
        for key, val in urlscan_data: urlscan_table.add_row(key, val)
        console.print(urlscan_table)


def main():
    """Main function to parse arguments and run the queries."""
    parser = argparse.ArgumentParser(
        description="A powerful threat intelligence tool to query multiple services via API and web scraping.",
        epilog="Example: python advanced-threat-intel.py --format ticket 8.8.8.8 example.com"
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
                }
                full_report_text.append(format_for_ticket(indicator, report_data))
            console.rule("[bold green]Report Complete[/bold green]")
            for report in full_report_text:
                console.print(report)
        else: # Table format
            for indicator in args.indicators:
                display_as_tables(indicator, {
                    "virustotal": query_virustotal(indicator),
                    "otx": query_otx(indicator),
                    "greynoise": query_greynoise(indicator),
                    "abuseipdb": query_abuseipdb(indicator),
                    "shodan": query_shodan(indicator),
                    "urlscan": query_urlscan(indicator),
                    # "xforce": scrape_xforce(indicator, driver),
                    # "talos": scrape_talos(indicator, driver)
                })

    finally:
        if driver:
            driver.quit()
    
    console.rule("[bold green]Report Complete[/bold green]")


if __name__ == "__main__":
    main()
