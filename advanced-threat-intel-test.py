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
    """Scrapes the Cisco Talos Intelligence page and returns data as a list of tuples."""
    console.print(f"[cyan]Querying Cisco Talos for {indicator}...[/cyan]")
    report = []
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

        web_rep_element = soup.find('span', class_='web-rep-label')
        if web_rep_element:
            report.append(("Web Reputation", web_rep_element.text.strip()))
            
        email_rep_element = soup.find('div', class_='email-rep-details')
        if email_rep_element and (rep_label := email_rep_element.find('div', class_='rep-label')):
            report.append(("Email Reputation", rep_label.text.strip()))

        owner_div = soup.find('div', class_='whois-data')
        if owner_div and len(owner_info := owner_div.find_all('div')) > 1:
             report.append(("Network Owner", owner_info[1].text.strip()))
        
        return report
    except Exception as e:
        print_error(f"Failed to scrape Cisco Talos for {indicator}. Error: {e}")
        return None


def scrape_xforce(indicator, driver):
    """Scrapes the IBM X-Force Exchange page and returns data as a list of tuples."""
    console.print(f"[cyan]Querying IBM X-Force for {indicator}...[/cyan]")
    report = []
    try:
        driver.get("https://exchange.xforce.ibmcloud.com/")
        try:
            cookie_button = WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.ID, "onetrust-accept-btn-handler")))
            cookie_button.click()
            time.sleep(1)
        except TimeoutException:
            pass # No cookie banner

        search_box = WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.XPATH, "//input[contains(@placeholder, 'Search by')]"))
        )
        search_box.send_keys(indicator)
        search_box.send_keys(Keys.RETURN)

        WebDriverWait(driver, 20).until(EC.visibility_of_element_located((By.CLASS_NAME, "details-table")))
        soup = BeautifulSoup(driver.page_source, 'lxml')

        if risk_element := soup.find('span', {'data-test-id': 'risk-score-value'}):
            report.append(("Risk Score", risk_element.text.strip()))
        
        if cat_heading := soup.find('h5', string='Categorization'):
            if cat_container := cat_heading.find_parent('div').find_next_sibling('div'):
                categories = [a.text.strip() for a in cat_container.find_all('a')]
                report.append(("Categorization", ", ".join(categories)))

        if details_table := soup.find('table', class_='details-table'):
            for row in details_table.find_all('tr'):
                cells = row.find_all('td')
                if len(cells) == 2:
                    key, value = cells[0].text.strip(), cells[1].text.strip()
                    if "Location" in key: report.append(("Location", value))
                    elif "ASN" in key: report.append(("ASN", value))
        
        return report
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
        response.raise_for_status()
        data = response.json().get("data", {}).get("attributes", {})
        
        stats = data.get("last_analysis_stats", {})
        malicious_vendors = stats.get("malicious", 0)
        last_analysis = datetime.fromtimestamp(data.get("last_analysis_date", 0)).strftime('%Y-%m-%d %H:%M:%S')

        main_data = [
            ("Malicious Vendors", f"[red]{malicious_vendors}[/red]" if malicious_vendors > 0 else "[green]0[/green]"),
            ("Country", data.get("country", "N/A")),
            ("Last Analysis", last_analysis),
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
    """Queries AlienVault OTX and returns data as a list of tuples."""
    if not API_KEYS["otx"]: return None
    console.print(f"[cyan]Querying AlienVault OTX for {indicator}...[/cyan]")

    indicator_type = "IPv4" if is_ipv4(indicator) else "domain"
    url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
    headers = {"X-OTX-API-KEY": API_KEYS["otx"]}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        related_pulses = data.get("pulse_info", {}).get("pulses", [])
        all_tags = {tag for pulse in related_pulses for tag in pulse.get("tags", [])}

        return [
            ("Pulse Count", str(data.get("pulse_info", {}).get("count", 0))),
            ("Location", f"{data.get('city', 'N/A')}, {data.get('country_name', 'N/A')}"),
            ("ASN", data.get("asn", "N/A")),
            ("Related Tags", ", ".join(sorted(list(all_tags))) if all_tags else "N/A")
        ]
    except Exception as e:
        print_error(f"AlienVault OTX API request for {indicator} failed: {e}")
        return None


def query_greynoise(indicator):
    """Queries the GreyNoise Enterprise API and returns data as a dictionary."""
    if not is_ipv4(indicator) or not API_KEYS["greynoise"]: return None
    console.print(f"[cyan]Querying GreyNoise for {indicator}...[/cyan]")

    url = f"https://api.greynoise.io/v3/ip/{indicator}"
    headers = {"key": API_KEYS["greynoise"]}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print_error(f"GreyNoise API request for {indicator} failed: {e}")
        return None


def query_abuseipdb(indicator):
    """Queries the AbuseIPDB API and returns data as a list of tuples."""
    if not is_ipv4(indicator) or not API_KEYS["abuseipdb"]: return None
    console.print(f"[cyan]Querying AbuseIPDB for {indicator}...[/cyan]")
    
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
        ]
    except Exception as e:
        print_error(f"AbuseIPDB API request for {indicator} failed: {e}")
        return None

# --- Formatting Function ---

def format_for_ticket(indicator, all_data):
    """Formats the collected data into a clean, copy-paste friendly string with rich markup."""
    output = [
        "\n" + "="*50,
        f"[bold]Threat Intelligence Report for: {indicator}[/bold]",
        "="*50
    ]

    service_map = {
        "virustotal": "VirusTotal", "xforce": "IBM X-Force", "otx": "AlienVault OTX",
        "greynoise": "GreyNoise", "abuseipdb": "AbuseIPDB", "talos": "Cisco Talos"
    }

    for service_key, data in all_data.items():
        if not data: continue
        
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

        elif isinstance(data, list): # Standard key-value list
            for key, value in data:
                output.append(f"  [dim]{key:<25}:[/dim] {value}")
        
        elif isinstance(data, dict) and service_key == "greynoise": # Special handling for GreyNoise
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


def main():
    """Main function to parse arguments and run the queries."""
    parser = argparse.ArgumentParser(
        description="A powerful threat intelligence tool to query multiple services via API and web scraping.",
        epilog="Example: python advanced-threat-intel.py 8.8.8.8 1.1.1.1 example.com"
    )
    parser.add_argument("indicators", nargs='+', help="One or more IP addresses or domains to look up.")
    
    args = parser.parse_args()
    if not args.indicators:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    driver = setup_selenium_driver()
    full_report_text = []
    
    try:
        for indicator in args.indicators:
            console.rule(f"[bold]Processing: {indicator}[/bold]")
            
            vt_main, vt_vendor = query_virustotal(indicator)

            report_data = {
                "virustotal": (vt_main, vt_vendor),
                "otx": query_otx(indicator),
                "greynoise": query_greynoise(indicator),
                "abuseipdb": query_abuseipdb(indicator),
                # "xforce": scrape_xforce(indicator, driver),
                # "talos": scrape_talos(indicator, driver)
            }
            
            full_report_text.append(format_for_ticket(indicator, report_data))
    finally:
        if driver:
            driver.quit()
    
    console.rule("[bold green]Report Complete[/bold green]")
    for report in full_report_text:
        console.print(report)


if __name__ == "__main__":
    main()
