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


# --- Web Scraping & Public API Functions ---

def scrape_talos(indicator, driver):
    """Scrapes the Cisco Talos Intelligence page by mimicking the user's search workflow."""
    console.print("[cyan]Querying Cisco Talos via Selenium web scraping...[/cyan]")
    
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
    console.print("[cyan]Querying IBM X-Force via Selenium web scraping...[/cyan]")
    
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
        return

    indicator_type = "ip_addresses" if is_ipv4(indicator) else "domains"
    url = f"https://www.virustotal.com/api/v3/{indicator_type}/{indicator}"
    headers = {"x-apikey": API_KEYS["virustotal"]}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json().get("data", {}).get("attributes", {})

        table = Table(title="VirusTotal Intelligence", show_header=True, header_style="bold magenta", row_styles=["", "on #202020"])
        table.add_column("Attribute", style="dim")
        table.add_column("Value")

        stats = data.get("last_analysis_stats", {})
        malicious_vendors = stats.get("malicious", 0)
        table.add_row("Malicious Vendors", f"[red]{malicious_vendors}[/red]" if malicious_vendors > 0 else "[green]0[/green]")
        table.add_row("Country", data.get("country", "N/A"))
        
        last_analysis_date = datetime.fromtimestamp(data.get("last_analysis_date", 0)).strftime('%Y-%m-%d %H:%M:%S')
        table.add_row("Last Analysis", last_analysis_date)

        table.add_row("IP Address / Domain", indicator)
        table.add_row("Network", data.get("network", "N/A"))
        table.add_row("ASN", str(data.get("asn", "N/A")))
        table.add_row("AS Owner", data.get("as_owner", "N/A"))

        console.print(table)

        vendor_table = Table(title="Vendor Analysis Breakdown", show_header=True, header_style="bold blue", row_styles=["", "on #202020"])
        vendor_table.add_column("Vendor Name")
        vendor_table.add_column("Result")
        vendor_table.add_column("Category")

        analysis_results = data.get("last_analysis_results", {})
        for vendor, result in analysis_results.items():
            category = result.get("category", "N/A")
            if category != "harmless" and category != "undetected":
                 vendor_table.add_row(vendor, result.get("result"), f"[yellow]{category}[/yellow]")
        
        if vendor_table.row_count > 0:
            console.print(vendor_table)

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print_error(f"Indicator '{indicator}' not found in VirusTotal.")
        else:
            print_error(f"VirusTotal API request failed: {e}")
    except Exception as e:
        print_error(f"An unexpected error occurred with VirusTotal: {e}")


def query_otx(indicator):
    """Queries AlienVault OTX for IP or domain information."""
    if not API_KEYS["otx"]:
        print_error("AlienVault OTX API key is not set. Skipping.")
        return

    indicator_type = "IPv4" if is_ipv4(indicator) else "domain"
    url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
    headers = {"X-OTX-API-KEY": API_KEYS["otx"]}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        table = Table(title="AlienVault OTX", show_header=True, header_style="bold green", row_styles=["", "on #202020"])
        table.add_column("Attribute", style="dim")
        table.add_column("Value")

        table.add_row("Indicator", data.get("indicator", "N/A"))
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        table.add_row("Pulse Count", str(pulse_count))
        table.add_row("Location", f"{data.get('city', 'N/A')}, {data.get('country_name', 'N/A')}")
        table.add_row("ASN", data.get("asn", "N/A"))
        
        related_pulses = data.get("pulse_info", {}).get("pulses", [])
        all_tags = set()
        for pulse in related_pulses:
            for tag in pulse.get("tags", []):
                all_tags.add(tag)
        table.add_row("Related Tags", ", ".join(sorted(list(all_tags))) if all_tags else "N/A")

        cves = set()
        for pulse in related_pulses:
            for indicator_data in pulse.get("indicators", []):
                if 'cve' in indicator_data.get('indicator', '').lower():
                    cves.add(indicator_data.get('indicator'))
        
        table.add_row("Exploited CVEs", ", ".join(cves) if cves else "None found in recent pulses")

        console.print(table)

    except requests.exceptions.HTTPError as e:
        print_error(f"AlienVault OTX API request failed: {e}")
    except Exception as e:
        print_error(f"An unexpected error occurred with AlienVault OTX: {e}")


def query_greynoise(indicator):
    """Queries the GreyNoise Enterprise API for IP information."""
    if not is_ipv4(indicator):
        console.print(Panel("[yellow]Skipping GreyNoise:[/yellow] This service is for IP addresses only.", title="Notice"))
        return
    if not API_KEYS["greynoise"]:
        print_error("GreyNoise API key is not set. Skipping.")
        return

    url = f"https://api.greynoise.io/v3/ip/{indicator}"
    headers = {"key": API_KEYS["greynoise"]}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        # Main Table
        main_table = Table(title="GreyNoise Intelligence", show_header=True, header_style="bold yellow", row_styles=["", "on #202020"])
        main_table.add_column("Attribute", style="dim")
        main_table.add_column("Value")
        main_table.add_row("IP Address", data.get("ip", "N/A"))
        console.print(main_table)

        # Business Service Intelligence Table
        if data.get("business_service_intelligence", {}).get("found"):
            bsi = data["business_service_intelligence"]
            bsi_table = Table(title="Business Service Intelligence", show_header=True, header_style="bold cyan", row_styles=["", "on #202020"])
            bsi_table.add_column("Attribute", style="dim")
            bsi_table.add_column("Value")
            bsi_table.add_row("Category", bsi.get("category"))
            bsi_table.add_row("Name", bsi.get("name"))
            bsi_table.add_row("Description", bsi.get("description"))
            bsi_table.add_row("Trust Level", bsi.get("trust_level"))
            console.print(bsi_table)

        # Internet Scanner Intelligence Table
        if data.get("internet_scanner_intelligence", {}).get("found"):
            isi = data["internet_scanner_intelligence"]
            metadata = isi.get("metadata", {})
            
            isi_table = Table(title="Internet Scanner Intelligence", show_header=True, header_style="bold green", row_styles=["", "on #202020"])
            isi_table.add_column("Attribute", style="dim")
            isi_table.add_column("Value")
            
            isi_table.add_row("Classification", isi.get("classification"))
            isi_table.add_row("Actor", isi.get("actor"))
            isi_table.add_row("Last Seen", isi.get("last_seen"))
            isi_table.add_row("Spoofable", str(isi.get("spoofable")))
            isi_table.add_row("CVEs", ", ".join(isi.get("cves", [])))
            
            # Metadata
            isi_table.add_row("Organization", metadata.get("organization"))
            isi_table.add_row("Country", metadata.get("source_country"))
            isi_table.add_row("City", metadata.get("source_city"))
            isi_table.add_row("rDNS", metadata.get("rdns"))
            isi_table.add_row("ASN", metadata.get("asn"))
            isi_table.add_row("OS", metadata.get("os"))
            isi_table.add_row("Domain", metadata.get("domain"))
            isi_table.add_row("Datacenter", metadata.get("datacenter"))
            isi_table.add_row("Carrier", metadata.get("carrier"))

            # Tags
            tags_list = isi.get("tags", [])
            if tags_list:
                 isi_table.add_row("Tags", ", ".join(tag.get("name") for tag in tags_list))

            console.print(isi_table)

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
             print_error(f"IP '{indicator}' not found in GreyNoise.")
        else:
             print_error(f"GreyNoise API request failed: {e}")
    except Exception as e:
        print_error(f"An unexpected error occurred with GreyNoise: {e}")


def query_abuseipdb(indicator):
    """Queries the AbuseIPDB API for all available information."""
    if not is_ipv4(indicator):
        console.print(Panel("[yellow]Skipping AbuseIPDB:[/yellow] This service is for IP addresses only.", title="Notice"))
        return
    
    if not API_KEYS["abuseipdb"]:
        print_error("AbuseIPDB API key is not set. Skipping.")
        return

    table = Table(title="AbuseIPDB", show_header=True, header_style="bold red", row_styles=["", "on #202020"])
    table.add_column("Attribute", style="dim")
    table.add_column("Value")
    
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": indicator, "maxAgeInDays": "90", "verbose": True}
    headers = {"Key": API_KEYS["abuseipdb"], "Accept": "application/json"}
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json().get("data", {})
        
        abuse_score = data.get("abuseConfidenceScore", 0)
        table.add_row("Abuse Confidence", f"[red]{abuse_score}%[/red]" if abuse_score > 0 else "[green]0%[/green]")
        table.add_row("Total Reports", str(data.get("totalReports", "N/A")))
        table.add_row("Country", data.get("countryName", "N/A"))
        table.add_row("City", data.get("city", "N/A"))
        table.add_row("ISP", data.get("isp", "N/A"))
        table.add_row("Usage Type", data.get("usageType", "N/A"))
        table.add_row("Domain Name", data.get("domain", "N/A"))
        table.add_row("Hostname(s)", ", ".join(data.get("hostnames", [])) if data.get("hostnames") else "N/A")
        table.add_row("Is Whitelisted", str(data.get("isWhitelisted", "N/A")))
        table.add_row("Last Reported", data.get("lastReportedAt", "N/A"))

        console.print(table)

    except requests.exceptions.HTTPError as e:
        print_error(f"AbuseIPDB API request failed: {e.response.json().get('errors', [{}])[0].get('detail')}")
    except Exception as e:
        print_error(f"An unexpected error occurred with AbuseIPDB: {e}")


def main():
    """Main function to parse arguments and run the queries."""
    parser = argparse.ArgumentParser(
        description="A powerful threat intelligence tool to query multiple services via API and web scraping.",
        epilog="Example: python advanced-threat-intel.py 8.8.8.8"
    )
    parser.add_argument("indicator", help="The IP address or domain to look up.")
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    indicator = args.indicator

    console.rule(f"[bold]Threat Intelligence Report for: {indicator}[/bold]")

    driver = setup_selenium_driver()
    
    try:
        query_virustotal(indicator)
        # scrape_xforce(indicator, driver)
        query_otx(indicator)
        query_greynoise(indicator) 
        query_abuseipdb(indicator) # Now API only
        # scrape_talos(indicator, driver)
    finally:
        if driver:
            driver.quit()
    
    console.rule("[bold]Report Complete[/bold]")


if __name__ == "__main__":
    main()
