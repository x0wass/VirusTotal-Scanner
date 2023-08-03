# VirusTotal Scanner

This project is a Python script that uses the VirusTotal API to scan files and URLs for malicious content. The scanner utilizes several antivirus engines and URL/domain blacklisting services to provide a comprehensive scan report.

## Features

* File Scan: The application can scan files either from a local path or based on a given file hash (MD5, SHA1, SHA256).
* URL Scan: Enter any URL to receive a comprehensive scan report.
* Scan Reports: The application generates detailed scan reports in text files, listing the results from each antivirus engine used.

## Prerequisites

This script requires Python 3 and the `requests` library. You also need a VirusTotal API key, which you can obtain by creating a free account on the [VirusTotal](https://www.virustotal.com/gui/join-us) website.

## How to Use

1. Clone the repository or download the python script.
2. Replace `API_KEY` in the script with your VirusTotal API key.
3. Install the `requests` library if it's not already installed: `pip install requests`
4. Run the script in your Python environment: `python virustotal_scanner.py`
5. Choose an option from the console menu: file scan (1), URL scan (2), or exit (3).

## Scan Reports

Scan reports are saved in the `report` folder:
* File scan reports are named `scan_file_report.txt`
* URL scan reports are named `scan_url_report.txt`

The reports contain detailed results from each antivirus engine used in the scan.

## Disclaimer

This tool should not be used as the only indicator of a file or URL's safety. It is recommended to use multiple security tools and practices to ensure total security.
