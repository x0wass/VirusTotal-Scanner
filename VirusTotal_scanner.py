import requests
import json
import os

# Lambda function to clear the console; compatible with Linux and Windows
clearConsole = lambda: os.system('cls' if os.name in ('nt', 'dos') else 'clear')

# API key for VirusTotal
API_KEY = 'YOUR_API_KEY' 

###################### File Scan ###################################
def scan_file_by_path(path):
    """
    Sends the file (path) for scanning to VirusTotal API.
    
    :param string path: file path.
    :returns: the sha256 hash of the scanned file to later access its report in VirusTotal.
    :rtype: string
    """
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': API_KEY}
    files = {'file': ('fileToBeScanned', open(path, 'rb'))}
    response = requests.post(url, files=files, params=params) 
    return response.json()['sha256'] 

def file_report(hashcode):   
    """
    Sends the file hash (MD5,SHA1,SHA256) to VirusTotal API, to access its scan report.

    :param string hashcode: hash of the scanned or to-be-scanned file.
    :returns: scan result report of the file by VirusTotal API.
    :rtype: dictionary
    """
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': hashcode} 
    response = requests.get(url, params=params)
    return response.json()

def file_report_write(json_file):
    """
    Writes the file scan results into a .txt file (report/scan_file_report.txt) based on the json passed as parameter.

    :param dictionary json_file: file scan results in json.
    """
    # Comprehensive file containing the antiviruses used by VirusTotal to scan files
    Antivirus_name_file = open("./antivirus_file.txt", "r") 

    # Opening scan_file_report.txt for writing; the file will be created if it does not exist
    report_file = open("./report/scan_file_report.txt", "w") 

    # File info and scan result details
    file_info = "File hash:\nSHA256 " + json_file['sha256'] +"\nSHA1: " + json_file['sha1']  +"\nMD5: " + json_file['md5'] +"\n"
    scan_date = "Scan date: " + json_file['scan_date'] +"\n"
    number_positive = "Positive scans: "+ str(json_file['positives']) + "\n"
    total_scan = "Total: " + str(json_file['total']) + "\n\n"

    # Writing info and scan results into scan_file_report.txt
    report_file.write(file_info + scan_date + number_positive + total_scan)

    # Reading antivirus names line by line
    line = Antivirus_name_file.readline()

    while line:
        line = line.replace('\n','')
        try:
            # Getting scan results by antivirus
            antivir = json_file['scans'][line] 
        
            # Result details
            detected = "YES" if antivir['detected'] else "NO"
            malware_details = "NONE" if antivir['result'] is None else antivir['result']
            version = "NONE" if antivir['version'] is None else antivir['version']

            line += ":\n malware detected: " + detected + " | version: " + version + " | malware details: " + malware_details + "\n"

            # Writing the line into scan_file_report.txt
            report_file.write(line) 
        except KeyError: 
            # Ignoring the error if VirusTotal did not use the same antiviruses for different file scans
            print("Scan File Info: " + line + "n'a pas été utilisé pour ce scan de fichier par VirusTotal")
        line = Antivirus_name_file.readline()
    report_file.close
    Antivirus_name_file.close()

def file_scan():
    """
    Scans a file based on its input type (path or hash (MD5,SHA1, or SHA256)) and writes the result in a report (text file).
    """
    report_json = None

    print("1: local file path\n2: hash")
    menu_file = input()
    clearConsole()
    if(menu_file == "1"):

        print("Enter the file path:")
        path = input()
        clearConsole()

        if(os.path.isfile(path)):
            report_json = file_report(scan_file_by_path(path))
        else: print("File Scan Error: the file does not exist")
        
    elif(menu_file == "2"):
        
        print("Enter the file hash (MD5,SHA1, or SHA256):")
        hashage = input()
        clearConsole()

        report_json = file_report(hashage)

    else:
        print("File Menu Error: incorrect input (enter 1 or 2)")
    
    if(report_json != None):
        file_report_write(report_json)
    

###################### URL Scan ###################################

def URL_report(url):
    """
    Sends the URL to VirusTotal API for comprehensive scan.

    :param string url: website link to scan.
    :returns: the scan result report of the URL by VirusTotal API.
    :rtype: dictionary
    """
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': API_KEY, 'resource':url}
    response = requests.get(url, params=params)
    return response.json()

def url_report_write(json_file):
    """
    Writes the URL scan results into a .txt file (report/scan_url_report.txt) based on the json passed as parameter.

    :param dictionary json_file: URL scan results in json.
    """
    # Comprehensive file containing the antiviruses used by VirusTotal to scan URLs
    Antivirus_name_url = open("./antivirus_url.txt", "r") 

    # Opening scan_url_report.txt for writing; the file will be created if it does not exist
    report_url = open("./report/scan_url_report.txt", "w") 

    # URL info and scan result details
    file_info = "URL: " + json_file['url'] +"\n"
    scan_date = "Scan date: " + json_file['scan_date'] +"\n"
    number_positive = "Positive scans: "+ str(json_file['positives']) + "\n"
    total_scan = "Total: " + str(json_file['total']) + "\n\n"

    # Writing info and scan results into scan_url_report.txt
    report_url.write(file_info + scan_date + number_positive + total_scan)

    # Reading antivirus names line by line
    line = Antivirus_name_url.readline()

    while line:
        line = line.replace('\n','')
        try:
            # Getting scan results by antivirus
            antivir = json_file['scans'][line] 

            # Result details
            detected = "YES" if antivir['detected'] else "NO"
            malware_details = "NONE" if antivir['result'] is None else antivir['result']

            line += ":\n malware detected: " + detected + " | malware details: " + malware_details + "\n"

            # Writing the line into scan_url_report.txt
            report_url.write(line) 
        except KeyError:
            # Ignoring the error if VirusTotal did not use the same antiviruses for different URL scans
            print("URL Scan Info: " + line + "n'a pas été utilisé pour ce scan d'URL par VirusTotal")
        line = Antivirus_name_url.readline()
    report_url.close
    Antivirus_name_url.close()

def url_scan():
    """
    Scans a URL and writes the result in a report (text file).
    """
    print("Enter the URL:")
    url = input()
    clearConsole()
    
    url_report_write(URL_report(url))


###################### Main ###################################

while True:

    print("\nWelcome to our VirusTotal Scanner\n")
    print("Choose an option:")
    print("1: File Scan\n2: URL Scan\n3: Exit")
    menu_main = input()
    clearConsole()

    if(menu_main == "1"):
        file_scan()
    elif(menu_main == "2"):
        url_scan()
    elif(menu_main == "3"):
        break
    else:
        print("Menu Error: incorrect input (enter 1, 2 or 3)")
