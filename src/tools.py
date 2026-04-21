import base64
import ipaddress
import os
from typing import Any
from urllib.parse import urlparse

import requests
from langchain_core.tools import tool


NVD_API_KEY = os.getenv("NVD_API_KEY", "")
VIRUS_API_KEY = os.getenv("VIRUS_API_KEY", "")
VIRUS_BASE_URL = os.getenv("VIRUS_BASE_URL", "https://www.virustotal.com/api/v3").rstrip("/")
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))


class ToolConfigurationError(RuntimeError):
    pass


def _virustotal_headers() -> dict[str, str]:
    if not VIRUS_API_KEY:
        raise ToolConfigurationError("VIRUS_API_KEY is not configured.")
    return {"x-apikey": VIRUS_API_KEY}


def _get_json(url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    try:
        data = response.json()
    except ValueError:
        return {"error": {"message": response.text, "status_code": response.status_code}}
    if response.status_code >= 400:
        return {"error": data.get("error", data), "status_code": response.status_code}
    return data


def _post_json(url: str, headers: dict[str, str], data: dict[str, str]) -> dict[str, Any]:
    response = requests.post(url, headers=headers, data=data, timeout=REQUEST_TIMEOUT)
    try:
        payload = response.json()
    except ValueError:
        return {"error": {"message": response.text, "status_code": response.status_code}}
    if response.status_code >= 400:
        return {"error": payload.get("error", payload), "status_code": response.status_code}
    return payload


@tool
def cve_id_lookup_tool(cve_id: str) -> dict[str, Any] | str:
    """Look up CVE information by CVE ID using the NVD API."""
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        return "Invalid CVE ID. Please provide a valid CVE ID in the format CVE-YYYY-NNNN."

    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else None
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    data = _get_json(url, headers=headers)

    if "error" in data:
        return f"Invalid CVE ID {cve_id} or CVE not found in NVD. Please provide a valid CVE ID."
    if not data.get("vulnerabilities"):
        return f"CVE ID {cve_id} was not found in NVD. Please provide a valid CVE ID."
    return data


@tool
def ip_address_lookup_tool(ip_address: str) -> dict[str, Any] | str:
    """Look up public IP address reputation information using the VirusTotal API."""
    ip_address = ip_address.strip()
    try:
        parsed_ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return f"Invalid IP Address {ip_address}. Please provide a valid IPv4 or IPv6 address."

    if parsed_ip.is_private:
        return f"The given IP Address {ip_address} is a private IP address. Please provide a public IP address for further analysis."

    try:
        url = f"{VIRUS_BASE_URL}/ip_addresses/{ip_address}"
        data = _get_json(url, headers=_virustotal_headers())
        if "error" in data:
            return f"Invalid IP Address {ip_address} or IP Address not found in the VirusTotal database. Please provide a valid IP address."
        return data
    except ToolConfigurationError as exc:
        return str(exc)


@tool
def domain_lookup_tool(domain: str) -> dict[str, Any] | str:
    """Look up domain reputation information using the VirusTotal API."""
    domain = domain.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc.lower()
    domain = domain.split("/")[0].strip()

    if not domain or "." not in domain:
        return f"Invalid Domain {domain}. Please provide a valid domain such as example.com."

    try:
        url = f"{VIRUS_BASE_URL}/domains/{domain}"
        data = _get_json(url, headers=_virustotal_headers())
        if "error" in data:
            return f"Given Domain {domain} does not exist in the VirusTotal database. Please provide a valid domain."
        return data
    except ToolConfigurationError as exc:
        return str(exc)


@tool
def hash_lookup_tool(file_hash: str) -> dict[str, Any] | str:
    """Look up file hash reputation information using the VirusTotal API."""
    file_hash = file_hash.strip().lower()
    allowed_lengths = {32, 40, 64}
    if len(file_hash) not in allowed_lengths or any(char not in "0123456789abcdef" for char in file_hash):
        return "Invalid File Hash. Please provide a valid MD5, SHA-1, or SHA-256 hash."

    try:
        url = f"{VIRUS_BASE_URL}/files/{file_hash}"
        data = _get_json(url, headers=_virustotal_headers())
        if "error" in data:
            return f"Given File Hash {file_hash} does not exist in the VirusTotal database. Please provide a valid file hash."
        return data
    except ToolConfigurationError as exc:
        return str(exc)


@tool
def url_lookup_tool(url: str) -> dict[str, Any] | str:
    """Look up URL reputation information using the VirusTotal API."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed_url = urlparse(url)
    if not parsed_url.netloc or "." not in parsed_url.netloc:
        return f"Invalid URL {url}. Please provide a valid URL such as https://example.com/path."

    try:
        headers = _virustotal_headers()
        scan_result = _post_json(f"{VIRUS_BASE_URL}/urls", headers=headers, data={"url": url})
        if "error" in scan_result:
            return scan_result

        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")
        report_url = f"{VIRUS_BASE_URL}/urls/{url_id}"
        data = _get_json(report_url, headers=headers)
        if "error" in data:
            return f"Given URL {url} does not exist in the VirusTotal database. Please provide a valid URL."
        return data
    except ToolConfigurationError as exc:
        return str(exc)
