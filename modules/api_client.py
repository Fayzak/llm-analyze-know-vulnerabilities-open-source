"""
The module for queries to NVD, KEV, EPSS and more.
"""

from pydantic import ValidationError
import requests
from nvdlib import searchCVE
from nvdlib.classes import CVE

from modules.models import EPSSResponse


def check_CVE_in_KEV(cve_id: str) -> bool:
    """
    Checks for the presence of CVE ID in KEV
    """
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred: {req_err}")
        return False

    try:
        vulnerabilities = response.json().get("vulnerabilities", [])
    except ValueError as json_err:
        print(f"Error parsing KEV JSON: {json_err}")
        return False

    for vulnerability in vulnerabilities:
        if vulnerability.get("cveID") == cve_id:
            return True

    return False


def get_CVE_EPSS_score(cve_id: str) -> float | None:
    """
    Gets the EPSS score for the specified CVE ID via the FIRST.org EPSS API
    """
    api_url = "https://api.first.org/data/v1/epss/"
    params = {"cve": cve_id}

    try:
        response = requests.get(api_url, params=params, timeout=15)
        response.raise_for_status()

        api_response = EPSSResponse(**response.json())

        if not api_response.data:
            print(f"No EPSS data found for {cve_id}")
            return None

        return api_response.data[0].epss

    except ValidationError as e:
        print(f"Invalid EPSS API response format: {e.json()}")
    except requests.exceptions.RequestException as e:
        print(f"EPSS API request failed: {str(e)}")

    return None


def get_CVE_CVSS_score(cve_id: str) -> float | None:
    """
    Gets CVSS score for CVE ID through multiple sources with foulback:
    1. NVD -> 2. Red Hat API
    """
    try:
        nvd_data = searchCVE(cveId=cve_id)
        if not nvd_data:
            print(f"No CVSS score found for {cve_id}")
            return None

        nvd_cve: CVE = nvd_data[0]
        result = (
            nvd_cve.v31score
            if nvd_cve.v31score
            else (
                nvd_cve.v30score
                if nvd_cve.v31score
                else nvd_cve.v2score if nvd_cve.v2score else None
            )
        )
        if not result:
            print(f"{cve_id} has not CVSS score")
            return None

        return result

    except IndexError as e:
        print(f"NVD API error: {str(e)}")

    try:
        redhat_url = (
            f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"
        )
        response = requests.get(redhat_url, timeout=15)
        response.raise_for_status()

        redhat_data = response.json()
        return redhat_data["cvss3"]["cvss3_base_score"]

    except IndexError as e:
        print(f"RedHat API error: {str(e)}")
    except requests.exceptions.RequestException as e:
        print(f"RedHat API request failed: {str(e)}")

    return None
