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


def get_CVE_details(cve_id: str) -> dict | None:
    """
    Gets details about a CVE from NVD API
    """
    try:
        nvd_data = searchCVE(cveId=cve_id)
        if not nvd_data:
            print(f"No data found for {cve_id}")
            return None

        nvd_cve: CVE = nvd_data[0]
        
        # Structure the results
        details = {
            "id": nvd_cve.id,
            "description": nvd_cve.descriptions[0].value if hasattr(nvd_cve, 'descriptions') and nvd_cve.descriptions else None,
            "published_date": nvd_cve.published,
            "last_modified": nvd_cve.lastModified,
            "cvss_v3": {
                "base_score": nvd_cve.v31score or nvd_cve.v30score,
                "severity": nvd_cve.v31severity or nvd_cve.v30severity
            } if hasattr(nvd_cve, 'v31score') or hasattr(nvd_cve, 'v30score') else None,
            "cvss_v2": {
                "base_score": nvd_cve.v2score,
                "severity": nvd_cve.v2severity
            } if hasattr(nvd_cve, 'v2score') and nvd_cve.v2score else None,
        }
        
        # Add CWE information
        try:
            if hasattr(nvd_cve, 'weaknesses') and nvd_cve.weaknesses:
                details["cwe"] = []
                for weakness in nvd_cve.weaknesses:
                    if hasattr(weakness, 'description'):
                        for desc in weakness.description:
                            if hasattr(desc, 'value'):
                                details["cwe"].append(desc.value)
            else:
                details["cwe"] = []
        except Exception as e:
            print(f"Error processing CWE data: {str(e)}")
            details["cwe"] = []
        
        # Add affected products
        details["affected_products"] = []
        try:
            import json
            
            # CPE format: cpe:2.3:part(a=app,o=os,h=hw):vendor:product:version:update:*:*:*:*:*
            # Example: cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:* (Apache Log4j 2.14.1)
            
            # Convert configurations to JSON string and then parse back to Python 
            # This ensures we get a clean representation
            if hasattr(nvd_cve, 'configurations'):
                try:
                    config_dict = json.loads(json.dumps(nvd_cve.configurations, default=lambda o: o.__dict__ if hasattr(o, '__dict__') else str(o)))
                    
                    # Extract all CPEs from configurations
                    cpes = []
                    
                    # Process nodes structure
                    if isinstance(config_dict, list):
                        for config in config_dict:
                            if 'nodes' in config:
                                for node in config['nodes']:
                                    if 'cpeMatch' in node:
                                        for match in node['cpeMatch']:
                                            if 'criteria' in match and isinstance(match['criteria'], str):
                                                if match['criteria'].startswith('cpe:'):
                                                    cpes.append(match['criteria'])
                    elif isinstance(config_dict, dict):
                        if 'nodes' in config_dict:
                            for node in config_dict['nodes']:
                                if 'cpeMatch' in node:
                                    for match in node['cpeMatch']:
                                        if 'criteria' in match and isinstance(match['criteria'], str):
                                            if match['criteria'].startswith('cpe:'):
                                                cpes.append(match['criteria'])
                    
                    # To avoid overwhelming output
                    details["affected_products"] = list(set(cpes))[:50]
                except Exception as e:
                    print(f"Error converting configurations to JSON: {str(e)}")
                    
                if not details["affected_products"] and hasattr(nvd_cve.configurations, '__dict__'):
                    print("Using backup direct access method")
                    try:
                        if hasattr(nvd_cve.configurations, 'nodes'):
                            for node in nvd_cve.configurations.nodes:
                                if hasattr(node, 'cpeMatch'):
                                    for match in node.cpeMatch:
                                        if hasattr(match, 'criteria'):
                                            if match.criteria.startswith('cpe:'):
                                                details["affected_products"].append(match.criteria)
                    except Exception as e:
                        print(f"Backup method error: {str(e)}")
        except Exception as e:
            print(f"Error processing affected products: {str(e)}")
        
        # Add references
        try:
            if hasattr(nvd_cve, 'references') and nvd_cve.references:
                details["references"] = []
                for ref in nvd_cve.references:
                    if hasattr(ref, 'url'):
                        details["references"].append(ref.url)
            else:
                details["references"] = []
        except Exception as e:
            print(f"Error processing references: {str(e)}")
            details["references"] = []
        
        return details

    except IndexError as e:
        print(f"NVD API error: {str(e)}")
    except Exception as e:
        print(f"Error retrieving CVE details: {str(e)}")
    
    return None


def get_github_patch_info(cve_id: str) -> list | None:
    """
    Attempts to find GitHub repositories with patches for the specified CVE
    Returns a list of dictionaries with repository and commit information
    """
    try:
        search_url = "https://api.github.com/search/commits"
        headers = {"Accept": "application/vnd.github.cloak-preview+json"}
        params = {"q": cve_id}

        response = requests.get(search_url, headers=headers, params=params, timeout=15)
        response.raise_for_status()

        data = response.json()
        if not data.get("items"):
            return None

        patches = []
        for item in data["items"][:5]:  # limit to 5 results
            patches.append({
                "repository": item["repository"]["full_name"],
                "commit_url": item["html_url"],
                "commit_message": item["commit"]["message"]
            })

        return patches

    except requests.exceptions.RequestException as e:
        print(f"GitHub API request failed: {str(e)}")
    except Exception as e:
        print(f"Error retrieving GitHub patch info: {str(e)}")

    return None


# Добавил метод для получения данных от RedHat/SuSE:

def get_redhat_cvss(cve_id: str) -> dict:
    """Получает CVSS от RedHat"""
    try:
        response = requests.get(
            f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"
        )
        return {
            "cvss": response.json().get("cvss3", {}).get("cvss3_base_score"),
            "vector": response.json().get("cvss3", {}).get("cvss3_scoring_vector"),
        }
    except Exception as e:
        print(f"RedHat Error: {str(e)}")
        return {}
