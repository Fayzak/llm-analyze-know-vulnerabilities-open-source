"""
The main script for CVE processing.
"""

from modules.prompt_generator import create_prompt
from modules.api_client import (
    check_CVE_in_KEV,
    get_CVE_EPSS_score,
    get_CVE_details,
    get_github_patch_info,
)


def main(cve_id: str):
    # Сбор данных
    data = {
        "cve_id": cve_id,
        "kev_status": check_CVE_in_KEV(cve_id),
        "epss": get_CVE_EPSS_score(cve_id),
        "nvd_details": get_CVE_details(cve_id),
        "github_details": get_github_patch_info(cve_id),
    }

    # Генерация промпта
    prompt = create_prompt(**data)
    print(prompt)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--cve", required=True)
    args = parser.parse_args()
    main(args.cve)
