"""
The main script for CVE processing.
"""
import argparse
import time
from modules.prompt_generator import create_prompt, create_retry_prompt
from modules.api_client import (
    check_CVE_in_KEV,
    get_CVE_EPSS_score,
    get_CVE_details,
    get_github_patch_info,
)
from modules.llm_handler import get_llm_response
from modules.validator import validate_response


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
    if not prompt:
        print("Ошибка генерации промпта!")
        return

    # Запрос к LLM
    now = time.time()
    llm_response = get_llm_response(prompt)
    print(f"Время выполнения запроса: {time.time() - now}")
    if not llm_response:
        print("LLM не вернула ответ")
        return

    # Валидация и вывод
    if validate_response(llm_response):
        print("Вердикт LLM:")
        print(llm_response)
    else:
        print("Попытка уточнения запроса к LLM")
        prompt = create_retry_prompt()
        now = time.time()
        llm_response = get_llm_response(prompt)
        print(f"Время выполнения запроса: {time.time() - now}")
        if validate_response(llm_response):
            print("Вердикт LLM:")
            print(llm_response)
        else:
            print("LLM вернул некорректный ответ")
            print(f"Ответ LLM {llm_response}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve", required=True)
    args = parser.parse_args()
    main(args.cve)
