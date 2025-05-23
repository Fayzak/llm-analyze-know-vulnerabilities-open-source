"""
The main script for CVE processing.
"""
import argparse
import time
import logging
from typing import Dict, Any, Optional

from modules.api_client import (
    check_CVE_in_KEV,
    get_CVE_EPSS_score,
    get_CVE_details,
    get_github_patch_info
)
from modules.llm_handler import get_llm_response
from modules.prompt_generator import create_prompt
from modules.validator import validate_response
from modules.model_mistake_detector import check_model_mistakes

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_RETRY_ATTEMPTS = 3

def main(cve_id: str, model: str = "mistral:7b"):
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
        logger.error("Ошибка генерации промпта!")
        return

    # Запрос к LLM
    now = time.time()
    llm_response = get_llm_response_with_mistake_check(prompt, model)
    if not llm_response:
        logger.error("Ошибка получения ответа от LLM!")
        return
    
    print("Ответ: ")
    print(llm_response)

def get_response_with_mistake_check(prompt: str, model: str = "mistral:7b") -> Optional[str]:
    """
    Gets a response from LLM with mistake checking and retry attempts.
    """
    attempts = 0
    
    while attempts < MAX_RETRY_ATTEMPTS:
        attempts += 1
        logger.info(f"Attempt {attempts}/{MAX_RETRY_ATTEMPTS} to get LLM response")
        
        start_time = time.time()
        llm_response = get_llm_response(prompt, model)
        logger.info(f"Время выполнения запроса: {time.time() - start_time:.3f} seconds")
        
        if not llm_response:
            logger.warning("LLM не вернула ответ")
            continue
            
        # Базовая проверка структуры ответа
        if not validate_response(llm_response):
            logger.warning("Ответ LLM не прошел проверку структуры")
            continue
            
        # Проверка на адекватность модели
        logger.info("Проверка ошибок модели через вопросы-индикаторы...")
        mistake_detected, mistake_details = check_model_mistakes(model, num_questions=2)
        
        if mistake_detected:
            logger.warning(f"Обнаружена ошибка модели: {mistake_details}")
            continue
        
        # Если мы здесь - ответ валидный и ошибок не обнаружено
        logger.info("Получен валидный ответ, ошибок не обнаружено")
        return llm_response
        
    # Если достигнуто максимальное количество попыток
    logger.error(f"Достигнуто максимальное количество попыток ({MAX_RETRY_ATTEMPTS})")
    logger.error("Необходимо улучшить промпты - модель не улавливает контекст и уходит не в ту сторону")
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve", required=True)
    parser.add_argument("--model", default="mistral:7b")
    args = parser.parse_args()
    main(args.cve, args.model)
