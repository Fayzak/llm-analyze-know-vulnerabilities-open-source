"""
The module for interaction with LLM.
"""

import requests
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_llm_response(prompt: str, model: str = "mistral:7b") -> str:
    """
    Отправляет промпт в локальный LLM через Ollama API.
    Возвращает сгенерированный ответ.
    """
    try:
        # Формируем запрос с явным требованием JSON
        payload = {
            "model": model,
            "prompt": f'{prompt}\nОтвет предоставь в формате JSON. Пример: {{"CVE": "...", "Решение": "..."}}',
            "stream": False,
            "options": {"temperature": 0.1, "seed": 42},  # Для детерминированности
        }

        response = requests.post(
                "http://localhost:11434/api/generate",
            json=payload,
            timeout=300,
        )

        response.raise_for_status()
        logger.debug(f"Сырой ответ: {response.text}")

        return response.json()["response"]

    except requests.exceptions.RequestException as e:
        logging.error(f"Oшибка запроса к Ollama: {str(e)}")
        return ""
    except json.JSONDecodeError as e:
        logger.error(f"Ошибка декодирования JSON: {str(e)}")
        return ""
    except Exception as e:
        logger.error(f"Неожиданная ошибка: {str(e)}")
        return ""
