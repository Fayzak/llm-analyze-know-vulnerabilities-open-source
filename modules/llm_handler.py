"""
The module for interaction with LLM.
"""

import requests
import logging

logging.basicConfig(level=logging.INFO)


def get_llm_response(prompt: str, model: str = "mistral:7b") -> str:
    """
    Sends a prompt to the local LLM via Ollama API.
    Returns the generated response.
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
            json=payload,  # Исправлено с json_format_prompt → json
            timeout=300,
        )

        response.raise_for_status()
        # logging.info(f"Сырой ответ: {response.text}")  # Для отладки

        return response.json()["response"]

    except requests.exceptions.RequestException as e:
        logging.error(f"Ollama request error: {str(e)}")
        return ""
    except Exception as e:
        logging.error(f"Unexpected LLM response error: {str(e)}")
        return ""
