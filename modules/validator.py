"""
The module for checking LLM answers.
"""

# modules/validator.py
import json
import re


def validate_response(response: str) -> bool:
    """
    Проверяет корректность ответа LLM.
    Возвращает True, если ответ содержит все обязательные поля.
    """
    try:
        # Ищем JSON в тексте через регулярные выражения
        json_str = re.search(r"\{.*\}", response, re.DOTALL).group()
        data = json.loads(json_str)
        return all(field in data for field in ["CVE", "Решение", "Обоснование"])

    except (AttributeError, json.JSONDecodeError) as e:
        print(f"Ошибка валидации: {str(e)}")
        return False
