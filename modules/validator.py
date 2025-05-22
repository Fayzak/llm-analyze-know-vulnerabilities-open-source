"""
The module for checking LLM answers.
"""

# modules/validator.py
import json
import re


def validate_response(response: str) -> bool:
    """
    Checks if the LLM response is correct.
    Returns True if the response contains all mandatory fields.
    """
    try:
        # Ищем JSON в тексте через регулярные выражения
        json_str = re.search(r"\{.*\}", response, re.DOTALL).group()
        data = json.loads(json_str)
        return all(field in data for field in ["CVE", "Решение", "Обоснование"])

    except (AttributeError, json.JSONDecodeError) as e:
        print(f"LLM response validation error: {str(e)}")
        return False
