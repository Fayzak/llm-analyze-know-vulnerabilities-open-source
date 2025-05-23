"""
Module for detecting llm mistakes through indicator questions.
"""

import json
import re
from typing import Dict, List, Tuple, Any
import requests

INDICATOR_QUESTIONS = [
    {
        "question": "List three main Linux commands for vulnerability scanning and specify minimum privilege level required for each.",
        "validators": [
            # Проверяет, что упомянуты инструменты
            lambda resp: bool(re.search(r"(nmap|openvas|lynis|nikto|chkrootkit|rkhunter|clamav|snort|ossec)", resp, re.IGNORECASE)),
            # Проверяет, что упомянуты уровни привилегий
            lambda resp: bool(re.search(r"(root|sudo|administrator|privilege|superuser|elevated)", resp, re.IGNORECASE)),
            # Проверяет, что >= 3 команд
            lambda resp: len(re.findall(r'`[^`]+`|```[^`]+```', resp)) >= 3
        ]
    },
    {
        "question": "List three Linux commands for managing user accounts and the minimum permission level required for each.",
        "validators": [
            # Проверяет, что упомянуты команды управления пользователями
            lambda resp: bool(re.search(r"(useradd|adduser|usermod|userdel|deluser|passwd|chage|groups|gpasswd|groupadd|groupdel|groupmod)", resp, re.IGNORECASE)),
            # Проверяет, что упомянуты уровни привилегий
            lambda resp: bool(re.search(r"(root|sudo|administrator|superuser|elevated|privileges)", resp, re.IGNORECASE)),
            # Проверяет, что >= 3 команд
            lambda resp: len(re.findall(r'`[^`]+`|```[^`]+```', resp)) >= 3
        ]
    },
    {
        "question": "Explain which Linux package management commands require root privileges and why.",
        "validators": [
            # Проверяет, что упомянуты команды управления пакетами
            lambda resp: bool(re.search(r"(apt|apt-get|yum|dnf|pacman|rpm|dpkg|snap|flatpak)", resp, re.IGNORECASE)),
            # Проверяет, что упомянуты права root
            lambda resp: bool(re.search(r"(root|sudo|superuser|administrator|elevated)", resp, re.IGNORECASE)),
            # Проверяет, что есть объяснения безопасности/системности
            lambda resp: bool(re.search(r"(system|files|directories|security|integrity|libraries|binaries|conflicts)", resp, re.IGNORECASE))
        ]
    },
    {
        "question": "What Linux commands can be used to monitor network traffic and which require elevated permissions?",
        "validators": [
            # Проверяет, что упомянуты сетевые инструменты
            lambda resp: bool(re.search(r"(tcpdump|wireshark|tshark|netstat|ss|iftop|nethogs|iptraf|nload|bmon|vnstat)", resp, re.IGNORECASE)),
            # Проверяет, что упомянута необходимость привилегий
            lambda resp: bool(re.search(r"(root|sudo|administrator|privileges|elevated|superuser|capabilities|cap_net)", resp, re.IGNORECASE)),
            # Проверяет, что объяснена причина необходимости привилегий
            lambda resp: bool(re.search(r"(raw socket|packet capture|interface|promiscuous|device access|kernel|system)", resp, re.IGNORECASE))
        ]
    }
]

def send_indicator_question(question: str, model: str = "mistral:7b") -> str:
    """
    Sends an indicator question to the LLM and gets a response.
    """
    try:
        payload = {
            "model": model,
            "prompt": question,
            "stream": False,
            "options": {"temperature": 0.1}
        }
        
        response = requests.post(
            "http://localhost:11434/api/generate",
            json=payload,
            timeout=60
        )
        
        response.raise_for_status()
        return response.json().get("response", "")
        
    except Exception as e:
        print(f"Ошибка при отправке вопроса-индикатора: {str(e)}")
        return ""

def check_model_mistakes(model: str = "mistral:7b", num_questions: int = 2) -> Tuple[bool, Dict[str, Any]]:
    """
    Checks for model mistakes by asking indicator questions.
    """
    import random
    
    selected_questions = random.sample(INDICATOR_QUESTIONS, min(num_questions, len(INDICATOR_QUESTIONS)))
    mistake_detected = False
    results = []
    
    for question_data in selected_questions:
        question = question_data["question"]
        validators = question_data["validators"]
        
        response = send_indicator_question(question, model)
        
        validation_results = [validator(response) for validator in validators]
        is_valid = all(validation_results)
        
        results.append({
            "question": question,
            "response": response,
            "passed": is_valid,
            "validation_details": validation_results
        })
        
        if not is_valid:
            mistake_detected = True
    
    return mistake_detected, {
        "results": results,
        "mistake_detected": mistake_detected
    }