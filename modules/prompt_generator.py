"""
The module for generating prompts based on data.
"""

from typing import Optional, List, Dict


def create_prompt(
        cve_id: str,
        cvss: Optional[float] = None,
        epss: Optional[float] = None,
        kev_status: bool = False,
        nvd_details: Optional[Dict] = None,
        github_details: Optional[List[Dict]] = None,
) -> Optional[str]:
    try:
        # Обработка None
        nvd_details = nvd_details or {}
        github_details = github_details or []

        # Базовые характеристики
        cvss_v3 = nvd_details.get("cvss_v3", {})
        base_score = cvss_v3.get("base_score", cvss or "не найден")
        severity = cvss_v3.get("severity", "не определена")

        prompt = (
            f"Проанализируй уязвимость {cve_id} на основе следующих данных:\n\n"
            f"1. Базовые характеристики:\n"
            f"   - Включение в KEV: {'Да' if kev_status else 'Нет'}\n"
            f"   - Уровень EPSS: {epss or 'не найден'}\n"
            f"   - Уровень CVSS v3: {base_score} ({severity})\n\n"
            f"2. Описание уязвимости:\n"
            f"   {nvd_details.get('description', 'не найдено')}\n\n"
            f"3. Критические технические детали:\n"
            f"   - CWE: {', '.join(nvd_details.get('cwe', [])) or 'не найдены'}\n"
            f"   - Затронутые продукты: {nvd_details.get('affected_products', ['не найдены'])[0]}\n"
            f"   - Дата публикации: {nvd_details.get('published_date', 'не найдена')}\n\n"
            f"4. Ссылки на патчи:\n"
        )

        # Добавление патчей
        if github_details:
            for commit in github_details[:3]:  # Ограничение до 3 патчей
                prompt += f"   - {commit['repository']}: {commit['commit_url']}\n"
        else:
            prompt += "   не найдены\n"

        # Инструкции
        prompt += (
            "\nПросьба:\n"
            "1. Оцени критичность уязвимости с учётом противоречия между CVSS и EPSS\n"
            "2. Определи приоритетность патча на основе KEV и вектора атаки\n"
            "3. Предложи конкретные действия для mitigation\n"
            "4. Укажи на необходимость дополнительных проверок\n"
            "5. Объясни расхождения между метриками"
            "6. Явно кратко выведи данные на основе которых делаются выводы - включение в KEV, уровень EPSS, CVSS"
            "7. Перепроверь свои выводы на отсутствие противоречий с исходными данными"
        )

        prompt += (
            "\n\nОтвет предоставь В ВИДЕ ВАЛИДНОГО JSON БЕЗ КОММЕНТАРИЕВ. Пример:\n"
            '{"CVE": "CVE-2024-XXXX", "Решение": "игнорировать", "Обоснование": "...", "Патч": "ссылка"}\n'
            "Если патча нет, укажи null."
        )

        return prompt

    except Exception as e:
        print(f"Ошибка при создании промпта: {str(e)}")
        return None


def create_retry_prompt() -> str:
    prompt = (
        f"Некорректный ответ LLM. Пример ожидаемого формата:\n"
        f'{{"CVE": "CVE-2024-XXXX", "Решение": "игнорировать", "Обоснование": "...", "Патч": "ссылка"}}\n'
        f"Составь ответ данного формата на основе данных и требований из прошлого запроса\n"
        f"Если существуют причины по которым данные требования невозможны укажи их в ответе"
    )
    # Инструкции
    prompt += (
        "\nПросьба:\n"
        "1. Оцени критичность уязвимости с учётом противоречия между CVSS и EPSS\n"
        "2. Определи приоритетность патча на основе KEV и вектора атаки\n"
        "3. Предложи конкретные действия для mitigation\n"
        "4. Укажи на необходимость дополнительных проверок\n"
        "5. Объясни расхождения между метриками"
        "6. Явно кратко выведи данные на основе которых делаются выводы - включение в KEV, уровень EPSS, CVSS"
        "7. Перепроверь свои выводы на отсутствие противоречий с исходными данными"
    )

    prompt += (
        "\n\nОтвет предоставь В ВИДЕ ВАЛИДНОГО JSON БЕЗ КОММЕНТАРИЕВ. Пример:\n"
        '{"CVE": "CVE-2024-XXXX", "Решение": "игнорировать", "Обоснование": "...", "Патч": "ссылка"}\n'
        "Если патча нет, укажи null."
    )
    return prompt
