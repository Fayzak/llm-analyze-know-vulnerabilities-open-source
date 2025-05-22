"""
The module for generating prompts based on data.
"""

from typing import Optional, List, Dict

from modules.models import PromptDataModel


def get_prompt(prompt_data: PromptDataModel, attempt: int) -> str:
    """Returns three different prompt under different attempts"""
    prompt = (
        f"Проанализируй уязвимость {prompt_data.cve_id} как эксперт по информационной безопасности на основе следующих данных:\n\n"
        f"1. Базовые характеристики:\n"
        f"   - Включение в KEV: {'Да' if prompt_data.kev_status else 'Нет'}\n"
        f"   - Уровень EPSS: {prompt_data.epss * 100:.2f}% (вероятность эксплуатации)\n"
        f"   - Уровень CVSS v3: {prompt_data.base_score} ({prompt_data.severity})\n"
        f"     • Вектор: {prompt_data.nvd_details.get('cvss_v3', {}).get('vector', 'N/A')}\n"
        f"2. Описание уязвимости:\n"
        f"   {prompt_data.nvd_details.get('description', 'нет данных')}\n\n"
        f"3. Технические детали:\n"
        f"   - CWE: {', '.join(prompt_data.nvd_details.get('cwe', [])) or 'не найдены'}\n"
        f"   - Затронутые продукты: {prompt_data.nvd_details.get('affected_products', ['не найдены'])[0]}\n"
        f"   - Дата публикации: {prompt_data.nvd_details.get('published_date', 'неизвестна')}\n\n"
        f"4. Ссылки на патчи:\n"
    )

    prompt += _select_patches(prompt_data.github_details)

    if attempt == 1:
        return prompt
    elif attempt == 2:
        prompt += (
            f"\nДополнительные метрики:\n"
            f"   - Влияние на пользователя: {prompt_data.nvd_details.get('cvss_v3', {}).get('impact', 'N/A')} (значение от 0 до 10)\n"
        )
    elif attempt == 3:
        prompt += (
            f"\nДополнительные метрики:\n"
            f"   - Влияние на пользователя: {prompt_data.nvd_details.get('cvss_v3', {}).get('impact', 'N/A')} (значение от 0 до 10)\n"
            f"   - Эксплуатируемость: {prompt_data.nvd_details.get('cvss_v3', {}).get('exploitability', 'N/A')} (значение от 0 до 10)\n"
        )

    return prompt


def _select_patches(commits: List[Dict]) -> Optional[str]:
    patches = ""
    if commits:
        for commit in commits[:3]:  # Ограничение до 3 патчей
            patches += f"   - {commit['repository']}: {commit['commit_url']}\n"
    else:
        patches += "   не найдены\n"
    return patches


def get_recomedations() -> str:
    return (
        "\nПросьба:\n"
        "1. Оценить критичность с учётом противоречий CVSS и EPSS\n"
        "2. Определить приоритет патча на основе KEV и вектора атаки\n"
        "3. Предложить конкретные меры митигации\n"
        "4. Указать необходимые дополнительные проверки\n"
        "5. Объяснить расхождения между метриками, которые получены для данного CVE ID\n"
        "6. Не используй жаргонизмы и фразеологизмы\n"
        "7. Исправляй неверную грамматику русского языка перед ответом"
    )


def get_explanations() -> str:
    return (
        "\n\nОтвет предоставь В ВИДЕ ВАЛИДНОГО JSON БЕЗ КОММЕНТАРИЕВ. Пример:\n"
        '{"CVE": "CVE-2024-XXXX", "Решение": "игнорировать", '
        '"Обоснование": "...", "Патч": "ссылка", "Приоритетность патча": "...", "Дополнительные проверки": "...", '
        '"Митигация": "...", "Расхождение между метриками": "..."}\n'
        "Если патча нет, укажи null в поле Патч."
    )


def create_prompt(
    cve_id: str,
    cvss: Optional[float] = None,
    epss: Optional[float] = None,
    kev_status: bool = False,
    nvd_details: Optional[Dict] = None,
    github_details: Optional[List[Dict]] = None,
    attempt: int = 1,
) -> Optional[str]:
    try:
        nvd_details = nvd_details or {}
        github_details = github_details or []

        cvss_v3 = nvd_details.get("cvss_v3", {})
        base_score = cvss_v3.get("base_score", cvss or "не найден")
        severity = cvss_v3.get("severity", "не определена")

        prompt_data = PromptDataModel(
            cve_id=cve_id,
            kev_status=kev_status,
            epss=epss,
            base_score=base_score,
            severity=severity,
            nvd_details=nvd_details,
            github_details=github_details,
        )

        prompt = get_prompt(prompt_data, attempt)
        prompt += get_recomedations()
        prompt += get_explanations()

        return prompt

    except Exception as e:
        print(f"Error when creating a prompt: {str(e)}")
        return None
