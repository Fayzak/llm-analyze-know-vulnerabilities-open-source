# LLM Analyze Known Vulnerabilities in Open-Source

Анализ уязвимостей в open-source проектах с использованием LLM (Mistral-7B).  
Проект автоматизирует оценку угроз на основе данных из NVD, GitHub, RedHat и других источников.

---

## 📋 Содержание
- [⚙️ Требования](#-требования)
- [🛠️ Установка](#-установка)
- [🚀 Запуск](#-запуск)
- [🌟 Примеры](#-примеры)
- [🏗️ Архитектура](#-архитектура)
- [📞 Контакты](#-контакты)

---

## ⚙️ Требования
- Python 3.10+
- 8 ГБ+ оперативной памяти (для работы Mistral-7B)
- Утилита `ollama` ([инструкция по установке](https://ollama.com/download/windows))

---

## 🛠️ Установка

### 1. Клонирование репозитория

```bash
git clone https://github.com/Fayzak/llm-analyze-know-vulnerabilities-open-source
cd llm-analyze-know-vulnerabilities-open-source
```

### 2. Установка зависимостей

```bash
pip install -r requirements.txt
```

### 3. Установка Ollama

**Linux/macOS:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Windows (PowerShell):**
```powershell
irm https://ollama.com/install.ps1 | iex
```

### 4. Загрузка модели Mistral-7B

```bash
ollama pull mistral:7b
```

---

## 🚀 Запуск

### 1. Запустите сервер Ollama (в отдельном терминале)

```bash
ollama serve
```

### 2. Запустите скрипт анализа

```bash
python main.py --cve [-CVE-id]
```

---

## 🌟 Примеры

**Пример запроса:**

```bash
python main.py --cve CVE-2024-49960
```

**Пример вывода:**

```json
Ответ:
{
      "CVE": "CVE-2024-49960",
      "Решение": "применить патч",
      "Обоснование": "Уязвимость имеет уровень CVSS v3 7.8 (HIGH) и связана с CWE-416, что делает её критической для систем на 
основе Linux. Патч решает проблему использования памяти после удаления в ext4_fill_super функции.",
      "Патч": "https://github.com/CVEProject/cvelistV5/commit/03aee0876092795e6928dfbb3b959548cd4daf9d",
      "Приоритетность патча": "высокая (High)",
      "Митигация": "Обновите свою систему на основе Linux, как только будет доступен патч.",
      "Дополнительные проверки": "Проведите полную сканирование системы на наличие устарелых компонентов и обновите их в случае необходимости.",
      "Расхождения между метриками": "CVSS оценивает уязвимость по критериям, связанным с её воздействием на систему, в то время как EPSS (Exploit Prediction Scoring System) определяет вероятность того, что эта уязвимость будет использована для атак. В данном случае EPSS имеет низкий уровень, но CVSS показывает, что уязвимость может быть использована в ходе атаки."
   }
```

---

## 🏗️ Архитектура

```
.
├── modules/
│   ├── api_client.py        # Запросы к NVD, GitHub, RedHat API
│   ├── llm_handler.py       # Взаимодействие с Mistral через Ollama
|   ├── models.py            # Структура классов
│   ├── prompt_generator.py  # Генерация промптов
│   └── validator.py         # Валидация ответов LLM
├── main.py                  # Точка входа
└── requirements.txt         # Зависимости
```

---

## 📞 Контакты

**Команда:** ПрофIT
