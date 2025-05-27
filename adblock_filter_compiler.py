import re
import requests
import concurrent.futures
from datetime import datetime, timezone
import json
import logging
from typing import Set, List, Tuple, Dict, Iterator, Optional, Any
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# --- Константы ---
ADBLOCK_RULE_PREFIX = "||"
ADBLOCK_RULE_SUFFIX = "^"
COMMENT_SYMBOLS = ('#', '!')
DEFAULT_REQUEST_TIMEOUT_SECONDS = 10
DEFAULT_REQUEST_RETRIES = 3
DEFAULT_RETRY_BACKOFF_FACTOR = 0.3
DEFAULT_OUTPUT_FILENAME = 'blocklist.txt' # Имя файла по умолчанию

# --- Регулярные выражения ---
IP_ADDRESS_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
DOMAIN_NAME_REGEX = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$",
    re.IGNORECASE
)

# --- Настройка логирования ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)

# --- Вспомогательные функции и классы ---

def is_valid_domain_candidate(domain_candidate: str) -> bool:
    """
    Проверяет, является ли строка валидным кандидатом в домены.
    (Без использования tldextract)
    """
    if not isinstance(domain_candidate, str) or not domain_candidate:
        return False
    if IP_ADDRESS_REGEX.fullmatch(domain_candidate): # IP-адреса не считаем валидными *доменами* для блокировки по имени
        return False
    
    # Простая проверка на соответствие общему паттерну доменного имени
    return bool(DOMAIN_NAME_REGEX.fullmatch(domain_candidate))


def parse_hosts_line(line: str) -> Optional[str]:
    """
    Парсит одну строку из hosts-подобного файла, извлекая домен.
    """
    line_stripped = line.strip()
    if not line_stripped or line_stripped.startswith(COMMENT_SYMBOLS):
        return None

    line_no_comment = line_stripped.split(COMMENT_SYMBOLS[0], 1)[0].strip()
    if not line_no_comment: return None

    parts = line_no_comment.split()
    if not parts: return None

    domain_candidate = ""
    if IP_ADDRESS_REGEX.fullmatch(parts[0]):
        if len(parts) > 1:
            domain_candidate = parts[1]
        else:
            return None # Строка содержит только IP
    else:
        domain_candidate = parts[0]
    
    domain_candidate_lower = domain_candidate.lower()
    if is_valid_domain_candidate(domain_candidate_lower):
        return domain_candidate_lower
    else:
        logger.debug(f"Невалидный кандидат в домены из hosts-строки '{line_stripped}': '{domain_candidate}'")
        return None


def parse_adblock_rule_to_domain(rule: str) -> Optional[str]:
    """
    Извлекает домен из существующего Adblock-правила.
    """
    rule_stripped = rule.strip()
    if rule_stripped.startswith(ADBLOCK_RULE_PREFIX) and rule_stripped.endswith(ADBLOCK_RULE_SUFFIX):
        domain = rule_stripped[len(ADBLOCK_RULE_PREFIX):-len(ADBLOCK_RULE_SUFFIX)]
        domain_lower = domain.lower()
        if is_valid_domain_candidate(domain_lower):
            return domain_lower
        else:
            logger.debug(f"Невалидный домен в Adblock-правиле '{rule_stripped}': '{domain}'")
    return None


def generate_adblock_rule_from_domain(domain: str) -> str:
    """Создает Adblock-правило из домена."""
    return f"{ADBLOCK_RULE_PREFIX}{domain}{ADBLOCK_RULE_SUFFIX}"


def generate_filter(
    file_contents_iterator: Iterator[str],
    config: Dict[str, Any] 
) -> Tuple[str, Dict[str, int]]:
    """
    Генерирует Adblock фильтр из содержимого файлов.
    Оптимизация по родительским доменам удалена из-за отсутствия tldextract.
    """
    final_domains_to_block: Set[str] = set()
    
    stats = {
        "lines_processed": 0,
        "valid_domains_extracted_initial": 0,
        "exact_duplicates_omitted": 0,
        # "subdomains_omitted_parent_blocked": 0, # Удалено, т.к. логика удалена
        # "parent_rule_replaced_subdomains": 0,  # Удалено, т.к. логика удалена
        "invalid_or_comment_lines_skipped": 0,
        "domain_rule_count": 0
    }
    
    all_extracted_domains_candidates: Set[str] = set()

    for content_block in file_contents_iterator:
        if not content_block: continue
        for line in content_block.splitlines():
            stats["lines_processed"] += 1
            
            domain_from_rule = parse_adblock_rule_to_domain(line)
            if domain_from_rule:
                all_extracted_domains_candidates.add(domain_from_rule)
                continue

            domain_from_hosts = parse_hosts_line(line)
            if domain_from_hosts:
                all_extracted_domains_candidates.add(domain_from_hosts)
                continue
            
            stats["invalid_or_comment_lines_skipped"] += 1
    
    stats["valid_domains_extracted_initial"] = len(all_extracted_domains_candidates)

    # Сортировка больше не нужна для сложной логики оптимизации,
    # но может быть полезна для консистентности порядка обработки, если она важна.
    # В данном упрощенном варианте можно и без нее, но оставим для возможной будущей логики.
    sorted_domains = sorted(list(all_extracted_domains_candidates), key=lambda d: (len(d), d))

    for domain in sorted_domains:
        if domain in final_domains_to_block: 
            stats["exact_duplicates_omitted"] += 1
            continue
        
        # Упрощенная логика: просто добавляем домен, если он еще не там.
        # Вся сложная логика с registered_domain и blocked_registered_domains удалена.
        final_domains_to_block.add(domain)

    final_adblock_rules = sorted([generate_adblock_rule_from_domain(d) for d in final_domains_to_block])
    stats["domain_rule_count"] = len(final_adblock_rules)
    
    header = generate_header_content(stats["domain_rule_count"], stats)
    return '\n'.join([header, *final_adblock_rules]), stats


def generate_header_content(domain_rule_count: int, stats: Dict[str, int]) -> str:
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
    # Обновлено описание, т.к. оптимизация по родительским доменам удалена
    return f"""# Title: Ghostnetic's Enhanced Blocklist (Midas v4.0 Refactor - No TLDextract)
# Description: Python script that generates adblock filters with deduplication.
# Source: (Укажите ваш URL репозитория здесь, если хотите)
# Last Modified: {timestamp}
# Domain Rule Count: {domain_rule_count}
# --- Statistics ---
# Total lines processed from sources: {stats.get('lines_processed', 0)}
# Valid domains extracted initially: {stats.get('valid_domains_extracted_initial', 0)}
# Exact duplicate rules omitted: {stats.get('exact_duplicates_omitted', 0)}
# Invalid or comment lines skipped: {stats.get('invalid_or_comment_lines_skipped', 0)}
# --- End Statistics ---
"""

def fetch_blocklist_content(
    url: str,
    session: requests.Session,
    timeout: int
) -> Optional[str]:
    """
    Загружает содержимое блоклиста по URL.
    """
    try:
        response = session.get(url, timeout=timeout)
        response.raise_for_status()
        if response.encoding is None or response.encoding == 'ISO-8859-1':
            response.encoding = response.apparent_encoding or 'utf-8'
        return response.text
    except requests.RequestException as e:
        logger.error(f"Ошибка при загрузке {url}: {e}")
        return None
    except Exception as e: 
        logger.error(f"Неожиданная ошибка при обработке {url}: {e}")
        return None


def load_config(config_path: str = 'config.json') -> Optional[Dict[str, Any]]:
    """Загружает конфигурацию из JSON файла."""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
        if 'blocklist_urls' not in config_data or not isinstance(config_data['blocklist_urls'], list):
            logger.error("Файл конфигурации должен содержать список 'blocklist_urls'.")
            return None
        return config_data
    except FileNotFoundError:
        logger.error(f"Файл конфигурации '{config_path}' не найден.")
        return None
    except json.JSONDecodeError:
        logger.error(f"Ошибка декодирования JSON в файле конфигурации '{config_path}'.")
        return None
    except Exception as e:
        logger.error(f"Неожиданная ошибка при загрузке конфигурации '{config_path}': {e}")
        return None

def create_session_with_retries(
    retries: int,
    backoff_factor: float,
    status_forcelist: Tuple[int, ...] = (500, 502, 503, 504)
) -> requests.Session:
    """Создает сессию requests с настроенными повторными попытками."""
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def main():
    logger.info("Запуск генератора Adblock фильтров (Midas v4.0 Refactor - No TLDextract)")

    config = load_config()
    if not config:
        logger.critical("Завершение работы: критическая ошибка конфигурации (файл config.json не найден или некорректен).")
        return

    blocklist_urls: List[str] = config.get('blocklist_urls', [])
    output_filename: str = config.get('output_filename', DEFAULT_OUTPUT_FILENAME)
    request_timeout: int = config.get('request_timeout_seconds', DEFAULT_REQUEST_TIMEOUT_SECONDS)
    num_retries: int = config.get('request_retries', DEFAULT_REQUEST_RETRIES)
    retry_backoff: float = config.get('retry_backoff_factor', DEFAULT_RETRY_BACKOFF_FACTOR)
    max_workers: Optional[int] = config.get('max_workers')

    if not blocklist_urls:
        logger.warning("Список 'blocklist_urls' в конфигурации пуст. Нечего загружать.")
        empty_header = generate_header_content(0, {})
        try:
            with open(output_filename, 'w', encoding='utf-8') as f:
                f.write(empty_header)
            logger.info(f"Создан пустой файл фильтра: {output_filename}")
        except IOError as e:
            logger.critical(f"КРИТИЧЕСКАЯ ОШИБКА записи пустого файла {output_filename}: {e}")
        return

    downloaded_contents: List[str] = []
    try:
        # tldextract больше не импортируется и не проверяется
        with create_session_with_retries(retries=num_retries, backoff_factor=retry_backoff) as session:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_url = {
                    executor.submit(fetch_blocklist_content, url, session, request_timeout): url
                    for url in blocklist_urls
                }
                for future in concurrent.futures.as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        content = future.result()
                        if content:
                            downloaded_contents.append(content)
                            logger.info(f"Успешно загружен контент с {url}")
                    except Exception as exc: 
                        logger.error(f"URL {url} сгенерировал исключение при получении результата из future: {exc}")
    except Exception as e: 
        logger.critical(f"Критическая ошибка на этапе загрузки или инициализации потоков: {e}")
        return


    if not downloaded_contents:
        logger.warning("Не удалось загрузить контент ни из одного источника. Итоговый файл будет содержать только заголовок.")
        empty_header = generate_header_content(0, {})
        try:
            with open(output_filename, 'w', encoding='utf-8') as f:
                f.write(empty_header)
            logger.info(f"Создан файл фильтра (только заголовок): {output_filename}")
        except IOError as e:
            logger.critical(f"КРИТИЧЕСКАЯ ОШИБКА записи файла (только заголовок) {output_filename}: {e}")
        return

    logger.info(f"Начинается генерация фильтра из {len(downloaded_contents)} загруженных источников.")
    
    try:
        filter_content_str, final_stats = generate_filter(iter(downloaded_contents), config)
    except Exception as e_filter:
        logger.critical(f"Критическая ошибка во время генерации фильтра: {e_filter}")
        return


    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write(filter_content_str)
        
        actual_rules_in_file = final_stats.get("domain_rule_count", 0)

        logger.info(f"Файл блоклиста успешно сгенерирован: {output_filename}")
        # Обновлена строка логирования статистики
        logger.info(f"Итоговая статистика: Доменных правил: {actual_rules_in_file}, "
                    f"Обработано строк: {final_stats.get('lines_processed',0)}, "
                    f"Извлечено доменов: {final_stats.get('valid_domains_extracted_initial',0)}, "
                    f"Удалено дубликатов: {final_stats.get('exact_duplicates_omitted',0)}, "
                    f"Пропущено невалидных строк: {final_stats.get('invalid_or_comment_lines_skipped',0)}")

    except IOError as e:
        logger.critical(f"КРИТИЧЕСКАЯ ОШИБКА записи в файл {output_filename}: {e}")
    except Exception as e: 
        logger.critical(f"КРИТИЧЕСКАЯ НЕОЖИДАННАЯ ОШИБКА при записи файла {output_filename}: {e}")

if __name__ == "__main__":
    # Для работы этого скрипта необходимы библиотеки:
    # pip install requests
    #
    # Пример config.json:
    # {
    #   "blocklist_urls": [
    #     "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    #     "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&mimetype=plaintext"
    #   ],
    #   "output_filename": "blocklist_final_no_tld.txt",
    #   "request_timeout_seconds": 15,
    #   "request_retries": 3,
    #   "retry_backoff_factor": 0.5,
    #   "max_workers": null
    # }
    main()
