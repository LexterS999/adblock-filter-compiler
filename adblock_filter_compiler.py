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
    level=logging.INFO, # Только критические ошибки будут выводиться
    format="%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)

# --- Вспомогательные функции и классы ---

_tldextract_module = None

def _ensure_tldextract_imported():
    """Ленивый импорт tldextract."""
    global _tldextract_module
    if _tldextract_module is None:
        try:
            import tldextract
            _tldextract_module = tldextract
            # Проверим версию tldextract для информирования о no_fetch
            if hasattr(tldextract, '__version__'):
                version_parts = tuple(map(int, tldextract.__version__.split('.')))
                if version_parts < (2, 0, 0):
                    logger.info( # Это INFO, не будет видно при CRITICAL, но полезно для отладки
                        f"Установлена старая версия tldextract ({tldextract.__version__}). "
                        "Параметр 'no_fetch' может не поддерживаться. Рекомендуется обновление."
                    )
        except ImportError:
            logger.critical("Библиотека 'tldextract' не найдена. Пожалуйста, установите ее: pip install tldextract requests")
            raise
    return _tldextract_module

def get_tld_extract_result(domain: str):
    """
    Безопасно извлекает компоненты домена с помощью tldextract.
    """
    tldextract_mod = _ensure_tldextract_imported()
    try:
        # Используем no_fetch=True, если версия позволяет, для предотвращения сетевых запросов
        # Это актуально для tldextract >= 2.0.0
        if hasattr(tldextract_mod, '__version__') and tuple(map(int, tldextract_mod.__version__.split('.'))) >= (2, 0, 0):
            return tldextract_mod.extract(domain, no_fetch=True)
        else:
            return tldextract_mod.extract(domain) # Для старых версий без no_fetch
    except TypeError as te:
        # Обработка ошибки для очень старых версий, где extract может быть не методом объекта
        if "got an unexpected keyword argument 'no_fetch'" in str(te):
            logger.warning(f"Версия tldextract не поддерживает 'no_fetch' для '{domain}'. Попытка без него.")
            try:
                return tldextract_mod.extract(domain)
            except Exception as e_fallback_no_fetch:
                logger.warning(f"Ошибка при извлечении TLD для '{domain}' (даже без no_fetch): {e_fallback_no_fetch}")
                return None
        elif "'extract' object is not callable" in str(te):
             logger.warning(f"Старая версия tldextract для '{domain}'. Попытка инициализации объекта.")
             try:
                extractor = tldextract_mod.TLDExtract()
                return extractor(domain)
             except Exception as e_fallback_callable:
                logger.warning(f"Ошибка при извлечении TLD для '{domain}' (fallback с TLDExtract()): {e_fallback_callable}")
                return None
        else:
            logger.warning(f"Ошибка TypeError при извлечении TLD для '{domain}': {te}")
            return None
    except Exception as e:
        logger.warning(f"Общая ошибка при извлечении TLD для '{domain}': {e}")
        return None


def get_registered_domain(domain: str) -> Optional[str]:
    """
    Возвращает зарегистрированный домен (SLD + TLD), например, 'example.com' из 'sub.example.com'.
    Или None, если домен невалидный или не удается извлечь.
    Использует 'top_domain_under_public_suffix' вместо устаревшего 'registered_domain'.
    """
    if not isinstance(domain, str) or not domain:
        return None
    ext = get_tld_extract_result(domain)
    # ИЗМЕНЕНО: используется top_domain_under_public_suffix
    if ext and ext.top_domain_under_public_suffix:
        return ext.top_domain_under_public_suffix.lower() # Всегда в нижнем регистре для сравнения
    return None

def is_valid_domain_candidate(domain_candidate: str) -> bool:
    """
    Проверяет, является ли строка валидным кандидатом в домены.
    Использует 'top_domain_under_public_suffix' вместо устаревшего 'registered_domain'.
    """
    if not isinstance(domain_candidate, str) or not domain_candidate:
        return False
    if IP_ADDRESS_REGEX.fullmatch(domain_candidate): # IP-адреса не считаем валидными *доменами* для блокировки по имени
        return False
    
    if not DOMAIN_NAME_REGEX.fullmatch(domain_candidate): # Предварительная быстрая проверка
        return False

    ext = get_tld_extract_result(domain_candidate)
    # ИЗМЕНЕНО: используется top_domain_under_public_suffix
    # Валидным считаем, если tldextract смог определить суффикс и зарегистрированный домен
    return bool(ext and ext.suffix and ext.top_domain_under_public_suffix)


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
    config: Dict[str, Any] # Оставлено для возможной будущей конфигурации логики фильтрации
) -> Tuple[str, Dict[str, int]]:
    """
    Генерирует Adblock фильтр из содержимого файлов.
    """
    final_domains_to_block: Set[str] = set()
    blocked_registered_domains: Set[str] = set() # Для оптимизации: храним множество уже заблокированных зарегистрированных доменов

    stats = {
        "lines_processed": 0,
        "valid_domains_extracted_initial": 0,
        "exact_duplicates_omitted": 0,
        "subdomains_omitted_parent_blocked": 0,
        "parent_rule_replaced_subdomains": 0,
        "invalid_or_comment_lines_skipped": 0,
        "domain_rule_count": 0 # Добавлено для точного подсчета правил
    }
    
    all_extracted_domains_candidates: Set[str] = set()

    for content_block in file_contents_iterator:
        if not content_block: continue
        for line in content_block.splitlines():
            stats["lines_processed"] += 1
            
            domain_from_rule = parse_adblock_rule_to_domain(line)
            if domain_from_rule:
                all_extracted_domains_candidates.add(domain_from_rule)
                # stats["valid_domains_extracted_initial"] инкрементируется ниже, после сортировки и уникализации
                continue

            domain_from_hosts = parse_hosts_line(line)
            if domain_from_hosts:
                all_extracted_domains_candidates.add(domain_from_hosts)
                continue
            
            stats["invalid_or_comment_lines_skipped"] += 1
    
    stats["valid_domains_extracted_initial"] = len(all_extracted_domains_candidates)

    sorted_domains = sorted(list(all_extracted_domains_candidates), key=lambda d: (len(d), d))

    for domain in sorted_domains:
        if domain in final_domains_to_block: # Уже обработан и добавлен (или был субдоменом удаленного родителя)
            stats["exact_duplicates_omitted"] += 1
            continue

        registered_domain = get_registered_domain(domain)

        if not registered_domain: 
            final_domains_to_block.add(domain)
            continue

        if registered_domain in blocked_registered_domains and domain != registered_domain:
            stats["subdomains_omitted_parent_blocked"] += 1
            logger.debug(f"Субдомен '{domain}' не добавлен, т.к. родительский '{registered_domain}' уже блокируется.")
            continue

        if domain == registered_domain:
            subdomains_to_remove = {
                sub
                for sub in final_domains_to_block
                if get_registered_domain(sub) == domain and sub != domain
            }
            if subdomains_to_remove:
                final_domains_to_block.difference_update(subdomains_to_remove)
                stats["parent_rule_replaced_subdomains"] += len(subdomains_to_remove)
                logger.debug(f"Родительский домен '{domain}' заменил субдомены: {subdomains_to_remove}")
            
            final_domains_to_block.add(domain)
            blocked_registered_domains.add(domain)
        else: 
            final_domains_to_block.add(domain)

    final_adblock_rules = sorted([generate_adblock_rule_from_domain(d) for d in final_domains_to_block])
    stats["domain_rule_count"] = len(final_adblock_rules) # Точный подсчет итоговых правил
    
    header = generate_header_content(stats["domain_rule_count"], stats)
    return '\n'.join([header, *final_adblock_rules]), stats


def generate_header_content(domain_rule_count: int, stats: Dict[str, int]) -> str:
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
    return f"""# Title: Ghostnetic's Enhanced Blocklist (Midas v4.0 Refactor)
# Description: Python script that generates adblock filters with deduplication and parent domain optimization.
# Source: (Укажите ваш URL репозитория здесь, если хотите)
# Last Modified: {timestamp}
# Domain Rule Count: {domain_rule_count}
# --- Statistics ---
# Total lines processed from sources: {stats.get('lines_processed', 0)}
# Valid domains extracted initially: {stats.get('valid_domains_extracted_initial', 0)}
# Exact duplicate rules omitted: {stats.get('exact_duplicates_omitted', 0)}
# Subdomains omitted (parent already blocked): {stats.get('subdomains_omitted_parent_blocked', 0)}
# Parent rules replaced existing subdomains: {stats.get('parent_rule_replaced_subdomains', 0)}
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
        # Пытаемся определить кодировку более надежно
        if response.encoding is None or response.encoding == 'ISO-8859-1': # Часто неверно определяется
            response.encoding = response.apparent_encoding or 'utf-8'
        return response.text
    except requests.RequestException as e:
        logger.error(f"Ошибка при загрузке {url}: {e}")
        return None
    except Exception as e: # Ловим другие возможные ошибки
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
    status_forcelist: Tuple[int, ...] = (500, 502, 503, 504) # Стандартные коды для повтора
) -> requests.Session:
    """Создает сессию requests с настроенными повторными попытками."""
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=["HEAD", "GET", "OPTIONS"] # Безопасные методы для повтора
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def main():
    logger.info("Запуск генератора Adblock фильтров (Midas v4.0 Refactor)")

    config = load_config()
    if not config:
        logger.critical("Завершение работы: критическая ошибка конфигурации (файл config.json не найден или некорректен).")
        return

    blocklist_urls: List[str] = config.get('blocklist_urls', [])
    output_filename: str = config.get('output_filename', DEFAULT_OUTPUT_FILENAME)
    request_timeout: int = config.get('request_timeout_seconds', DEFAULT_REQUEST_TIMEOUT_SECONDS)
    num_retries: int = config.get('request_retries', DEFAULT_REQUEST_RETRIES)
    retry_backoff: float = config.get('retry_backoff_factor', DEFAULT_RETRY_BACKOFF_FACTOR)
    max_workers: Optional[int] = config.get('max_workers') # None - Python выберет оптимальное

    if not blocklist_urls:
        logger.warning("Список 'blocklist_urls' в конфигурации пуст. Нечего загружать.")
        empty_header = generate_header_content(0, {}) # Передаем 0 правил и пустую статистику
        try:
            with open(output_filename, 'w', encoding='utf-8') as f:
                f.write(empty_header)
            logger.info(f"Создан пустой файл фильтра: {output_filename}")
        except IOError as e:
            logger.critical(f"КРИТИЧЕСКАЯ ОШИБКА записи пустого файла {output_filename}: {e}")
        return

    downloaded_contents: List[str] = []
    try:
        # Убедимся, что tldextract импортирован и доступен перед созданием потоков
        _ensure_tldextract_imported()

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
                        # Если content is None, ошибка уже залогирована в fetch_blocklist_content (как logger.error)
                    except Exception as exc: 
                        logger.error(f"URL {url} сгенерировал исключение при получении результата из future: {exc}")
    except ImportError: # Если tldextract не установлен, _ensure_tldextract_imported вызовет raise
        # logger.critical уже был вызван в _ensure_tldextract_imported
        return # Просто выходим, так как критическая зависимость отсутствует
    except Exception as e: # Другие неожиданные ошибки на этапе инициализации или загрузки
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
    except ImportError: # Если tldextract не был импортирован ранее (маловероятно здесь, но для полноты)
        return
    except Exception as e_filter:
        logger.critical(f"Критическая ошибка во время генерации фильтра: {e_filter}")
        return


    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write(filter_content_str)
        
        # Используем точное количество правил из final_stats
        actual_rules_in_file = final_stats.get("domain_rule_count", 0)

        logger.info(f"Файл блоклиста успешно сгенерирован: {output_filename}")
        logger.info(f"Итоговая статистика: Доменных правил: {actual_rules_in_file}, "
                    f"Обработано строк: {final_stats.get('lines_processed',0)}, "
                    f"Извлечено доменов: {final_stats.get('valid_domains_extracted_initial',0)}, "
                    f"Удалено дубликатов: {final_stats.get('exact_duplicates_omitted',0)}, "
                    f"Пропущено субдоменов: {final_stats.get('subdomains_omitted_parent_blocked',0)}, "
                    f"Заменено субдоменов родительскими: {final_stats.get('parent_rule_replaced_subdomains',0)}")

    except IOError as e:
        logger.critical(f"КРИТИЧЕСКАЯ ОШИБКА записи в файл {output_filename}: {e}")
    except Exception as e: # Другие неожиданные ошибки при записи
        logger.critical(f"КРИТИЧЕСКАЯ НЕОЖИДАННАЯ ОШИБКА при записи файла {output_filename}: {e}")

if __name__ == "__main__":
    # Для работы этого скрипта необходимы библиотеки:
    # pip install requests tldextract
    # Рекомендуется tldextract >= 3.0.0 для использования top_domain_under_public_suffix
    # и поддержки no_fetch.
    #
    # Пример config.json:
    # {
    #   "blocklist_urls": [
    #     "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    #     "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&mimetype=plaintext"
    #   ],
    #   "output_filename": "blocklist_final.txt", # Можно переопределить имя файла здесь
    #   "request_timeout_seconds": 15,
    #   "request_retries": 3,
    #   "retry_backoff_factor": 0.5,
    #   "max_workers": null # null или отсутствие означает, что Python выберет оптимальное количество
    # }
    main()
