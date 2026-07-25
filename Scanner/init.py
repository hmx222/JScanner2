from config.config import WHITE_SCOPE_PATH
from storage.filerw import read
from processor.analysis.api.api_scan import get_root_domain
from infra.dedup import DuplicateChecker


def load_initial_urls(url):
    white_list_domains = read(WHITE_SCOPE_PATH)
    if url and url.strip():
        try:
            seed_root_domain = get_root_domain(url.strip())
            if seed_root_domain and seed_root_domain not in white_list_domains:
                white_list_domains.append(seed_root_domain)
        except Exception:
            pass
    return list(set(filter(None, white_list_domains)))


def create_duplicate_checker(db_handler, initial_urls):
    return DuplicateChecker(db_handler=db_handler, initial_root_domain=initial_urls)
