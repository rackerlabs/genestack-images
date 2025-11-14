import os
import time
import logging
from typing import Dict, Tuple

import requests
from keystoneauth1 import session as ks_session
from keystoneauth1.identity import v3 as ks_v3
from prometheus_client import start_http_server, REGISTRY
from prometheus_client.core import GaugeMetricFamily

LOG_LEVEL = os.getenv("EXPORTER_LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("barbican_exporter")

def _build_keystone_session() -> ks_session.Session:
    """Build a Keystone session from environment variables.
    Supports either application credentials or username/password auth.
    Required env for password auth:
      OS_AUTH_URL, OS_USERNAME, OS_PASSWORD, OS_PROJECT_NAME,
      OS_USER_DOMAIN_NAME, OS_PROJECT_DOMAIN_NAME
    Required env for application credential auth:
      OS_AUTH_URL, OS_APPLICATION_CREDENTIAL_ID, OS_APPLICATION_CREDENTIAL_SECRET
    """
    auth_url = os.environ.get("OS_AUTH_URL")
    if not auth_url:
        raise RuntimeError("OS_AUTH_URL is required for authentication")

    app_cred_id = os.environ.get("OS_APPLICATION_CREDENTIAL_ID")
    app_cred_secret = os.environ.get("OS_APPLICATION_CREDENTIAL_SECRET")

    if app_cred_id and app_cred_secret:
        auth = ks_v3.ApplicationCredential(
            auth_url=auth_url,
            application_credential_id=app_cred_id,
            application_credential_secret=app_cred_secret,
        )
    else:
        username = os.environ.get("OS_USERNAME")
        password = os.environ.get("OS_PASSWORD")
        project_name = os.environ.get("OS_PROJECT_NAME")
        user_domain_name = os.environ.get("OS_USER_DOMAIN_NAME", "default")
        project_domain_name = os.environ.get("OS_PROJECT_DOMAIN_NAME", "default")

        missing = [
            name for name, val in [
                ("OS_USERNAME", username),
                ("OS_PASSWORD", password),
                ("OS_PROJECT_NAME", project_name),
            ] if not val
        ]
        if missing:
            raise RuntimeError(
                f"Missing required environment variables for password auth: {', '.join(missing)}"
            )

        auth = ks_v3.Password(
            auth_url=auth_url,
            username=username,
            password=password,
            project_name=project_name,
            user_domain_name=user_domain_name,
            project_domain_name=project_domain_name,
        )

    verify = True
    os_cacert = os.environ.get("OS_CACERT")
    if os_cacert:
        verify = os_cacert

    return ks_session.Session(auth=auth, verify=verify, timeout=float(os.getenv("EXPORTER_HTTP_TIMEOUT", "10")))

class BarbicanCollector:
    def __init__(self, barbican_api_url: str, sess: ks_session.Session, cache_ttl_seconds: int = 60,
                 page_limit: int = 100, max_pages: int = 100):
        self._base_url = barbican_api_url.rstrip("/")
        self._sess = sess
        self._cache_ttl = cache_ttl_seconds
        self._page_limit = page_limit
        self._max_pages = max_pages
        self._cache: Dict[str, Tuple[float, Dict[str, float]]] = {}

    def _now(self) -> float:
        return time.time()

    def _fetch_count_with_pagination(self, collection: str) -> int:
        """Fetch count of items for a Barbican collection by following pagination.
        Barbican collections typically return payload like:
          {"secrets": [...], "next": "https://.../v1/secrets?limit=...&offset=..."}
        This function follows the `next` link up to max_pages.
        """
        url = f"{self._base_url}/v1/{collection}?limit={self._page_limit}"
        count = 0
        pages = 0
        while url and pages < self._max_pages:
            try:
                resp = self._sess.get(url)
                if resp.status_code != 200:
                    logger.warning("%s page request failed: %s %s", collection, resp.status_code, resp.text)
                    break
                data = resp.json()
                items = data.get(collection) or data.get(collection.rstrip("s")) or []
                count += len(items)
                url = data.get("next")
                pages += 1
            except Exception as exc:
                logger.exception("Error fetching %s: %s", collection, exc)
                break
        return count

    def _get_counts(self) -> Dict[str, float]:
        # Simple cache to avoid heavy scans every scrape
        cache_key = "counts"
        cached = self._cache.get(cache_key)
        if cached and (self._now() - cached[0] < self._cache_ttl):
            return cached[1]

        counts = {
            "secrets": float(self._fetch_count_with_pagination("secrets")),
            "containers": float(self._fetch_count_with_pagination("containers")),
            "orders": float(self._fetch_count_with_pagination("orders")),
        }
        self._cache[cache_key] = (self._now(), counts)
        return counts

    def _api_up(self) -> float:
        try:
            # Lightweight check: list secrets with limit=1
            url = f"{self._base_url}/v1/secrets?limit=1"
            resp = self._sess.get(url)
            return 1.0 if resp.status_code == 200 else 0.0
        except Exception:
            return 0.0

    def collect(self):
        # Health metric
        api_up = GaugeMetricFamily("barbican_api_up", "Barbican API health (1=up, 0=down)")
        api_up.add_metric([], self._api_up())
        yield api_up

        # Resource counts
        counts = self._get_counts()
        for name, value in counts.items():
            g = GaugeMetricFamily(f"barbican_{name}_count", f"Number of {name} in Barbican")
            g.add_metric([], value)
            yield g

def main():
    barbican_api_url = os.environ.get("BARBICAN_API_URL")
    if not barbican_api_url:
        raise RuntimeError("BARBICAN_API_URL is required")

    port = int(os.environ.get("EXPORTER_PORT", "9100"))
    addr = os.environ.get("EXPORTER_ADDRESS", "0.0.0.0")
    cache_ttl = int(os.environ.get("EXPORTER_CACHE_TTL", "60"))
    page_limit = int(os.environ.get("EXPORTER_PAGE_LIMIT", "100"))
    max_pages = int(os.environ.get("EXPORTER_MAX_PAGES", "100"))

    logger.info("Starting barbican exporter on %s:%s, api=%s", addr, port, barbican_api_url)

    sess = _build_keystone_session()

    collector = BarbicanCollector(
        barbican_api_url=barbican_api_url,
        sess=sess,
        cache_ttl_seconds=cache_ttl,
        page_limit=page_limit,
        max_pages=max_pages,
    )
    REGISTRY.register(collector)

    # Start HTTP server and block forever
    start_http_server(port, addr)
    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()
