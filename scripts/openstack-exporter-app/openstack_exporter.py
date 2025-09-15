# Openstack API Exporter
import os
import time
import yaml
from datetime import datetime
from keystoneauth1.identity import v3
from keystoneauth1 import session
from openstack import connection
from prometheus_client import Gauge, Histogram, start_http_server
import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

OPENSTACK_UP = Gauge('openstack_api_up', 'API availability', ['service', 'endpoint'])
LATENCY = Histogram('openstack_api_latency_seconds', 'API latency', ['service'])

def load_services(config_path):
    try:
        with open(config_path, 'r') as f:
            services = yaml.safe_load(f)['services']
        return [(s['name'], s['endpoint'], 'public') for s in services]  # Adjusted for config.yaml structure
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        return []

def check_service_status(service_name, endpoint, sess):
    try:
        start = time.time()
        response = requests.get(endpoint, headers={"X-Auth-Token": sess.get_token()}, timeout=5)
        latency = time.time() - start
        status = 1 if 200 <= response.status_code < 300 else 0
        OPENSTACK_UP.labels(service=service_name, endpoint=endpoint).set(status)
        LATENCY.labels(service=service_name).observe(latency)
        logger.info(f"{datetime.now()} INFO: {service_name} is up.")
    except Exception as e:
        OPENSTACK_UP.labels(service=service_name, endpoint=endpoint).set(0)
        LATENCY.labels(service=service_name).observe(0)
        logger.error(f"{datetime.now()} ERROR: {service_name} - {e}")

def main():
    port = int(os.environ.get('EXPORTER_PORT', 49152))
    config_path = '/etc/openstack-exporter/config.yaml'

    start_http_server(port)
    logger.info(f"Prometheus metrics available at http://0.0.0.0:{port}/metrics")

    auth = v3.Password(
        auth_url=os.getenv('AUTH_URL'),
        username=os.getenv('USERNAME'),
        password=os.getenv('PASSWORD'),
        user_domain_name=os.getenv('USER_DOMAIN_NAME', 'Default'),
        project_name=os.getenv('PROJECT_NAME', 'admin'),
        project_domain_name=os.getenv('PROJECT_DOMAIN_NAME', 'Default')
    )
    sess = session.Session(auth=auth)

    services = load_services(config_path)
    if not services:
        logger.error("No services loaded, exiting.")
        return
    while True:
        for service_name, endpoint, _ in services:
            check_service_status(service_name, endpoint, sess)
        time.sleep(15)  # Check every 15 seconds

if __name__ == "__main__":
    main()

