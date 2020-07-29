import requests
import logging

logger = logging.getLogger(__name__)

DEBUG = True


def send_attack_ip(ip_addr):
    if DEBUG:
        logger.warning("warning: in debug mode, receive parameter: %s", ip_addr)
        return

        # url = "http://172.17.0.5:8181/onos/DNSReflectionDefence/DNSDefense/start?target=10.0.0.1"
    url = "http://172.17.0.5:8181/onos/DNSReflectionDefence/DNSDefense/start?target=" + str(ip_addr)

    payload = {}
    headers = {}

    response = requests.request("GET", url, headers=headers, data=payload)

    logger.info(response.text.encode('utf8'))
