#!/usr/bin/env python3
"""
Standalone domain resolver - no pritunl imports
Runs every 5 minutes, resolves domains, stores IPs in MongoDB
"""

import time
import socket
import logging
from pymongo import MongoClient
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s][%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('/var/log/pritunl-domain-resolver.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

MONGO_URI = 'mongodb://localhost:27017/pritunl'
RESOLVE_INTERVAL = 300  # 5 minutes


def resolve_domain(domain):
    try:
        results = socket.getaddrinfo(domain, None)
        ips = list(set([r[4][0] for r in results if ':' not in r[4][0]]))
        logger.info(f'Resolved {domain} -> {ips}')
        return ips
    except Exception as e:
        logger.error(f'Failed to resolve {domain}: {e}')
        return []


def run():
    logger.info('Domain resolver started')

    while True:
        try:
            client = MongoClient(MONGO_URI)
            db = client['pritunl']
            collection = db['domain_routes']

            domains = list(collection.find({}))
            logger.info(f'Resolving {len(domains)} domain(s)')

            for doc in domains:
                domain = doc['domain']
                ips = resolve_domain(domain)

                if ips:
                    collection.update_one(
                        {'_id': doc['_id']},
                        {'$set': {
                            'resolved_ips': ips,
                            'last_resolved': datetime.utcnow(),
                            'error': None
                        }}
                    )
                    logger.info(f'Stored {len(ips)} IPs for {domain}')
                else:
                    collection.update_one(
                        {'_id': doc['_id']},
                        {'$set': {
                            'error': 'Resolution failed',
                            'last_resolved': datetime.utcnow()
                        }}
                    )

            client.close()

        except Exception as e:
            logger.error(f'Resolver loop error: {e}')

        time.sleep(RESOLVE_INTERVAL)


if __name__ == '__main__':
    run()
