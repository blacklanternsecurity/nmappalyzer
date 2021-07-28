#!/usr/bin/env python3

import logging
import unittest
from .main import NmapScan, log
logging.getLogger('nmappalyzer').setLevel(logging.DEBUG)

class Testnmappalyzer(unittest.TestCase):

    def test_scan(self):

        scan = NmapScan(['scanme.nmap.org'], ['-F', '-Pn', '-T5', '-sV', '--script=asn-query,banner'])
        self.assertTrue(scan.results)
        log.debug(f'{len(scan.results):,} results')
        for host in scan.results:
            log.debug(f'    host: {host}')
            log.debug(f'        open ports: {host.open_ports}')
            log.debug(f'        closed ports: {host.closed_ports}')
            log.debug(f'        filtered ports: {host.filtered_ports}')
            log.debug(f'        scripts: {host.scripts}')
            self.assertIn('scanme.nmap.org', host.hostnames)
            self.assertIn('80/tcp', host.open_ports)
            self.assertIn('asn-query', host.scripts['hostscripts'])

if __name__ == '__main__':
    unittest.main()