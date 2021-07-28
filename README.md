# nmappalyzer

[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://raw.githubusercontent.com/blacklanternsecurity/nmappalyzer/master/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.6+-blue)](https://www.python.org)
[![Build Status](https://github.com/blacklanternsecurity/nmappalyzer/workflows/nmappalyzer%20Test%20Scan/badge.svg)](https://github.com/blacklanternsecurity/nmappalyzer/actions/workflows/scan-test.yml")

A lightweight Python 3 Nmap wrapper that doesn't try too hard. Gracefully handles any Nmap command, providing access to all output types (normal, greppable, xml), plus JSON!

## Installation
NOTE: Nmap must be installed.
~~~
$ pip install nmappalyzer
~~~

## Usage
1. Start the scan and wait for it to finish
~~~
from nmappalyzer import NmapScan

#                target            Nmap args (optional)
scan = NmapScan('scanme.nmap.org', ['-Pn', '-F', '-T4' '-sV', '--script=banner'])
~~~
2. Access information about the scan
~~~
scan.command
"/usr/bin/nmap -oA /tmp/rhw2r_q9 -Pn -F -T4 -sV --script=banner scanme.nmap.org"

# Terminal output
scan.stdout
# Terminal errors
scan.stderr

# Normal output
scan.results.output_nmap
# Greppable output
scan.results.output_gnmap
# XML output
scan.results.output_xml
# Parsed XML (lxml etree):
scan.results.etree
# Python dictionary (converted from xml)
scan.results.json
~~~
3. Access information about the hosts
~~~
for host in scan:
    host.status
    host.address
    host.scripts
    host.hostnames
    host.open_ports
    host.closed_ports
    host.filtered_ports

    # Parsed XML (lxml etree)
    host.etree

    # Python dictionary (converted from xml)
    host.json
~~~