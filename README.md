# nmapper
A lightweight Python 3 Nmap wrapper that doesn't try too hard. Gracefully handles any Nmap command, providing full access to all output types (normal, greppable, xml), plus JSON!

[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://raw.githubusercontent.com/blacklanternsecurity/nmapper/master/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.6+-green)](https://www.python.org)
![Build Status](https://github.com/blacklanternsecurity/nmapper/workflows/scan-test/badge.svg)

## Installation
NOTE: Nmap must be installed.
~~~
$ pip install nmapper
~~~

## Usage
~~~
from nmapper import NmapScan

#                target            Nmap args (optional)
scan = NmapScan('scanme.nmap.org', ['-Pn', '-F', '-T4' '-sV', '--script=banner'])

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

for host in scan:
    host.status
    host.address
    host.hostnames
    host.open_ports
    host.closed_ports
    host.filtered_ports
    host.scripts

    # Parsed XML (lxml etree)
    host.etree

    # Python dictionary (converted from xml)
    host.json
~~~