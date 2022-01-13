import logging
import tempfile
import xmltodict
import subprocess
from sys import stdout
from lxml import etree
from shutil import which
from pathlib import Path


log = logging.getLogger('nmappalyzer')


def is_iterable(i):
    return any([issubclass(i.__class__, x) for x in (list, tuple)])



class NmapScan:

    def __init__(self, targets, nmap_args=None, nmap_executable=None, start=True):

        # main nmap executable/binary
        if nmap_executable is None:
            self.executable = which('nmap') or 'nmap'
        else:
            self.executable = str(nmap_executable)

        # target hosts
        if is_iterable(targets):
            self.targets = tuple(set([str(t).strip().lstrip('-') for t in targets]))
        else:
            self.targets = (str(targets).strip(),)

        # additional nmap arguments
        if nmap_args is None:
            self.args = tuple()
        elif is_iterable(nmap_args):
            self.args = tuple(nmap_args)
        else:
            self.args = (str(nmap_args),)

        # nmap output
        self._outfile_base = Path(tempfile._get_default_tempdir()) / next(tempfile._get_candidate_names())
        self._process = None
        self._results = None
        self.stdout = ''
        self.stderr = ''

        outfile_arg = ('-oA', str(self._outfile_base))
        self.command = (self.executable,) + outfile_arg + self.args + self.targets

        # dew it
        if start:
            self.start()


    def start(self):

        if self._results is None:

            log.debug(f'Executing: {" ".join(self.command)}')

            try:
                self._process = subprocess.run(self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as e:
                log.error(f'Error executing nmap: {e}')
            finally:
                if self._process is not None:
                    self.stderr = getattr(self._process, 'stderr', b'').decode('utf-8', errors='ignore')
                    self.stdout = getattr(self._process, 'stdout', b'').decode('utf-8', errors='ignore')
                    if self._process.returncode != 0:
                        log.error(f'Non-zero return code: {self._process.returncode}')
                        if self.stderr:
                            log.debug(str(self.stderr))
                        if self.stdout:
                            log.debug(str(self.stdout))
                    self._results = NmapResults(outfile_base=self._outfile_base)
                # clean up
                for ext in ('gnmap', 'nmap', 'xml'):
                    Path(f'{self._outfile_base}.{ext}').unlink(missing_ok=True)

        return self._results


    @property
    def results(self):

        if self._results is None:
            self.run()
        return self._results
            

    def __iter__(self):

        yield from self.results




class NmapResults(list):

    def __init__(self, *args, **kwargs):

        outfile_base = kwargs.pop('outfile_base', '')

        super().__init__(*args, **kwargs)

        self._json = None
        self.output_xml = ''
        self.output_nmap = ''
        self.output_gnmap = ''

        for ext in ('gnmap', 'nmap', 'xml'):
            filename = f'{outfile_base}.{ext}'
            try:
                if ext == 'xml':
                    try:
                        with open(str(filename), 'rb') as f:
                            self.etree = etree.parse(f)
                            for host in self.etree.iter('host'):
                                self.append(NmapHost(host))
                    except Exception as e:
                        log.error(f'Error parsing Nmap XML: {e}')
                with open(str(filename)) as f:
                    setattr(self, f'output_{ext}', f.read())
            except Exception as e:
                log.error(f'Error reading {filename}: {e}')


    @property
    def json(self):

        if self._json is None:
            self._json = xmltodict.parse(etree.tostring(self.etree))
        return self._json



class NmapHost(str):

    def __init__(self, xml):

        self.etree = xml
        self._json = None

        # convenient host information
        self.status = self.etree.find('status').attrib.get('state', 'down')
        self.address = self.etree.find('address').attrib.get('addr', '')
        self.hostnames = []
        for hostname in self.etree.findall('hostnames/hostname'):
            hostname = hostname.attrib.get('name')
            if hostname and not hostname in self.hostnames:
                self.hostnames.append(hostname)

        # convenient port information
        self.scripts = dict()
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        for port in self.etree.findall('ports/port'):
            port_name = port.attrib.get('portid', '0') + '/' + port.attrib.get('protocol', 'tcp').lower()
            port_status = port.find('state').attrib.get('state', 'closed')
            if port_status in ('open', 'closed', 'filtered'):
                getattr(self, f'{port_status}_ports').append(port_name)
            for script in port.iter('script'):
                script_name = script.attrib.get('id', '')
                script_output = script.attrib.get('output', '')
                if script_name:
                    try:
                        self.scripts[port_name][script_name] = script_output
                    except KeyError:
                        self.scripts[port_name] = {script_name: script_output}

        # convenient script information
        for script in self.etree.findall('hostscript/script'):
            script_name = script.attrib.get('id', '')
            script_output = script.attrib.get('output', '')
            if script_name:
                try:
                    self.scripts['hostscripts'][script_name] = script_output
                except KeyError:
                    self.scripts['hostscripts'] = {script_name: script_output}


    @property
    def json(self):

        if self._json is None:
            self._json = xmltodict.parse(etree.tostring(self.etree))
        return self._json


    def __str__(self):

        address = self.address + " " if self.address else ""
        hostnames = "(" + ", ".join(self.hostnames) + ")" if self.hostnames else ""
        return f'{address}{hostnames}'


    def __repr__(self):

        return str(self)


    def __iter__(self):

        return self.json.items()
