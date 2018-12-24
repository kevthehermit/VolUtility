import os
import string
import logging
import contextlib
import tempfile
import shutil
import ConfigParser
import hashlib

try:
    from subprocess import getoutput
except ImportError:
    from commands import getoutput

logger = logging.getLogger(__name__)
volutility_version = '1.3'
volrc_file = os.path.join(os.path.expanduser('~'), '.volatilityrc')


def string_clean_hex(line):
    """
    replace non printable chars with their hex code
    :param line:
    :return: str
    """
    line = str(line)
    new_line = ''
    for c in line:
        if c in string.printable:
            new_line += c
        else:
            new_line += '\\x' + c.encode('hex')
    return new_line


def hex_dump(hex_cmd):
    """
    return hexdump in html formatted data
    :param hex_cmd:
    :return: str
    """
    hex_string = getoutput(hex_cmd)

    # Format the data
    html_string = ''
    hex_rows = hex_string.split('\n')
    for row in hex_rows:
        if len(row) > 9:
            off_str = row[0:8]
            hex_str = row[9:58]
            asc_str = row[58:78]
            asc_str = asc_str.replace('"', '&quot;')
            asc_str = asc_str.replace('<', '&lt;')
            asc_str = asc_str.replace('>', '&gt;')
            html_string += '<div class="row"><span class="text-info mono">{0}</span> ' \
                           '<span class="text-primary mono">{1}</span> <span class="text-success mono">' \
                           '{2}</span></div>'.format(off_str, hex_str, asc_str)
    # return the data
    return html_string


@contextlib.contextmanager
def temp_dumpdir():
    """
    Create temporary temp directories
    :return:
    """
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


def checksum_md5(file_path):
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5.update(chunk)
    return md5.hexdigest()

def parse_config():
    config_dict = {}
    config = ConfigParser.ConfigParser(allow_no_value=True)

    # Order of precedence is ~/.volutility.conf, volutility.conf, volutility.conf.sample

    if os.path.exists(os.path.join(os.path.expanduser("~"), '.volutility.conf')):
        conf_file = os.path.join(os.path.expanduser("~"), '.volutility.conf')

    elif os.path.exists('volutility.conf'):
        conf_file = 'volutility.conf'

    else:
        conf_file = 'volutility.conf.sample'
        logger.warning('Using default config file. Check your volutility.conf file exists')

    valid = config.read(conf_file)
    if len(valid) > 0:
        config_dict['valid'] = True
        for section in config.sections():
            section_dict = {}
            for key, value in config.items(section):
                section_dict[key] = value
            config_dict[section] = section_dict
    else:
        config_dict['valid'] = False
        logger.error('Unable to find a valid volutility.conf file.')

    logger.info("Loaded configuration from {0}".format(conf_file))

    return config_dict


class Extension(object):

    '''
    ToDo: Need to load the HTML and put it in the right place
    extension_inject_point = None

    Need a single place in the DB so we can always call it out. Or do i?
    Look at this

    '''

    extension_name = None
    extension_type = None
    render_type = None
    render_data = None
    render_file = None
    render_javascript = None
    extra_js = None

    def __init__(self):
        pass

    def set_request(self, request):
        self.request = request

    def set_config(self, config):
        self.config = config

    def set_plugin_results(self, data):
        self.plugin_results = data



def rec(key, depth=0, all_nodes=''):
    all_nodes += "\t" * depth + key.path()

    for subkey in key.subkeys():
        rec(subkey, depth + 1, all_nodes=all_nodes)

    return all_nodes
