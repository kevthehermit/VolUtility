import os
import string
import logging
import contextlib
import tempfile
import shutil

try:
    from subprocess import getoutput
except ImportError:
    from commands import getoutput

logger = logging.getLogger(__name__)
volutility_version = '0.1'
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
            html_string += '<div class="row"><span class="text-info mono">{0}</span> <span class="text-primary mono">{1}</span> <span class="text-success mono">{2}</span></div>'.format(off_str, hex_str, asc_str)
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
