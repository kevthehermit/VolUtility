import re
import string
from web.common import Extension
from web.database import Database

class ExtractStrings(Extension):

    extension_name = 'HexViewer'
    extension_type = 'filedetails'

    def run(self):
        db = Database()
        if 'file_id' in self.request.POST:
            file_id = self.request.POST['file_id']
            file_object = db.get_filebyid(file_id)
            file_data = file_object.read()
            html_string = ''

            start_offset = int(self.request.POST['start_offset'])
            end_offset = int(self.request.POST['end_offset'])



            if start_offset >= len(file_data):
                start_offset = 0
            if end_offset > len(file_data):
                end_offset = len(file_data)

            hex_data = file_data[start_offset:end_offset]

            split_list = [hex_data[i:i + 16] for i in range(0, len(hex_data), 16)]

            offset_counter = start_offset

            for item in split_list:
                hex_encode = item.encode('hex')
                hex_chars = " ".join(hex_encode[i:i+2] for i in range(0, len(hex_encode), 2))
                ascii_chars = ''
                for char in item:
                    if char in string.printable:
                        ascii_chars += char
                    else:
                        ascii_chars += '.'

                html_string += '\n<div class="row"><span class="text-info mono">{0}</span> ' \
                               '<span class="text-primary mono">{1}</span> <span class="text-success mono">' \
                               '|{2}|</span></div>'.format("{0:#0{1}x}".format(offset_counter, 8), hex_chars, ascii_chars)

                offset_counter += 16

            self.render_type = 'html'
            self.render_data = html_string

    def display(self):
        # Always display first 256 bytes
        self.render_data = {'HexViewer': None}

    def hex_html(self, hex_rows):
        html_string = ''
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
