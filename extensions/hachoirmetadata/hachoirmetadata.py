from web.common import Extension, string_clean_hex
from web.database import Database
from hachoir_core.error import HachoirError
from hachoir_core.stream import InputIOStream
from hachoir_parser import guessParser
from hachoir_metadata import extractMetadata


class HachoirMetaData(Extension):

    extension_name = 'HachoirMetaData'
    extension_type = 'filedetails'

    def run(self):
        db = Database()
        file_id = False
        if 'file_id' in self.request.POST:
            file_id = self.request.POST['file_id']
            file_object = db.get_filebyid(file_id)
            file_data = file_object.read()

            stream = InputIOStream(file_object, None, tags=[])
            parser = guessParser(stream)

            if not parser:
                metadata = None

            try:
                metadata = extractMetadata(parser)
                metadata_list = str(metadata).split('\n')
                for row in metadata_list:
                    key, value = row.split(':', 1)

                if 'JPEG' in str(metadata):
                    from base64 import b64encode
                    img_src = b64encode(file_data)

            except HachoirError as e:
                metadata = e

            results = metadata_list

            self.render_type = 'file'
            self.render_data = {'HachoirMetaData': {'results': results, 'file_id': file_id, 'img_src': img_src}}

    def display(self):
        file_id = self.request.POST['file_id']
        self.render_data = {'HachoirMetaData': {'results': None, 'file_id': file_id}}

