from web.common import Extension, string_clean_hex
from web.database import Database
import exiftool
import tempfile
from base64 import b64encode


class ExifData(Extension):

    extension_name = 'ExifData'
    extension_type = 'filedetails'

    def run(self):
        db = Database()
        metadata = {}
        img_src = None
        if 'file_id' in self.request.POST:
            file_id = self.request.POST['file_id']
            file_object = db.get_filebyid(file_id)
            file_data = file_object.read()

            with tempfile.NamedTemporaryFile() as tmp:
                tmp.write(file_data)

                try:
                    with exiftool.ExifTool() as et:
                        metadata = et.get_metadata(tmp.name)
                        if 'File:MIMEType' in metadata:
                            if 'image' in metadata['File:MIMEType']:
                                img_src = b64encode(file_data)

                        # Clean up the metadata to remove things we don't need.
                        remove = ['File:Directory',
                                  'File:FileInodeChangeDate',
                                  'File:FileModifyDate',
                                  'File:FileAccessDate',
                                  'SourceFile',
                                  'File:FilePermissions']

                        print metadata
                        for item in remove:
                            if item in metadata:
                                print metadata[item]
                                print "Dropping"
                                del metadata[item]


                except OSError:
                    metadata['error'] = "Exiftool is not installed. 'sudo apt-get install libimage-exiftool-perl'"
                except Exception as e:
                    metadata['error'] = "Error colleting EXIF data: {0}".format(e)



            self.render_type = 'file'
            self.render_data = {'ExifData': {'results': metadata, 'file_id': file_id, 'img_src': img_src}}

    def display(self):
        file_id = self.request.POST['file_id']
        self.render_data = {'ExifData': {'results': None, 'file_id': file_id}}

