import re
import tempfile
from web.common import Extension
from web.database import Database

# Floss Strings
try:
    import viv_utils
    from floss import strings
    from floss import stackstrings
    from floss import string_decoder


    from floss.plugins import arithmetic_plugin
    from floss import identification_manager as im
    from floss.plugins import library_function_plugin
    from floss.plugins import function_meta_data_plugin
    from floss.plugins import mov_plugin
    from floss.interfaces import DecodingRoutineIdentifier
    from floss.decoding_manager import LocationType
    from base64 import b64encode

    from floss.utils import get_vivisect_meta_info

    # Deliberate fail over to normal strings
    import failfloss

    HAVE_FLOSS = True
except ImportError:
    HAVE_FLOSS = False


KILOBYTE = 1024
MEGABYTE = 1024 * KILOBYTE
MAX_FILE_SIZE = 16 * MEGABYTE

SUPPORTED_FILE_MAGIC = set(["MZ"])

MIN_STRING_LENGTH_DEFAULT = 4


class ExtractStrings(Extension):

    extension_name = 'ExtractStrings'
    extension_type = 'filedetails'

    def is_supported_file_type(self, sample_file_path):
        """
        Return if FLOSS supports the input file type, based on header bytes
        :param sample_file_path:
        :return: True if file type is supported, False otherwise
        """
        with open(sample_file_path, "rb") as f:
            magic = f.read(2)

        if magic in SUPPORTED_FILE_MAGIC:
            return True
        else:
            return False

    def ascii_strings(self, file_data, min_len):
        string_list = ''
        if HAVE_FLOSS:
            for s in strings.extract_ascii_strings(file_data, n=min_len):
                # s is a tuple (string, offset)
                string_list += '\n{0}\t{1}'.format(s.offset, s.s)
        else:
            chars = " !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
            regexp = '[%s]{%d,}' % (chars, min_len)
            pattern = re.compile(regexp)
            for s in pattern.finditer(file_data):
                string_list += '\n{0}\t{1}'.format(s.start(), s.group())
        return string_list

    def unicode_strings(self, file_data, min_len):
        string_list = ''
        if HAVE_FLOSS:
            for s in strings.extract_unicode_strings(file_data, n=min_len):
                # s is a tuple (string, offset)
                string_list += '\n{0}\t{1}'.format(s.offset, s.s)
        else:
            chars = " !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
            regexp = b'((?:[%s]\x00){%d,})' % (chars, min_len)
            pattern = re.compile(regexp)
            for s in pattern.finditer(file_data):
                string_list += '\n{0}\t{1}'.format(s.start(), s.group().decode('utf-16').encode('ascii'))
        return string_list


    def run(self):
        db = Database()
        # Get Options

        if "min_length" in self.request.POST:
            min_len = self.request.POST['min_length']
        else:
            min_len = 4

        if 'file_id' in self.request.POST:
            file_id = self.request.POST['file_id']
            # Check to see if we already have strings stored.
            new_strings = db.get_strings(file_id)
            if new_strings:
                string_id = new_strings._id
            else:

                file_object = db.get_filebyid(file_id)

                # Always get ASCII and Unicode

                file_data = file_object.read()

                ascii_strings = self.ascii_strings(file_data, 4)
                unicode_strings = self.unicode_strings(file_data, 4)

                if HAVE_FLOSS:

                    # Advacned Floss needs a file on disk
                    with tempfile.NamedTemporaryFile() as tmp:
                        tmp.write(file_data)

                        file_path = tmp.name

                        if self.is_supported_file_type(file_path):
                            try:
                                vw = viv_utils.getWorkspace(file_path, should_save=False)
                            except Exception:
                                print "ahhhhhhhhhhhhhh"
                                raise

                            # Decode Strings
                            #decoding_functions_candidates = im.identify_decoding_functions(vw, selected_plugins, selected_functions)
                            #function_index = viv_utils.InstructionFunctionIndex(vw)

                            #decoded_strings = decode_strings(vw, function_index, decoding_functions_candidates)

                            # Stack Strings

                # Generate the final output file

                string_list = '##### ASCII Strings #####\n {0} \n ##### Unicode Strings #####\n {1}'.format(ascii_strings, unicode_strings)

                '''
                String lists can get larger than the 16Mb bson limit
                Need to store in GridFS
                '''
                store_data = {'file_id': file_id, 'string_list': string_list}
                string_id = db.create_file(string_list, 'session_id', 'sha256', '{0}_strings.txt'.format(file_id))
                print string_id

            self.render_type = 'html'
            self.render_data = '<td><a class="btn btn-success" role="button" href="/download/file/{0}">Download</a></td>'.format(
                        string_id)

    def display(self):
        db = Database()
        if 'file_id' in self.request.POST:
            file_id = self.request.POST['file_id']
            # Check to see if we already have strings stored.
            new_strings = db.get_strings(file_id)
            if new_strings:
                string_id = new_strings._id
            else:
                string_id = False
        print string_id

        self.render_data = {'ExtractStrings': {'string_id': string_id}}