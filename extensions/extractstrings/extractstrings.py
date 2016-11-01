import re
from web.common import Extension
from web.database import Database

class ExtractStrings(Extension):

    extension_name = 'ExtractStrings'
    extension_type = 'filedetails'

    def run(self):
        db = Database()
        if 'file_id' in self.request.POST:
            file_id = self.request.POST['file_id']
            # Check to see if we already have strings stored.
            new_strings = db.get_strings(file_id)
            if new_strings:
                string_id = new_strings._id
            else:

                file_object = db.get_filebyid(file_id)
                file_data = file_object.read()
                chars = " !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
                shortest_run = 4
                regexp = '[%s]{%d,}' % (chars, shortest_run)
                pattern = re.compile(regexp)
                string_list_a = pattern.findall(file_data)
                regexp = b'((?:[%s]\x00){%d,})' % (chars, shortest_run)
                pattern = re.compile(regexp)
                string_list_u = [w.decode('utf-16').encode('ascii') for w in pattern.findall(file_data)]
                merged_list = string_list_a + string_list_u
                #logger.debug('Joining Strings')
                string_list = '\n'.join(merged_list)

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

        self.render_data = string_id