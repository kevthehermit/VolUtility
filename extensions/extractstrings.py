import re
from web.common import Extension
from web.database import Database

class VirusTotalSearch(Extension):

    extension_name = 'ExtractStrings'

    def run(self):
        db = Database()
        if 'file_id' in self.request.POST:
            file_id = self.request.POST['file_id']
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
            # Store the list in datastore
            store_data = {'file_id': file_id, 'string_list': string_list}
            #logger.debug('Store Strings in DB')
            string_id = db.create_file(string_list, 'session_id', 'sha256', '{0}_strings.txt'.format(file_id))

            self.render_type = 'html'
            self.render_data = '<td><a class="btn btn-success" role="button" href="/download/file/{0}">Download</a></td>'.format(
                        string_id)