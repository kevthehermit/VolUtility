from web.common import Extension, string_clean_hex
from web.database import Database
import os
try:
    import yara
    YARA = True
except ImportError:
    YARA = False


class YaraScanner(Extension):

    extension_name = 'YaraScanner'
    extension_type = 'filedetails'

    def run(self):
        db = Database()
        file_id = rule_file = False
        if 'file_id' in self.request.POST:
            file_id = self.request.POST['file_id']

        if 'rule_file' in self.request.POST:
            rule_file = self.request.POST['rule_file']

        if rule_file and file_id and YARA:
            file_object = db.get_filebyid(file_id)
            file_data = file_object.read()
            rule_file = os.path.join('yararules', rule_file)

            if os.path.exists(rule_file):
                rules = yara.compile(rule_file)
                matches = rules.match(data=file_data)
                results = {'rows': [], 'columns': ['Rule', 'Offset', 'Data']}
                for match in matches:
                    for item in match.strings:
                        results['rows'].append([match.rule, item[0], string_clean_hex(item[2])])

            else:
                raise IOError("Unable to locate rule file: {0}".format(rule_file))

            if len(results['rows']) > 0:
                # Store the results in datastore
                store_data = {'file_id': file_id, 'yara': results}
                db.create_datastore(store_data)
            else:
                results = 'NoMatch'
            self.render_type = 'file'
            self.render_data = {'YaraScanner': {'yara_list': sorted(os.listdir('yararules')), 'yara_results': results}}

    def display(self):
        self.render_data = {'YaraScanner': {'yara_list': sorted(os.listdir('yararules')), 'yara_results': None}}
