import os
import urllib
import json
import string
from web.common import Extension
from web.database import Database
from Registry import Registry

class HiveViewer(Extension):

    # Paths should be relative to the extensions folder
    extension_name = 'HiveViewer'
    extension_type = 'filedetails'
    extra_js = 'hiveviewer/hiveviewer.js'

    def reg_sub_keys(self, key):
        sub_keys = []

        for subkey in key.subkeys():
            sub_keys.append(subkey)

        return sub_keys

    def reg_key_values(self, key):
        key_values = []
        for value in [v for v in key.values()
                      if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:
            key_values.append([value.name(), value.value()])
        return key_values

    def display(self):
        self.render_data = {'HiveViewer': None}

    def run(self):
        db = Database()
        # https://github.com/williballenthin/python-registry
        file_id = self.request.POST['file_id']
        key_request = urllib.unquote(self.request.POST['key'])
        reg_data = db.get_filebyid(file_id)
        reg = Registry.Registry(reg_data)

        if key_request == 'root':
            key = reg.root()

        else:
            try:
                key = reg.open(key_request)
            except Registry.RegistryKeyNotFoundException:
                # Check for values
                key = False

        if key:
            # Get the Parent
            try:
                parent_path = "\\".join(key.parent().path().strip("\\").split('\\')[1:])
                print key.parent().path()
            except Registry.RegistryKeyHasNoParentException:
                parent_path = None


            json_response = {'parent_key': parent_path}

            # Get Sub Keys
            child_keys = []
            for sub in self.reg_sub_keys(key):
                sub_path = "\\".join(sub.path().strip("\\").split('\\')[1:])
                child_keys.append(sub_path)

            # Get Values
            key_values = []
            for value in key.values():

                val_name = value.name()
                val_type = value.value_type_str()
                val_value = value.value()

                # Replace Unicode Chars
                try:
                    val_value = val_value.replace('\x00', ' ')
                except AttributeError:
                    pass

                # Convert Bin to Hex chars

                if val_type == 'RegBin' and all(c in string.printable for c in val_value) == False:
                    val_value = val_value.encode('hex')

                if val_type == 'RegNone' and all(c in string.printable for c in val_value) == False:
                    val_value = val_value.encode('hex')

                # Assemble and send
                key_values.append([val_name, val_type, val_value])

                # print val_type, val_value

            json_response['child_keys'] = child_keys
            json_response['key_values'] = key_values

            json_response = json.dumps(json_response)


        self.render_type = 'json'
        self.render_data = json_response
        self.render_javascript = open(os.path.join('extensions', self.extra_js), 'rb').read()
