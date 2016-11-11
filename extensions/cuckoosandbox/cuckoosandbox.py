from web.common import Extension, string_clean_hex
from web.database import Database
import os
import requests


class CuckooSandbox(Extension):

    extension_name = 'CuckooSandbox'
    extension_type = 'filedetails'


    def api_query(self, api_method, api_uri, files=None, params=None):
        response = None
        if files:
            try:
                response = requests.post(api_uri, files=files, data=params)

            except requests.ConnectionError:
                print "Unable to connect to Cuckoo API at '{0}'.".format(api_uri)
                return
            except Exception as e:
                print "Failed performing request at '{0}': {1}".format(api_uri, e)
                return

        if not files and api_method == 'post':
            # POST to API
            return

        if not files and api_method == 'get':
            # GET from API
            try:
                response = requests.get(api_uri)
            except requests.ConnectionError:
                print "Unable to connect to Cuckoo API at '{0}'.".format(api_uri)
                return
            except Exception as e:
                print "Failed performing request at '{0}': {1}".format(api_uri, e)
                return
        if response and response.status_code == 200:
            return response
        else:
            print "Failed to retrieve Object HTTP Status Code: {0}".format(response.status_code)


    def run(self):
        db = Database()
        # Get correct API URIS

        cuckoo_modified = self.config.cuckoo_modified
        cuckoo_host = self.config.cuckoo_host

        if cuckoo_modified:
            search_url = '{0}/api/tasks/search/sha256'.format(cuckoo_host)
            submit_file_url = '{0}/api/tasks/create/file/'.format(cuckoo_host)
            status_url = '{0}/api/cuckoo/status'.format(cuckoo_host)
            machine_url = '{0}/api/machines/list/'.format(cuckoo_host)
        else:
            search_url = '{0}/tasks/list'.format(cuckoo_host)
            submit_file_url = '{0}/tasks/create/file'.format(cuckoo_host)
            status_url = '{0}/cuckoo/status'.format(cuckoo_host)
            machine_url = '{0}/api/machines/list/'.format(cuckoo_host)


        params = {}
        file_id = rule_file = False
        if 'file_id' in self.request.POST:
            file_id = self.request.POST['file_id']

            file_object = db.get_filebyid(file_id)
            file_data = file_object.read()

            files = {'file': {file_object.filename, file_data}}

        if 'machine' in self.request.POST:
            params['machine'] = self.request.POST['machine']

        if 'package' in self.request.POST:
            params['package'] = self.request.POST['package']

        if 'options' in self.request.POST:
            params['options'] = self.request.POST['options']

        submit_file = self.api_query('post', submit_file_url, files=files, params=params).json()

        try:
            print "Task Submitted ID: {0}".format(submit_file['task_id'])
        except KeyError:
            try:
                print "Task Submitted ID: {0}".format(submit_file['task_ids'][0])
            except KeyError:
                print submit_file

        self.render_type = 'file'
        self.render_data = {'CuckooSandbox': {'machine_list': None}}

    def display(self):

        cuckoo_modified = self.config.cuckoo_modified
        cuckoo_host = self.config.cuckoo_host

        if cuckoo_modified:
            search_url = '{0}/api/tasks/search/sha256'.format(cuckoo_host)
            submit_file_url = '{0}/api/tasks/create/file/'.format(cuckoo_host)
            status_url = '{0}/api/cuckoo/status'.format(cuckoo_host)
            machine_url = '{0}/api/machines/list/'.format(cuckoo_host)
        else:
            search_url = '{0}/tasks/list'.format(cuckoo_host)
            submit_file_url = '{0}/tasks/create/file'.format(cuckoo_host)
            status_url = '{0}/cuckoo/status'.format(cuckoo_host)
            machine_url = '{0}/api/machines/list/'.format(cuckoo_host)

        # Get a list of machines from the API to populate a dropdown
        machine_list = []
        json_response = self.api_query('get', machine_url)
        if json_response:
            json_response = json_response.json()

            json_data = json_response['data']

            for machine in json_data:

                machine_string = '{0}: {1}'.format(machine['name'], ','.join(machine['tags']))
                machine_dict = {'name': machine['name'], 'display': machine_string}
                machine_list.append(machine_dict)
        else:
            machine_list.append('Unable to connect to Cuckoo')


        # Get any matching files in the dataset
        file_hash = 'd0f83f8b55c8990858a775d94a15c018'
        file_hash = '0ce826f59270141457351ff85eb6a7cecd324d42cbb0c2f7550bca880718ffe3'

        # Check for existing Session
        if cuckoo_modified:
            search_results = self.api_query('get',
                                            '{0}/{1}'.format(search_url, file_hash)).json()
            if search_results['data'] != "Sample not found in database":
                print "Found {0} Results".format(len(search_results['data']))
                rows = []
                header = ['ID', 'Started On', 'Status', 'Completed On']
                for result in search_results['data']:
                    rows.append([result['id'], result['started_on'], result['status'], result['completed_on'], '{0}/analysis/{1}'.format(cuckoo_host, result['id'])])
                print "use -r, --resubmit to force a new analysis"
        else:
            search_results = self.api_query('get', search_url).json()
            count = 0
            if 'tasks' in search_results:
                rows = []
                header = ['ID', 'Started On', 'Status', 'Completed On']
                for result in search_results['tasks']:
                    try:
                        if result['sample']['sha256'] == file_hash:
                            rows.append([result['id'], result['started_on'], result['status'], result['completed_on']])
                            count += 1
                    except:
                        pass


        print rows

        self.render_type = 'file'
        self.render_data = {'CuckooSandbox': {'machine_list': machine_list, 'results': rows}}
