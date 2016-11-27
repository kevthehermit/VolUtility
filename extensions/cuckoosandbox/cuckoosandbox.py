from web.common import Extension
from web.database import Database
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
        cuckoo_modified = self.config['cuckoo']['modified']
        cuckoo_host = self.config['cuckoo']['host']

        if cuckoo_modified == 'True':
            submit_file_url = '{0}/api/tasks/create/file/'.format(cuckoo_host)
        else:
            submit_file_url = '{0}/tasks/create/file'.format(cuckoo_host)

        params = {}
        if 'file_id' in self.request.POST:
            file_id = self.request.POST['file_id']

            file_object = db.get_filebyid(file_id)
            file_data = file_object.read()

            files = {'file': (file_object.filename, file_data)}

        if 'machine' in self.request.POST:
            if self.request.POST['machine'] != '':
                params['machine'] = self.request.POST['machine']

        if 'package' in self.request.POST:
            if self.request.POST['package'] != '':
                params['package'] = self.request.POST['package']

        if 'options' in self.request.POST:
            if self.request.POST['options'] != '':
                params['options'] = self.request.POST['options']
        submit_file = self.api_query('post', submit_file_url, files=files, params=params)
        response_json = submit_file.json()

        if 'error' in response_json and response_json['error']:
            rows = [['ID', 'Error', response_json['error_value'], '', '']]
        else:
            try:
                print "Task Submitted ID: {0}".format(response_json['task_id'])
                task_id = response_json['task_id']
            except KeyError:
                try:
                    print "Task Submitted ID: {0}".format(response_json['data']['task_ids'][0])
                    task_id = response_json['data']['task_ids'][0]
                except KeyError:
                    task_id = 0

            rows = [[task_id, 'Pending', 'Running', '', '{0}/analysis/{1}'.format(cuckoo_host, task_id)]]

        self.render_type = 'file'
        self.render_data = {'CuckooSandbox': {'machine_list': None, 'results': rows, 'file_id': file_id}}

    def display(self):
        db = Database()

        cuckoo_modified = self.config['cuckoo']['modified']
        cuckoo_host = self.config['cuckoo']['host']

        if cuckoo_modified == 'True':
            search_url = '{0}/api/tasks/search/sha256'.format(cuckoo_host)
            machine_url = '{0}/api/machines/list/'.format(cuckoo_host)
        else:
            search_url = '{0}/tasks/list'.format(cuckoo_host)
            machine_url = '{0}/machines/list'.format(cuckoo_host)

        # Get a list of machines from the API to populate a dropdown
        machine_list = []
        json_response = self.api_query('get', machine_url)

        if json_response:
            json_response = json_response.json()

            if cuckoo_modified == 'True':

                json_data = json_response['data']

            else:
                json_data = json_response['machines']


            for machine in json_data:

                machine_string = '{0}: {1}'.format(machine['name'], ','.join(machine['tags']))
                machine_dict = {'name': machine['name'], 'display': machine_string, 'label': machine['label']}
                machine_list.append(machine_dict)
        else:
            machine_list.append('Unable to connect to Cuckoo')

        file_id = rule_file = False
        if 'file_id' in self.request.POST:
            file_id = self.request.POST['file_id']
            file_object = db.get_filebyid(file_id)

            file_hash = file_object.sha256
        else:
            file_hash = 'None'

        # Check for existing Entry
        if cuckoo_modified == 'True':
            search_results = self.api_query('get',
                                            '{0}/{1}'.format(search_url, file_hash)).json()
            if search_results['data'] != "Sample not found in database":
                print "Found {0} Results".format(len(search_results['data']))
                rows = []
                for result in search_results['data']:
                    rows.append([result['id'],
                                 result['started_on'],
                                 result['status'],
                                 result['completed_on'],
                                 '{0}/analysis/{1}'.format(cuckoo_host, result['id'])
                                 ])
        else:
            search_results = self.api_query('get', search_url).json()
            count = 0
            rows = []
            if 'tasks' in search_results:
                for result in search_results['tasks']:
                    try:
                        if result['sample']['sha256'] == file_hash:
                            rows.append([result['id'], result['started_on'], result['status'], result['completed_on']])
                            count += 1
                    except:
                        pass

        self.render_type = 'file'
        self.render_data = {'CuckooSandbox': {'machine_list': machine_list, 'results': rows, 'file_id': file_id}}
