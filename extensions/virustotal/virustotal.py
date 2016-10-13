from web.common import Extension
from web.database import Database
try:
    import virus_total_apis
    from virus_total_apis import PublicApi
    VT_LIB = True
    # Version check needs to be higher than 1.0.9
    vt_ver = virus_total_apis.__version__.split('.')
    if int(vt_ver[1]) < 1:
        VT_LIB = False
except ImportError:
    VT_LIB = False


class VirusTotalSearch(Extension):

    extension_name = 'VirusTotalSearch'
    extension_type = 'filedetails'
    template_name = 'virustotal/virustotal.html'

    def run(self):
        db = Database()
        #self.render_javascript = "function test(){  alert(1); }; test();"
        self.render_javascript = ""
        if not self.config.api_key or not VT_LIB:
            #logger.error('No Virustotal key provided in volutitliy.conf')
            #return HttpResponse("Unable to use Virus Total. No Key or Library Missing. Check the Console for details")
            self.render_type = 'error'
            self.render_data = "Unable to use Virus Total. No Key or Library Missing. Check the Console for details"

        if 'file_id' in self.request.POST:
            file_id = self.request.POST['file_id']

            file_object = db.get_filebyid(file_id)
            sha256 = file_object.sha256
            vt = PublicApi(self.config.api_key)

            if 'upload' in self.request.POST:
                response = vt.scan_file(file_object.read(), filename=file_object.filename, from_disk=False)
                if response['results']['response_code'] == 1 and 'Scan request successfully queued' in response['results']['verbose_msg']:
                    state = 'pending'
                else:
                    state = 'error'
                self.render_type = 'file'
                self.render_file = 'virustotal/virustotal.html'
                self.render_data = {'state': state, 'vt_results': '', 'file_id': file_id}

            else:

                response = vt.get_file_report(sha256)
                vt_fields = {}
                if response['results']['response_code'] == 1:
                    vt_fields['permalink'] = response['results']['permalink']
                    vt_fields['total'] = response['results']['total']
                    vt_fields['positives'] = response['results']['positives']
                    vt_fields['scandate'] = response['results']['scan_date']
                    vt_fields['scans'] = response['results']['scans']
                    # Store the results in datastore
                    store_data = {'file_id': file_id, 'vt': vt_fields}
                    db.create_datastore(store_data)
                    state = 'complete'

                elif response['results']['response_code'] == -2:
                    # Still Pending
                    state = 'pending'

                elif response['results']['response_code'] == 0:
                    # Not present in data set prompt to uploads
                    state = 'missing'

                self.render_type = 'file'
                self.render_file = 'file_details_vt.html'
                self.render_data = {'state': state, 'vt_results': vt_fields, 'file_id': file_id}


    def display(self):
        db = Database()
        file_id = self.request.POST['file_id']
        file_datastore = db.search_datastore({'file_id': file_id})
        vt_results = None
        state = 'Not Checked'
        for row in file_datastore:

            if 'vt' in row:
                vt_results = row['vt']
                state = 'complete'

        self.render_data = {'state': state, 'vt_results': vt_results, 'file_id': file_id}
