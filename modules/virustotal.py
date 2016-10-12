from bson.objectid import ObjectId
from web.common import Module
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

class VirusTotalModule(Module):

    '''Render type is one of error, file, html, json'''
    render_type = None
    render_data = None
    render_file = None

    def run(self, request):
        if not self.config.api_key or not VT_LIB:
            #logger.error('No Virustotal key provided in volutitliy.conf')
            #return HttpResponse("Unable to use Virus Total. No Key or Library Missing. Check the Console for details")
            self.render_type = 'error'
            self.render_data = "Unable to use Virus Total. No Key or Library Missing. Check the Console for details"

        if 'file_id' in request.POST:
            file_id = request.POST['file_id']

            file_object = self.db.get_filebyid(ObjectId(file_id))
            sha256 = file_object.sha256
            vt = PublicApi(self.config.api_key)

            if 'upload' in request.POST:
                response = vt.scan_file(file_object.read(), filename=file_object.filename, from_disk=False)
                if response['results']['response_code'] == 1 and 'Scan request successfully queued' in response['results']['verbose_msg']:
                    state = 'pending'
                else:
                    state = 'error'
                self.render_type = 'file'
                self.render_file = 'file_details_vt.html'
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
                    store_data = {'file_id': ObjectId(file_id), 'vt': vt_fields}
                    self.db.create_datastore(store_data)
                    state = 'complete'

                elif response['results']['response_code'] == -2:
                    # Still Pending
                    state = 'pending'

                elif response['results']['response_code'] == 0:
                    # Not present in data set prompt to uploads
                    state = 'missing'

                self.render_type = 'file'
                self.render_file = 'file_details_vt.html'
                self.render_data = {'state': state, 'vt_results': '', 'file_id': file_id}