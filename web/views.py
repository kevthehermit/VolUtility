import re
import sys
from datetime import datetime
from web.common import *
import multiprocessing
from common import Config, checksum_md5
config = Config()

logger = logging.getLogger(__name__)

try:
    from bson.objectid import ObjectId
except ImportError:
    logger.error('Unable to import pymongo')

from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseServerError
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.views.decorators.csrf import csrf_exempt

try:
    from virus_total_apis import PublicApi
    VT_LIB = True
except ImportError:
    VT_LIB = False
    logger.warning("Unable to import VirusTotal API Library")

try:
    import yara
    YARA = True
except ImportError:
    YARA = False
    logger.warning("Unable to import Yara")

##
# Import The volatility Interface and DB Class
##
import vol_interface
from vol_interface import RunVol

try:
    from web.database import Database
    db = Database()
except Exception as e:
    logger.error("Unable to access mongo database: {0}".format(e))


##
# Page Views
##

def main_page(request, error_line=False):
    """
    Returns the main vol page
    :param request:
    :param error_line:
    :return:
    """

    # Check Vol Version

    try:
        vol_ver = vol_interface.vol_version.split('.')
        if int(vol_ver[1]) < 5:
            error_line = 'UNSUPPORTED VOLATILITY VERSION. REQUIRES 2.5 FOUND {0}'.format(vol_interface.vol_version)
    except Exception as error:
        error_line = 'Unable to find a volatility version'
        logger.error(error_line)

    # Set Pagination
    page = request.GET.get('page')
    if not page:
        page = 1
    page_count = request.GET.get('count')
    if not page_count:
        page_count = 30

    # Get All Sessions
    session_list = db.get_allsessions()

    # Paginate
    session_count = len(session_list)
    first_session = int(page) * int(page_count) - int(page_count) + 1
    last_session = int(page) * int(page_count)

    paginator = Paginator(session_list, page_count)

    try:
        sessions = paginator.page(page)
    except PageNotAnInteger:
        sessions = paginator.page(1)
    except EmptyPage:
        sessions = paginator.page(paginator.num_pages)

    # Show any extra loaded plugins
    plugin_dirs = []
    if os.path.exists(volrc_file):
        vol_conf = open(volrc_file, 'r').readlines()
        for line in vol_conf:
            if line.startswith('PLUGINS'):
                plugin_dirs = line.split(' = ')[-1]

    # Profile_list for add session
    RunVol('', '')
    profile_list = vol_interface.profile_list()

    return render(request, 'index.html', {'session_list': sessions,
                                          'session_counts': [session_count, first_session, last_session],
                                          'profile_list': profile_list,
                                          'plugin_dirs': plugin_dirs,
                                          'error_line': error_line
                                          })


def session_page(request, sess_id):
    """
    returns the seesion page thats used to run plugins
    :param request:
    :param sess_id:
    :return:
    """
    error_line = False

    # Check Vol Version
    if float(vol_interface.vol_version) < 2.5:
        error_line = 'UNSUPPORTED VOLATILITY VERSION. REQUIRES 2.5 FOUND {0}'.format(vol_interface.vol_version)

    # Get the session
    session_id = ObjectId(sess_id)
    session_details = db.get_session(session_id)
    comments = db.get_commentbysession(session_id)
    plugin_list = []
    yara_list = os.listdir('yararules')
    plugin_text = db.get_pluginbysession(ObjectId(sess_id))
    version_info = {'python': str(sys.version).split()[0],
                    'volatility': vol_interface.vol_version,
                    'volutility': volutility_version}

    # Check if file still exists

    if not os.path.exists(session_details['session_path']):
        error_line = 'Memory Image can not be found at {0}'.format(session_details['session_path'])


    return render(request, 'session.html', {'session_details': session_details,
                                            'plugin_list': plugin_list,
                                            'plugin_output': plugin_text,
                                            'comments': comments,
                                            'error_line': error_line,
                                            'version_info': version_info,
                                            'yara_list': yara_list})


def create_session(request):
    """
    post handler to create a new session
    :param request:
    :return:
    """
    # Get some vars
    new_session = {'created': datetime.now(), 'modified': datetime.now(), 'file_hash': 'Not Selected'}

    file_hash = False
    if 'sess_name' in request.POST:
        new_session['session_name'] = request.POST['sess_name']
    if 'sess_path' in request.POST:
        new_session['session_path'] = request.POST['sess_path']
    if 'description' in request.POST:
        new_session['session_description'] = request.POST['description']
    if 'plugin_path' in request.POST:
        new_session['plugin_path'] = request.POST['plugin_path']
    if 'file_hash' in request.POST:
        file_hash = True

    # Check for mem file
    if not os.path.exists(new_session['session_path']):
        logger.error('Unable to find an image file at {0}'.format(request.POST['sess_path']))
        return main_page(request, error_line='Unable to find an image file at {0}'.format(request.POST['sess_path']))

    # Generate FileHash (MD5 for now)
    if file_hash:
        logger.debug('Generating MD5 for Image')
        md5_hash = checksum_md5(new_session['session_path'])
        new_session['file_hash'] = md5_hash


    # Get a list of plugins we can use. and prepopulate the list.

    if 'profile' in request.POST:
        if request.POST['profile'] != 'AutoDetect':
            profile = request.POST['profile']
            new_session['session_profile'] = profile
        else:
            profile = None

    vol_int = RunVol(profile, new_session['session_path'])

    image_info = {}

    if not profile:
        logger.debug('AutoDetecting Profile')
        # kdbg scan to get a profile suggestion

        # Doesnt support json at the moment
        kdbg_results = vol_int.run_plugin('kdbgscan', output_style='text')

        lines = kdbg_results['rows'][0][0]

        profiles = []

        for line in lines.split('\n'):
            if 'Profile suggestion' in line:
                profiles.append(line.split(':')[1].strip())

        if len(profiles) == 0:
            logger.error('Unable to find a valid profile with kdbg scan')
            return main_page(request, error_line='Unable to find a valid profile with kdbg scan')

        profile = profiles[0]

        # Re initialize with correct profile
        vol_int = RunVol(profile, new_session['session_path'])

    # Get compatible plugins

    plugin_list = vol_int.list_plugins()

    new_session['session_profile'] = profile

    new_session['image_info'] = image_info

    # Plugin Options
    plugin_filters = vol_interface.plugin_filters

    # Store it
    session_id = db.create_session(new_session)

    # Autorun list from config
    if config.autorun:
        auto_list = config.plugins.split(',')
    else:
        auto_list = False

    # Merge Autorun from manual post with config
    if 'auto_run' in request.POST:
        run_list = request.POST['auto_run'].split(',')
        if not auto_list:
            auto_list = run_list
        else:
            for run in run_list:
                if run not in auto_list:
                    auto_list.append(run)

    # For each plugin create the entry
    for plugin in plugin_list:
        db_results = {}
        db_results['session_id'] = session_id
        plugin_name = plugin[0]
        db_results['plugin_name'] = plugin_name

        # Ignore plugins we cant handle
        if plugin_name in plugin_filters['drop']:
            continue

        db_results['help_string'] = plugin[1]
        db_results['created'] = None
        db_results['plugin_output'] = None
        db_results['status'] = None
        # Write to DB
        plugin_id = db.create_plugin(db_results)

        if auto_list:
            if plugin_name in auto_list:
                multiprocessing.Process(target=run_plugin, args=(session_id, plugin_id)).start()

    return redirect('/session/{0}'.format(str(session_id)))


def run_plugin(session_id, plugin_id, pid=None):
    """
    return the results json from a plugin
    :param session_id:
    :param plugin_id:
    :param pid:
    :return:
    """
    dump_dir = None
    error = None
    plugin_id = ObjectId(plugin_id)
    sess_id = ObjectId(session_id)
    if pid:
        pid = str(pid)

    if sess_id and plugin_id:
        # Get details from the session
        session = db.get_session(sess_id)
        # Get details from the plugin
        plugin_row = db.get_pluginbyid(ObjectId(plugin_id))

        plugin_name = plugin_row['plugin_name'].lower()

        logger.debug('Running Plugin: {0}'.format(plugin_name))

        # Set plugin status
        new_values = {'status': 'processing'}
        db.update_plugin(ObjectId(plugin_id), new_values)

        # set vol interface
        vol_int = RunVol(session['session_profile'], session['session_path'])

        # Run the plugin with json as normal
        output_style = 'json'
        try:
            results = vol_int.run_plugin(plugin_name, output_style=output_style, pid=pid)
        except Exception as error:
            results = False
            logger.error('Json Output error in {0} - {1}'.format(plugin_name, error))

        if 'unified output format has not been implemented' in str(error) or 'JSON output for trees' in str(error):
            output_style = 'text'
            try:
                results = vol_int.run_plugin(plugin_name, output_style=output_style, pid=pid)
                error = None
            except Exception as error:
                logger.error('Json Output error in {0}, {1}'.format(plugin_name, error))
                results = False


        # If we need a DumpDir
        if '--dump-dir' in str(error) or 'specify a dump directory' in str(error):
            # Create Temp Dir
            logger.debug('{0} - Creating Temp Directory'.format(plugin_name))
            temp_dir = tempfile.mkdtemp()
            dump_dir = temp_dir
            try:
                results = vol_int.run_plugin(plugin_name, dump_dir=dump_dir, output_style=output_style, pid=pid)
            except Exception as error:
                results = False
                # Set plugin status
                new_values = {'status': 'error'}
                db.update_plugin(ObjectId(plugin_id), new_values)
                logger.error('Error: Unable to run plugin {0} - {1}'.format(plugin_name, error))

        # Check for result set
        if not results:
            # Set plugin status
            new_values = {'status': 'completed'}
            db.update_plugin(ObjectId(plugin_id), new_values)
            return 'Warning: No output from Plugin {0}'.format(plugin_name)

        ##
        # Files that dump output to disk
        ##

        if dump_dir:
            file_list = os.listdir(temp_dir)
            '''
            I need to process the results and the items in the dump dir.

            Add Column for ObjectId

            Store the file in the GridFS get an ObjectId
            add the ObjectId to the rows, each has a differnet column format so this could be a pain.

            '''

            # Add Rows

            if plugin_row['plugin_name'] == 'dumpfiles':
                for row in results['rows']:
                    try:
                        filename = row[3]
                        file_data = row[-1].decode('hex')
                        sha256 = hashlib.sha256(file_data).hexdigest()
                        file_id = db.create_file(file_data, sess_id, sha256, filename)
                        row[-1] = '<a class="text-success" href="#" ' \
                                  'onclick="ajaxHandler(\'filedetails\', {\'file_id\':\'' + str(file_id) + '\'}, false ); return false">' \
                                  'File Details</a>'

                    except Exception as error:
                        row[-1] = 'Not Stored: {0}'.format(error)

            if plugin_row['plugin_name'] in ['procdump', 'dlldump']:
                # Add new column
                results['columns'].append('StoredFile')
                for row in results['rows']:
                    if row[-1].startswith("OK"):
                        filename = row[-1].split("OK: ")[-1]
                        if filename in file_list:
                            file_data = open(os.path.join(temp_dir, filename), 'rb').read()
                            sha256 = hashlib.sha256(file_data).hexdigest()
                            file_id = db.create_file(file_data, sess_id, sha256, filename)
                            row.append('<a class="text-success" href="#" '
                                  'onclick="ajaxHandler(\'filedetails\', {\'file_id\':\'' + str(file_id) + '\'}, false ); return false">'
                                  'File Details</a>')
                    else:
                        row.append('Not Stored')

            if plugin_row['plugin_name'] == 'dumpregistry':
                results = {}
                results['columns'] = ['Hive Name', 'StoredFile']
                results['rows'] = []
                for filename in file_list:
                    file_data = open(os.path.join(temp_dir, filename), 'rb').read()
                    sha256 = hashlib.sha256(file_data).hexdigest()
                    file_id = db.create_file(file_data, sess_id, sha256, filename)
                    results['rows'].append([filename, '<a class="text-success" href="#" '
                                  'onclick="ajaxHandler(\'filedetails\', {\'file_id\':\'' + str(file_id) + '\'}, false ); return false">'
                                  'File Details</a>'])

            if plugin_row['plugin_name'] in ['dumpcerts']:
                # Add new column
                for row in results['rows']:
                    filename = row[5]
                    if filename in file_list:
                        file_data = open(os.path.join(temp_dir, filename), 'rb').read()
                        sha256 = hashlib.sha256(file_data).hexdigest()
                        file_id = db.create_file(file_data, sess_id, sha256, filename)
                        row[-1] ='<a class="text-success" href="#" ' \
                              'onclick="ajaxHandler(\'filedetails\', {\'file_id\':\'' + str(file_id) + '\'}, false ); return false">' \
                              'File Details</a>'
                    else:
                        row.append('Not Stored')

            if plugin_row['plugin_name'] in ['memdump']:
                logger.debug('Processing Rows')
                # Convert text to rows
                if not plugin_row['plugin_output']:
                    new_results = {'rows': [], 'columns': ['Process', 'PID', 'StoredFile']}
                else:
                    new_results = plugin_row['plugin_output']
                base_output = results['rows'][0][0]
                base_output = base_output.lstrip('<pre>').rstrip('</pre>')
                for line in base_output.split('*'*72):
                    if '.dmp' not in line:
                        continue
                    row = line.split()
                    process = row[1]
                    dump_file = row[-1]
                    pid = dump_file.split('.')[0]

                    if dump_file not in file_list:
                        new_results['rows'].append([process, pid, 'Not Stored'])
                    else:
                        logger.debug('Store memdump file')
                        file_data = open(os.path.join(temp_dir, dump_file), 'rb').read()
                        sha256 = hashlib.sha256(file_data).hexdigest()
                        file_id = db.create_file(file_data, sess_id, sha256, dump_file)
                        row_file = '<a class="text-success" href="#" ' \
                              'onclick="ajaxHandler(\'filedetails\', {\'file_id\':\'' + str(file_id) + '\'}, false ); return false">' \
                              'File Details</a>'
                        new_results['rows'].append([process, pid, row_file])

                results = new_results




            # Remove the dumpdir
            shutil.rmtree(temp_dir)

        ##
        # Extra processing on some outputs
        ##

        # Add option to process hive keys
        if plugin_row['plugin_name'] in ['hivelist', 'hivescan']:
            results['columns'].insert(0, '#')
            results['columns'].append('Extract Keys')

            counter = 0
            for row in results['rows']:
                counter += 1
                row.insert(0, counter)

                ajax_string = "onclick=\"ajaxHandler('hivedetails', {'plugin_id':'" + str(plugin_id) + "', 'rowid':'" + str(counter) + "'}, true )\"; return false"
                row.append('<a class="text-success" href="#" ' + ajax_string + '>View Hive Keys</a>')


        # Image Info
        image_info = False
        if plugin_name == 'imageinfo':
            imageinfo_text = results['rows'][0][0]
            image_info = {}
            for line in imageinfo_text.split('\n'):
                try:
                    key, value = line.split(' : ')
                    image_info[key.strip()] = value.strip()
                except Exception as e:
                    print 'Error Getting imageinfo: {0}'.format(e)

        # update the plugin
        new_values = {}
        new_values['created'] = datetime.now()
        new_values['plugin_output'] = results
        new_values['status'] = 'completed'


        try:
            db.update_plugin(ObjectId(plugin_id), new_values)
            # Update the session
            new_sess = {}
            new_sess['modified'] = datetime.now()
            if image_info:
                new_sess['image_info'] = image_info
            db.update_session(sess_id, new_sess)

            return plugin_row['plugin_name']

        except Exception as error:
            # Set plugin status
            new_values = {'status': 'error'}
            db.update_plugin(ObjectId(plugin_id), new_values)
            logger.error('Error: Unable to Store Output for {0} - {1}'.format(plugin_name, error))
            return 'Error: Unable to Store Output for {0} - {1}'.format(plugin_name, error)


def file_download(request, query_type, object_id):
    """
    return a file from the gridfs by id
    :param request:
    :param query_type:
    :param object_id:
    :return:
    """

    if query_type == 'file':
        file_object = db.get_filebyid(ObjectId(object_id))
        file_name = '{0}.bin'.format(file_object.filename)
        file_data = file_object.read()

    if query_type == 'plugin':
        plugin_object = db.get_pluginbyid(ObjectId(object_id))

        file_name = '{0}.csv'.format(plugin_object['plugin_name'])
        plugin_data = plugin_object['plugin_output']

        file_data = ""
        file_data += ",".join(plugin_data['columns'])
        file_data += "\n"
        for row in plugin_data['rows']:
            for item in row:
                file_data += "{0},".format(item)
            file_data.rstrip(',')
            file_data += "\n"

    response = HttpResponse(file_data, content_type='application/octet-stream')
    response['Content-Disposition'] = 'attachment; filename="{0}"'.format(file_name)
    return response


@csrf_exempt
def ajax_handler(request, command):
    """
    return data requested by the ajax handler in volutility.js
    :param request:
    :param command:
    :return:
    """

    if command == 'pollplugins':
        if 'session_id' in request.POST:
            # Get Current Session
            session_id = request.POST['session_id']

            session = db.get_session(ObjectId(session_id))

            plugin_rows = db.get_pluginbysession(ObjectId(session_id))

            # Check for new registered plugins

            # Get compatible plugins


            profile = session['session_profile']

            session_path = session['session_path']

            vol_int = RunVol(profile, session_path)

            plugin_list = vol_int.list_plugins()


            # Plugin Options
            plugin_filters = vol_interface.plugin_filters
            refresh_rows = False
            existing_plugins = []
            for row in plugin_rows:
                existing_plugins.append(row['plugin_name'])

            # For each plugin create the entry
            for plugin in plugin_list:

                # Ignore plugins we cant handle
                if plugin[0] in plugin_filters['drop']:
                    continue

                if plugin[0] in existing_plugins:
                    continue

                else:
                    print plugin[0]
                    db_results = {}
                    db_results['session_id'] = ObjectId(session_id)
                    db_results['plugin_name'] = plugin[0]
                    db_results['help_string'] = plugin[1]
                    db_results['created'] = None
                    db_results['plugin_output'] = None
                    db_results['status'] = None
                    # Write to DB
                    db.create_plugin(db_results)
                    refresh_rows = True

            if refresh_rows:
                plugin_rows = db.get_pluginbysession(ObjectId(session_id))

            return render(request, 'plugin_poll.html', {'plugin_output': plugin_rows})
        else:
            return HttpResponseServerError

    if command == 'dropplugin':
        if 'plugin_id' in request.POST:
            plugin_id = request.POST['plugin_id']
            # update the plugin
            new_values = {'created': None,'plugin_output': None, 'status': None}
            db.update_plugin(ObjectId(plugin_id), new_values)
            return HttpResponse('OK')

    if command == 'runplugin':
        if 'plugin_id' in request.POST and 'session_id' in request.POST:
            plugin_name = run_plugin(request.POST['session_id'], request.POST['plugin_id'])
            return HttpResponse(plugin_name)

    if command == 'plugin_dir':

        # Platform PATH seperator
        seperator = ':'
        if sys.platform.startswith('win'):
            seperator = ';'

        # Set Plugins
        if 'plugin_dir' in request.POST:
            plugin_dir = request.POST['plugin_dir']

            if os.path.exists(volrc_file):
                with open(volrc_file, 'a') as out:
                    output = '{0}{1}'.format(seperator, plugin_dir)
                    out.write(output)
                return HttpResponse(' No Plugin Path Provided')
            else:
                # Create new file.
                with open(volrc_file, 'w') as out:
                    output = '[DEFAULT]\nPLUGINS = {0}'.format(plugin_dir)
                    out.write(output)
                return HttpResponse(' No Plugin Path Provided')
        else:
            return HttpResponse(' No Plugin Path Provided')

    if command == 'filedetails':
        if 'file_id' in request.POST:
            file_id = request.POST['file_id']
            file_object = db.get_filebyid(ObjectId(file_id))
            file_datastore = db.search_datastore({'file_id': ObjectId(file_id)})
            file_meta = {'vt': None, 'string_list': None, 'yara': None }
            for row in file_datastore:

                if 'vt' in row:
                    file_meta['vt'] = row['vt']
                if 'string_list' in row:
                    file_meta['string_list'] = row['string_list']
                if 'yara' in row:
                    file_meta['yara'] = row['yara']

            # New String Store
            new_strings = db.get_strings(file_id)
            if new_strings:
                file_meta['string_list'] = new_strings._id
            else:
                file_meta['string_list'] = False

            yara_list = os.listdir('yararules')
            return render(request, 'file_details.html', {'file_details': file_object,
                                                         'file_id': file_id,
                                                         'file_datastore': file_meta,
                                                         'yara_list': yara_list
                                                         })

    if command == 'hivedetails':
        if 'plugin_id' and 'rowid' in request.POST:
            pluginid = request.POST['plugin_id']
            rowid = request.POST['rowid']

            plugin_details = db.get_pluginbyid(ObjectId(pluginid))

            key_name = 'hive_keys_{0}'.format(rowid)

            if key_name in plugin_details:
                hive_details = plugin_details[key_name]
            else:
                session_id = plugin_details['session_id']

                session = db.get_session(session_id)

                plugin_data = plugin_details['plugin_output']

                for row in plugin_data['rows']:
                    if str(row[0]) == rowid:
                        hive_offset = str(row[1])

                # Run the plugin
                vol_int = RunVol(session['session_profile'], session['session_path'])
                hive_details = vol_int.run_plugin('hivedump', hive_offset=hive_offset)

                # update the plugin / session
                new_values = {key_name: hive_details}
                db.update_plugin(ObjectId(ObjectId(pluginid)), new_values)
                # Update the session
                new_sess = {}
                new_sess['modified'] = datetime.now()
                db.update_session(session_id, new_sess)

            return render(request, 'hive_details.html', {'hive_details': hive_details})

    if command == 'dottree':
        session_id = request.POST['session_id']
        session = db.get_session(ObjectId(session_id))
        vol_int = RunVol(session['session_profile'], session['session_path'])
        results = vol_int.run_plugin('pstree', output_style='dot')
        return HttpResponse(results)

    if command == 'timeline':
        logger.debug('Running Timeline')
        session_id = request.POST['session_id']
        session = db.get_session(ObjectId(session_id))
        vol_int = RunVol(session['session_profile'], session['session_path'])
        results = vol_int.run_plugin('timeliner', output_style='dot')
        return HttpResponse(results)

    if command == 'virustotal':
        if not config.api_key or not VT_LIB:
            logger.error('No Virustotal key provided in volutitliy.conf')
            return HttpResponse("Unable to use Virus Total. No Key or Library Missing. Check the Console for details")

        if 'file_id' in request.POST:
            file_id = request.POST['file_id']

            file_object = db.get_filebyid(ObjectId(file_id))
            sha256 = file_object.sha256
            vt = PublicApi(config.api_key)
            response = vt.get_file_report(sha256)

            vt_fields = {}

            if response['results']['response_code'] == 1:
                vt_fields['permalink'] = response['results']['permalink']
                vt_fields['total'] = response['results']['total']
                vt_fields['positives'] = response['results']['positives']
                vt_fields['scandate'] = response['results']['scan_date']

                # Store the results in datastore
                store_data = {}
                store_data['file_id'] = ObjectId(file_id)
                store_data['vt'] = vt_fields

                update = db.create_datastore(store_data)

            return render(request, 'file_details_vt.html', {'vt_results': vt_fields})

    if command == 'yara-string':

        session_id = request.POST['session_id']

        if request.POST['yara-string'] != '':
            yara_string = request.POST['yara-string']
        else:
            yara_string = False

        if request.POST['yara-pid'] != '':
            yara_pid = request.POST['yara-pid']
        else:
            yara_pid = None

        if request.POST['yara-file'] != '':
            yara_file = os.path.join('yararules', request.POST['yara-file'])

        yara_hex = request.POST['yara-hex']
        if yara_hex != '':
            yara_hex = int(yara_hex)
        else:
            yara_hex = 256

        yara_reverse = request.POST['yara-reverse']
        if yara_reverse != '':
            yara_reverse = int(yara_reverse)
        else:
            yara_reverse = 0

        yara_case = request.POST['yara-case']
        if yara_case == 'true':
            yara_case = True
        else:
            yara_case = None

        yara_kernel = request.POST['yara-kernel']
        if yara_kernel == 'true':
            yara_kernel = True
        else:
            yara_kernel = None

        yara_wide = request.POST['yara-wide']
        if yara_wide == 'true':
            yara_wide = True
        else:
            yara_wide = None

        logger.debug('Yara String Scanner')

        try:
            session = db.get_session(ObjectId(session_id))
            vol_int = RunVol(session['session_profile'], session['session_path'])

            if yara_string:
                results = vol_int.run_plugin('yarascan', output_style='json', pid=yara_pid, plugin_options={'YARA_RULES': yara_string,
                                                                                          'CASE': yara_case,
                                                                                          'ALL': yara_kernel,
                                                                                          'WIDE': yara_wide,
                                                                                          'SIZE': yara_hex,
                                                                                          'REVERSE': yara_reverse})

            elif yara_file:
                results = vol_int.run_plugin('yarascan', output_style='json', pid=yara_pid, plugin_options={'YARA_FILE': yara_file,
                                                                                          'CASE': yara_case,
                                                                                          'ALL': yara_kernel,
                                                                                          'WIDE': yara_wide,
                                                                                          'SIZE': yara_hex,
                                                                                          'REVERSE': yara_reverse})

            else:
                return



            if 'Data' in results['columns']:
                row_loc = results['columns'].index('Data')

                for row in results['rows']:
                    try:
                        row[row_loc] = string_clean_hex(row[row_loc].decode('hex'))
                    except Exception as e:
                        logger.warning('Error converting hex to str: {0}'.format(e))


            return render(request, 'plugin_output_nohtml.html', {'plugin_results': results,
                                                          'plugin_id': None,
                                                          'bookmarks': []})
            #return HttpResponse(results)
        except Exception as error:
            logger.error(error)

    if command == 'yara':
        file_id = rule_file = False
        if 'file_id' in request.POST:
            file_id = request.POST['file_id']

        if 'rule_file' in request.POST:
            rule_file = request.POST['rule_file']

        if rule_file and file_id and YARA:
            file_object = db.get_filebyid(ObjectId(file_id))
            file_data = file_object.read()

            rule_file = os.path.join('yararules', rule_file)

            if os.path.exists(rule_file):
                rules = yara.compile(rule_file)
                matches = rules.match(data=file_data)
                results = []
                for match in matches:
                    for item in match.strings:
                        results.append({'rule': match.rule, 'offset': item[0], 'string': string_clean_hex(item[2])})

            else:
                return render(request, 'file_details_yara.html', {'yara': None, 'error': 'Could not find Rule File'})

            if len(results) > 0:

                # Store the results in datastore
                store_data = {}
                store_data['file_id'] = ObjectId(file_id)
                store_data['yara'] = results

                update = db.create_datastore(store_data)

            return render(request, 'file_details_yara.html', {'yara': results})

        else:
            return HttpResponse('Either No file ID or No Yara Rule was provided')

    if command == 'strings':
        if 'file_id' in request.POST:
            file_id = request.POST['file_id']
            file_object = db.get_filebyid(ObjectId(file_id))
            file_data = file_object.read()

            chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
            shortest_run = 4

            regexp = '[%s]{%d,}' % (chars, shortest_run)
            pattern = re.compile(regexp)

            string_list = pattern.findall(file_data)


            #regexp = '[\x20\x30-\x39\x41-\x5a\x61-\x7a\-\.:]{4,}'
            #string_list = re.findall(regexp, file_data)
            logger.debug('Joining Strings')
            string_list = '\n'.join(string_list)

            '''
            String lists can get larger than the 16Mb bson limit
            Need to store in GridFS
            '''
            # Store the list in datastore
            store_data = {}
            store_data['file_id'] = ObjectId(file_id)
            store_data['string_list'] = string_list
            logger.debug('Store Strings in DB')

            string_id = db.create_file(string_list, 'session_id', 'sha256', '{0}_strings.txt'.format(file_id))
            # Write to DB
            #db.create_datastore(store_data)

            return HttpResponse('<td><a class="btn btn-success" role="button" href="/download/file/{0}">Download</a></td>'.format(string_id))

    if command == 'dropsession':
        if 'session_id' in request.POST:
            session_id = ObjectId(request.POST['session_id'])
            db.drop_session(session_id)
            return HttpResponse('OK')

    if command == 'memhex':
        if 'session_id' in request.POST:
            session_id = ObjectId(request.POST['session_id'])
            session = db.get_session(session_id)
            mem_path = session['session_path']
            if 'start_offset' and 'end_offset' in request.POST:
                try:
                    start_offset = int(request.POST['start_offset'], 0)
                    end_offset = int(request.POST['end_offset'], 0)
                    hex_cmd = 'hexdump -C -s {0} -n {1} {2}'.format(start_offset, end_offset - start_offset, mem_path)
                    hex_output = hex_dump(hex_cmd)
                    return HttpResponse(hex_output)
                except Exception as e:
                    return HttpResponse(e)

    if command == 'memhexdump':
        if 'session_id' in request.POST:
            session_id = ObjectId(request.POST['session_id'])
            session = db.get_session(session_id)
            mem_path = session['session_path']
            if 'start_offset' and 'end_offset' in request.POST:
                try:
                    start_offset = int(request.POST['start_offset'], 0)
                    end_offset = int(request.POST['end_offset'], 0)
                    mem_file = open(mem_path, 'rb')
                    # Get to start
                    mem_file.seek(start_offset)
                    file_data = mem_file.read(end_offset - start_offset)
                    response = HttpResponse(file_data, content_type='application/octet-stream')
                    response['Content-Disposition'] = 'attachment; filename="{0}-{1}.bin"'.format(start_offset, end_offset)
                    return response
                except Exception as e:
                    logger.error('Error Getting hex dump: {0}'.format(e))

    if command == 'addcomment':
        html_resp = ''
        if 'session_id' and 'comment_text' in request.POST:
            session_id = request.POST['session_id']
            comment_text = request.POST['comment_text']
            comment_data = {'session_id': ObjectId(session_id), 'comment_text': comment_text, 'date_added': datetime.now()}
            db.create_comment(comment_data)

            # now return all the comments for the ajax update

            for comment in db.get_commentbysession(ObjectId(session_id)):
                html_resp += '<pre>{0}</pre>'.format(comment['comment_text'])

        return HttpResponse(html_resp)

    if command == 'searchbar':
        if 'search_type' and 'search_text' and 'session_id' in request.POST:
            search_type = request.POST['search_type']
            search_text = request.POST['search_text']
            session_id = request.POST['session_id']

            logger.debug('{0} search for {1}'.format(search_type, search_text))

            if search_type == 'plugin':
                results = {'rows':[]}
                results['columns'] = ['Plugin Name', 'View Results']
                rows = db.search_plugins(search_text, session_id=ObjectId(session_id))
                for row in rows:
                    results['rows'].append([row['plugin_name'], '<a href="#" onclick="ajaxHandler(\'pluginresults\', {{\'plugin_id\':\'{0}\'}}, false ); return false">View Output</a>'.format(row['_id'])])
                return render(request, 'plugin_output.html', {'plugin_results': results})

            if search_type == 'hash':
                pass
            if search_type == 'string':
                logger.debug('yarascan for string')
                # If search string ends with .yar assume a yara rule
                if any(ext in search_text for ext in ['.yar', '.yara']):
                    if os.path.exists(search_text):
                        try:
                            session = db.get_session(ObjectId(session_id))
                            vol_int = RunVol(session['session_profile'], session['session_path'])
                            results = vol_int.run_plugin('yarascan', output_style='json', plugin_options={'YARA_FILE': search_text})
                            return render(request, 'plugin_output_nohtml.html', {'plugin_results': results})
                        except Exception as error:
                            logger.error(error)
                    else:
                        logger.error('No Yara Rule Found')
                else:
                    try:
                        session = db.get_session(ObjectId(session_id))
                        vol_int = RunVol(session['session_profile'], session['session_path'])
                        results = vol_int.run_plugin('yarascan', output_style='json', plugin_options={'YARA_RULES': search_text})
                        return render(request, 'plugin_output_nohtml.html', {'plugin_results': results})
                    except Exception as error:
                        logger.error(error)

            if search_type == 'registry':

                logger.debug('Registry Search')
                try:
                    session = db.get_session(ObjectId(session_id))
                    vol_int = RunVol(session['session_profile'], session['session_path'])
                    results = vol_int.run_plugin('printkey', output_style='json', plugin_options={'KEY': search_text})
                    return render(request, 'plugin_output.html', {'plugin_results': results})
                except Exception as error:
                    logger.error(error)

            if search_type == 'vol':
                # Run a vol command and get the output

                vol_output = getoutput('vol.py {0}'.format(search_text))

                results = {'rows': [['<pre>{0}</pre>'.format(vol_output)]], 'columns': ['Volitlity Raw Output']}

                # Consider storing the output here as well.


                return render(request, 'plugin_output.html', {'plugin_results': results})

            return HttpResponse('No valid search query found.')

    if command == 'pluginresults':
        if 'plugin_id' in request.POST:
            plugin_id = ObjectId(request.POST['plugin_id'])
            plugin_id = ObjectId(plugin_id)
            plugin_results = db.get_pluginbyid(plugin_id)

            try:
                bookmarks = db.get_pluginbyid(plugin_id)['bookmarks']
            except:
                bookmarks = []

            return render(request, 'plugin_output.html', {'plugin_results': plugin_results['plugin_output'],
                                                          'plugin_id': plugin_id,
                                                          'bookmarks': bookmarks,
                                                          'plugin_name': plugin_results['plugin_name']})

    if command == 'bookmark':
        if 'row_id' in request.POST:
            plugin_id, row_id = request.POST['row_id'].split('_')
            plugin_id = ObjectId(plugin_id)
            row_id = int(row_id)
            # Get Bookmarks for plugin
            try:
                bookmarks = db.get_pluginbyid(plugin_id)['bookmarks']
            except:
                bookmarks = []
            # Update bookmarks
            if row_id in bookmarks:
                bookmarks.remove(row_id)
                bookmarked = 'remove'
            else:
                bookmarks.append(row_id)
                bookmarked = 'add'

            # Update Plugins
            new_values = {'bookmarks': bookmarks}
            db.update_plugin(ObjectId(plugin_id), new_values)
            return HttpResponse(bookmarked)

    if command == 'procmem':
        if 'row_id' in request.POST and 'session_id' in request.POST:
            plugin_id, row_id = request.POST['row_id'].split('_')
            session_id = request.POST['session_id']
            plugin_id = ObjectId(plugin_id)
            row_id = int(row_id)
            plugin_data = db.get_pluginbyid(ObjectId(plugin_id))['plugin_output']
            row = plugin_data['rows'][row_id - 1]
            pid = row[2]

            plugin_row = db.get_plugin_byname('memdump', ObjectId(session_id))

            logger.debug('Running Plugin: memdump with pid {0}'.format(pid))

            res = run_plugin(session_id, plugin_row['_id'], pid=pid)
            return HttpResponse(res)

    return HttpResponse('No valid search query found.')
