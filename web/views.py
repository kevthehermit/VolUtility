import re
import sys
import json
from datetime import datetime
from web.common import *
import multiprocessing
import tempfile
from common import parse_config, checksum_md5
from web.modules import __extensions__

config = parse_config()
logger = logging.getLogger(__name__)

from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse, HttpResponseServerError, StreamingHttpResponse
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

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


def session_creation(request, mem_image, session_id):

    if config['auth']['enable'] == 'True' and not request.user.is_authenticated:
        return HttpResponse('Auth Required.')

    # Get some vars
    new_session = db.get_session(session_id)
    file_hash = False
    if 'description' in request.POST:
        new_session['session_description'] = request.POST['description']
    if 'plugin_path' in request.POST:
        new_session['plugin_path'] = request.POST['plugin_path']
    if 'file_hash' in request.POST:
        file_hash = True
    # Check for mem file
    if not os.path.exists(mem_image):
        logger.error('Unable to find an image file at {0}'.format(mem_image))
        new_session['status'] = 'Unable to find an image file at {0}'.format(request.POST['sess_path'])
        return
    new_session['session_path'] = mem_image
    # Generate FileHash (MD5 for now)
    if file_hash:
        logger.debug('Generating MD5 for Image')
        # Update the status
        new_session['status'] = 'Calculating MD5'
        db.update_session(session_id, new_session)
        md5_hash = checksum_md5(new_session['session_path'])
        new_session['file_hash'] = md5_hash

    # Get a list of plugins we can use. and prepopulate the list.
    if 'profile' in request.POST:
        if request.POST['profile'] != 'AutoDetect':
            profile = request.POST['profile']
            new_session['session_profile'] = profile
        else:
            profile = None
    else:
        profile = None

    vol_int = RunVol(profile, new_session['session_path'])
    image_info = {}
    if not profile:
        logger.debug('AutoDetecting Profile')
        # kdbg scan to get a profile suggestion
        # Update the status
        new_session['status'] = 'Detecting Profile'
        db.update_session(session_id, new_session)
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
    # Update Session
    new_session['status'] = 'Complete'
    db.update_session(session_id, new_session)
    # Autorun list from config
    if config['autorun']['enable'] == 'True':
        auto_list = config['autorun']['plugins'].split(',')
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
        plugin_name = plugin[0]
        db_results = {'session_id': session_id, 'plugin_name': plugin_name}
        # Ignore plugins we cant handle
        if plugin_name in plugin_filters['drop']:
            continue
        plugin_output = plugin_status = None
        # Create placeholders for dumpfiles and memdump
        if plugin_name == 'dumpfiles':
            plugin_output = {'columns': ['Offset', 'File Name', 'Image Type', 'StoredFile'], 'rows': []}
            plugin_status = 'complete'
        elif plugin_name == 'memdump':
            plugin_output = {'columns': ['Process', 'PID', 'StoredFile'], 'rows': []}
            plugin_status = 'complete'
        db_results['help_string'] = plugin[1]
        db_results['created'] = None
        db_results['plugin_output'] = plugin_output
        db_results['status'] = plugin_status
        # Write to DB
        plugin_id = db.create_plugin(db_results)

        if auto_list:
            if plugin_name in auto_list:
                multiprocessing.Process(target=run_plugin, args=(session_id, plugin_id)).start()


##
# Page Views
##
def main_page(request, error_line=None):
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


    if config['auth']['enable'] == 'True' and not request.user.is_authenticated:
        return HttpResponse('Auth Required.')


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

def session_page(request, session_id):
    """
    returns the session page thats used to run plugins
    :param request:
    :param session_id:
    :return:
    """

    if config['auth']['enable'] == 'True' and not request.user.is_authenticated:
        return HttpResponse('Auth Required.')

    error_line = False
    includes = []

    # Check Vol Version
    if float(vol_interface.vol_version) < 2.5:
        error_line = 'UNSUPPORTED VOLATILITY VERSION. REQUIRES 2.5 FOUND {0}'.format(vol_interface.vol_version)

    # Get the session
    session_details = db.get_session(session_id)
    comments = db.get_commentbysession(session_id)
    extra_search = db.search_files({'file_meta': 'ExtraFile', 'session_id': session_id})
    extra_files = []
    for upload in extra_search:
        extra_files.append({'filename': upload.filename, 'file_id': upload._id})
    plugin_list = []
    yara_list = os.listdir('yararules')
    plugin_text = db.get_pluginbysession(session_id)
    version_info = {'python': str(sys.version).split()[0],
                    'volatility': vol_interface.vol_version,
                    'volutility': volutility_version}
    # Check if file still exists
    if not os.path.exists(session_details['session_path']):
        error_line = 'Memory Image can not be found at {0}'.format(session_details['session_path'])

    return render(request, 'session.html', {'includes': includes,
                                            'session_details': session_details,
                                            'plugin_list': plugin_list,
                                            'plugin_output': plugin_text,
                                            'comments': comments,
                                            'error_line': error_line,
                                            'version_info': version_info,
                                            'yara_list': yara_list,
                                            'extra_files': extra_files})


def create_session(request):
    """
    post handler to create a new session
    :param request:
    :return:
    """

    if config['auth']['enable'] == 'True' and not request.user.is_authenticated:
        return HttpResponse('Auth Required.')

    if 'process_dir' in request.POST:
        recursive_dir = True
    else:
        recursive_dir = False
    dir_listing = []
    if 'sess_path' not in request.POST:
        logger.error('No path or file selected')
        return main_page(request, error_line='No path or file selected')
    if recursive_dir:
        for root, subdir, filename in os.walk(request.POST['sess_path']):
            for name in filename:
                # ToDo: Add extension check
                extensions = ['.bin', '.mem', '.img', '.001', '.raw', '.dmp', '.vmem']
                for ext in extensions:
                    if name.lower().endswith(ext):
                        dir_listing.append(os.path.join(root, name))
    else:
        dir_listing.append(request.POST['sess_path'])
    for mem_image in dir_listing:
        # Create session in DB and set to pending
        new_session = {'created': datetime.now(),
                       'modified': datetime.now(),
                       'file_hash': 'Not Selected',
                       'status': 'Processing',
                       'session_profile': request.POST['profile']
                       }
        if 'sess_name' in request.POST:
            new_session['session_name'] = '{0} ({1})'.format(request.POST['sess_name'], mem_image.split('/')[-1])
        else:
            new_session['session_name'] = mem_image.split('/')[-1]
        # Store it
        session_id = db.create_session(new_session)
        # Run the multiprocessing
        p = multiprocessing.Process(target=session_creation, args=(request, mem_image, session_id)).start()
        # Add search all on main page filter sessions that match.
    return redirect('/')


def run_plugin(session_id, plugin_id, pid=None, plugin_options=None):
    """
    return the results json from a plugin
    :param session_id:
    :param plugin_id:
    :param pid:
    :param plugin_options:
    :return:
    """

    def try_run(plugin_name, dump_dir=None, output_style=None, pid=None, plugin_options=None):
        global plugin_style
        plugin_style = output_style
        logger.debug("Testing: {0}".format(plugin_style))
        try:
            results = vol_int.run_plugin(plugin_name,
                                         dump_dir=dump_dir,
                                         output_style=plugin_style,
                                         pid=pid,
                                         plugin_options=plugin_options
                                         )

            return [results, dump_dir]

        except Exception as error:
            logger.error('{0}'.format(error))
            if 'unified output format has not been implemented' in str(error) or 'JSON output for trees' in str(error):
                plugin_style = 'text'
                return try_run(plugin_name, dump_dir=dump_dir, output_style='text', pid=pid, plugin_options=plugin_options)

            elif '--dump-dir' in str(error) or 'specify a dump directory' in str(error):
                # Create Temp Dir
                logger.debug('{0} - Creating Temp Directory'.format(plugin_name))
                temp_dir = tempfile.mkdtemp()
                dump_dir = temp_dir
                return try_run(plugin_name, dump_dir=dump_dir, output_style=output_style, pid=pid, plugin_options=plugin_options)

            else:
                results = {'error': error}
                return [results, None]

    dump_dir = None
    error = None
    if pid:
        pid = str(pid)

    if session_id and plugin_id:
        # Get details from the session
        session = db.get_session(session_id)
        # Get details from the plugin
        plugin_row = db.get_pluginbyid(plugin_id)
        plugin_name = plugin_row['plugin_name'].lower()
        logger.debug('Running Plugin: {0}'.format(plugin_name))
        # Set plugin status
        new_values = {'status': 'processing'}
        db.update_plugin(plugin_id, new_values)
        # set vol interface
        vol_int = RunVol(session['session_profile'], session['session_path'])
        # Run the plugin with json as normal
        output_style = 'json'

        plugin_return = try_run(plugin_name,
                                    dump_dir=dump_dir,
                                    output_style='json',
                                    pid=pid,
                                    plugin_options=plugin_options
                                    )

        results = plugin_return[0]
        dump_dir = plugin_return[1]

        if 'error' in results:
            new_values = {'status': 'error'}
            db.update_plugin(plugin_id, new_values)
            logger.error('Error: Unable to run plugin {0} - {1}'.format(plugin_name, results['error']))
            return 'Error: Unable to Store Output for {0} - {1}'.format(plugin_name, results['error'])


        ##
        # Files that dump output to disk
        ##
        if dump_dir:
            file_list = os.listdir(dump_dir)
            '''
            I need to process the results and the items in the dump dir.

            Add Column for ObjectId

            Store the file in the GridFS get an ObjectId
            add the ObjectId to the rows, each has a differnet column format so this could be a pain.

            '''

            # Add Rows

            if plugin_row['plugin_name'] == 'dumpfiles':
                if not plugin_row['plugin_output']:
                    results = {'columns': ['Offset', 'File Name', 'Image Type', 'StoredFile'], 'rows': []}
                else:
                    results = plugin_row['plugin_output']

                for filename in file_list:
                    if filename.endswith('img'):
                        img_type = 'ImageSectionObject'
                    elif filename.endswith('dat'):
                        img_type = 'DataSectionObject'
                    elif filename.endswith('vacb'):
                        img_type = 'SharedCacheMap'
                    else:
                        img_type = 'N/A'
                    file_data = open(os.path.join(dump_dir, filename), 'rb').read()
                    sha256 = hashlib.sha256(file_data).hexdigest()
                    # ToDo:
                    # MIME type
                    # SSDEEP
                    # Header Bytes
                    file_id = db.create_file(file_data, session_id, sha256, filename)
                    results['rows'].append([plugin_options['PHYSOFFSET'],
                                            filename,
                                            img_type,
                                            '<a class="text-success" href="#" '
                                            'onclick="ajaxHandler(\'filedetails\', {\'file_id\':\'' +
                                            str(file_id) + '\'}, false ); return false">'
                                            'File Details</a>'])
                # Set plugin status to complete
                new_values = {'status': 'complete'}
                db.update_plugin(plugin_id, new_values)

            if plugin_row['plugin_name'] in ['procdump', 'dlldump']:
                # Add new column
                results['columns'].append('StoredFile')
                for row in results['rows']:
                    if row[-1].startswith("OK"):
                        filename = row[-1].split("OK: ")[-1]
                        if filename in file_list:
                            file_data = open(os.path.join(dump_dir, filename), 'rb').read()
                            sha256 = hashlib.sha256(file_data).hexdigest()
                            file_id = db.create_file(file_data, session_id, sha256, filename)
                            row.append('<a class="text-success" href="#" '
                                       'onclick="ajaxHandler(\'filedetails\', {\'file_id\':\'' + str(file_id) +
                                       '\'}, false ); return false">'
                                       'File Details</a>')
                    else:
                        row.append('Not Stored')

            if plugin_row['plugin_name'] == 'dumpregistry':
                results = {'columns': ['Hive Name', 'StoredFile'], 'rows': []}
                for filename in file_list:
                    file_data = open(os.path.join(dump_dir, filename), 'rb').read()
                    sha256 = hashlib.sha256(file_data).hexdigest()
                    file_id = db.create_file(file_data, session_id, sha256, filename)
                    results['rows'].append([filename,
                                            '<a class="text-success" href="#" '
                                            'onclick="ajaxHandler(\'filedetails\', {\'file_id\':\'' + str(file_id) +
                                            '\'}, false ); return false">'
                                            'File Details</a>'])

            if plugin_row['plugin_name'] in ['dumpcerts']:
                # Add new column
                for row in results['rows']:
                    filename = row[5]
                    if filename in file_list:
                        file_data = open(os.path.join(dump_dir, filename), 'rb').read()
                        sha256 = hashlib.sha256(file_data).hexdigest()
                        file_id = db.create_file(file_data, session_id, sha256, filename)
                        row[-1] = '<a class="text-success" href="#" ' \
                                  'onclick="ajaxHandler(\'filedetails\', {\'file_id\':\'' + \
                                  str(file_id) + '\'}, false ); return false">' \
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
                        file_data = open(os.path.join(dump_dir, dump_file), 'rb').read()
                        sha256 = hashlib.sha256(file_data).hexdigest()
                        file_id = db.create_file(file_data, session_id, sha256, dump_file)
                        row_file = '<a class="text-success" href="#" ' \
                                   'onclick="ajaxHandler(\'filedetails\', {\'file_id\':\'' + str(file_id) + \
                                   '\'}, false ); return false">' \
                                   'File Details</a>'
                        new_results['rows'].append([process, pid, row_file])

                results = new_results

            # ToDo
            '''
            if plugin_row['plugin_name'] in ['malfind']:
                logger.debug('Processing Rows')
                # Convert text to rows
                new_results = plugin_row['plugin_output']

                if len(file_list) == 0:
                    new_results['rows'].append([process, pid, 'Not Stored'])
                else:
                    for dump_file in file_list:
                        logger.debug('Store memdump file')
                        file_data = open(os.path.join(temp_dir, dump_file), 'rb').read()
                        sha256 = hashlib.sha256(file_data).hexdigest()
                        file_id = db.create_file(file_data, session_id, sha256, dump_file)
                        row_file = '<a class="text-success" href="#" ' \
                              'onclick="ajaxHandler(\'filedetails\', {\'file_id\':\'' + str(file_id) + '\'}, false ); return false">' \
                              'File Details</a>'
                        new_results['rows'].append([process, pid, row_file])

                results = new_results
            '''

            # Remove the dumpdir
            shutil.rmtree(dump_dir)

        ##
        # Extra processing output
        # Do everything in one loop to save time
        ##


        if results:
            # Start Counting
            counter = 1

            # Columns

            # Add Row ID Column
            if results['columns'][0] != '#':
                results['columns'].insert(0, '#')

            # Add option to process hive keys
            if plugin_row['plugin_name'] in ['hivelist', 'hivescan']:
                results['columns'].append('Extract Keys')

            # Add option to process malfind
            if plugin_row['plugin_name'] in ['malfind']:
                results['columns'].append('Extract Injected Code')

            # Now Rows
            for row in results['rows']:
                # Add Row ID
                if plugin_name == 'memdump':
                    if len(row) == 3:
                        row.insert(0, counter)
                elif plugin_name in ['dumpfiles', 'mac_dump_files']:
                    if len(row) == 4:
                        row.insert(0, counter)
                else:
                    row.insert(0, counter)

                if plugin_row['plugin_name'] in ['hivelist', 'hivescan']:
                    row.append('Use the "dumpregistry" plugin to view hive keys')

                # Add option to process malfind
                if plugin_row['plugin_name'] in ['malfind']:
                    ajax_string = "onclick=\"ajaxHandler('malfind_export', {'plugin_id':'" + str(plugin_id) + \
                                  "', 'rowid':'" + str(counter) + "'}, true )\"; return false"
                    row.append('<a class="text-success" href="#" ' + ajax_string + '>Extract Injected</a>')

                counter += 1

        # Image Info

        image_info = False
        if plugin_name == 'imageinfo':
            imageinfo_text = results['rows'][0][1]
            image_info = {}
            for line in imageinfo_text.split('\n'):
                try:
                    key, value = line.split(' : ')
                    image_info[key.strip()] = value.strip()
                except Exception as error:
                    print 'Error Getting imageinfo: {0}'.format(error)

        # update the plugin
        new_values = {'created': datetime.now(), 'plugin_output': results, 'status': 'completed'}

        try:
            db.update_plugin(plugin_id, new_values)
            # Update the session
            new_sess = {'modifed': datetime.now()}
            if image_info:
                new_sess['image_info'] = image_info
            db.update_session(session_id, new_sess)

            return plugin_row['plugin_name']

        except Exception as error:
            # Set plugin status
            new_values = {'status': 'error'}
            db.update_plugin(plugin_id, new_values)
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

    if config['auth']['enable'] == 'True' and not request.user.is_authenticated:
        return HttpResponse('Auth Required.')

    if query_type == 'file':
        file_object = db.get_filebyid(object_id)
        file_name = '{0}.bin'.format(file_object.filename)
        response = StreamingHttpResponse((chunk for chunk in file_object), content_type='application/octet-stream')
        response['Content-Disposition'] = 'attachment; filename="{0}"'.format(file_name)
        return response

    if query_type == 'plugin':
        plugin_object = db.get_pluginbyid(object_id)

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
def addfiles(request):

    if config['auth']['enable'] == 'True' and not request.user.is_authenticated:
        return HttpResponse('Auth Required.')

    if 'session_id' not in request.POST:
        logger.warning('No Session ID in POST')
        return HttpResponseServerError

    session_id = request.POST['session_id']

    for upload in request.FILES.getlist('files[]'):
        logger.debug('Storing File: {0}'.format(upload.name))
        file_data = upload.read()
        sha256 = hashlib.sha256(file_data).hexdigest()

        # Store file in GridFS
        db.create_file(file_data, session_id, sha256, upload.name, pid=None, file_meta='ExtraFile')

    # Return the new list
    extra_search = db.search_files({'file_meta': 'ExtraFile', 'sess_id': session_id})
    extra_files = []
    for upload in extra_search:
        extra_files.append({'filename': upload.filename, 'file_id': upload._id})

    return render(request, 'file_upload_table.html', {'extra_files': extra_files})


@csrf_exempt
def ajax_handler(request, command):
    """
    return data requested by the ajax handler in volutility.js
    :param request:
    :param command:
    :return:
    """

    if config['auth']['enable'] == 'True' and not request.user.is_authenticated:
        return HttpResponse('Auth Required.')

    if command in __extensions__:
        extension = __extensions__[command]['obj']()
        extension.set_request(request)
        extension.set_config(config)
        extension.run()
        if extension.render_type == 'file':
            template_name = '{0}/template.html'.format(extension.extension_name.lower())
            rendered_data = render(extension.request, template_name, extension.render_data)
            if rendered_data.status_code == 200:
                return_data = rendered_data.content
            else:
                return_data = str(rendered_data.status_code)
        else:
            return_data = extension.render_data
        json_response = {'data': return_data, 'javascript': extension.render_javascript}
        return JsonResponse(json_response, safe=False)

    if command == 'pollplugins':
        if 'session_id' in request.POST:
            # Get Current Session
            session_id = request.POST['session_id']
            session = db.get_session(session_id)
            plugin_rows = db.get_pluginbysession(session_id)
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
                    print "Adding Plugin", plugin
                    db_results = {'session_id': session_id,
                                  'plugin_name': plugin[0],
                                  'help_string': plugin[1],
                                  'created': None,
                                  'plugin_output': None,
                                  'status': None}
                    # Write to DB
                    db.create_plugin(db_results)
                    refresh_rows = True

            if refresh_rows:
                plugin_rows = db.get_pluginbysession(session_id)

            return render(request, 'plugin_poll.html', {'plugin_output': plugin_rows})
        else:
            return HttpResponseServerError

    if command == 'filtersessions':
        matching_sessions = []
        if ('pluginname' and 'searchterm') in request.POST:
            pluginname = request.POST['pluginname']
            searchterm = request.POST['searchterm']
            results = db.search_plugins(searchterm, plugin_name=pluginname)
            for row in results:
                matching_sessions.append(str(row))
        json_response = json.dumps(matching_sessions)

        return JsonResponse(matching_sessions, safe=False)

    if command == 'dropplugin':
        if 'plugin_id' in request.POST:
            plugin_id = request.POST['plugin_id']
            # update the plugin
            new_values = {'created': None, 'plugin_output': None, 'status': None}
            db.update_plugin(plugin_id, new_values)
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
        if 'session_id' in request.POST:
            session_id = request.POST['session_id']
            session_details = db.get_session(session_id)

        if 'file_id' in request.POST:
            file_id = request.POST['file_id']
            file_object = db.get_filebyid(file_id)

            includes = []
            response_dict = {'file_details': file_object,
                             'file_id': file_id,
                             'error': None,
                             'session_details': session_details,
                             'includes': includes
                             }

            # Register any extension templates
            for extension in __extensions__:
                if __extensions__[extension]['obj'].extension_type == 'filedetails':
                    extension_name = __extensions__[extension]['obj'].extension_name
                    template_name = '{0}/template.html'.format(extension_name.lower())
                    try:
                        includes.append([template_name, extension_name])

                        ext = __extensions__[extension]['obj']()
                        ext.set_request(request)
                        ext.set_config(config)
                        # This contains the rendered HTML
                        ext.display()
                        response_dict[extension_name] = ext.render_data[extension_name]
                    except Exception as e:
                        logger.error('Error getting data from extension: {0} - {1}'.format(extension_name, e))
                        pass

            return render(request, 'file_details.html', response_dict)

    if command == 'vaddot':
        session_id = request.POST['session_id']
        pid = request.POST['pid']
        # Check for existing Map
        dotvad = db.search_datastore({'session_id': session_id})
        if len(dotvad) > 0:
            if 'dotvad' in dotvad[0]:
                return HttpResponse(dotvad[0]['dotvad'])

        # Else Generate and store
        session = db.get_session(session_id)
        vol_int = RunVol(session['session_profile'], session['session_path'])
        results = vol_int.run_plugin('vadtree', output_style='dot', pid=pid)

        # Configure the output for svg with D3 and digraph-d3

        digraph = ''
        for line in results.split('\n'):

            # For each colour:
            if 'fillcolor = "yellow"' in line:
                # Mapped Files
                fillcolor = 'yellow'
                replace = True

            elif 'fillcolor = "red"' in line:
                # heaps
                fillcolor = 'red'
                replace = True

            elif 'fillcolor = "gray"' in line:
                # DLL
                fillcolor = 'gray'
                replace = True

            elif 'fillcolor = "green"' in line:
                # Stacks
                fillcolor = 'green'
                replace = True

            elif 'fillcolor = "white"' in line:
                # Stacks
                fillcolor = 'white'
                replace = True

            else:
                replace = False

            if replace:
                line = re.sub('"shape(.*)"];', '"style="fill: {0}; font-weight: bold"];'.format(fillcolor), line)
                digraph += '{0}\n'.format(line)
            else:
                digraph += '{0}\n'.format(line)

        return HttpResponse(digraph)

    if command == 'dottree':
        session_id = request.POST['session_id']
        # Check for existing Map
        dottree = db.search_datastore({'session_id': session_id})
        if len(dottree) > 0:
            if 'dottree' in dottree[0]:
                return HttpResponse(dottree[0]['dottree'])

        # Else Generate and store
        session = db.get_session(session_id)
        vol_int = RunVol(session['session_profile'], session['session_path'])
        results = vol_int.run_plugin('pstree', output_style='dot')

        # Configure the output for svg with D3 and digraph-d3

        digraph = ''
        for line in results.split('\n'):
            if line.startswith('  #'):
                pass
            elif line.startswith('  node[shape'):
                digraph += '{0}\n'.format('  node [labelStyle="font: 300 20px \'Helvetica Neue\', Helvetica"]')
            elif 'label="{' in line:
                # Format each node
                node_block = re.search('\[label="{(.*)}"\]', line)
                node_text = node_block.group(1)
                elements = node_text.split('|')
                label_style = '<table> \
                                <tbody> \
                                <tr><td>Name</td><td>|Name|</td></tr> \
                                <tr><td>PID</td><td>|Pid|</td></tr> \
                                <tr><td>PPID</td><td>|PPid|</td></tr> \
                                <tr><td>Offfset</td><td>|Offset|</td></tr> \
                                <tr><td>Threads</td><td>|Thds|</td></tr> \
                                <tr><td>Handles</td><td>|Hnds|</td></tr> \
                                <tr><td>Time</td><td>|Time|</td></tr> \
                                </tbody> \
                                </table>'

                for elem in elements:
                    key, value = elem.split(':', 1)
                    label_style = label_style.replace('|{0}|'.format(key), value)

                line = line.replace('label="', 'labelType="html" label="')
                line = line.replace('{'+node_text+'}', label_style)
                digraph += '{0}\n'.format(line)

            else:
                digraph += '{0}\n'.format(line)

        # Store the results in datastore
        store_data = {'session_id': session_id,
                      'dottree': digraph}
        db.create_datastore(store_data)

        return HttpResponse(digraph)

    if command == 'timeline':
        logger.debug('Running Timeline')
        session_id = request.POST['session_id']
        session = db.get_session(session_id)
        vol_int = RunVol(session['session_profile'], session['session_path'])
        results = vol_int.run_plugin('timeliner', output_style='dot')

        # Configure the output for svg with D3 and digraph-d3

        digraph = ''
        for line in results.split('\n'):
            if line.startswith('  #'):
                pass
            elif line.startswith('  node[shape'):
                digraph += '{0}\n'.format('  node [labelStyle="font: 300 20px \'Helvetica Neue\', Helvetica"]')
            elif 'label="{' in line:
                # Format each node
                node_block = re.search('\[label="{(.*)}"\]', line)
                node_text = node_block.group(1)
                elements = node_text.split('|')

                label_style = '<table> \
                                <tbody> \
                                <tr><td>Start</td><td>|Start|</td></tr> \
                                <tr><td>Header</td><td>|Header|</td></tr> \
                                <tr><td>Item</td><td>|Item|</td></tr> \
                                <tr><td>Details</td><td>|Details|</td></tr> \
                                <tr><td>End</td><td>|End|</td></tr> \
                                </tbody> \
                                </table>'

                for elem in elements:
                    key, value = elem.split(':', 1)
                    label_style = label_style.replace('|{0}|'.format(key), value)

                line = line.replace('label="', 'labelType="html" label="')
                line = line.replace('{'+node_text+'}', label_style)
                digraph += '{0}\n'.format(line)

            else:
                digraph += '{0}\n'.format(line)

        return HttpResponse(results)

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
        else:
            yara_file = None

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
            session = db.get_session(session_id)
            vol_int = RunVol(session['session_profile'], session['session_path'])

            if yara_string:
                results = vol_int.run_plugin('yarascan', output_style='json', pid=yara_pid, plugin_options={
                                                                                          'YARA_RULES': yara_string,
                                                                                          'CASE': yara_case,
                                                                                          'ALL': yara_kernel,
                                                                                          'WIDE': yara_wide,
                                                                                          'SIZE': yara_hex,
                                                                                          'REVERSE': yara_reverse})

            elif yara_file:
                results = vol_int.run_plugin('yarascan', output_style='json', pid=yara_pid, plugin_options={
                                                                                          'YARA_FILE': yara_file,
                                                                                          'CASE': yara_case,
                                                                                          'ALL': yara_kernel,
                                                                                          'WIDE': yara_wide,
                                                                                          'SIZE': yara_hex,
                                                                                          'REVERSE': yara_reverse})
            else:
                print "Not sure what to do here"
                return

            if 'Data' in results['columns']:
                row_loc = results['columns'].index('Data')

                for row in results['rows']:
                    try:
                        row[row_loc] = string_clean_hex(row[row_loc].decode('hex'))
                    except Exception as error:
                        logger.warning('Error converting hex to str: {0}'.format(error))

            return render(request, 'render_yara.html', {'yara': results, 'error': None})

        except Exception as error:
            logger.error(error)
            return HttpResponse('Error: {0}'.format(error))

    if command == 'deleteobject':
        if 'droptype' in request.POST:
            drop_type = request.POST['droptype']

        if 'session_id' in request.POST:
            session_id = request.POST['session_id']

        if drop_type == 'session' and session_id:
            session_id = request.POST['session_id']
            db.drop_session(session_id)
            return HttpResponse('OK')

        if 'file_id' in request.POST and drop_type == 'dumpfiles':

            plugin_id = request.POST['plugin_id']
            file_id = request.POST['file_id']
            plugin_details = db.get_pluginbyid(plugin_id)

            new_rows = []
            for row in plugin_details['plugin_output']['rows']:
                if str(file_id) in str(row):
                    pass
                else:
                    new_rows.append(row)
            plugin_details['plugin_output']['rows'] = new_rows

            # Drop file
            db.drop_file(file_id)

            # Update plugin
            db.update_plugin(plugin_id, plugin_details)

            return HttpResponse('OK')

    if command == 'memhex':
        if 'session_id' in request.POST:
            session_id = request.POST['session_id']
            session = db.get_session(session_id)
            mem_path = session['session_path']
            if 'start_offset' and 'end_offset' in request.POST:
                try:
                    start_offset = int(request.POST['start_offset'], 0)
                    end_offset = int(request.POST['end_offset'], 0)
                    hex_cmd = 'hexdump -C -s {0} -n {1} {2}'.format(start_offset, end_offset - start_offset, mem_path)
                    hex_output = hex_dump(hex_cmd)
                    return HttpResponse(hex_output)
                except Exception as error:
                    return HttpResponse(error)

    if command == 'memhexdump':
        if 'session_id' in request.POST:
            session_id = request.POST['session_id']
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
                    response['Content-Disposition'] = 'attachment; filename="{0}-{1}.bin"'.format(start_offset,
                                                                                                  end_offset)
                    return response
                except Exception as error:
                    logger.error('Error Getting hex dump: {0}'.format(error))

    if command == 'addcomment':
        html_resp = ''
        if 'session_id' and 'comment_text' in request.POST:
            session_id = request.POST['session_id']
            comment_text = request.POST['comment_text']
            comment_data = {'session_id': session_id,
                            'comment_text': comment_text,
                            'date_added': datetime.now()}
            db.create_comment(comment_data)

            # now return all the comments for the ajax update

            for comment in db.get_commentbysession(session_id):
                html_resp += '<pre>{0}</pre>'.format(comment['comment_text'])

        return HttpResponse(html_resp)

    if command == 'searchbar':
        if 'search_type' and 'search_text' and 'session_id' in request.POST:
            search_type = request.POST['search_type']
            search_text = request.POST['search_text']
            session_id = request.POST['session_id']

            logger.debug('{0} search for {1}'.format(search_type, search_text))

            if search_type == 'dumpfiles':
                regex = request.POST['search_text']
                session_id = request.POST['session_id']
                if regex and session_id:

                    plugin_row = db.get_plugin_byname('dumpfiles', session_id)

                    logger.debug('Running Plugin: dumpfiles with regex {0}'.format(regex))

                    res = run_plugin(session_id, plugin_row['_id'], plugin_options={'PHYSOFFSET': None,
                                                                                    'NAME': True,
                                                                                    'REGEX': regex,
                                                                                    'UNSAFE': True})
                    return HttpResponse(res)

            if search_type == 'plugin':
                results = {'columns': ['Plugin Name', 'View Results'], 'rows': []}
                rows = db.search_plugins(search_text, session_id=session_id)
                for row in rows:
                    results['rows'].append([row['plugin_name'], '<a href="#" onclick="ajaxHandler(\'pluginresults\', \{{\'plugin_id\':\'{0}\'}}, false ); return false">View Output</a>'.format(row['_id'])])
                return render(request, 'plugin_output.html', {'plugin_results': results,
                                                              'bookmarks': [],
                                                              'plugin_id': 'None',
                                                              'plugin_name': 'Search Results',
                                                              'resultcount': len(results['rows'])})

            if search_type == 'hash':
                pass

            if search_type == 'registry':
                logger.debug('Registry Search')
                try:
                    session = db.get_session(session_id)
                    vol_int = RunVol(session['session_profile'], session['session_path'])
                    results = vol_int.run_plugin('printkey', output_style='json', plugin_options={'KEY': search_text})
                    return render(request, 'plugin_output.html', {'plugin_results': results,
                                                                  'bookmarks': [],
                                                                  'plugin_id': 'None',
                                                                  'plugin_name': 'Registry Search',
                                                                  'resultcount': len(results['rows'])})
                except Exception as error:
                    logger.error(error)

            if search_type == 'vol':
                # Run a vol command and get the output
                session = db.get_session(session_id)
                search_text = search_text.replace('%profile%', '--profile={0}'.format(session['session_profile']))
                search_text = search_text.replace('%path%', '-f {0}'.format(session['session_path']))

                vol_output = getoutput('vol.py {0}'.format(search_text))

                results = {'rows': [['<pre>{0}</pre>'.format(vol_output)]], 'columns': ['Volatility Raw Output']}

                # Consider storing the output here as well.

                return render(request, 'plugin_output.html', {'plugin_results': results,
                                                              'bookmarks': [],
                                                              'plugin_id': 'None',
                                                              'plugin_name': 'Volatility Command Line',
                                                              'resultcount': len(results['rows'])})

            return HttpResponse('No valid search query found.')

    if command == 'pluginresults':
        if 'start' in request.POST:
            start = int(request.POST['start'])
        else:
            start = 0

        if 'length' in request.POST:
            length = int(request.POST['length'])
        else:
            length = 25

        if 'plugin_id' in request.POST:
            plugin_id = request.POST['plugin_id']
            plugin_results = db.get_pluginbyid(plugin_id)
            output = plugin_results['plugin_output']['rows']
            resultcount = len(plugin_results['plugin_output']['rows'])

            # Get Bookmarks
            try:
                bookmarks = db.get_pluginbyid(plugin_id)['bookmarks']
            except:
                bookmarks = []

        else:
            return JsonResponse({'error': 'No Plugin ID'})

        # Extensions Here
        final_javascript = ''
        for extension in __extensions__:
            if __extensions__[extension]['obj'].extension_type == 'postprocess':
                extension = __extensions__[extension]['obj']()
                extension.set_request(request)
                extension.set_config(config)
                extension.set_plugin_results(plugin_results)
                extension.run()
                if extension.render_data:
                    output = extension.render_data['plugin_output']['rows']
                    final_javascript += '\n\n{0}'.format(extension.render_javascript)

        # If we are paging with datatables
        if 'pagination' in request.POST:
            paged_data = []

            # Searching
            if 'search[value]' in request.POST:
                search_term = request.POST['search[value]']
                # output = [r for r in output if search_term.lower() in r]
                output = filter(lambda x: search_term.lower() in str(x).lower(), output)
            else:
                output = []

            # Column Sort
            col_index = int(request.POST['order[0][column]'])
            if request.POST['order[0][dir]'] == 'asc':
                direction = False
            else:
                direction = True

            # Test column data for correct sort
            try:
                output = sorted(output, key=lambda x: int(x[col_index]), reverse=direction)
            except:
                output = sorted(output, key=lambda x: str(x[col_index]).lower(), reverse=direction)

            # Get number of Rows
            for row in output[start:start+length]:
                paged_data.append(row)

            datatables = {
                "draw": int(request.POST['draw']),
                "recordsTotal": resultcount,
                "recordsFiltered": len(output),
                "data": paged_data
            }

            return_data = datatables

        # Else return standard 25 rows
        else:
            plugin_results['plugin_output']['rows'] = plugin_results['plugin_output']['rows'][start:length]
            rendered_data = render(request, 'plugin_output.html', {'plugin_results': plugin_results['plugin_output'],
                                                          'plugin_id': plugin_id,
                                                          'bookmarks': bookmarks,
                                                          'resultcount': resultcount,
                                                          'plugin_name': plugin_results['plugin_name']})
            if rendered_data.status_code == 200:
                return_data = rendered_data.content
            else:
                return_data = str(rendered_data.status_code)

        json_response = {'data': return_data, 'javascript': final_javascript}

        return JsonResponse(json_response, safe=False)

    if command == 'bookmark':
        if 'row_id' in request.POST:
            plugin_id, row_id = request.POST['row_id'].split('_')
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
            db.update_plugin(plugin_id, new_values)
            return HttpResponse(bookmarked)

    if command == 'procmem':
        if 'row_id' in request.POST and 'session_id' in request.POST:
            plugin_id, row_id = request.POST['row_id'].split('_')
            session_id = request.POST['session_id']
            row_id = int(row_id)
            plugin_data = db.get_pluginbyid(plugin_id)['plugin_output']
            row = plugin_data['rows'][row_id - 1]
            pid = row[3]

            plugin_row = db.get_plugin_byname('memdump', session_id)

            logger.debug('Running Plugin: memdump with pid {0}'.format(pid))

            res = run_plugin(session_id, plugin_row['_id'], pid=pid)
            return HttpResponse(res)

    if command == 'filedump':
        if 'row_id' in request.POST and 'session_id' in request.POST:
            plugin_id, row_id = request.POST['row_id'].split('_')
            session_id = request.POST['session_id']
            row_id = int(row_id)
            plugin_data = db.get_pluginbyid(plugin_id)['plugin_output']
            row = plugin_data['rows'][row_id - 1]
            offset = row[1]

            plugin_row = db.get_plugin_byname('dumpfiles', session_id)

            logger.debug('Running Plugin: dumpfiles with offset {0}'.format(offset))

            res = run_plugin(session_id, plugin_row['_id'], plugin_options={'PHYSOFFSET': str(offset),
                                                                            'NAME': True,
                                                                            'REGEX': None,
                                                                            'UNSAFE': True})
            return HttpResponse(res)

    if command == 'linux_find_file':
        if 'row_id' in request.POST and 'session_id' in request.POST:
            plugin_id, row_id = request.POST['row_id'].split('_')
            session_id = request.POST['session_id']
            row_id = int(row_id)
            plugin_data = db.get_pluginbyid(plugin_id)['plugin_output']

            row = plugin_data['rows'][row_id - 1]

            print "Base Row: ", row

            inode = row[1]

            print "Inode: ", inode

            temp_dir = tempfile.mkdtemp()
            dump_dir = temp_dir

            filename = row[-1].split('/')[-1]

            outfile = os.path.join(temp_dir, filename)

            print "Outfile", outfile


            results_plugin = db.get_plugin_byname('linux_find_file', session_id)

            if not results_plugin['plugin_output']:
                results = {'columns': ['Inode Address', 'Inode Number', 'Path', 'StoredFile'], 'rows': []}
            else:
                results = results_plugin['plugin_output']

            logger.debug('Running Plugin: linux_find_file with inode {0}'.format(inode))

            res = run_plugin(session_id, results_plugin['_id'], plugin_options={'INODE': int(inode, 0), 'OUTFILE': outfile})


            print "Checking for file"

            if os.path.exists(outfile):
                file_data = open(outfile, 'rb').read()
                print "FileData: ", file_data[:5]
                sha256 = hashlib.sha256(file_data).hexdigest()
                file_id = db.create_file(file_data, session_id, sha256, filename)
                row.append('<a class="text-success" href="#" '
                           'onclick="ajaxHandler(\'filedetails\', {\'file_id\':\'' + str(file_id) +
                           '\'}, false ); return false">'
                           'File Details</a>')
            else:
                row.append('Not Stored')
                print "Not Found"


            results['rows'].append(row[1:])

            # update the plugin
            new_values = {'created': datetime.now(), 'plugin_output': results, 'status': 'completed'}

            db.update_plugin(results_plugin['_id'], new_values)


            # Remove the dumpdir
            shutil.rmtree(temp_dir)



            return HttpResponse("200 OK")

    return HttpResponse('No valid search query found.')
