import re
import sys
import os
import contextlib
import tempfile
import shutil
import hashlib
import string
from datetime import datetime

import logging
logger = logging.getLogger(__name__)

try:
    from subprocess import getoutput
except ImportError:
    from commands import getoutput

try:
    from bson.objectid import ObjectId
except ImportError:
    logger.error('Unable to import pymongo')
    sys.exit()

from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseServerError
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.views.decorators.csrf import csrf_exempt

try:
    from virus_total_apis import PublicApi
    VT_LIB = True
except ImportError:
    VT_LIB = False
    logger.error("Unable to import API Library")

try:
    import yara
    YARA = True
except ImportError:
    YARA = False
    logger.error("Unable to import Yara")

try:
    from vt_key import API_KEY
    VT_KEY = True
except ImportError:
    VT_KEY = False
    logger.error("Unable to import API Key from vt_key.py")

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
# Helpers
##

volutility_version = '0.1'

volrc_file = os.path.join(os.path.expanduser('~'), '.volatilityrc')


def string_clean_hex(line):
    line = str(line)
    new_line = ''
    for c in line:
        if c in string.printable:
            new_line += c
        else:
            new_line += '\\x' + c.encode('hex')
    return new_line


def hex_dump(hex_cmd):
    hex_string = getoutput(hex_cmd)

    # Format the data
    html_string = ''
    hex_rows = hex_string.split('\n')
    for row in hex_rows:
        if len(row) > 9:
            off_str = row[0:8]
            hex_str = row[9:58]
            asc_str = row[58:78]
            asc_str = asc_str.replace('"', '&quot;')
            asc_str = asc_str.replace('<', '&lt;')
            asc_str = asc_str.replace('>', '&gt;')
            html_string += '<div class="row"><span class="text-info mono">{0}</span> <span class="text-primary mono">{1}</span> <span class="text-success mono">{2}</span></div>'.format(off_str, hex_str, asc_str)
    # return the data
    return html_string


# context manager for dump-dir
@contextlib.contextmanager
def temp_dumpdir():
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


##
# Page Views
##

def main_page(request):
    error_line = False
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
    # Get the session
    session_id = ObjectId(sess_id)
    session_details = db.get_session(session_id)
    comments = db.get_commentbysession(session_id)
    plugin_list = []
    plugin_text = db.get_pluginbysession(ObjectId(sess_id))
    version_info = {'python': str(sys.version).split()[0],
                    'volatility': vol_interface.vol_version,
                    'volutility': volutility_version}


    return render(request, 'session.html', {'session_details': session_details,
                                            'plugin_list': plugin_list,
                                            'plugin_output': plugin_text,
                                            'comments': comments,
                                            'version_info': version_info})


# Post Handlers
def create_session(request):
    # Get some vars
    new_session = {'created': datetime.now(), 'modified': datetime.now()}

    if 'sess_name' in request.POST:
        new_session['session_name'] = request.POST['sess_name']
    if 'sess_path' in request.POST:
        new_session['session_path'] = request.POST['sess_path']
    if 'description' in request.POST:
        new_session['session_description'] = request.POST['description']
    if 'plugin_path' in request.POST:
        new_session['plugin_path'] = request.POST['plugin_path']

    # Check for mem file
    if not os.path.exists(new_session['session_path']):
        return HttpResponse('File Not There')

    # Get a list of plugins we can use. and prepopulate the list.

    # Profile

    if 'profile' in request.POST:
        if request.POST['profile'] != 'AutoDetect':
            profile = request.POST['profile']
            new_session['session_profile'] = profile
        else:
            profile = None

    vol_int = RunVol(profile, new_session['session_path'])
    imageinfo = vol_int.run_plugin('imageinfo')

    imageinfo_text = imageinfo['rows'][0][0]

    # ImageInfo tends to error with json so parse text manually.

    image_info = {}
    for line in imageinfo_text.split('\n'):
        try:
            key, value = line.split(' : ')
            image_info[key.strip()] = value.strip()
        except Exception as e:
            print 'Error Getting imageinfo: {0}'.format(e)

    if not profile:
        profile = image_info['Suggested Profile(s)'].split(',')[0]

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
        db.create_plugin(db_results)

    return redirect('/session/{0}'.format(str(session_id)))


def plugin_output(plugin_id):
    plugin_id = ObjectId(plugin_id)
    plugin_data = db.get_pluginbyid(plugin_id)

    # Convert Int to Hex Here instead of plugin for now.

    try:

        for x in ['Offset', 'Offset(V)', 'Offset(P)', 'Process(V)', 'ImageBase', 'Base']:

            if x in plugin_data['plugin_output']['columns']:
                row_loc = plugin_data['plugin_output']['columns'].index(x)

                for row in plugin_data['plugin_output']['rows']:
                    row[row_loc] = hex(row[row_loc])
    except Exception as e:
        logger.error('Error converting hex a: {0}'.format(e))

    return plugin_data['plugin_output']


def run_plugin(session_id, plugin_id):

    target_pid = None
    dump_dir = None
    dump_dir = None
    error = None
    plugin_id = ObjectId(plugin_id)
    sess_id = ObjectId(session_id)

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
            results = vol_int.run_plugin(plugin_name, output_style=output_style)
        except Exception as error:
            results = False
            logger.error('Json Output error, {0}'.format(error))

        if 'unified output format has not been implemented' in str(error) or 'JSON output for trees' in str(error):
            output_style = 'text'
            try:
                results = vol_int.run_plugin(plugin_name, output_style=output_style)
                error = None
            except Exception as error:
                logger.error('Json Output error, {0}'.format(error))
                results = False


        # If we need a DumpDir
        if '--dump-dir' in str(error) or 'specify a dump directory' in str(error):
            # Create Temp Dir
            logger.debug('Creating Temp Directory')
            temp_dir = tempfile.mkdtemp()
            dump_dir = temp_dir
            try:
                results = vol_int.run_plugin(plugin_name, dump_dir=dump_dir, output_style=output_style)
            except Exception as error:
                results = False
                # Set plugin status
                new_values = {'status': 'error'}
                db.update_plugin(ObjectId(plugin_id), new_values)
                logger.error('Error: Unable to run plugin - {0}'.format(error))


        # Check for result set
        if not results:
            # Set plugin status
            new_values = {'status': 'error'}
            db.update_plugin(ObjectId(plugin_id), new_values)
            return 'Error: Unable to run plugin - {0}'.format(error)



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

                ajax_string = "onclick=\"ajaxHandler('hivedetails', {'plugin_id':'"+ str(plugin_id) +"', 'rowid':'"+ str(counter) +"'}, true )\"; return false"
                row.append('<a class="text-success" href="#" '+ ajax_string +'>View Hive Keys</a>')

        # update the plugin
        new_values = {}
        new_values['created'] = datetime.now()
        new_values['plugin_output'] = results
        new_values['status'] = 'completed'
        db.update_plugin(ObjectId(plugin_id), new_values)
        try:
            db.update_plugin(ObjectId(plugin_id), new_values)
            # Update the session
            new_sess = {}
            new_sess['modified'] = datetime.now()
            db.update_session(sess_id, new_sess)

            return plugin_row['plugin_name']

        except Exception as error:
            # Set plugin status
            new_values = {'status': 'error'}
            db.update_plugin(ObjectId(plugin_id), new_values)
            logger.error('Error: Unable to Store Output - {0}'.format(error))
            return 'Error: Unable to Store Output - {0}'.format(e)


def file_download(request, query_type, object_id):

    if query_type == 'file':
        file_object = db.get_filebyid(ObjectId(object_id))
        file_name = '{0}.bin'.format(file_object.filename)
        file_data = file_object.read()

    if query_type == 'plugin':
        plugin_object = db.get_pluginbyid(ObjectId(object_id))

        file_name = '{0}.csv'.format(plugin_object['plugin_name'])
        plugin_data = plugin_object['plugin_output']

        # Convert Int to Hex Here instead of plugin for now.
        try:

            for x in ['Offset', 'Offset(V)', 'Offset(P)', 'Process(V)', 'ImageBase', 'Base']:

                if x in plugin_data['columns']:
                    row_loc = plugin_data['columns'].index(x)

                    for row in plugin_data['rows']:
                        row[row_loc] = str(hex(row[row_loc])).rstrip('L')
        except Exception as error:
            logger.error("Error Converting to hex b: {0}".format(error))

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

    if command == 'pollplugins':
        if 'session_id' in request.POST:
            session_id = request.POST['session_id']
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

            return render(request, 'file_details.html', {'file_details': file_object,
                                                         'file_id': file_id,
                                                         'file_datastore': file_meta
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

    if command == 'virustotal':
        if not VT_KEY or not VT_LIB:
            return HttpResponse("Unable to use Virus Total. No Key or Library Missing. Check the Console for details")

        if 'file_id' in request.POST:
            file_id = request.POST['file_id']

            file_object = db.get_filebyid(ObjectId(file_id))
            sha256 = file_object.sha256
            vt = PublicApi(API_KEY)
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

    if command == 'yara':
        if 'file_id' in request.POST:
            file_id = request.POST['file_id']

        if 'rule_file' in request.POST:
            rule_file = request.POST['rule_file']


        if rule_file and file_id and YARA:
            file_object = db.get_filebyid(ObjectId(file_id))
            file_data = file_object.read()


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
            regexp = '[\x20\x30-\x39\x41-\x5a\x61-\x7a\-\.:]{4,}'
            string_list = re.findall(regexp, file_data)

            # Store the list in datastore
            store_data = {}
            store_data['file_id'] = ObjectId(file_id)
            store_data['string_list'] = string_list

            # Write to DB
            db.create_datastore(store_data)

            return render(request, 'file_details_strings.html', {'string_list': string_list})

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

            if search_type == 'plugin':
                results = {'rows':[]}
                results['columns'] = ['Plugin Name', 'View Results']
                rows = db.search_plugins(search_text, session_id=ObjectId(session_id))
                for row in rows:
                    results['rows'].append([row['plugin_name'], '<a href="#" onclick="ajaxHandler(\'pluginresults\', {{\'plugin_id\':\'{0}\'}}, false ); return false">View Output</a>'.format(row['_id'])])
                return render(request, 'plugin_output.html', {'plugin_results': results})

            elif search_type == 'hash':
                pass
            elif search_type == 'registry':
                pass
            elif search_type == 'vol':
                # Run a vol command and get the output

                vol_output = getoutput('vol.py {0}'.format(search_text))

                results = {'rows': [['<pre>{0}</pre>'.format(vol_output)]], 'columns': ['Volitlity Raw Output']}

                # Consider storing the output here as well.


                return render(request, 'plugin_output.html', {'plugin_results': results})
            else:
                return HttpResponse('No valid search query found.')

    if command == 'pluginresults':
        if 'plugin_id' in request.POST:
            plugin_id = ObjectId(request.POST['plugin_id'])
            plugin_results = plugin_output(plugin_id)
            return render(request, 'plugin_output.html', {'plugin_results': plugin_results})

    return HttpResponse('No valid search query found.')
