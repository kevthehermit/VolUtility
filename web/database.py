import json
import pymongo
from bson.objectid import ObjectId
from gridfs import GridFS
from common import parse_config

config = parse_config()

class Database():
    def __init__(self):
        # Create the connection
        if config['valid']:
            mongo_uri = config['database']['mongo_uri']
        else:
            mongo_uri = 'mongodb://localhost'

        connection = pymongo.MongoClient(mongo_uri)

        # Version Check
        server_version = connection.server_info()['version']
        if int(server_version[0]) < 3:
            raise UserWarning('Incompatible MongoDB Version detected. Requires 3 or higher. Found {0}'.format(server_version))

        # Connect to Databases.
        voldb = connection['voldb']
        voldbfs = connection['voldbfs']

        # Get Collections
        self.vol_sessions = voldb.sessions
        self.vol_comments = voldb.comments
        self.vol_plugins = voldb.plugins
        self.vol_datastore = voldb.datastore
        self.vol_files = GridFS(voldbfs)

        # Indexes
        self.vol_comments.create_index([('freetext', 'text')])

        self.vol_plugins.create_index([('$**', 'text')])

    ##
    # Sessions
    ##
    def get_allsessions(self):
        sessions = self.vol_sessions.find()
        return [x for x in sessions]

    def get_session(self, session_id):
        session_id = ObjectId(session_id)
        session = self.vol_sessions.find_one({'_id': session_id})
        return session

    def create_session(self, session_data):
        session_id = self.vol_sessions.insert_one(session_data).inserted_id
        return session_id

    def update_session(self, session_id, new_values):
        session_id = ObjectId(session_id)
        self.vol_sessions.update_one({'_id': session_id}, {"$set": new_values })
        return True

    ##
    # Comments
    ##
    def get_commentbyid(self, comment_id):
        comment_id = ObjectId(comment_id)
        comment = self.vol_comments.find({'_id': comment_id})
        return comment

    def get_commentbysession(self, session_id):
        session_id = ObjectId(session_id)
        comments = self.vol_comments.find({'session_id': session_id}).sort("created", -1)
        return [row for row in comments]

    def create_comment(self, comment_data):
        comment_id = self.vol_comments.insert_one(comment_data).inserted_id
        return comment_id

    def search_comments(self, search_text, session_id=None):
        results = []
        rows = self.vol_comments.find({"$text": {"$search": search_text}})
        for row in rows:
            if session_id:
                session_id = ObjectId(session_id)
                if row['session_id'] == session_id:
                    results.append(row)
            else:
                results.append(row)
        return results

    ##
    # Plugins
    ##

    def get_pluginbysession(self, session_id):
        session_id = ObjectId(session_id)
        result_rows = []
        plugin_output = self.vol_plugins.find({'session_id': session_id}).sort("created", -1)
        for row in plugin_output:
            result_rows.append(row)

        # result_rows.sort(key=lambda d: (d["plugin_name"]))

        return result_rows

    def get_pluginbyid(self, plugin_id):
        plugin_id = ObjectId(plugin_id)
        plugin_output = self.vol_plugins.find_one({'_id': plugin_id})
        if 'largedoc' in plugin_output:
            large_document_id = plugin_output['plugin_output']
            large_document = self.get_filebyid(large_document_id)
            plugin_output['plugin_output'] = json.loads(large_document.read())
        return plugin_output

    def get_plugin_byname(self, plugin_name, session_id):
        session_id = ObjectId(session_id)
        plugin_output = self.vol_plugins.find_one({'session_id': session_id, 'plugin_name': plugin_name})
        if plugin_output and 'largedoc' in plugin_output:
            large_document_id = plugin_output['plugin_output']
            large_document = self.get_filebyid(large_document_id)
            plugin_output['plugin_output'] = json.loads(large_document.read())
        return plugin_output

    def create_plugin(self, plugin_data):
        # Force session ID
        plugin_data['session_id'] = ObjectId(plugin_data['session_id'])
        plugin_id = self.vol_plugins.insert_one(plugin_data).inserted_id
        return plugin_id

    def search_plugins(self, search_text, session_id=None, plugin_name=None):
        results = []
        rows = self.vol_plugins.find({"$text": {"$search": search_text}})
        for row in rows:
            if session_id:
                session_id = ObjectId(session_id)
                if row['session_id'] == session_id:
                    results.append(row)
            # This is the session filter from the main page.
            elif plugin_name:
                if row['plugin_name'] == plugin_name:
                    if search_text in str(row['plugin_output']):
                        results.append(row['session_id'])

            else:
                results.append(row)
        return results

    def update_plugin(self, plugin_id, new_values):
        plugin_id = ObjectId(plugin_id)
        if len(str(new_values)) > 12000000:
            print "Storing Large Document in GridFS"
            large_document = json.dumps(new_values['plugin_output'])
            large_document_id = self.create_file(large_document, 'session_id', 'sha256', 'filename', pid=None, file_meta=None)
            new_values['plugin_output'] = large_document_id
            new_values['largedoc'] = 'True'

        self.vol_plugins.update_one({'_id': plugin_id}, {"$set": new_values})
        return True


    ##
    # File System
    ##
    def get_filebyid(self, file_id):
        file_id = ObjectId(file_id)
        file_object = self.vol_files.get(file_id)
        return file_object

    def list_files(self, session_id):
        session_id = ObjectId(session_id)
        results = self.vol_files.find({'session_id': session_id})
        return [row for row in results]

    def search_files(self, search_query):
        results = self.vol_files.find(search_query)
        return [row for row in results]

    def get_strings(self, file_id):
        file_id = ObjectId(file_id)
        results = self.vol_files.find_one({'filename': '{0}_strings.txt'.format(str(file_id))})
        return results

    def create_file(self, file_data, session_id, sha256, filename, pid=None, file_meta=None):
        if not isinstance(session_id, ObjectId) and len(session_id) == 24:
            session_id = ObjectId(session_id)
        file_id = self.vol_files.put(file_data, filename=filename, session_id=session_id, sha256=sha256, pid=pid, file_meta=file_meta)
        return file_id

    def drop_file(self, file_id):
        file_id = ObjectId(file_id)
        self.vol_files.delete(file_id)
        return True

    ##
    # DataStore
    ##

    def get_alldatastore(self):
        results = self.vol_datastore.find()
        return [row for row in results]

    def search_datastore(self, search_query):
        results = self.vol_datastore.find(search_query)
        return [row for row in results]

    def create_datastore(self, store_data):
        data_id = self.vol_datastore.insert_one(store_data).inserted_id
        return data_id

    def update_datastore(self, search_query, new_values):
        self.vol_datastore.update_one(search_query, {"$set": new_values})
        return True



    ##
    # Drop Session
    ##
    def drop_session(self, session_id):
        session_id = ObjectId(session_id)

        # Drop Plugins
        self.vol_plugins.delete_many({'session_id': session_id})
        # Drop Files
        results = self.vol_files.find({'session_id': session_id})
        for row in results:
            self.vol_files.delete(row._id)
        # Drop DataStore
        self.vol_datastore.delete_many({'session_id': session_id})
        # Drop Notes
        self.vol_comments.delete_many({'session_id': session_id})
        # Drop session
        self.vol_sessions.delete_many({'_id': session_id})
