import pypff
from web.common import Extension
from web.database import Database


class PSTViewer(Extension):

    # Paths should be relative to the extensions folder
    extension_type = 'filedetails'
    extension_name = 'PSTViewer'

    def recursive_walk_folders(self, node, path):
        if node.get_display_name():
            node_path = path + u"/" + unicode(node.get_display_name())
        else:
            node_path = path

        for i in range(0, node.get_number_of_sub_messages()):
            try:
                msg = node.get_sub_message(i)
                msg_dict = {
                    'delivery_time': msg.delivery_time,
                    'display_name': msg.display_name,
                    'att_count': msg.number_of_attachments,
                    'sender_name': msg.sender_name,
                    'subject': msg.subject,
                    'plain_body': msg.plain_text_body,
                    'html_body': msg.html_body,
                    'headers': msg.transport_headers,
                    'rtf_body': msg.rtf_body,
                    'conversation_topic': msg.conversation_topic,
                    'creation_time': msg.creation_time
                }

                if node.get_display_name() in self.email_dict:
                    self.email_dict[node.get_display_name()].append(msg_dict)
                else:
                    self.email_dict[node.get_display_name()] = [msg_dict]
            except Exception as e:
                print "Error: ", e

        for i in range(0, node.get_number_of_sub_folders()):
            folder = node.get_sub_folder(i)
            folder_name = folder.get_display_name()
            self.recursive_walk_folders(node.get_sub_folder(i), node_path)

    def run(self):
        db = Database()
        # https://github.com/williballenthin/python-registry
        file_id = self.request.POST['file_id']
        pst_file = db.get_filebyid(file_id)
        if not pst_file:
            raise IOError("File not found in DB")

        try:
            self.pst = pypff.file()
            self.pst.open_file_object(pst_file)
        except Exception as e:
            raise

        base_path = u""
        root_node = self.pst.get_root_folder()
        self.email_dict = {}
        self.recursive_walk_folders(root_node, base_path)

        # Store in DB Now
        store_data = {'file_id': file_id, 'pst': self.email_dict}
        db.create_datastore(store_data)


        self.render_type = 'file'
        self.render_data = {'PSTViewer': {'email_dict': self.email_dict, 'file_id': file_id}}

    def display(self):
        db = Database()
        file_id = self.request.POST['file_id']
        file_datastore = db.search_datastore({'file_id': file_id})
        pst_results = None
        for row in file_datastore:
            if 'pst' in row:
                pst_results = row['pst']

        self.render_data = {'PSTViewer': {'email_dict': pst_results, 'file_id': file_id}}

