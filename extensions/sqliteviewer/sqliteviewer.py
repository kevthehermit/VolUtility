import os
import json
import sqlite3
import tempfile
from web.common import Extension
from web.database import Database


class SqliteViewer(Extension):

    # Paths should be relative to the extensions folder
    extension_type = 'filedetails'
    extension_name = 'SqliteViewer'



    def run(self):
        db = Database()
        # https://github.com/williballenthin/python-registry
        file_id = self.request.POST['file_id']
        db_file = db.get_filebyid(file_id)
        if not db_file:
            raise IOError("File not found in DB")

        # Sqlite can only operate on a temp file. So.

        sqlite_data = {'table_meta': [], 'index_meta': [], 'table_data': []}

        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(db_file.read())

            # Now open in sqlite
            try:
                conn = sqlite3.connect(tmp.name)
                cursor = conn.cursor()


                # Get Table meta data
                cursor.execute("SELECT * FROM sqlite_master WHERE type='table';")

                table_data = cursor.fetchall()
                table_names = []

                for table in table_data:
                    table_meta_dict = {'type': table[0],
                                       'name': table[1],
                                       'int': table[3],
                                       'sqlquery': table[4]
                                       }
                    sqlite_data['table_meta'].append(table_meta_dict)
                    table_names.append(table[1])

                # Get index meta data
                cursor.execute("SELECT * FROM sqlite_master WHERE type='index';")
                index_data = cursor.fetchall()

                for index in index_data:
                    index_meta_dict = {'type': index[0],
                                       'name': index[2],
                                       'int': index[3],
                                       'sqlquery': index[4]
                                       }
                    sqlite_data['index_meta'].append(index_meta_dict)

                # Get Table data
                for table in table_names:
                    cursor.execute("SELECT * FROM {0}".format(table))
                    table_data = cursor.fetchall()

                    table_rows = []

                    for row in table_data:
                        new_row = []
                        for col in row:
                            try:
                                new_row.append(str(col))
                            except:
                                new_row.append(col.encode('hex'))
                        table_rows.append(new_row)

                    col_names = [str(description[0]) for description in cursor.description]
                    table_data_dict = {'columns': col_names, 'rows': table_rows}
                    sqlite_data['table_data'].append(table_data_dict)

            except Exception as e:
                raise

            json_response = json.dumps(sqlite_data)


        self.render_type = 'json'
        self.render_data = json_response

    def display(self):
        self.render_data = ''
