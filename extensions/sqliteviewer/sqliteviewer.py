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

        new_data = []
        first_table = None

        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(db_file.read())

            # Now open in sqlite
            try:
                conn = sqlite3.connect(tmp.name)
                cursor = conn.cursor()


                # Get Table meta data
                cursor.execute("SELECT * FROM sqlite_master WHERE type='table';")

                table_data = cursor.fetchall()

                # Do everything under this for loop.
                for table in table_data:
                    table_dict = {'Name': table[1], 'Meta': None, 'Data': None}
                    table_meta_dict = {'type': table[0],
                                       'name': table[1],
                                       'int': table[3],
                                       'sqlquery': table[4]
                                       }
                    table_dict['Meta'] = table_meta_dict

                    # Set active table
                    if not first_table:
                        first_table = table[1]

                    # Get Table data
                    cursor.execute("SELECT * FROM {0}".format(table[1]))
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
                    table_dict['Data'] = table_data_dict

                    new_data.append(table_dict)



            except Exception as e:
                raise

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

        self.render_type = 'file'
        self.render_data = {'SqliteViewer': {'sqlite_data': new_data, 'file_id': file_id}}
        self.render_javascript = "$('#sqlitescan').remove();"

    def display(self):
        self.render_data = {'SqliteViewer': None}
