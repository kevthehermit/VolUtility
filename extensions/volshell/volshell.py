import os
import re
import string
import pexpect
from web.common import Extension
from web.database import Database
from Registry import Registry
v = {'volshell_id': None, 'volshell_object': None}

class VolShell(Extension):

    # Paths should be relative to the extensions folder
    extension_name = 'VolShell'
    extension_type = 'toolbar'
    extra_js = 'volshell/volshell.js'

    def strip_ansi_codes(self, s):
        return re.sub(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]', '', s)

    def run(self):
        global v
        print v
        db = Database()
        session_id = self.request.POST['session_id']
        shell_input = self.request.POST['shell_input']

        if shell_input == 'resetvolshellsession':
            v = {'volshell_id': None, 'volshell_object': None}



        session = db.get_session(session_id)
        vol_shell_cmd = 'vol.py --profile={0} -f {1} volshell'.format(session['session_profile'],
                                                                       session['session_path']
                                                                       )



        if v['volshell_id']:
            print "a is a stored object"
            voll_shell = v['volshell_object']
        else:
            print "a is a new object"
            voll_shell = pexpect.spawn(vol_shell_cmd)
            print "b"

            voll_shell.expect('m.\[0m.\[J.\[0;38;5;28mIn')
            v['volshell_id'] = session_id



        voll_shell.sendline(shell_input)

        print "c"

        voll_shell.expect('m.\[0m.\[J.\[0;38;5;28mIn', timeout=60)

        print "d"


        v['volshell_object'] = voll_shell
        #returndata = voll_shell.read()

        print "e"

        before_data = self.strip_ansi_codes(voll_shell.before)
        after_data = self.strip_ansi_codes(voll_shell.after)


        print "Before Data: ", before_data

        print "After Data: ", after_data




        # lets start by getting input and saving it





        self.render_type = 'html'
        self.render_data = '<pre>{0}</pre>'.format(str(before_data))
        self.render_javascript = open(os.path.join('extensions', self.extra_js), 'rb').read()
