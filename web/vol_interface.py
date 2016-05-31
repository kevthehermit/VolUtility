import logging
import sys
import os
import copy
import StringIO
import json

# Need to do this before importing Volatility

volrc_file = os.path.join(os.path.expanduser('~'), '.volatilityrc')
plugin_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../plugins')

# Platform PATH seperator
seperator = ':'
if sys.platform.startswith('win'):
    seperator = ';'

if os.path.exists(volrc_file):
    with open(volrc_file, 'ab+') as out:
        if plugin_dir not in out.read():
            output = '{0}{1}'.format(seperator, plugin_dir)
            out.write(output)
else:
    # Create new file.
    with open(volrc_file, 'w') as out:
        output = '[DEFAULT]\nPLUGINS = {0}'.format(plugin_dir)
        out.write(output)

# Then import

import volatility.conf as conf
import volatility.obj as obj
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.constants as constants
import volatility.debug as debug
import volatility.utils as utils


logger = logging.getLogger(__name__)


##
# Patch the volatility debug to prevent sys.exit calls
##
def new_error(msg):
    raise Exception(msg)
debug.error = new_error

# Stop these plugins being listed as we can or will not handle them
plugin_filters = {
    "drop": ['crashdump', 'crashinfo', 'volshell', 'chromecookies', 'poolpeek', 'impscan', 'hivedump', 'pstree', 'yarascan']
}

vol_version = constants.VERSION


def profile_list():
    """
    Return a list of available Profiles
    :return:
    """
    prof_list = ['AutoDetect']
    profs = registry.get_plugin_classes(obj.Profile)
    for profile in profs.iterkeys():
        prof_list.append(profile)
    return sorted(prof_list)


class RunVol:
    def __init__(self, profile, mem_path):
        """
        setup base config
        :param profile:
        :param mem_path:
        :return:
        """
        debug.setup()
        registry.PluginImporter()
        self.memdump = mem_path
        self.osprofile = profile
        self.config = None
        self.addr_space = None
        self.init_config()

    def init_config(self):
        """Creates a volatility configuration."""
        if self.config is not None and self.addr_space is not None:
            return self.config

        self.config = conf.ConfObject()
        self.config.optparser.set_conflict_handler("resolve")
        registry.register_global_options(self.config, commands.Command)
        registry.register_global_options(self.config, addrspace.BaseAddressSpace)
        base_conf = {
            "profile": "WinXPSP2x86",
            "use_old_as": None,
            "kdbg": None,
            "help": False,
            "kpcr": None,
            "tz": None,
            "pid": None,
            "output_file": None,
            "physical_offset": None,
            "conf_file": None,
            "dtb": None,
            "output": None,
            "info": None,
            "location": "file://" + self.memdump,
            "plugins": 'plugins',
            "debug": 4,
            "cache_dtb": True,
            "filename": None,
            "cache_directory": None,
            "verbose": None,
            "write": False
        }

        if self.osprofile:
            base_conf["profile"] = self.osprofile

        for key, value in base_conf.items():
            self.config.update(key, value)

        self.plugins = registry.get_plugin_classes(commands.Command, lower=True)
        return self.config

    def profile_list(self):
        """
        return a list of profiles
        :return: list
        """
        prof_list = []
        profs = registry.get_plugin_classes(obj.Profile)
        for profile in profs.iterkeys():
            prof_list.append(profile)
        return sorted(prof_list)

    def list_plugins(self):
        """
        list of plugins valid for the selected profile
        :return:
        """
        plugin_list = []
        cmds = registry.get_plugin_classes(commands.Command, lower=True)
        profs = registry.get_plugin_classes(obj.Profile)
        profile_type = self.config.PROFILE
        if profile_type not in profs:
            print "Not a valid profile"
        profile = profs[profile_type]()
        for cmdname in sorted(cmds):
            command = cmds[cmdname]
            helpline = command.help() or ''

            if command.is_valid_profile(profile):
                plugin_list.append([cmdname, helpline])
        return plugin_list

    def get_dot(self, plugin_class):
        """
        return dot output for a plugin
        :param plugin_class:
        :return:
        """
        strio = StringIO.StringIO()
        plugin = plugin_class(copy.deepcopy(self.config))
        plugin.render_dot(strio, plugin.calculate())
        return strio.getvalue()

    def get_json(self, plugin_class):
        """
        return json output for a plugin
        :param plugin_class:
        :return:
        """
        strio = StringIO.StringIO()
        plugin = plugin_class(copy.deepcopy(self.config))
        plugin.render_json(strio, plugin.calculate())
        return json.loads(strio.getvalue())

    def get_text(self, plugin_class):
        """
        return text output of a plugin in json format
        :param plugin_class:
        :return:
        """
        strio = StringIO.StringIO()
        plugin = plugin_class(copy.deepcopy(self.config))
        plugin.render_text(strio, plugin.calculate())
        plugin_data = strio.getvalue()

        # Return a json object from our string so it matches the json output.
        # Also going to drop in pre tags here
        return {'columns': ['Plugin Output'], 'rows': [['<pre>\n{0}\n</pre>'.format(plugin_data)]]}

    def result_modifier(self, results):
        """
        Change the style or formatting of columns and values
        :param results:
        :return:
        """


        # Convert Hex ints to 0x Values
        try:
            for x in ['Offset', 'Offset (V)', 'Offset(V)', 'Offset(P)', 'Process(V)', 'ImageBase', 'Base', 'Address']:

                if x in results['columns']:
                    row_loc = results['columns'].index(x)
                    for row in results['rows']:
                        row[row_loc] = hex(row[row_loc])
        except Exception as e:
            logger.error('Error converting hex: {0}'.format(e))

        return results


    def run_plugin(self, plugin_name, pid=None, dump_dir=None, plugin_options=None, hive_offset=None, output_style="json"):
        """
        run a plugin and set config options
        :param plugin_name:
        :param pid:
        :param dump_dir:
        :param plugin_options:
        :param hive_offset:
        :param output_style:
        :return: json
        """

        # Get Valid commands
        cmds = registry.get_plugin_classes(commands.Command, lower=True)

        if plugin_name in cmds.keys():
            command = cmds[plugin_name]
            # Set Config options
            self.config.PID = pid
            self.config.DUMP_DIR = dump_dir
            self.config.hive_offset = hive_offset
            if plugin_options:
                for option, value in plugin_options.iteritems():
                    logger.debug('Setting Config {0} to {1}'.format(option, value))
                    self.config.update(option, value)

            # Plugins with specific output types
            if plugin_name == 'pstree':
                output_data = self.get_dot(command)
                return output_data

            elif plugin_name == 'imageinfo':
                output_data = self.get_text(command)
                return output_data

            elif plugin_name == 'memdump':
                if not pid:
                    return None
                output_data = self.get_text(command)
                return output_data

            elif plugin_name == 'dumpfiles':
                if 'PHYSOFFSET' not in plugin_options:
                    logger.debug('No Offset Provided')
                    return None
                output_data = self.get_text(command)
                return output_data

            # All other plugins
            else:
                if output_style == 'json':
                    output_data = self.get_json(command)
                    if plugin_name in ['mftparser']:
                        return output_data
                    else:
                        return self.result_modifier(output_data)

                if output_style == 'text':
                    output_data = self.get_text(command)
                    return output_data

                if output_style == 'dot':
                    output_data = self.get_dot(command)
                    return output_data
        else:
            return 'Error: Not a valid plugin'


    def read_memory(self, offset=0, length=0):
        self.addr_space = utils.load_as(copy.deepcopy(self.config), 'virtual')

        this = self.addr_space

        print dir(this)

        print "hello"

        #print this.read(0, 100).encode('hex')

        a = self.addr_space.get_available_addresses()

        for b, c in a:
            print hex(b),c


