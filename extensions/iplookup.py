from web.common import Extension
from web.database import Database


class IPLookup(Extension):

    extension_name = 'IPLookup'
    extension_type = 'postprocess'
    render_javascript = ''

    def run(self):
        plugin_results = self.plugin_results
        plugin_name = plugin_results['plugin_name']

        if plugin_name == 'netscan':
            plugin_columns = plugin_results['plugin_output']['columns']
            # Add Country Column Name
            plugin_columns.insert(5, 'Country')
            for row in plugin_results['plugin_output']['rows']:
                row.insert(5, 'China')

            self.render_data = plugin_results
        else:
            self.render_data = None
