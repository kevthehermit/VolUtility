import os
from web.common import Extension
from web.database import Database
import geoip2.database

# Get the database from
# https://dev.maxmind.com/geoip/geoip2/geolite2/

maxmind_city_db = '/usr/share/GeoIP/GeoLite2-City.mmdb'
if not os.path.exists(maxmind_city_db):
    raise "File Doesnt exist"


class IPLookup(Extension):

    extension_name = 'IPLookup'
    extension_type = 'postprocess'
    render_javascript = ''

    def run(self):
        plugin_results = self.plugin_results
        plugin_name = plugin_results['plugin_name']
        reader = geoip2.database.Reader(maxmind_city_db)
        if plugin_name == 'netscan':
            plugin_columns = plugin_results['plugin_output']['columns']
            if 'Country' in plugin_columns:
                self.render_data = plugin_results
            else:
                # Add Country Column Name
                plugin_columns.insert(5, 'Country')
                for row in plugin_results['plugin_output']['rows']:
                    ip_addr = row[4].split(':')[0]
                    try:
                        record = reader.city(ip_addr)
                        if record.country.iso_code == None:
                            country = 'Unknown'
                        else:
                            country = record.country.name
                    except Exception as e:
                        country = 'unknown'
                    row.insert(5, country)

                self.render_data = plugin_results
        else:
            self.render_data = None
