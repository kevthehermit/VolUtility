import os
from web.common import Extension
from web.database import Database
import geoip2.database

from struct import unpack
from socket import AF_INET, inet_pton

# Get the database from
# https://dev.maxmind.com/geoip/geoip2/geolite2/

maxmind_city_db = '/usr/share/GeoIP/GeoLite2-City.mmdb'
if not os.path.exists(maxmind_city_db):
    raise IOError("Unable to locate GeoLite2-City.mmdb")


class IPLookup(Extension):

    extension_name = 'IPLookup'
    extension_type = 'postprocess'
    render_javascript = ''

    # https://stackoverflow.com/questions/691045/how-do-you-determine-if-an-ip-address-is-private-in-python
    def private_ip(self, ip):
        f = unpack('!I', inet_pton(AF_INET, ip))[0]
        private = (
            [2130706432, 4278190080],  # 127.0.0.0,   255.0.0.0   http://tools.ietf.org/html/rfc3330
            [3232235520, 4294901760],  # 192.168.0.0, 255.255.0.0 http://tools.ietf.org/html/rfc1918
            [2886729728, 4293918720],  # 172.16.0.0,  255.240.0.0 http://tools.ietf.org/html/rfc1918
            [167772160, 4278190080],  # 10.0.0.0,    255.0.0.0   http://tools.ietf.org/html/rfc1918
        )
        for net in private:
            if (f & net[1]) == net[0]:
                return True
        return False

    def run(self):
        plugin_results = self.plugin_results
        plugin_name = plugin_results['plugin_name']
        reader = geoip2.database.Reader(maxmind_city_db)

        # Only run on plugins that return net data

        if plugin_name in ['netscan', 'connscan', 'connections', 'sockets', 'sockscan']:
            plugin_columns = plugin_results['plugin_output']['columns']
            insert_index = 0
            if plugin_name == 'netscan':
                insert_index = plugin_columns.index('ForeignAddr')
            elif plugin_name in ['connscan', 'connections']:
                insert_index = plugin_columns.index('RemoteAddress')
            elif plugin_name in ['sockets', 'sockscan']:
                insert_index = plugin_columns.index('Address')

            # Check if we already created the row.
            if 'Country' in plugin_columns:
                self.render_data = plugin_results
            else:
                # Add Country Column Name
                plugin_columns.insert(insert_index + 1, 'Country')
                for row in plugin_results['plugin_output']['rows']:
                    ip_addr = row[insert_index].split(':')[0]
                    try:
                        if self.private_ip(ip_addr):
                            country = 'RFC 1918'
                        elif ip_addr == '0.0.0.0':
                            country = 'All Interfaces'
                        else:
                            record = reader.city(ip_addr)
                            if not record.country.iso_code:
                                country = 'Unknown'
                            else:
                                country = record.country.name
                    except Exception as e:
                        print e
                        country = 'unknown'
                    row.insert(insert_index + 1, country)
                # Add to DB to save future lookups
                self.render_data = plugin_results
        else:
            self.render_data = None
