from django.core.checks import Error, Warning, register
from django.core.checks import Tags
import vol_interface


##
# Django System Checks
##


@register(Tags.compatibility)
def compat_check(app_configs=None, **kwargs):
    errors = []

    # Imports first
    try:
        import pymongo
        have_mongo = True
    except ImportError:
        have_mongo = False
        errors.append(Error('Unable to import pymongo', hint='sudo pip install pymongo'))

    try:
        from Registry import Registry
    except ImportError:
        errors.append(Error('Unable to import python-registry', hint='sudo pip install python-registry'))

    try:
        from virus_total_apis import PublicApi
    except ImportError:
        errors.append(Warning('Unable to import virustotalapi', hint='sudo pip install virustotal-api'))

    try:
        import yara
    except ImportError:
        errors.append(Warning('Unable to import Yara', hint='Read the Wiki or google Yara'))

    try:
        import distorm3
    except ImportError:
        errors.append(Warning('Unable to import distorm3', hint='sudo pip install distorm3'))

    # Check Vol Version

    try:
        vol_ver = vol_interface.vol_version.split('.')
        if int(vol_ver[1]) < 5:
            errors.append(Error('Unsupported Volatility version found. Need 2.5 or greater. Found: {0}'.format('.'.join(vol_ver))))
    except Exception as error:
        errors.append(Error('Unable to find Volatility Version Number', hint='Read the installation wiki'))

    # Config
    try:
        from common import parse_config
        config = parse_config()
        if config['valid']:
            pass

    except:
        errors.append(Error('Unable to parse a volutility.conf file', hint='Copy volutiltiy.conf.sample to volutitliy.conf'))


    # Database Connection finally
    if have_mongo:
        try:
            if config['valid']:
                mongo_uri = config['database']['mongo_uri']
            else:
                mongo_uri = 'mongodb://localhost'

            connection = pymongo.MongoClient(mongo_uri)

            # Version Check
            server_version = connection.server_info()['version']

            if int(server_version[0]) < 3:
                errors.append(Error(str('Incompatible MongoDB Version detected. Requires 3 or higher. Found {0}'.format(server_version))))

            connection.close()

        except Exception as error:
            errors.append(Error('Unable to connect to MongoDB: {0}'.format(error)))

    return errors