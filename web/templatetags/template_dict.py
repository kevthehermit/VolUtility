from django import template
from web.common import parse_config

config = parse_config()
register = template.Library()

# Lets me call dict values with spaces and hypens from a django template
@register.filter
def get(mapping, key):
    return mapping.get(key, '')

@register.filter
def theme(mapping, key):
    if 'style' in config:
        style_elements = config['style']
    else:
        # Backwards compat
        style_elements = {'spinner': 'cat_spinner.gif', 'theme': 'slate.min.css'}

    if key == 'spinner':
        return 'img/{0}'.format(style_elements['spinner'])

    if key == 'theme':
        return 'css/{0}'.format(style_elements['theme'])
