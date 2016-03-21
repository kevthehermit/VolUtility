from django import template
register = template.Library()

# Lets me call dict values with spaces and hypens from a django template
@register.filter
def get(mapping, key):
  return mapping.get(key, '')