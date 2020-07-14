"""Skynet statistics API.
"""


from . import utils


def default_get_statistics_options():
    """Returns the default stats options."""
    return __fill_with_default_get_statistics_options()


def __fill_with_default_get_statistics_options(opts=None):
    """Fills in missing options with the default stats options."""
    portal_url = getattr(opts, 'portal_url', utils.default_portal_url())

    return type('obj', (object,), {
        'portal_url': portal_url,
    })


def get_statistics(opts=None):
    """Returns statistical information about Skynet, e.g. number of files \
    uploaded."""

    raise NotImplementedError
