#!/usr/bin/python2
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

from xml.dom.minidom import parseString

class Component(object):
    """ A quick'n'dirty MetaInfo parser """

    def __init__(self):
        """ Set defaults """
        self.guid = None
        self.version = None

    def parse(self, xml_data):
        """ Parse XML data """

        # parse component
        dom = parseString(xml_data)
        n_component = dom.getElementsByTagName('component')
        if not n_component:
            raise RuntimeError('expected <component> tag')

        # get version
        n_releases = n_component[0].getElementsByTagName('releases')
        if not n_releases:
            raise RuntimeError('expected <releases> tag')
        n_release = n_releases[0].getElementsByTagName('release')
        if not n_release:
            raise RuntimeError('expected <release> tag')
        self.version = n_release[0].getAttribute('version')

        # get guid
        n_provides = n_component[0].getElementsByTagName('provides')
        if not n_provides:
            raise RuntimeError('expected <provides> tag')
        n_firmware = n_provides[0].getElementsByTagName('firmware')
        if not n_firmware:
            raise RuntimeError('expected <firmware> tag')
        val = n_firmware[0].childNodes[0]
        if not val:
            raise RuntimeError('expected <firmware> contents')
        self.guid = val.wholeText.lower()
