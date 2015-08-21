#!/usr/bin/python2
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

from xml.dom.minidom import parseString

class Component(object):
    """ A quick'n'dirty MetaInfo parser """

    def __init__(self):
        """ Set defaults """
        self.id = None
        self.guid = None
        self.version = None
        self.name = None
        self.summary = None

    def parse(self, xml_data):
        """ Parse XML data """

        # parse component
        dom = parseString(xml_data)
        n_component = dom.getElementsByTagName('component')
        if not n_component:
            raise RuntimeError('expected <component> tag')

        # get id
        n_id = n_component[0].getElementsByTagName('id')
        if not n_id:
            raise RuntimeError('expected <id> tag')
        val = n_id[0].childNodes[0]
        if not val:
            raise RuntimeError('expected <id> contents')
        self.id = val.wholeText

        # get name
        n_name = n_component[0].getElementsByTagName('name')
        if not n_name:
            raise RuntimeError('expected <name> tag')
        val = n_name[0].childNodes[0]
        if not val:
            raise RuntimeError('expected <name> contents')
        self.name = val.wholeText

        # get id
        n_summary = n_component[0].getElementsByTagName('summary')
        if not n_summary:
            raise RuntimeError('expected <summary> tag')
        val = n_summary[0].childNodes[0]
        if not val:
            raise RuntimeError('expected <summary> contents')
        self.summary = val.wholeText

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

def main():

    data = """<?xml version="1.0" encoding="UTF-8"?>
<!-- Copyright 2015 Richard Hughes <richard@hughsie.com> -->
<component type="firmware">
  <id>com.hughski.ColorHug.firmware</id>
  <name>ColorHug Device Update</name>
  <summary>Firmware for the Hughski ColorHug Colorimeter</summary>
  <description>
    <p>
      Updating the firmware on your ColorHug device improves performance and
      adds new features.
    </p>
  </description>
  <provides>
    <firmware type="flashed">40338ceb-b966-4eae-adae-9c32edfcc484</firmware>
  </provides>
  <url type="homepage">http://www.hughski.com/</url>
  <metadata_license>CC0-1.0</metadata_license>
  <project_license>GPL-2.0+</project_license>
  <updatecontact>richard_at_hughsie.com</updatecontact>
  <developer_name>Hughski Limited</developer_name>
  <releases>
    <release version="1.2.4" timestamp="1438454314">
      <description>
        <p>
          This release adds support for verifying the firmware contents using fwupd.
        </p>
      </description>
    </release>
  </releases>
</component>
"""
    print data

    app = Component()
    app.parse(data)
    print ("ID:      %s" % app.id)
    print ("Version: %s" % app.version)
    print ("GUID:    %s" % app.guid)
    print ("Name:    %s" % app.name)
    print ("Summary: %s" % app.summary)

if __name__ == "__main__":
    main()
