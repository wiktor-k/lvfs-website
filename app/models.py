#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2017 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

#from app import db

class User(object):
    def __init__(self):
        """ Constructor for object """
        self.username = None
        self.password = None
        self.display_name = None
        self.email = None
        self.is_enabled = False
        self.is_qa = False
        self.qa_group = None
        self.is_locked = False
        self.pubkey = None

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.username)

    def __repr__(self):
        return "User object %s" % self.username

class EventLogItem(object):
    def __init__(self):
        """ Constructor for object """
        self.timestamp = None
        self.username = None
        self.qa_group = None
        self.address = None
        self.message = None
        self.is_important = False
    def __repr__(self):
        return "EventLogItem object %s" % self.message

class FirmwareMd(object):
    def __init__(self):
        """ Constructor for object """
        self.fwid = None    # this maps the object back into a Firmware
        self.cid = None
        self.guids = []
        self.version = None
        self.name = None
        self.summary = None
        self.checksum_contents = None
        self.release_description = None
        self.release_timestamp = 0
        self.developer_name = None
        self.metadata_license = None
        self.project_license = None
        self.url_homepage = None
        self.description = None
        self.checksum_container = None
        self.filename_contents = None
        self.release_installed_size = 0
        self.release_download_size = 0
        self.release_urgency = None
        self.screenshot_url = None
        self.screenshot_caption = None
        self.metainfo_id = None
    def __repr__(self):
        return "FirmwareMd object %s" % self.fwid

class Firmware(object):
    def __init__(self):
        """ Constructor for object """
        self.qa_group = None
        self.addr = None
        self.timestamp = None
        self.filename = None
        self.fwid = None
        self.target = None
        self.version_display = None
        self.mds = []
    def __repr__(self):
        return "Firmware object %s" % self.fwid

class DownloadKind(object):
    METADATA = 0
    FIRMWARE = 1
    SIGNING = 2
