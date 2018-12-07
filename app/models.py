#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2018 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2
#
# pylint: disable=too-few-public-methods,too-many-instance-attributes,too-many-arguments,too-many-lines,protected-access

import datetime
import fnmatch
import re

from gi.repository import AppStreamGlib

from flask import g, url_for

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, Unicode, Index
from sqlalchemy.orm import relationship

from app import db
from .hash import _qa_hash, _password_hash
from .util import _generate_password, _xml_from_markdown, _get_update_description_problems

class Problem(object):
    def __init__(self, kind, description=None, url=None):
        self.kind = kind
        self.description = description
        self.url = url

    @property
    def summary(self):
        if self.kind == 'unsigned':
            return 'Firmware is unsigned'
        if self.kind == 'deleted':
            return 'Firmware has been deleted'
        if self.kind == 'no-release-urgency':
            return 'No update urgency'
        if self.kind == 'no-release-description':
            return 'No update description'
        if self.kind == 'invalid-release-description':
            return 'No valid update description'
        return 'Unknown problem %s' % self.kind

    @property
    def icon_name(self):
        if self.kind == 'unsigned':
            return 'task-due'
        if self.kind == 'deleted':
            return 'emblem-readonly'
        return 'dialog-warning'

class Agreement(db.Model):

    # database
    __tablename__ = 'agreements'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    agreement_id = Column(Integer, primary_key=True, unique=True, nullable=False)
    created = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    version = Column(Integer, nullable=False)
    text = Column(Unicode, default=None)

class User(db.Model):

    # database
    __tablename__ = 'users'
    __table_args__ = (Index('idx_users_username_password', 'username', 'password'),
                      {'mysql_character_set': 'utf8mb4'}
                     )

    user_id = Column(Integer, primary_key=True, unique=True, nullable=False)
    username = Column(String(80), nullable=False, index=True)
    password = Column(String(40), default=None)
    password_ts = Column(DateTime, default=None)
    password_recovery = Column(String(40), default=None)
    password_recovery_ts = Column(DateTime, default=None)
    display_name = Column(Unicode, default=None)
    vendor_id = Column(Integer, ForeignKey('vendors.vendor_id'), nullable=False)
    auth_type = Column(Text, default='disabled')
    auth_warning = Column(Text, default=None)
    is_qa = Column(Boolean, default=False)
    is_robot = Column(Boolean, default=False)
    is_analyst = Column(Boolean, default=False)
    is_vendor_manager = Column(Boolean, default=False)
    is_approved_public = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)
    agreement_id = Column(Integer, ForeignKey('agreements.agreement_id'))
    ctime = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    mtime = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    atime = Column(DateTime, default=None)
    dtime = Column(DateTime, default=None)
    human_user_id = Column(Integer, ForeignKey('users.user_id'), nullable=True)

    # link using foreign keys
    vendor = relationship('Vendor', foreign_keys=[vendor_id])
    agreement = relationship('Agreement', foreign_keys=[agreement_id])
    human_user = relationship('User', remote_side=[user_id])

    fws = relationship('Firmware',
                       order_by="desc(Firmware.timestamp)",
                       primaryjoin='Firmware.user_id==User.user_id')

    def __init__(self, username, password=None, display_name=None,
                 vendor_id=None, auth_type='disabled', is_analyst=False, is_qa=False,
                 is_admin=False, is_vendor_manager=False, is_approved_public=False):
        """ Constructor for object """
        self.username = username
        self.password = password
        self.display_name = display_name
        self.auth_type = auth_type
        self.is_analyst = is_analyst
        self.is_qa = is_qa
        self.vendor_id = vendor_id
        self.is_admin = is_admin
        self.is_vendor_manager = is_vendor_manager
        self.is_approved_public = is_approved_public

    def check_acl(self, action=None):

        # anyone who is an admin can do everything
        if self.is_admin:
            return True

        # disabled users can do nothing
        if self.auth_type == 'disabled':
            return False

        # decide based on the action
        if action == '@admin':
            return False
        elif action == '@view-profile':
            return self.auth_type == 'local'
        elif action == '@view-analytics':
            if self.is_qa or self.is_analyst:
                return True
            return False
        elif action == '@add-attribute-manager':
            if not self.vendor.check_acl('@manage-users'):
                return False
            return self.is_vendor_manager
        elif action == '@add-attribute-approved':
            if not self.vendor.check_acl('@manage-users'):
                return False
            return self.is_approved_public
        elif action == '@add-attribute-analyst':
            if not self.vendor.check_acl('@manage-users'):
                return False
            return self.is_analyst
        elif action == '@add-attribute-qa':
            if not self.vendor.check_acl('@manage-users'):
                return False
            return self.is_qa
        elif action == '@add-attribute-admin':
            if not self.vendor.check_acl('@manage-users'):
                return False
            return self.is_admin
        elif action == '@add-attribute-robot':
            return self.vendor.check_acl('@manage-users')
        elif action in ('@view-eventlog', '@view-issues'):
            return self.is_qa
        raise NotImplementedError('unknown security check type: %s' % self)

    def generate_password_recovery(self):
        if self.is_robot:
            raise RuntimeError('account is a robot')
        if self.auth_type == 'disabled':
            raise RuntimeError('account is locked')
        if self.auth_type == 'local+locked':
            raise RuntimeError('account is locked')
        if self.auth_type == 'oauth':
            raise RuntimeError('account set to OAuth only')
        self.mtime = datetime.datetime.utcnow()
        self.password_recovery = _password_hash(_generate_password())
        self.password_recovery_ts = datetime.datetime.utcnow()

    @property
    def is_authenticated(self):
        return True

    @property
    def email_address(self):
        if self.human_user:
            return self.human_user.username
        return self.username

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

class Restriction(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'restrictions'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    restriction_id = Column(Integer, primary_key=True, unique=True, nullable=False)
    vendor_id = Column(Integer, ForeignKey('vendors.vendor_id'), nullable=False)
    value = Column(Text, nullable=False)

    # link back to parent
    vendor = relationship("Vendor", back_populates="restrictions")

    def __init__(self, value=None):
        """ Constructor for object """
        self.value = value

    def __repr__(self):
        return "Restriction object %s" % self.restriction_id

class Affiliation(db.Model):

    # database
    __tablename__ = 'affiliations'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    affiliation_id = Column(Integer, primary_key=True, unique=True, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    vendor_id = Column(Integer, ForeignKey('vendors.vendor_id'), nullable=False)
    vendor_id_odm = Column(Integer, ForeignKey('vendors.vendor_id'), nullable=False)

    # link using foreign keys
    vendor = relationship("Vendor", foreign_keys=[vendor_id], back_populates="affiliations")
    vendor_odm = relationship("Vendor", foreign_keys=[vendor_id_odm])

    def __init__(self, vendor_id, vendor_id_odm):
        self.vendor_id = vendor_id
        self.vendor_id_odm = vendor_id_odm

    def __repr__(self):
        return "Affiliation object %s" % self.affiliation_id

class Vendor(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'vendors'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    vendor_id = Column(Integer, primary_key=True, unique=True)
    group_id = Column(Text, nullable=False, index=True)
    display_name = Column(Unicode, default=None)
    plugins = Column(Text, default=None)
    description = Column(Unicode, default=None)
    visible = Column(Boolean, default=False)
    visible_for_search = Column(Boolean, default=False)
    is_embargo_default = Column(Boolean, default=False)
    is_fwupd_supported = Column(String(16), nullable=False, default='no')
    is_account_holder = Column(String(16), nullable=False, default='no')
    is_uploading = Column(String(16), nullable=False, default='no')
    comments = Column(Unicode, default=None)
    icon = Column(Text, default=None)
    keywords = Column(Unicode, default=None)
    oauth_unknown_user = Column(Text, default=None)
    oauth_domain_glob = Column(Text, default=None)
    remote_id = Column(Integer, ForeignKey('remotes.remote_id'), nullable=False)
    username_glob = Column(Text, default=None)
    version_format = Column(String(10), default=None) # usually 'triplet' or 'quad'
    banned_country_codes = Column(Text, default=None) # ISO 3166, delimeter ','

    # magically get the users in this vendor group
    users = relationship("User",
                         back_populates="vendor",
                         cascade='all,delete-orphan')
    restrictions = relationship("Restriction",
                                back_populates="vendor",
                                cascade='all,delete-orphan')
    affiliations = relationship("Affiliation",
                                foreign_keys=[Affiliation.vendor_id],
                                back_populates="vendor",
                                cascade='all,delete-orphan')
    affiliations_for = relationship("Affiliation",
                                    foreign_keys=[Affiliation.vendor_id_odm],
                                    back_populates="vendor")
    fws = relationship("Firmware",
                       cascade='all,delete-orphan')

    # link using foreign keys
    remote = relationship('Remote',
                          foreign_keys=[remote_id],
                          single_parent=True,
                          cascade='all,delete-orphan')

    def __init__(self, group_id=None, remote_id=None):
        """ Constructor for object """
        self.group_id = group_id
        self.display_name = None
        self.plugins = None
        self.description = None
        self.visible = False
        self.is_fwupd_supported = None
        self.is_account_holder = None
        self.is_uploading = None
        self.comments = None
        self.icon = None
        self.keywords = None
        self.remote_id = remote_id

    def get_sort_key(self):
        val = 0
        if self.is_fwupd_supported == 'yes':
            val += 0x200
        if self.is_fwupd_supported == 'na':
            val += 0x100
        if self.is_account_holder == 'yes':
            val += 0x20
        if self.is_account_holder == 'na':
            val += 0x10
        if self.is_uploading == 'yes':
            val += 0x2
        if self.is_uploading == 'na':
            val += 0x1
        return val

    def is_affiliate_for(self, vendor_id):
        for rel in self.affiliations_for:
            if rel.vendor_id == vendor_id:
                return True
        return False

    def is_affiliate(self, vendor_id_odm):
        for rel in self.affiliations:
            if rel.vendor_id_odm == vendor_id_odm:
                return True
        return False

    def check_acl(self, action, user=None):

        # fall back
        if not user:
            user = g.user
        if user.is_admin:
            return True

        # depends on the action requested
        if action == '@upload':
            # all members of a group can upload to that group
            if user.vendor_id == self.vendor_id:
                return True
            # allow vendor affiliates too
            if self.is_affiliate(user.vendor_id):
                return True
            return False
        elif action == '@view-metadata':
            # all members of a group can generate the metadata file
            if user.vendor_id == self.vendor_id:
                return True
            return False
        elif action == '@manage-users':
            # manager user can modify any users in his group
            if user.is_vendor_manager and user.vendor_id == self.vendor_id:
                return True
            return False
        elif action == '@modify-oauth':
            return False
        elif action == '@view-affiliations':
            return user.is_qa
        elif action == '@modify-affiliations':
            return False
        raise NotImplementedError('unknown security check action: %s:%s' % (self, action))

    def __repr__(self):
        return "Vendor object %s" % self.group_id

class Event(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'event_log'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    id = Column(Integer, primary_key=True, nullable=False, unique=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    vendor_id = Column(Integer, ForeignKey('vendors.vendor_id'), nullable=False)
    address = Column('addr', String(40), nullable=False)
    message = Column(Unicode, default=None)
    is_important = Column(Integer, default=0)
    request = Column(Text, default=None)

    # link using foreign keys
    vendor = relationship('Vendor', foreign_keys=[vendor_id])
    user = relationship('User', foreign_keys=[user_id])

    def __init__(self, user_id, vendor_id=None, address=None, message=None,
                 request=None, is_important=False):
        """ Constructor for object """
        self.timestamp = None
        self.user_id = user_id
        self.vendor_id = vendor_id
        self.address = address
        self.message = message
        self.request = request
        self.is_important = is_important
    def __repr__(self):
        return "Event object %s" % self.message

class Requirement(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'requirements'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    requirement_id = Column(Integer, primary_key=True, unique=True)
    component_id = Column(Integer, ForeignKey('components.component_id'), nullable=False)
    kind = Column(Text, nullable=False)
    value = Column(Text, default=None)
    compare = Column(Text, default=None)
    version = Column(Text, default=None)

    # link back to parent
    md = relationship("Component", back_populates="requirements")

    def __init__(self, component_id=None, kind=None, value=None, compare=None, version=None):
        """ Constructor for object """
        self.kind = kind        # e.g. 'id', 'firmware' or 'hardware'
        self.value = value      # e.g. 'bootloader' or 'org.freedesktop.fwupd'
        self.compare = compare
        self.version = version
        self.component_id = component_id

    def __repr__(self):
        return "Requirement object %s/%s/%s/%s" % (self.kind, self.value, self.compare, self.version)

class Guid(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'guids'
    guid_id = Column(Integer, primary_key=True, unique=True, nullable=False)
    component_id = Column(Integer, ForeignKey('components.component_id'), nullable=False)
    value = Column(Text, nullable=False)

    # link back to parent
    md = relationship("Component", back_populates="guids")

    def __init__(self, component_id=None, value=None):
        """ Constructor for object """
        #self.guid_id = 0
        self.component_id = component_id
        self.value = value

    def __repr__(self):
        return "Guid object %s" % self.guid_id

class Keyword(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'keywords'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    keyword_id = Column(Integer, primary_key=True, unique=True, nullable=False)
    component_id = Column(Integer, ForeignKey('components.component_id'), nullable=False)
    priority = Column(Integer, default=0)
    value = Column(Unicode, nullable=False)

    # link back to parent
    md = relationship("Component", back_populates="keywords")

    def __init__(self, value, priority=0, md=None):
        """ Constructor for object """
        self.value = value
        self.priority = priority
        self.md = md

def _is_keyword_valid(value):
    if not len(value):
        return False
    if value.find('.') != -1:
        return False
    if value in ['a',
                 'bios',
                 'company',
                 'corporation',
                 'development',
                 'device',
                 'firmware',
                 'for',
                 'limited',
                 'system',
                 'the',
                 'update']:
        return False
    return True

def _sanitize_keyword(value):
    for rpl in ['(', ')', '[', ']', '*', '?']:
        value = value.replace(rpl, '')
    return value.strip().lower()

def _split_search_string(value):
    for delim in ['/', ',']:
        value = value.replace(delim, ' ')
    keywords = []
    for word in value.split(' '):
        keyword = _sanitize_keyword(word)
        if not _is_keyword_valid(keyword):
            continue
        if keyword in keywords:
            continue
        keywords.append(keyword)
    return keywords

class Component(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'components'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    component_id = Column(Integer, primary_key=True, unique=True, nullable=False, index=True)
    firmware_id = Column(Integer, ForeignKey('firmware.firmware_id'), nullable=False, index=True)
    checksum_contents = Column(String(40), nullable=False)
    appstream_id = Column(Text, nullable=False)
    name = Column(Unicode, default=None)
    summary = Column(Unicode, default=None)
    description = Column(Unicode, default=None)         # markdown format
    release_description = Column(Unicode, default=None) # markdown format
    url_homepage = Column(Unicode, default=None)
    metadata_license = Column(Text, default=None)
    project_license = Column(Text, default=None)
    developer_name = Column(Unicode, default=None)
    filename_contents = Column(Text, nullable=False)
    release_timestamp = Column(Integer, default=0)
    version = Column(Text, nullable=False)
    release_installed_size = Column(Integer, default=0)
    release_download_size = Column(Integer, default=0)
    release_urgency = Column(Text, default=None)
    screenshot_url = Column(Unicode, default=None)
    screenshot_caption = Column(Unicode, default=None)
    inhibit_download = Column(Boolean, default=False)
    version_format = Column(String(10), default=None) # usually 'triplet' or 'quad'
    priority = Column(Integer, default=0)
    install_duration = Column(Integer, default=0)

    # link back to parent
    fw = relationship("Firmware", back_populates="mds", lazy='joined')

    # include all Component objects
    requirements = relationship("Requirement",
                                back_populates="md",
                                cascade='all,delete-orphan')
    guids = relationship("Guid",
                         back_populates="md",
                         lazy='joined',
                         cascade='all,delete-orphan')
    keywords = relationship("Keyword",
                            back_populates="md",
                            cascade='all,delete-orphan')

    def __init__(self):
        """ Constructor for object """
        self.appstream_id = None            # e.g. com.hughski.ColorHug.firmware
        self.guids = []
        self.version = None
        self.name = None
        self.summary = None
        self.checksum_contents = None       # SHA1 of the firmware.bin
        self.release_description = None
        self.release_timestamp = 0
        self.developer_name = None
        self.metadata_license = None
        self.project_license = None
        self.url_homepage = None
        self.description = None
        self.filename_contents = None       # filename of the firmware.bin
        self.release_installed_size = 0
        self.release_download_size = 0
        self.release_urgency = None
        self.screenshot_url = None
        self.screenshot_caption = None
        self.priority = 0

    @property
    def developer_name_display(self):
        return self.developer_name.split(' ')[0]

    @property
    def name_display(self):
        return self.name.replace(' System Update', '')

    @property
    def version_display(self):
        if self.version.isdigit():
            v = int(self.version)
            if self.version_format == 'quad':
                return '%02i.%02i.%02i.%02i' % ((v & 0xff000000) >> 24,
                                                (v & 0x00ff0000) >> 16,
                                                (v & 0x0000ff00) >> 8,
                                                v & 0x000000ff)
            elif self.version_format == 'triplet':
                return '%02i.%02i.%04i' % ((v & 0xff000000) >> 24,
                                           (v & 0x00ff0000) >> 16,
                                           v & 0x0000ffff)
            elif self.version_format == 'pair':
                return '%02i.%02i' % ((v & 0xffff0000) >> 16, v & 0x0000ffff)
            elif self.version_format == 'intel-me':
                return '%i.%i.%i.%i' % (((v & 0xe0000000) >> 29) + 0x0b,
                                        (v & 0x1f000000) >> 24,
                                        (v & 0x00ff0000) >> 16,
                                        v &  0x0000ffff)
            elif self.version_format == 'intel-me2':
                return '%i.%i.%i.%i' % ((v & 0xf0000000) >> 28,
                                        (v & 0x0f000000) >> 24,
                                        (v & 0x00ff0000) >> 16,
                                        v &  0x0000ffff)
        return self.version

    @property
    def problems(self):

        # verify update description
        if self.release_description:
            root = _xml_from_markdown(self.release_description)
            problems = _get_update_description_problems(root)
        else:
            problems = []
            problems.append(Problem('invalid-release-description',
                                    'Release description is missing'))

        # check for OEMs just pasting in the XML like before
        for element_name in ['p', 'li', 'ul', 'ol']:
            if self.release_description.find('<' + element_name + '>') != -1:
                problems.append(Problem('invalid-release-description',
                                        'Release description cannot contain XML markup'))
                break
        if self.release_urgency == 'unknown':
            problems.append(Problem('no-release-urgency',
                                    'Release urgency has not been set'))

        # set the URL for the component
        for problem in problems:
            problem.url = url_for('.firmware_component_show',
                                  component_id=self.component_id,
                                  page='update')
        return problems

    def add_keywords_from_string(self, value, priority=0):
        existing_keywords = {}
        for kw in self.keywords:
            existing_keywords[kw.value] = kw
        for keyword in _split_search_string(value):
            if keyword in existing_keywords:
                continue
            self.keywords.append(Keyword(keyword, priority))

    def find_req(self, kind=None, value=None):
        """ Find a Requirement from the kind and/or value """
        for rq in self.requirements:
            if kind and rq.kind != kind:
                continue
            if value and rq.value != value:
                continue
            return rq
        return None

    def check_acl(self, action, user=None):

        # fall back
        if not user:
            user = g.user
        if user.is_admin:
            return True

        # depends on the action requested
        if action == '@modify-updateinfo':
            if not self.fw.remote.is_public:
                if user.is_qa and self.fw._is_vendor(user):
                    return True
                if self.fw._is_owner(user):
                    return True
            return False
        elif action in ('@modify-keywords', '@modify-requirements'):
            if user.is_qa and self.fw._is_vendor(user):
                return True
            if self.fw._is_owner(user) and not self.fw.remote.is_public:
                return True
            return False
        raise NotImplementedError('unknown security check action: %s:%s' % (self, action))

    def __repr__(self):
        return "Component object %s" % self.appstream_id

class Remote(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'remotes'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    remote_id = Column(Integer, primary_key=True, unique=True, nullable=False)
    name = Column(Text, nullable=False)
    is_public = Column(Boolean, default=False)
    is_dirty = Column(Boolean, default=False)

    # link using foreign keys
    vendors = relationship("Vendor", back_populates="remote")

    def check_fw(self, fw):
        # remote is specified exactly
        if self.remote_id == fw.remote.remote_id:
            return True
        # odm uploaded to oem remote, but also include for odm
        if not self.is_public and fw.user.vendor in self.vendors:
            return True
        return False

    @property
    def is_deleted(self):
        return self.name == 'deleted'

    @property
    def is_signed(self):
        return self.name != 'deleted' and self.name != 'private'

    @property
    def filename(self):
        if self.name == 'private':
            return None
        if self.name == 'stable':
            return 'firmware.xml.gz'
        if self.name == 'testing':
            return 'firmware-testing.xml.gz'
        return 'firmware-%s.xml.gz' % _qa_hash(self.name[8:])

    @property
    def scheduled_signing(self):
        now = datetime.datetime.now()
        secs = ((30 - (now.minute % 30)) * 60) + (60 - now.second)
        return datetime.datetime.now() + datetime.timedelta(seconds=secs)

    def __repr__(self):
        return "Remote object %s [%s]" % (self.remote_id, self.name)

class FirmwareEvent(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'firmware_events'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    firmware_event_id = Column(Integer, primary_key=True, unique=True, nullable=False)
    firmware_id = Column(Integer, ForeignKey('firmware.firmware_id'), nullable=False)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    remote_id = Column(Integer, ForeignKey('remotes.remote_id'), nullable=False)

    # link back to parent
    fw = relationship("Firmware", back_populates="events")

    # link using foreign keys
    user = relationship('User', foreign_keys=[user_id])
    remote = relationship('Remote', foreign_keys=[remote_id], lazy='joined')

    def __init__(self, remote_id=None, user_id=0, timestamp=None):
        """ Constructor for object """
        self.remote_id = remote_id
        self.user_id = user_id
        self.timestamp = timestamp

    def __repr__(self):
        return "FirmwareEvent object %s" % self.firmware_event_id

class FirmwareLimit(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'firmware_limits'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    firmware_limit_id = Column(Integer, primary_key=True, unique=True, nullable=False)
    firmware_id = Column(Integer, ForeignKey('firmware.firmware_id'), nullable=False)
    value = Column(Integer, nullable=False)
    user_agent_glob = Column(Text, default=None)
    response = Column(Text, default=None)

    # link back to parent
    fw = relationship("Firmware", back_populates="limits")

class Firmware(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'firmware'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    firmware_id = Column(Integer, primary_key=True, unique=True, nullable=False, index=True)
    vendor_id = Column(Integer, ForeignKey('vendors.vendor_id'), nullable=False)
    addr = Column(String(40), nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    filename = Column(Text, nullable=False)
    download_cnt = Column(Integer, default=0)
    checksum_upload = Column(String(40), nullable=False, index=True)
    _version_display = Column('version_display', Text, nullable=True, default=None)
    remote_id = Column(Integer, ForeignKey('remotes.remote_id'), nullable=False)
    checksum_signed = Column(String(40), nullable=False)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    signed_timestamp = Column(DateTime, default=None)
    is_dirty = Column(Boolean, default=False)   # waiting to be included in metadata

    # include all Component objects
    mds = relationship("Component",
                       back_populates="fw",
                       lazy='joined',
                       cascade='all,delete-orphan')
    events = relationship("FirmwareEvent",
                          back_populates="fw",
                          cascade='all,delete-orphan')
    reports = relationship("Report",
                           back_populates="fw",
                           cascade='all,delete-orphan')
    clients = relationship("Client",
                           back_populates="fw",
                           cascade='all,delete-orphan')
    limits = relationship("FirmwareLimit",
                          back_populates="fw",
                          cascade='all,delete-orphan')

    # link using foreign keys
    vendor = relationship('Vendor', foreign_keys=[vendor_id])
    user = relationship('User', foreign_keys=[user_id])
    remote = relationship('Remote', foreign_keys=[remote_id], lazy='joined')

    @property
    def target_duration(self):
        if not self.events:
            return 0
        return datetime.datetime.utcnow() - self.events[-1].timestamp

    @property
    def is_deleted(self):
        return self.remote.is_deleted

    @property
    def inhibit_download(self):
        for md in self.mds:
            if md.inhibit_download:
                return True
        return False

    @property
    def scheduled_signing(self):
        now = datetime.datetime.now()
        secs = ((5 - (now.minute % 5)) * 60) + (60 - now.second)
        return datetime.datetime.now() + datetime.timedelta(seconds=secs)

    @property
    def version_display(self):
        if self._version_display:
            return self._version_display
        md_versions = []
        for md in self.mds:
            if md.version_display not in md_versions:
                md_versions.append(md.version_display)
        return ', '.join(md_versions)

    @version_display.setter
    def version_display(self, value):
        self._version_display = value

    @property
    def problems(self):
        # does the firmware have any warnings
        problems = []
        if self.is_deleted:
            problem = Problem('deleted')
            problem.url = url_for('.firmware_show', firmware_id=self.firmware_id)
            problems.append(problem)
        if not self.signed_timestamp:
            problem = Problem('unsigned')
            problem.url = url_for('.firmware_show', firmware_id=self.firmware_id)
            problems.append(problem)
        for md in self.mds:
            problems.extend(md.problems)
        return problems

    def __init__(self):
        """ Constructor for object """
        self.addr = None
        self.timestamp = None
        self.filename = None        # filename of the original .cab file
        self.checksum_upload = None # SHA1 of the original .cab file
        self._version_display = None # from the firmware.inf file
        self.download_cnt = 0       # generated from the client database
        self.checksum_signed = None # SHA1 of the signed .cab
        self.user_id = None         # user_id of the uploader
        self.mds = []

    def _is_owner(self, user):
        return self.user_id == user.user_id

    def _is_vendor(self, user):
        return self.vendor_id == user.vendor_id

    def check_acl(self, action, user=None):

        # fall back
        if not user:
            user = g.user
        if user.is_admin:
            return True

        # depends on the action requested
        if action == '@delete':
            if self.is_deleted:
                return False
            if user.is_qa and self._is_vendor(user):
                return True
            if self._is_owner(user) and not self.remote.is_public:
                return True
            return False
        elif action == '@nuke':
            if not self.is_deleted:
                return False
            return False
        elif action == '@view':
            if user.is_qa and self._is_vendor(user):
                return True
            if user.is_analyst and self._is_vendor(user):
                return True
            if self._is_owner(user):
                return True
            return False
        elif action == '@view-analytics':
            if not self.check_acl('@view', user):
                return False
            if user.is_qa or user.is_analyst:
                return True
            return False
        elif action == '@undelete':
            if user.is_qa and self._is_vendor(user):
                return True
            if self._is_owner(user):
                return True
            return False
        elif action in ('@promote-stable', '@promote-testing'):
            if user.is_approved_public and self._is_vendor(user):
                return True
            return False
        elif action.startswith('@promote-'):
            if user.is_qa and self._is_vendor(user):
                return True
            # is original file uploader can move private<->embargo
            if self._is_owner(user):
                old = self.remote.name
                if old.startswith('embargo-'):
                    old = 'embargo'
                new = action[9:]
                if new.startswith('embargo-'):
                    new = 'embargo'
                if old in ('private', 'embargo') and new in ('private', 'embargo'):
                    return True
            return False
        elif action == '@add-limit':
            if user.is_qa and self._is_vendor(user):
                return True
            if self._is_owner(user):
                return True
            return False
        elif action == '@remove-limit':
            if user.is_qa and self._is_vendor(user):
                return True
            return False
        elif action == '@modify-affiliation':
            if not self.vendor.affiliations_for:
                return False
            # is original file uploader and uploaded to ODM group
            if self._is_owner(user) and self._is_vendor(user):
                return True
            # is QA user for the current assigned vendor
            if user.is_qa and self._is_vendor(user):
                return True
            return False
        raise NotImplementedError('unknown security check action: %s:%s' % (self, action))

    def __repr__(self):
        return "Firmware object %s" % self.checksum_upload

class Client(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'clients'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    id = Column(Integer, primary_key=True, nullable=False, unique=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.utcnow, index=True)
    addr = Column(String(40), nullable=False)
    firmware_id = Column(Integer, ForeignKey('firmware.firmware_id'), nullable=False, index=True)
    user_agent = Column(Text, default=None)

    # link using foreign keys
    fw = relationship('Firmware', foreign_keys=[firmware_id])

    def __init__(self, addr=None, firmware_id=None, user_agent=None, timestamp=None):
        """ Constructor for object """
        self.timestamp = timestamp
        self.addr = addr
        self.firmware_id = firmware_id
        self.user_agent = user_agent

    def __repr__(self):
        return "Client object %s" % self.id

class Condition(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'conditions'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    condition_id = Column(Integer, primary_key=True, nullable=False, unique=True)
    issue_id = Column(Integer, ForeignKey('issues.issue_id'), nullable=False)
    key = Column(Text, nullable=False)
    value = Column(Text, nullable=False)
    compare = Column(Text, default='eq', nullable=False)

    # link back to parent
    issue = relationship("Issue", back_populates="conditions")

    def matches(self, value):
        if self.compare == 'eq':
            return value == self.value
        if self.compare == 'lt':
            return AppStreamGlib.utils_vercmp(value, self.value) < 0
        if self.compare == 'le':
            return AppStreamGlib.utils_vercmp(value, self.value) <= 0
        if self.compare == 'gt':
            return AppStreamGlib.utils_vercmp(value, self.value) > 0
        if self.compare == 'ge':
            return AppStreamGlib.utils_vercmp(value, self.value) >= 0
        if self.compare == 'glob':
            return fnmatch.fnmatch(value, self.value)
        if self.compare == 'regex':
            return re.search(self.value, value)
        return False

    @property
    def relative_cost(self):
        if self.compare == 'eq':
            return 0
        if self.compare in ['lt', 'le', 'gt', 'ge']:
            return 1
        if self.compare == 'glob':
            return 5
        if self.compare == 'regex':
            return 10
        return False

    def __init__(self, issue_id=0, key=None, value=None, compare='eq'):
        """ Constructor for object """
        self.issue_id = issue_id
        self.key = key
        self.value = value
        self.compare = compare

    def __repr__(self):
        return "Condition object %s %s %s" % (self.key, self.compare, self.value)

class Issue(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'issues'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    issue_id = Column(Integer, primary_key=True, nullable=False, unique=True)
    priority = Column(Integer, default=0)
    enabled = Column(Boolean, default=False)
    vendor_id = Column(Integer, ForeignKey('vendors.vendor_id'), nullable=False)
    url = Column(Text, default='')
    name = Column(Text, default=None)
    description = Column(Text, default='')
    conditions = relationship("Condition",
                              back_populates="issue",
                              cascade='all,delete-orphan')

    # link using foreign keys
    vendor = relationship('Vendor', foreign_keys=[vendor_id])

    def __init__(self, url=None, name=None, description=None, enabled=False, vendor_id=None, priority=0):
        """ Constructor for object """
        self.url = url
        self.name = name
        self.enabled = enabled
        self.priority = priority
        self.description = description
        self.enabled = enabled
        self.vendor_id = vendor_id
        self.priority = priority

    def matches(self, data):
        """ if all conditions are satisfied from data """
        for condition in sorted(self.conditions, key=lambda x: x.relative_cost):
            if not condition.key in data:
                return False
            if not condition.matches(data[condition.key]):
                return False
        return True

    def check_acl(self, action, user=None):

        # fall back
        if not user:
            user = g.user
        if user.is_admin:
            return True

        # depends on the action requested
        if action == '@create':
            return user.is_qa
        elif action == '@modify':
            if user.is_qa and user.vendor_id == self.vendor_id:
                return True
            return False
        elif action == '@view':
            if user.is_qa and user.vendor_id == self.vendor_id:
                return True
            # any issues owned by admin can be viewed by a QA user
            if user.is_qa and self.vendor_id == 1:
                return True
            return False
        raise NotImplementedError('unknown security check action: %s:%s' % (self, action))

    def __repr__(self):
        return "Issue object %s" % self.url

class ReportAttribute(db.Model):
    __tablename__ = 'report_attributes'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    report_attribute_id = Column(Integer, primary_key=True, nullable=False, unique=True)
    report_id = Column(Integer, ForeignKey('reports.report_id'), nullable=False)
    key = Column(Text, nullable=False)
    value = Column(Text, default=None)

    # link back to parent
    report = relationship("Report", back_populates="attributes")

    def __init__(self, report_id=0, key=None, value=None):
        """ Constructor for object """
        self.report_id = report_id
        self.key = key
        self.value = value

    def __repr__(self):
        return "ReportAttribute object %s=%s" % (self.key, self.value)

class Report(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'reports'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    report_id = Column(Integer, primary_key=True, nullable=False, unique=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    state = Column(Integer, default=0)
    machine_id = Column(String(64), nullable=False)
    firmware_id = Column(Integer, ForeignKey('firmware.firmware_id'), nullable=False, index=True)
    checksum = Column(String(64), nullable=False) #fixme remove?
    issue_id = Column(Integer, default=0)

    # link using foreign keys
    fw = relationship('Firmware', foreign_keys=[firmware_id])
    attributes = relationship("ReportAttribute",
                              back_populates="report",
                              cascade='all,delete-orphan')

    def __init__(self, firmware_id, machine_id=None, state=0, checksum=None, issue_id=0):
        """ Constructor for object """
        self.timestamp = None
        self.state = state
        self.machine_id = machine_id
        self.firmware_id = firmware_id
        self.issue_id = issue_id
        self.checksum = checksum

    def to_flat_dict(self):
        data = {}
        if self.state == 1:
            data['UpdateState'] = 'pending'
        elif self.state == 2:
            data['UpdateState'] = 'success'
        elif self.state == 3:
            data['UpdateState'] = 'failed'
        elif self.state == 4:
            data['UpdateState'] = 'needs-reboot'
        else:
            data['UpdateState'] = 'unknown'
        if self.machine_id:
            data['MachineId'] = self.machine_id
        if self.firmware_id:
            data['FirmwareId'] = self.firmware_id
        for attr in self.attributes:
            data[attr.key] = attr.value
        return data

    def to_kvs(self):
        flat_dict = self.to_flat_dict()
        kv_array = []
        for key in flat_dict:
            kv_array.append('%s=%s' % (key, flat_dict[key]))
        return ', '.join(sorted(kv_array))

    def check_acl(self, action, user=None):

        # fall back
        if not user:
            user = g.user
        if user.is_admin:
            return True

        # depends on the action requested
        if action == '@delete':
            # only admin
            return False
        elif action == '@view':
            # QA user can modify any issues matching vendor_id
            if user.is_qa and self.fw._is_vendor(user):
                return True
            return False
        raise NotImplementedError('unknown security check action: %s:%s' % (self, action))

    def __repr__(self):
        return "Report object %s" % self.report_id

class Setting(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'settings'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    setting_id = Column(Integer, primary_key=True, nullable=False, unique=True)
    key = Column('config_key', Text)
    value = Column('config_value', Text)

    def __init__(self, key, value=None):
        """ Constructor for object """
        self.key = key
        self.value = value
    def __repr__(self):
        return "Setting object %s" % self.key

def _get_datestr_from_datetime(when):
    return int("%04i%02i%02i" % (when.year, when.month, when.day))

class Analytic(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'analytics'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    datestr = Column(Integer, primary_key=True, unique=True, default=0, index=True)
    cnt = Column(Integer, default=1)

    def __init__(self, datestr=0):
        """ Constructor for object """
        self.cnt = 1
        self.datestr = datestr

    def __repr__(self):
        return "Analytic object %s" % self.datestr

class Useragent(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'useragents'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    useragent_id = Column(Integer, primary_key=True, nullable=False, unique=True)
    datestr = Column(Integer, default=0)
    value = Column(Text, default=None)
    cnt = Column(Integer, default=1)

    def __init__(self, value, datestr=0, cnt=1):
        """ Constructor for object """
        self.value = value
        self.cnt = cnt
        self.datestr = datestr

    def __repr__(self):
        return "Useragent object %i:%s" % (self.kind, self.datestr)


class SearchEvent(db.Model):

    # sqlalchemy metadata
    __tablename__ = 'search_events'
    __table_args__ = {'mysql_character_set': 'utf8mb4'}

    search_event_id = Column(Integer, primary_key=True, unique=True, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    addr = Column(String(40), nullable=False)
    value = Column(Unicode, nullable=False)
    count = Column(Integer, default=0)
    method = Column(Text, default=None)

    def __init__(self, value, addr=None, timestamp=None, count=0, method=None):
        """ Constructor for object """
        self.value = value
        self.addr = addr
        self.timestamp = timestamp
        self.count = count
        self.method = method

    def __repr__(self):
        return "SearchEvent object %s" % self.search_event_id
