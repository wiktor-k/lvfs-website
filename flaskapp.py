#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os
import gzip
from datetime import datetime
from flask import Flask, session, request, flash, url_for, redirect, \
     render_template, abort, send_from_directory

if not 'OPENSHIFT_PYTHON_DIR' in os.environ:
    STATIC_DIR = 'static'
    UPLOAD_DIR = 'uploads'
    DOWNLOAD_DIR = 'downloads'
    KEYRING_DIR = 'gnupg'
    BACKUP_DIR = 'backup'
    CABEXTRACT_CMD = '/usr/bin/cabextract'
else:
    STATIC_DIR = os.path.join(os.environ['OPENSHIFT_REPO_DIR'], 'static')
    UPLOAD_DIR = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'uploads')
    DOWNLOAD_DIR = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'downloads')
    KEYRING_DIR = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'gnupg')
    BACKUP_DIR = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'backup')

    # this needs to be setup using:
    # cd app-root/data/
    # wget http://www.cabextract.org.uk/cabextract-1.6.tar.gz
    # tar xvfz cabextract-1.6.tar.gz
    # cd cabextract-1.6 && ./configure --prefix=/tmp && make
    # rm cabextract-1.6.tar.gz
    CABEXTRACT_CMD = os.path.join(os.environ['OPENSHIFT_DATA_DIR'],
                                  'cabextract-1.6',
                                  'cabextract')

import hashlib
import math
import glob
import calendar
import datetime
import ConfigParser

import cabarchive
import appstream
from affidavit import Affidavit, NoKeyError
from db import LvfsDatabase, CursorError
from db_clients import LvfsDatabaseClients, LvfsDownloadKind
from db_eventlog import LvfsDatabaseEventlog
from db_firmware import LvfsDatabaseFirmware, LvfsFirmware, LvfsFirmwareMd
from db_users import LvfsDatabaseUsers, _password_hash
from inf_parser import InfParser

def _qa_hash(value):
    """ Generate a salted hash of the QA group """
    salt = 'vendor%%%'
    return hashlib.sha1(salt + value).hexdigest()

def sizeof_fmt(num, suffix='B'):
    """ Generate user-visible size """
    if not type(num) in (int, long):
        return "???%s???" % num
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

def _password_check(value):
    """ Check the password for suitability """
    if len(value) < 8:
        return 'The password is too short, the minimum is 8 characters'
    if len(value) > 40:
        return 'The password is too long, the maximum is 40 characters'
    if value.lower() == value:
        return 'The password requires at least one uppercase character'
    if value.isalnum():
        return 'The password requires at least one non-alphanumeric character'
    return None

def _email_check(value):
    """ Do a quick and dirty check on the email address """
    if len(value) < 5 or value.find('@') == -1 or value.find('.') == -1:
        return 'Invalid email address'
    return None

def _get_chart_labels_months():
    """ Gets the chart labels """
    now = datetime.date.today()
    labels = []
    offset = 0
    for i in range(0, 12):
        if now.month - i == 0:
            offset = 1
        labels.append(calendar.month_name[now.month - i - offset])
    return labels

def _get_chart_labels_days():
    """ Gets the chart labels """
    now = datetime.date.today()
    labels = []
    for i in range(0, 30):
        then = now - datetime.timedelta(i)
        labels.append("%02i-%02i-%02i" % (then.year, then.month, then.day))
    return labels

def _get_chart_labels_hours():
    """ Gets the chart labels """
    labels = []
    for i in range(0, 24):
        labels.append("%02i" % i)
    return labels

def _to_javascript_array(arr):
    tmp = '['
    for a in arr:
        if type(a) == unicode:
            tmp += '"' + a + '",'
        elif type(a) == long:
            tmp += str(a) + ','
        else:
            tmp += '"' + str(a) + '",'
    if len(tmp) > 1:
        tmp = tmp[:-1]
    tmp += ']'
    return tmp

def _get_client_address():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    else:
        return request.remote_addr

def _event_log(msg, is_important=False):
    """ Adds an item to the event log """
    username = None
    qa_group = None
    if 'username' in session:
        username = session['username']
    if not username:
        username = 'anonymous'
    if 'qa_group' in session:
        qa_group = session['qa_group']
    if not qa_group:
        qa_group = 'admin'
    db = LvfsDatabase(os.environ)
    db_eventlog = LvfsDatabaseEventlog(db)
    db_eventlog.add(msg, username, qa_group,
                    _get_client_address(), is_important)

def _check_session():
    if not 'username' in session:
        abort(401)
    if not 'qa_group' in session:
        abort(401)
    if not 'qa_capability' in session:
        abort(401)
    if not 'is_locked' in session:
        abort(401)

def create_affidavit():
    """ Create an affidavit that can be used to sign files """
    db = LvfsDatabase(os.environ)
    db_users = LvfsDatabaseUsers(db)
    key_uid = db_users.get_signing_uid()
    return Affidavit(key_uid, KEYRING_DIR)

def _create_backup(filename, include_clients=False):
    """ Create a checkpoint """

    # ensure directory exists
    if not os.path.exists(BACKUP_DIR):
        os.mkdir(BACKUP_DIR)

    # does the file already exists right now?
    if os.path.exists(filename):
        return False

    # save
    db = LvfsDatabase(os.environ)
    content = db.generate_backup(include_clients)
    with gzip.open(filename, 'wb') as f:
        f.write(content)
    return True

def ensure_checkpoint():
    """ Create a checkpoint """

    # checkpointing happens up to once per minute
    now = datetime.datetime.now()
    filename = BACKUP_DIR + "/restore_" + now.strftime("%Y%m%d%H%M") + ".sql.gz"
    if _create_backup(filename):
        db = LvfsDatabase(os.environ)
        db_eventlog = LvfsDatabaseEventlog(db)
        db_eventlog.add('Created restore checkpoint', session['username'], 'admin',
                        _get_client_address(), False)

    # full backups happens up to once per week
    now = datetime.datetime.now()
    filename = BACKUP_DIR + "/backup_week" + now.strftime("%W") + ".sql.gz"
    if _create_backup(filename, True):
        db = LvfsDatabase(os.environ)
        db_eventlog = LvfsDatabaseEventlog(db)
        db_eventlog.add('Created weekly backup', session['username'], 'admin',
                        _get_client_address(), False)

def _generate_metadata_kind(filename, targets=None, qa_group=None):
    """ Generates AppStream metadata of a specific kind """
    try:
        db = LvfsDatabase(os.environ)
        db_firmware = LvfsDatabaseFirmware(db)
        items = db_firmware.get_items()
    except CursorError as e:
        return error_internal(str(e))
    store = appstream.Store('lvfs')
    for item in items:

        # filter
        if item.target == 'private':
            continue
        if targets and item.target not in targets:
            continue
        if qa_group and qa_group != item.qa_group:
            continue

        # add each component
        for md in item.mds:
            component = appstream.Component()
            component.id = md.cid
            component.kind = 'firmware'
            component.name = md.name
            component.summary = md.summary
            component.description = md.description
            if md.url_homepage:
                component.urls['homepage'] = md.url_homepage
            component.metadata_license = md.metadata_license
            component.project_license = md.project_license
            component.developer_name = md.developer_name

            # add provide
            if md.guid:
                prov = appstream.Provide()
                prov.kind = 'firmware-flashed'
                prov.value = md.guid
                component.add_provide(prov)


            # add release
            if md.version:
                rel = appstream.Release()
                rel.version = md.version
                rel.description = md.release_description
                if md.release_timestamp:
                    rel.timestamp = md.release_timestamp
                rel.checksums = []
                rel.location = 'https://secure-lvfs.rhcloud.com/downloads/' + item.filename
                rel.size_installed = md.release_installed_size
                rel.size_download = md.release_download_size
                component.add_release(rel)

                # add container checksum
                if md.checksum_container:
                    csum = appstream.Checksum()
                    csum.target = 'container'
                    csum.value = md.checksum_container
                    csum.filename = item.filename
                    rel.add_checksum(csum)

                # add content checksum
                if md.checksum_contents:
                    csum = appstream.Checksum()
                    csum.target = 'content'
                    csum.value = md.checksum_contents
                    csum.filename = md.filename_contents
                    rel.add_checksum(csum)

            # add component
            store.add(component)

    # dump to file
    if not os.path.exists(DOWNLOAD_DIR):
        os.mkdir(DOWNLOAD_DIR)
    filename = os.path.join(DOWNLOAD_DIR, filename)
    store.to_file(filename)

    # create .asc file
    affidavit = create_affidavit()
    affidavit.create_detached(filename)

    # log
    if targets:
        _event_log("Generated metadata for %s target" % ', '.join(targets))
    if qa_group:
        _event_log("Generated metadata for %s QA group" % qa_group)

def update_metadata_by_qa_group(qa_group):
    """ updates metadata for a specific qa_group """

    # explicit
    if qa_group:
        filename = 'firmware-%s.xml.gz' % _qa_hash(qa_group)
        _generate_metadata_kind(filename, qa_group=qa_group)
        return

    # do for all
    try:
        db = LvfsDatabase(os.environ)
        db_firmware = LvfsDatabaseFirmware(db)
        qa_groups = db_firmware.get_qa_groups()
    except CursorError as e:
        return error_internal(str(e))
    for qa_group in qa_groups:
        filename = 'firmware-%s.xml.gz' % _qa_hash(qa_group)
        _generate_metadata_kind(filename, qa_group=qa_group)

def update_metadata_by_targets(targets):
    """ updates metadata for a specific target """
    for target in targets:
        if target == 'stable':
            filename = 'firmware.xml.gz'
            _generate_metadata_kind(filename, targets=['stable'])
        elif target == 'testing':
            filename = 'firmware-testing.xml.gz'
            _generate_metadata_kind(filename, targets=['stable', 'testing'])

################################################################################

app = Flask(__name__)
app.config.from_pyfile('flaskapp.cfg')

@app.errorhandler(404)
def error_page_not_found(msg=None):
    """ Error handler: File not found """
    return render_template('error.html', error_msg=msg), 404

@app.errorhandler(401)
def error_permission_denied(msg=None):
    """ Error handler: Permission Denied """
    _event_log("Permission denied: %s" % msg, is_important=True)
    return render_template('error.html', error_msg=msg), 401

@app.errorhandler(402)
def error_internal(msg=None):
    """ Error handler: Internal """
    _event_log("Internal error: %s" % msg, is_important=True)
    return render_template('error.html', error_msg=msg), 402

################################################################################

@app.route('/')
def fwupd_index():
    """ Main fwupd.org site """
    return render_template('fwupd/index.html')

@app.route('/users')
def fwupd_users():
    """ User-centric fwupd help """
    return render_template('fwupd/users.html')

@app.route('/developers')
def fwupd_developers():
    """ Developer-centric fwupd help """
    return render_template('fwupd/developers.html')

@app.route('/vendors')
def fwupd_vendors():
    """ Vendor-centric fwupd help """
    return render_template('fwupd/vendors.html')

################################################################################

@app.route('/lvfs')
def lvfs_index(error_msg=None):
    """
    The main page that shows existing firmware and also allows the
    user to add new firmware.
    """
    if not 'username' in session:
        return redirect(url_for('lvfs_login'))

    return render_template('lvfs/index.html', error_msg=error_msg)

@app.route('/lvfs/newaccount')
def lvfs_new_account():
    """ New account page for prospective vendors """
    return render_template('lvfs/new-account.html')

@app.route('/lvfs/metadata')
def lvfs_metadata():
    """
    Show all metadata available to this user.
    """

    # security check
    _check_session()

    # show static lists based on QA group
    qa_url = '/downloads/firmware-%s.xml.gz' % _qa_hash(session['qa_group'])
    qa_disp = 'firmware-%s&hellip;.xml.gz' % _qa_hash(session['qa_group'])[0:8]
    return render_template('lvfs/metadata.html',
                           qa_group=session['qa_group'],
                           qa_url=qa_url,
                           qa_desc=qa_disp)

@app.route('/lvfs/devicelist')
def lvfs_device_list():
    # add devices in stable or testing
    try:
        db = LvfsDatabase(os.environ)
        db_firmware = LvfsDatabaseFirmware(db)
        items = db_firmware.get_items()
    except CursorError as e:
        return error_internal(str(e))

    # get a sorted list of vendors
    vendors = []
    for item in items:
        if item.target != 'stable':
            continue
        vendor = item.mds[0].developer_name
        if vendor in vendors:
            continue
        vendors.append(vendor)

    html = ''
    seen_guid = {}
    for vendor in sorted(vendors):

        html += '<h2>%s</h2>\n' % vendor
        html += '<ul>\n'
        for item in items:
            if item.target != 'stable':
                continue

            for md in item.mds:

                # only show correct vendor
                if vendor != md.developer_name:
                    continue

                # only show the newest version
                if md.guid in seen_guid:
                    continue
                seen_guid[md.guid] = 1

                # show name and version
                version = item.version_display
                if not version:
                    version = md.version
                url = '/downloads/' + item.filename
                html += '<li><a href="%s">%s %s</a></li>\n' % (url, md.name, version)
        html += '</ul>\n'
    return render_template('lvfs/devicelist.html', dyncontent=html)

@app.route('/lvfs/upload', methods=['GET', 'POST'])
def lvfs_upload():
    """ Upload a .cab file to the LVFS service """

    # only accept form data
    if request.method != 'POST':
        return redirect(url_for('lvfs_index'))

    # security check
    _check_session()

    # not correct parameters
    if not 'target' in request.form:
        return error_internal('No target')
    if not 'file' in request.files:
        return error_internal('No file')

    # can the user upload directly to stable
    if request.form['target'] in ['stable', 'testing']:
        if not session['qa_capability']:
            return error_permission_denied('Unable to upload to this target as not QA user')

    # check size < 50Mb
    fileitem = request.files['file']
    if not fileitem:
        return error_internal('No file object')
    data = fileitem.read()
    if len(data) > 50000000:
        # set response code = '413 Payload Too Large')
        return error_internal('File too large, limit is 50Mb')
    if len(data) == 0:
        return error_internal('File has no content')
    if len(data) < 1024:
        return error_internal('File too small, mimimum is 1k')

    # check the file does not already exist
    db = LvfsDatabase(os.environ)
    db_firmware = LvfsDatabaseFirmware(db)
    fwid = hashlib.sha1(data).hexdigest()
    try:
        item = db_firmware.get_item(fwid)
    except CursorError as e:
        return error_internal(str(e))
    if item:
        # set response code = '422 Entity Already Exists')
        return error_internal("A firmware file with hash %s already exists" % fwid)

    # parse the file
    arc = cabarchive.CabArchive()
    arc.set_decompressor(CABEXTRACT_CMD)
    try:
        arc.parse(data)
    except cabarchive.CorruptionError as e:
        # set response code = '415 Unsupported Media Type')
        return error_internal('Invalid file type: %s' % str(e))
    except cabarchive.NotSupportedError as e:
        # set response code = '415 Unsupported Media Type')
        return error_internal('The file is unsupported: %s' % str(e))

    # check .inf exists
    fw_version_inf = None
    fw_version_display_inf = None
    cf = arc.find_file("*.inf")
    if cf:
        if cf.contents.find('FIXME') != -1:
            return error_internal("The inf file was not complete; "
                                  "Any FIXME text must be replaced with the correct values.")

        # check .inf file is valid
        cfg = InfParser()
        cfg.read_data(cf.contents)
        try:
            tmp = cfg.get('Version', 'Class')
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError) as e:
            return error_internal('The inf file Version:Class was missing')
        if not tmp == 'Firmware':
            return error_internal('The inf file Version:Class was invalid')
        try:
            tmp = cfg.get('Version', 'ClassGuid')
        except ConfigParser.NoOptionError as e:
            return error_internal('The inf file Version:ClassGuid was missing')
        if not tmp == '{f2e7dd72-6468-4e36-b6f1-6488f42c1b52}':
            return error_internal('The inf file Version:ClassGuid was invalid')
        try:
            tmp = cfg.get('Version', 'DriverVer')
            fw_version_display_inf = tmp.split(',')
            if len(fw_version_display_inf) != 2:
                return error_internal('The inf file Version:DriverVer was invalid')
        except ConfigParser.NoOptionError as e:
            pass

        # this is optional, but if supplied must match the version in the XML
        # -- also note this will not work with multi-firmware .cab files
        try:
            fw_version_inf = cfg.get('Firmware_AddReg', 'HKR->FirmwareVersion')
            if fw_version_inf.startswith('0x'):
                fw_version_inf = str(int(fw_version_inf[2:], 16))
            if fw_version_inf == '0':
                fw_version_inf = None
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError) as e:
            pass

    # check metainfo exists
    cfs = arc.find_files("*.metainfo.xml")
    if len(cfs) == 0:
        return error_internal('The firmware file had no .metadata.xml files')

    # parse each MetaInfo file
    apps = []
    for cf in cfs:
        app = appstream.Component()
        try:
            app.parse(str(cf.contents))
            app.validate()
        except appstream.ParseError as e:
            return error_internal('The metadata could not be parsed: ' + str(e))
        except appstream.ValidationError as e:
            return error_internal('The metadata file did not validate: ' + str(e))

        # check the file does not have any missing request.form
        if cf.contents.find('FIXME') != -1:
            return error_internal("The metadata file was not complete; "
                                  "Any FIXME text must be replaced with the correct values.")

        # check the firmware provides something
        if len(app.provides) == 0:
            return error_internal("The metadata file did not provide any GUID.")
        if len(app.releases) == 0:
            return error_internal("The metadata file did not provide any releases.")

        # check the inf file matches up with the .xml file
        if fw_version_inf and fw_version_inf != app.releases[0].version:
            return error_internal("The inf Firmware_AddReg[HKR->FirmwareVersion] "
                                  "'%s' did not match the metainfo.xml value '%s'."
                                  % (fw_version_inf, app.releases[0].version))

        # check the guid and version does not already exist
        try:
            items = db_firmware.get_items()
        except CursorError as e:
            return error_internal(str(e))
        for item in items:
            for md in item.mds:
                if md.guid == app.provides[0].value and md.version == app.releases[0].version:
                    # set response code = '422 Entity Already Exists')
                    return error_internal("A firmware file for this version already exists")

        # check the ID hasn't been reused by a different GUID
        for item in items:
            for md in item.mds:
                if md.cid == app.id and not md.guid == app.provides[0].value:
                    # set response code = '422 Entity Already Exists')
                    return error_internal("The %s ID has already been used by GUID %s" % (md.cid, md.guid))

        # add to array
        apps.append(app)

    # only save if we passed all tests
    basename = os.path.basename(fileitem.filename)
    new_filename = fwid + '-' + basename
    if not os.path.exists(UPLOAD_DIR):
        os.mkdir(UPLOAD_DIR)
    open(os.path.join(UPLOAD_DIR, new_filename), 'wb').write(data)

    # fix up the checksums and add the detached signature
    for app in apps:

        # ensure there's always a container checksum
        release = app.releases[0]
        csum = release.get_checksum_by_target('content')
        if not csum:
            csum = appstream.Checksum()
            csum.target = 'content'
            csum.filename = 'firmware.bin'
            app.releases[0].add_checksum(csum)

        # get the contents checksum
        fw_data = arc.find_file(csum.filename)
        if not fw_data:
            return error_internal('No %s found in the archive' % csum.filename)
        csum.kind = 'sha1'
        csum.value = hashlib.sha1(fw_data.contents).hexdigest()

        # set the sizes
        release.size_installed = len(fw_data.contents)
        release.size_download = len(data)

        # add the detached signature if not already signed
        sig_data = arc.find_file(csum.filename + ".asc")
        if not sig_data:
            try:
                affidavit = create_affidavit()
            except NoKeyError as e:
                return error_internal('Failed to sign archive: ' + str(e))
            cff = cabarchive.CabFile(fw_data.filename + '.asc',
                                     affidavit.create(fw_data.contents))
            arc.add_file(cff)
        else:
            # check this file is signed by something we trust
            try:
                affidavit = create_affidavit()
                affidavit.verify(fw_data.contents)
            except NoKeyError as e:
                return error_internal('Failed to verify archive: ' + str(e))

    # export the new archive and get the checksum
    cab_data = arc.save(compressed=True)
    checksum_container = hashlib.sha1(cab_data).hexdigest()

    # dump to a file
    if not os.path.exists(DOWNLOAD_DIR):
        os.mkdir(DOWNLOAD_DIR)
    fn = os.path.join(DOWNLOAD_DIR, new_filename)
    open(fn, 'wb').write(cab_data)

    # create parent firmware object
    target = request.form['target']
    fwobj = LvfsFirmware()
    fwobj.qa_group = session['qa_group']
    fwobj.addr = _get_client_address()
    fwobj.filename = new_filename
    fwobj.fwid = fwid
    fwobj.target = target
    if fw_version_display_inf:
        fwobj.version_display = fw_version_display_inf[1]

    # create child metadata object for the component
    for app in apps:
        md = LvfsFirmwareMd()
        md.fwid = fwid
        md.cid = app.id
        md.name = app.name
        md.summary = app.summary
        md.developer_name = app.developer_name
        md.metadata_license = app.metadata_license
        md.project_license = app.project_license
        md.url_homepage = app.urls['homepage']
        md.description = app.description
        md.checksum_container = checksum_container

        # from the provide
        prov = app.provides[0]
        md.guid = prov.value

        # from the release
        rel = app.releases[0]
        md.version = rel.version
        md.release_description = rel.description
        md.release_timestamp = rel.timestamp
        md.release_installed_size = rel.size_installed
        md.release_download_size = rel.size_download

        # from the content checksum
        csum = app.releases[0].get_checksum_by_target('content')
        md.checksum_contents = csum.value
        md.filename_contents = csum.filename

        fwobj.mds.append(md)

    # add to database
    try:
        db_firmware.add(fwobj)
    except CursorError as e:
        return error_internal(str(e))
    # set correct response code
    _event_log("Uploaded file %s to %s" % (new_filename, target))
    # set response code = '201 Created')

    # ensure up to date
    try:
        if target != 'private':
            update_metadata_by_qa_group(fwobj.qa_group)
        if target == 'stable':
            update_metadata_by_targets(['stable', 'testing'])
        elif target == 'testing':
            update_metadata_by_targets(['testing'])
    except NoKeyError as e:
        return error_internal('Failed to sign metadata: ' + str(e))

    # ensure we save the latest data
    ensure_checkpoint()

    return redirect(url_for('lvfs_firmware_id', fwid=fwid))

@app.route('/lvfs/firmware')
def lvfs_firmware(show_all=False):
    """
    Show all previsouly uploaded firmware for this user.
    """

    # security check
    _check_session()

    # get all firmware
    try:
        db = LvfsDatabase(os.environ)
        db_firmware = LvfsDatabaseFirmware(db)
        items = db_firmware.get_items()
    except CursorError as e:
        return error_internal(str(e))

    # nothing!
    if len(items) == 0:
        html = "<p>No firmware has been uploaded to the " \
               "&lsquo;%s&rsquo; QA group yet.</p>" % session['qa_group']
        return render_template('lvfs/firmware.html', dyncontent=html)

    # group by the firmware name
    names = {}
    for item in items:
        # admin can see everything
        if session['username'] != 'admin':
            if item.qa_group != session['qa_group']:
                continue
        name = item.mds[0].name
        if not name in names:
            names[name] = []
        names[name].append(item)

    html = "<p>"
    html += "The following firmware files have been uploaded to the " \
            "&lsquo;%s&rsquo; QA group. " % session['qa_group']
    if not show_all:
        html += "By default only one firmware per device is shown in each state. "
        html += "To show all files for all devices, <a href=\"/lvfs/firmware_all\">click here</a>."
    html += "</p>"

    # group each thing in it's own header
    for name in sorted(names):
        html += "<h2>%s</h2>\n" % name
        html += "<table class=\"history\">"
        html += "<tr>"
        html += "<th>Submitted</td>"
        html += "<th>Version</td>"
        html += "<th>Target</td>"
        html += "<th></td>"
        html += "</tr>\n"

        # by default we only show the first version of each target
        targets_seen = {}

        for item in names[name]:

            # only show one
            if item.target in targets_seen:
                continue
            if not show_all:
                targets_seen[item.target] = item

            buttons = "<form method=\"get\" action=\"/lvfs/firmware/%s\">" \
                      "<button class=\"fixedwidth\">Details</button>" \
                      "</form>" % item.fwid
            html += '<tr>'
            html += "<td>%s</td>" % item.timestamp
            if not item.version_display or item.mds[0].version == item.version_display:
                html += "<td>%s</td>" % item.mds[0].version
            else:
                html += "<td>%s [%s]</td>" % (item.version_display, item.mds[0].version)
            html += "<td>%s</td>" % item.target
            html += "<td>%s</td>" % buttons
            html += '</tr>\n'
        html += "</table>"
    return render_template('lvfs/firmware.html', dyncontent=html)

@app.route('/lvfs/firmware_all')
def lvfs_firmware_all():
    return lvfs_firmware(True)

@app.route('/lvfs/firmware/<fwid>/delete')
def lvfs_firmware_delete(fwid):
    """ Confirms deletion of firmware """
    return render_template('lvfs/firmware-delete.html', fwid=fwid), 406

@app.route('/lvfs/firmware/<fwid>/delete_force')
def lvfs_firmware_delete_force(fwid):
    """ Delete a firmware entry and also delete the file from disk """

    # security check
    _check_session()

    # check firmware exists in database
    db = LvfsDatabase(os.environ)
    db_firmware = LvfsDatabaseFirmware(db)
    try:
        item = db_firmware.get_item(fwid)
    except CursorError as e:
        return error_internal(str(e))
    if not item:
        return error_internal("No firmware file with hash %s exists" % fwid)
    if session['username'] != 'admin' and item.qa_group != session['qa_group']:
        return error_permission_denied("No QA access to %s" % fwid)

    # only QA users can delete once the firmware has gone stable
    if not session['qa_capability'] and item.target == 'stable':
        return error_permission_denied('Unable to delete stable firmware as not QA')

    # delete id from database
    try:
        db_firmware.remove(fwid)
    except CursorError as e:
        return error_internal(str(e))

    # delete file(s)
    for loc in [UPLOAD_DIR, DOWNLOAD_DIR]:
        path = os.path.join(loc, item.filename)
        if os.path.exists(path):
            os.remove(path)

    # update everything
    try:
        update_metadata_by_qa_group(item.qa_group)
        if item.target == 'stable':
            update_metadata_by_targets(targets=['stable', 'testing'])
        elif item.target == 'testing':
            update_metadata_by_targets(targets=['testing'])
    except NoKeyError as e:
        return error_internal('Failed to sign metadata: ' + str(e))

    _event_log("Deleted firmware %s" % fwid)

    # ensure we save the latest data
    ensure_checkpoint()
    return redirect(url_for('lvfs_firmware'))

@app.route('/lvfs/firmware/<fwid>/promote/<target>')
def lvfs_firmware_promote(fwid, target):
    """
    Promote or demote a firmware file from one target to another,
    for example from testing to stable, or stable to testing.
     """

    # security check
    _check_session()

    # check is QA
    if not session['qa_capability']:
        return error_permission_denied('Unable to promote as not QA')

    # check valid
    if target not in ['stable', 'testing', 'private', 'embargo']:
        return error_internal("Target %s invalid" % target)

    # check firmware exists in database
    db = LvfsDatabase(os.environ)
    db_firmware = LvfsDatabaseFirmware(db)
    try:
        item = db_firmware.get_item(fwid)
    except CursorError as e:
        return error_internal(str(e))
    if session['username'] != 'admin' and item.qa_group != session['qa_group']:
        return error_permission_denied("No QA access to %s" % fwid)
    try:
        db_firmware.set_target(fwid, target)
    except CursorError as e:
        return error_internal(str(e))
    # set correct response code
    _event_log("Moved firmware %s to %s" % (fwid, target))

    # update everything
    try:
        update_metadata_by_qa_group(item.qa_group)
        if target == 'stable':
            update_metadata_by_targets(['stable', 'testing'])
        elif target == 'testing':
            update_metadata_by_targets(['testing'])
    except NoKeyError as e:
        return error_internal('Failed to sign metadata: ' + str(e))

    # ensure we save the latest data
    ensure_checkpoint()

    return redirect(url_for('lvfs_firmware_id', fwid=fwid))

@app.route('/lvfs/firmware/<fwid>')
def lvfs_firmware_id(fwid):
    """ Show firmware information """

    # security check
    _check_session()

    # get details about the firmware
    db = LvfsDatabase(os.environ)
    db_firmware = LvfsDatabaseFirmware(db)
    try:
        item = db_firmware.get_item(fwid)
    except CursorError as e:
        return error_internal(str(e))
    if not item:
        return error_internal('No firmware matched!')

    # we can only view our own firmware, unless admin
    qa_group = item.qa_group
    if qa_group != session['qa_group'] and session['username'] != 'admin':
        return error_permission_denied('Unable to view other vendor firmware')
    if not qa_group:
        embargo_url = '/downloads/firmware.xml.gz'
        qa_group = 'None'
    else:
        embargo_url = '/downloads/firmware-%s.xml.gz' % _qa_hash(qa_group)
    file_uri = '/downloads/' + item.filename

    buttons = ''
    if session['qa_capability'] or item.target == 'private':
        buttons += "<form method=\"get\" action=\"/lvfs/firmware/%s/delete\">" \
                   "<button class=\"fixedwidth\">Delete</button>" \
                   "</form>" % fwid
    if session['qa_capability']:
        if item.target == 'private':
            buttons += "<form method=\"get\" action=\"/lvfs/firmware/%s/promote/embargo\">" \
                       "<button class=\"fixedwidth\">&#8594; Embargo</button>" \
                       "</form>" % fwid
        elif item.target == 'embargo':
            buttons += "<form method=\"get\" action=\"/lvfs/firmware/%s/promote/testing\">" \
                       "<button class=\"fixedwidth\">&#8594; Testing</button>" \
                       "</form>" % fwid
        elif item.target == 'testing':
            buttons += "<form method=\"get\" action=\"/lvfs/firmware/%s/promote/stable\">" \
                       "<button class=\"fixedwidth\">&#8594; Stable</button>" \
                       "</form>" % fwid

    html = '<table class="history">'
    orig_filename = '-'.join(item.filename.split('-')[1:])
    html += '<tr><th>Filename</th><td><a href=\"%s\">%s</a></td></tr>' % (file_uri, orig_filename)
    html += '<tr><th>Current Target</th><td>%s</td></tr>' % item.target
    html += '<tr><th>Submitted</th><td>%s</td></tr>' % item.timestamp
    html += '<tr><th>QA Group</th><td><a href="%s">%s</a></td></tr>' % (embargo_url, qa_group)
    html += '<tr><th>Uploaded from</th><td>%s</td></tr>' % item.addr
    if item.version_display:
        html += '<tr><th>Version (display only)</th><td>%s</td></tr>' % item.version_display
    db = LvfsDatabase(os.environ)
    db_clients = LvfsDatabaseClients(db)
    cnt_fn = db_clients.get_firmware_count_filename(item.filename)
    html += '<tr><th>Downloads</th><td>%i</td></tr>' % cnt_fn
    html += '<tr><th>Actions</th><td>%s</td></tr>' % buttons
    html += '</table>'

    # show each component
    for md in item.mds:
        html += '<h2>%s</h2>' % md.name
        html += '<p>%s</p>' % md.summary
        html += '<table class="history">'
        html += '<tr><th>ID</th><td>%s</td></tr>' % md.cid
        html += '<tr><th>Device GUID</th><td><code>%s</code></td></tr>' % md.guid
        html += '<tr><th>Version</th><td>%s</td></tr>' % md.version
        html += '<tr><th>Installed Size</th><td>%s</td></tr>' % sizeof_fmt(md.release_installed_size)
        html += '<tr><th>Download Size</th><td>%s</td></tr>' % sizeof_fmt(md.release_download_size)
        html += '</table>'

    # show graph
    db_clients = LvfsDatabaseClients(db)
    data_fw = db_clients.get_stats_for_fn(12, 30, item.filename)
    html += '<h1>User Downloads</h1>'
    html += '<p>This graph will only show downloads since 2015-11-02.</p>'
    html += '<canvas id="metadataChartMonths" width="800" height="400"></canvas>'
    html += '<script>'
    html += 'var ctx = document.getElementById("metadataChartMonths").getContext("2d");'
    html += 'var data = {'
    html += '    labels: %s,' % _get_chart_labels_months()[::-1]
    html += '    datasets: ['
    html += '        {'
    html += '            label: "Firmware",'
    html += '            fillColor: "rgba(251,14,5,0.2)",'
    html += '            strokeColor: "rgba(151,14,5,0.1)",'
    html += '            pointColor: "rgba(151,14,5,0.3)",'
    html += '            pointStrokeColor: "#fff",'
    html += '            pointHighlightFill: "#fff",'
    html += '            pointHighlightStroke: "rgba(151,187,205,1)",'
    html += '            data: %s' % data_fw[::-1]
    html += '        },'
    html += '    ]'
    html += '};'
    html += 'var myLineChartMonths = new Chart(ctx).Line(data, null);'
    html += '</script>'

    return render_template('lvfs/firmware-details.html', dyncontent=html)

@app.route('/lvfs/analytics')
def lvfs_analytics():
    """ A analytics screen to show information about users """

    # security check
    _check_session()
    if session['username'] != 'admin':
        return error_permission_denied('Unable to view analytics')

    # add days
    db = LvfsDatabase(os.environ)
    db_clients = LvfsDatabaseClients(db)
    data_md = db_clients.get_stats(30, 1, LvfsDownloadKind.METADATA)
    data_fw = db_clients.get_stats(30, 1, LvfsDownloadKind.FIRMWARE)
    data_asc = db_clients.get_stats(30, 1, LvfsDownloadKind.SIGNING)
    html = '<h2>Metadata and Firmware Downloads (day)</h2>'
    html += '<canvas id="metadataChartMonthsDays" width="800" height="400"></canvas>'
    html += '<script>'
    html += 'var ctx = document.getElementById("metadataChartMonthsDays").getContext("2d");'
    html += 'var data = {'
    html += '    labels: %s,' % _get_chart_labels_days()[::-1]
    html += '    datasets: ['
    html += '        {'
    html += '            label: "Signing",'
    html += '            fillColor: "rgba(120,120,120,0.15)",'
    html += '            strokeColor: "rgba(120,120,120,0.15)",'
    html += '            pointColor: "rgba(120,120,120,0.20)",'
    html += '            pointStrokeColor: "#fff",'
    html += '            pointHighlightFill: "#fff",'
    html += '            pointHighlightStroke: "rgba(220,220,220,1)",'
    html += '            data: %s' % data_asc[::-1]
    html += '        },'
    html += '        {'
    html += '            label: "Metadata",'
    html += '            fillColor: "rgba(20,120,220,0.2)",'
    html += '            strokeColor: "rgba(20,120,120,0.1)",'
    html += '            pointColor: "rgba(20,120,120,0.3)",'
    html += '            pointStrokeColor: "#fff",'
    html += '            pointHighlightFill: "#fff",'
    html += '            pointHighlightStroke: "rgba(220,220,220,1)",'
    html += '            data: %s' % data_md[::-1]
    html += '        },'
    html += '        {'
    html += '            label: "Firmware",'
    html += '            fillColor: "rgba(251,14,5,0.2)",'
    html += '            strokeColor: "rgba(151,14,5,0.1)",'
    html += '            pointColor: "rgba(151,14,5,0.3)",'
    html += '            pointStrokeColor: "#fff",'
    html += '            pointHighlightFill: "#fff",'
    html += '            pointHighlightStroke: "rgba(151,187,205,1)",'
    html += '            data: %s' % data_fw[::-1]
    html += '        },'
    html += '    ]'
    html += '};'
    html += 'var myLineChartDays = new Chart(ctx).Line(data, null);'
    html += '</script>'

    # add months
    data_md = db_clients.get_metadata_by_month(LvfsDownloadKind.METADATA)
    data_fw = db_clients.get_metadata_by_month(LvfsDownloadKind.FIRMWARE)
    data_asc = db_clients.get_metadata_by_month(LvfsDownloadKind.SIGNING)
    html += '<h2>Metadata and Firmware Downloads (month)</h2>'
    html += '<canvas id="metadataChartMonths" width="800" height="400"></canvas>'
    html += '<script>'
    html += 'var ctx = document.getElementById("metadataChartMonths").getContext("2d");'
    html += 'var data = {'
    html += '    labels: %s,' % _get_chart_labels_months()[::-1]
    html += '    datasets: ['
    html += '        {'
    html += '            label: "Signing",'
    html += '            fillColor: "rgba(120,120,120,0.15)",'
    html += '            strokeColor: "rgba(120,120,120,0.15)",'
    html += '            pointColor: "rgba(120,120,120,0.20)",'
    html += '            pointStrokeColor: "#fff",'
    html += '            pointHighlightFill: "#fff",'
    html += '            pointHighlightStroke: "rgba(220,220,220,1)",'
    html += '            data: %s' % data_asc[::-1]
    html += '        },'
    html += '        {'
    html += '            label: "Metadata",'
    html += '            fillColor: "rgba(20,120,220,0.2)",'
    html += '            strokeColor: "rgba(20,120,120,0.1)",'
    html += '            pointColor: "rgba(20,120,120,0.3)",'
    html += '            pointStrokeColor: "#fff",'
    html += '            pointHighlightFill: "#fff",'
    html += '            pointHighlightStroke: "rgba(220,220,220,1)",'
    html += '            data: %s' % data_md[::-1]
    html += '        },'
    html += '        {'
    html += '            label: "Firmware",'
    html += '            fillColor: "rgba(251,14,5,0.2)",'
    html += '            strokeColor: "rgba(151,14,5,0.1)",'
    html += '            pointColor: "rgba(151,14,5,0.3)",'
    html += '            pointStrokeColor: "#fff",'
    html += '            pointHighlightFill: "#fff",'
    html += '            pointHighlightStroke: "rgba(151,187,205,1)",'
    html += '            data: %s' % data_fw[::-1]
    html += '        },'
    html += '    ]'
    html += '};'
    html += 'var myLineChartMonths = new Chart(ctx).Line(data, null);'
    html += '</script>'

    # add user agent
    labels, data = db_clients.get_user_agent_stats()
    html += '<h2>User Agents</h2>'
    html += '<canvas id="metadataChartUserAgents" width="800" height="400"></canvas>'
    html += '<script>'
    html += 'var ctx = document.getElementById("metadataChartUserAgents").getContext("2d");'
    html += 'var data = {'
    html += '    labels: %s,' % _to_javascript_array(labels)
    html += '    datasets: ['
    html += '        {'
    html += '            label: "User Agents",'
    html += '            fillColor: "rgba(20,120,220,0.2)",'
    html += '            strokeColor: "rgba(20,120,120,0.1)",'
    html += '            pointColor: "rgba(20,120,120,0.3)",'
    html += '            pointStrokeColor: "#fff",'
    html += '            pointHighlightFill: "#fff",'
    html += '            pointHighlightStroke: "rgba(220,220,220,1)",'
    html += '            data: %s' % _to_javascript_array(data)
    html += '        },'
    html += '    ]'
    html += '};'
    html += 'var myLineChartUserAgent = new Chart(ctx).Bar(data, null);'
    html += '</script>'

    # add hours
    data_md = db_clients.get_metadata_by_hour()
    html += '<h2>Metadata and Firmware Downloads (hour)</h2>'
    html += '<canvas id="metadataChartHours" width="800" height="400"></canvas>'
    html += '<script>'
    html += 'var ctx = document.getElementById("metadataChartHours").getContext("2d");'
    html += 'var data = {'
    html += '    labels: %s,' % _get_chart_labels_hours()
    html += '    datasets: ['
    html += '        {'
    html += '            label: "Metadata",'
    html += '            fillColor: "rgba(20,120,220,0.2)",'
    html += '            strokeColor: "rgba(20,120,120,0.1)",'
    html += '            pointColor: "rgba(20,120,120,0.3)",'
    html += '            pointStrokeColor: "#fff",'
    html += '            pointHighlightFill: "#fff",'
    html += '            pointHighlightStroke: "rgba(220,220,220,1)",'
    html += '            data: %s' % data_md
    html += '        },'
    html += '    ]'
    html += '};'
    html += 'var myLineChartHours = new Chart(ctx).Line(data, null);'
    html += '</script>'
    return render_template('lvfs/analytics.html', dyncontent=html)

@app.route('/lvfs/login', methods=['GET', 'POST'])
def lvfs_login(error_msg=None):
    """ A login screen to allow access to the LVFS main page """
    if request.method != 'POST':
        return render_template('lvfs/login.html', error_msg=error_msg)

    # auth check
    item = None
    password = _password_hash(request.form['password'])
    try:
        db = LvfsDatabase(os.environ)
        db_users = LvfsDatabaseUsers(db)
        item = db_users.get_item(request.form['username'],
                                 password)
    except CursorError as e:
        return error_internal(str(e))
    if not item:
        # log failure
        _event_log('Failed login attempt')
        return render_template('lvfs/login.html', error_msg='Incorrect username or password')
    if not item.is_enabled:
        # log failure
        _event_log('Failed login attempt (user disabled)')
        return render_template('lvfs/login.html', error_msg='User account is disabled')

    # this is signed, not encrypted
    session['username'] = item.username
    session['qa_capability'] = item.is_qa
    session['qa_group'] = item.qa_group
    session['is_locked'] = item.is_locked

    # log success
    _event_log('Logged on')
    return redirect(url_for('lvfs_index'))

@app.route('/lvfs/logout')
def lvfs_logout():
    # remove the username from the session
    session.pop('username', None)
    return redirect(url_for('lvfs_index'))

@app.route('/lvfs/eventlog')
@app.route('/lvfs/eventlog/<start>')
@app.route('/lvfs/eventlog/<start>/<length>')
def lvfs_eventlog(start=0, length=20):
    """
    Show an event log of user actions.
    """
    # security check
    _check_session()
    if not session['qa_capability']:
        return error_permission_denied('Unable to show event log for non-QA user')

    # get the page selection correct
    db = LvfsDatabase(os.environ)
    db_eventlog = LvfsDatabaseEventlog(db)
    if session['username'] == 'admin':
        eventlog_len = db_eventlog.size()
    else:
        eventlog_len = db_eventlog.size_for_qa_group(session['qa_group'])
    nr_pages = int(math.ceil(eventlog_len / float(length)))

    # table contents
    html = ''
    try:
        if session['username'] == 'admin':
            items = db_eventlog.get_items(int(start), int(length))
        else:
            items = db_eventlog.get_items_for_qa_group(session['qa_group'], int(start), int(length))
    except CursorError as e:
        return error_internal(str(e))
    if len(items) == 0:
        return error_internal('No event log available!')
    for item in items:
        html += '<tr>'
        html += '<td class="history">%s</td>' % str(item.timestamp).split('.')[0]
        html += '<td class="history">%s</td>' % item.address
        html += '<td class="history">%s</td>' % item.username
        if item.is_important == 1:
            html += '<td class="history">&#x272a;</td>'
        else:
            html += '<td class="history"></td>'
        html += '<td class="history">%s</td>' % item.message
        html += '</tr>\n'
    html += '</table>'

    # limit this to keep the UI sane
    if nr_pages > 20:
        nr_pages = 20

    for i in range(nr_pages):
        if int(start) == i * int(length):
            html += '%i ' % (i + 1)
        else:
            html += '<a href="/lvfs/eventlog/%i/%s">%i</a> ' % (i * int(length), int(length), i + 1)
    return render_template('lvfs/eventlog.html', dyncontent=html)

def _update_metadata_from_fn(fwobj, fn):
    """
    Re-parses the .cab file and updates the database version.
    """

    # load cab file
    arc = cabarchive.CabArchive()
    arc.set_decompressor(CABEXTRACT_CMD)
    try:
        arc.parse_file(fn)
    except cabarchive.CorruptionError as e:
        return error_internal('Invalid file type: %s' % str(e))

    # parse the MetaInfo file
    cf = arc.find_file("*.metainfo.xml")
    if not cf:
        return error_internal('The firmware file had no valid metadata')
    app = appstream.Component()
    try:
        app.parse(str(cf.contents))
    except appstream.ParseError as e:
        return error_internal('The metadata could not be parsed: ' + str(e))

    # parse the inf file
    cf = arc.find_file("*.inf")
    if not cf:
        return error_internal('The firmware file had no valid inf file')
    cfg = InfParser()
    cfg.read_data(cf.contents)
    try:
        tmp = cfg.get('Version', 'DriverVer')
        driver_ver = tmp.split(',')
        if len(driver_ver) != 2:
            return error_internal('The inf file Version:DriverVer was invalid')
    except ConfigParser.NoOptionError as e:
        driver_ver = None

    # get the contents
    fw_data = arc.find_file('*.bin')
    if not fw_data:
        fw_data = arc.find_file('*.rom')
    if not fw_data:
        fw_data = arc.find_file('*.cap')
    if not fw_data:
        return error_internal('No firmware found in the archive')

    # update sizes
    fwobj.mds[0].release_installed_size = len(fw_data.contents)
    fwobj.mds[0].release_download_size = os.path.getsize(fn)

    # update the descriptions
    fwobj.mds[0].release_description = app.releases[0].description
    fwobj.mds[0].description = app.description
    if driver_ver:
        fwobj.version_display = driver_ver[1]
    db = LvfsDatabase(os.environ)
    db_firmware = LvfsDatabaseFirmware(db)
    db_firmware.update(fwobj)
    return None

@app.route('/lvfs/user/<username>/modify', methods=['GET', 'POST'])
def lvfs_user_modify(username):
    """ Change details about the current user """

    # only accept form data
    if request.method != 'POST':
        return redirect(url_for('lvfs_profile'))

    # security check
    _check_session()
    if session['username'] != username:
        return error_permission_denied('Unable to modify a different user')
    if session['is_locked']:
        return error_permission_denied('Unable to change user as account locked')

    # check we got enough data
    if not 'password_new' in request.form:
        return error_permission_denied('Unable to change user as no data')
    if not 'password_old' in request.form:
        return error_permission_denied('Unable to change user as no data')
    if not 'name' in request.form:
        return error_permission_denied('Unable to change user as no data')
    if not 'email' in request.form:
        return error_permission_denied('Unable to change user as no data')
    db = LvfsDatabase(os.environ)
    db_users = LvfsDatabaseUsers(db)
    try:
        auth = db_users.verify(session['username'], request.form['password_old'])
    except CursorError as e:
        return error_internal(str(e))
    if not auth:
        return error_internal('Incorrect existing password')

    # check password
    password = request.form['password_new']
    pw_check = _password_check(password)
    if pw_check:
        # set response code = '400 Bad Request')
        return lvfs_profile(pw_check)

    # check email
    email = request.form['email']
    email_check = _email_check(email)
    if email_check:
        return lvfs_profile(email_check)

    # check pubkey
    pubkey = ''
    if 'pubkey' in request.form:
        pubkey = request.form['pubkey']
        if pubkey:
            if len(pubkey) > 0:
                if not pubkey.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"):
                    return lvfs_profile('Invalid GPG public key')

    # verify name
    name = request.form['name']
    if len(name) < 3:
        # set response code = '400 Bad Request')
        return lvfs_profile('Name invalid')
    try:
        db_users.update(session['username'], password, name, email, pubkey)
    except CursorError as e:
        return error_internal(str(e))
    #session['password'] = _password_hash(password)
    _event_log('Changed password')
    # set response code = '200 OK')
    return lvfs_profile('Updated profile')

@app.route('/lvfs/user/add', methods=['GET', 'POST'])
def lvfs_useradd():
    """ Add a user [ADMIN ONLY] """

    # only accept form data
    if request.method != 'POST':
        return redirect(url_for('lvfs_profile'))

    # security check
    _check_session()
    if session['username'] != 'admin':
        return error_permission_denied('Unable to add user as non-admin')

    db = LvfsDatabase(os.environ)
    db_users = LvfsDatabaseUsers(db)
    if not 'password_new' in request.form:
        return error_permission_denied('Unable to add user an no data')
    if not 'username_new' in request.form:
        return error_permission_denied('Unable to add user an no data')
    if not 'qa_group' in request.form:
        return error_permission_denied('Unable to add user an no data')
    if not 'name' in request.form:
        return error_permission_denied('Unable to add user an no data')
    if not 'email' in request.form:
        return error_permission_denied('Unable to add user an no data')
    try:
        auth = db_users.is_enabled(request.form['username_new'])
    except CursorError as e:
        return error_internal(str(e))
    if auth:
        # set response code = '422 Entity Already Exists')
        return error_permission_denied('Already a entry with that username')

    # verify password
    password = request.form['password_new']
    pw_check = _password_check(password)
    if pw_check:
        # set response code = '400 Bad Request')
        return lvfs_userlist(pw_check)

    # verify email
    email = request.form['email']
    email_check = _email_check(email)
    if email_check:
        # set response code = '400 Bad Request')
        return lvfs_userlist(email_check)

    # verify qa_group
    qa_group = request.form['qa_group']
    if len(qa_group) < 3:
        # set response code = '400 Bad Request')
        return lvfs_userlist('QA group invalid')

    # verify name
    name = request.form['name']
    if len(name) < 3:
        # set response code = '400 Bad Request')
        return lvfs_userlist('Name invalid')

    # verify username
    username_new = request.form['username_new']
    if len(username_new) < 3:
        # set response code = '400 Bad Request')
        return lvfs_userlist('Username invalid')
    try:
        db_users.add(username_new, password, name, email, qa_group)
    except CursorError as e:
        #FIXME
        pass

    _event_log("Created user %s" % username_new)
    # set response code = '201 Created')

    # ensure we save the latest data
    ensure_checkpoint()

    return lvfs_userlist('Added user')

@app.route('/lvfs/user/<username>/delete')
def lvfs_user_delete(username):
    """ Delete a user """

    # security check
    _check_session()
    if session['username'] != 'admin':
        return error_permission_denied('Unable to remove user as not admin')

    # check whether exists in database
    db = LvfsDatabase(os.environ)
    db_users = LvfsDatabaseUsers(db)
    try:
        exists = db_users.is_enabled(username)
    except CursorError as e:
        return error_internal(str(e))
    if not exists:
        # set response code = '400 Bad Request'
        return lvfs_userlist("No entry with username %s" % username)
    try:
        db_users.remove(username)
    except CursorError as e:
        return error_internal(str(e))
    _event_log("Deleted user %s" % username)

    # ensure we save the latest data
    ensure_checkpoint()

    return lvfs_userlist('Deleted user')

def lvfs_usermod(username, key, value):
    """ Adds or remove a capability to a user """

    # security check
    _check_session()
    if session['username'] != 'admin':
        return error_permission_denied('Unable to inc user as not admin')

    # save new value
    try:
        db = LvfsDatabase(os.environ)
        db_users = LvfsDatabaseUsers(db)
        db_users.set_property(username, key, value)
    except CursorError as e:
        return error_internal(str(e))
    except RuntimeError as e:
        return error_permission_denied('Unable to change user as key invalid')

    # set correct response code
    _event_log("Set %s=%s for user %s" % (key, value, username))

    # ensure we save the latest data
    ensure_checkpoint()

    return lvfs_userlist()

@app.route('/lvfs/user/<username>/enable')
def lvfs_user_enable(username):
    return lvfs_usermod(username, 'enabled', True)

@app.route('/lvfs/user/<username>/disable')
def lvfs_user_disable(username):
    return lvfs_usermod(username, 'enabled', False)

@app.route('/lvfs/user/<username>/lock')
def lvfs_user_lock(username):
    return lvfs_usermod(username, 'locked', True)

@app.route('/lvfs/user/<username>/unlock')
def lvfs_user_unlock(username):
    return lvfs_usermod(username, 'locked', False)

@app.route('/lvfs/user/<username>/promote')
def lvfs_user_promote(username):
    return lvfs_usermod(username, 'qa', True)

@app.route('/lvfs/user/<username>/demote')
def lvfs_user_demote(username):
    return lvfs_usermod(username, 'qa', False)

@app.route('/lvfs/userlist')
def lvfs_userlist(error_msg=None):
    """
    Show a list of all users
    """

    if session['username'] != 'admin':
        return error_permission_denied('Unable to show userlist for non-admin user')
    try:
        db = LvfsDatabase(os.environ)
        db_users = LvfsDatabaseUsers(db)
        items = db_users.get_items()
    except CursorError as e:
        return error_internal(str(e))
    html = ''
    for item in items:
        if item.username == 'admin':
            button = ''
        else:
            button = "<form method=\"get\" action=\"/lvfs/user/%s/delete\">" \
                     "<button class=\"fixedwidth\">Delete</button>" \
                     "</form>" % item.username
            if not item.is_enabled:
                button += "<form method=\"get\" action=\"/lvfs/user/%s/enable\">" \
                          "<button class=\"fixedwidth\">Enable</button>" \
                          "</form>" % item.username
            else:
                button += "<form method=\"get\" action=\"/lvfs/user/%s/disable\">" \
                          "<button class=\"fixedwidth\">Disable</button>" \
                          "</form>" % item.username
            if not item.is_locked:
                button += "<form method=\"get\" action=\"/lvfs/user/%s/lock\">" \
                          "<button class=\"fixedwidth\">Lock</button>" \
                          "</form>" % item.username
            else:
                button += "<form method=\"get\" action=\"/lvfs/user/%s/unlock\">" \
                          "<button class=\"fixedwidth\">Unlock</button>" \
                          "</form>" % item.username
            if not item.is_qa:
                button += "<form method=\"get\" action=\"/lvfs/user/%s/promote\">" \
                          "<button class=\"fixedwidth\">+QA</button>" \
                          "</form>" % item.username
            else:
                button += "<form method=\"get\" action=\"/lvfs/user/%s/demote\">" \
                          "<button class=\"fixedwidth\">-QA</button>" \
                          "</form>" % item.username
        html += '<tr>'
        html += "<td>%s</td>\n" % item.username
        html += "<td>%s&hellip;</td>\n" % item.password[0:8]
        html += "<td>%s</td>\n" % item.display_name
        html += "<td>%s</td>\n" % item.email
        html += "<td>%s</td>\n" % item.qa_group
        html += "<td>%s</td>\n" % button
        html += '</tr>'

    # add new user form
    html += "<tr>"
    html += "<form method=\"post\" action=\"/lvfs/user/add\">"
    html += "<td><input type=\"text\" size=\"8\" name=\"username_new\" placeholder=\"username\" required></td>"
    html += "<td><input type=\"password\" size=\"8\" name=\"password_new\" placeholder=\"password\" required></td>"
    html += "<td><input type=\"text\" size=\"14\" name=\"name\" placeholder=\"Example Name\" required></td>"
    html += "<td><input type=\"text\" size=\"14\" name=\"email\" placeholder=\"info@example.com\" required></td>"
    html += "<td><input type=\"text\" size=\"8\" name=\"qa_group\" placeholder=\"example\" required></td>"
    html += "<td><input type=\"submit\" style=\"width: 6em\" value=\"Add\"></td>"
    html += "</form>"
    html += "</tr>\n"
    html += '</table>'
    return render_template('lvfs/userlist.html', error_msg=error_msg, dyncontent=html)

@app.route('/lvfs/profile')
def lvfs_profile(error_msg=None):
    """
    Allows the normal user to change details about the account,
    """

    # security check
    _check_session()
    if session['is_locked']:
        return error_permission_denied('Unable to view profile as account locked')

    # auth check
    try:
        db = LvfsDatabase(os.environ)
        db_users = LvfsDatabaseUsers(db)
        item = db_users.get_item(session['username'])
    except CursorError as e:
        return error_internal(str(e))
    if not item:
        return error_internal('Invalid username query')

    # add defaults
    if not item.display_name:
        item.display_name = "Example Name"
    if not item.email:
        item.email = "info@example.com"
    return render_template('lvfs/profile.html',
                           error_msg=error_msg,
                           vendor_name=item.display_name,
                           contact_email=item.email,
                           pubkey=item.pubkey)

@app.route('/lvfs/metadata_rebuild')
def lvfs_metadata_rebuild():
    """
    Forces a rebuild of all metadata.
    """

    # security check
    _check_session()
    if session['username'] != 'admin':
        return error_permission_denied('Only admin is allowed to force-rebuild firmware')

    # go through existing files and fix descriptions
    try:
        db = LvfsDatabase(os.environ)
        db_firmware = LvfsDatabaseFirmware(db)
        items = db_firmware.get_items()
    except CursorError as e:
        return error_internal(str(e))
    for fn in glob.glob(os.path.join(UPLOAD_DIR, "*.cab")):
        fwupd = os.path.basename(fn).split('-')[0]
        for fwobj in items:
            if fwobj.fwid == fwupd:
                err_page = _update_metadata_from_fn(fwobj, fn)
                if err_page:
                    return err_page

    # update metadata
    try:
        update_metadata_by_qa_group(None)
        update_metadata_by_targets(['stable', 'testing'])
    except NoKeyError as e:
        return error_internal('Failed to sign metadata: ' + str(e))
    return redirect(url_for('lvfs_metadata'))

@app.route('/<path:resource>')
def serveStaticResource(resource):
    """ Return a static image or resource """

    # use apache for the static file so we can scale
    if 'OPENSHIFT_APP_DNS' in os.environ:
        if resource.startswith('download/'):
            uri = "https://%s/static/%s" % (os.environ['OPENSHIFT_APP_DNS'], resource)
            return redirect(uri, 301)

    # log certain kinds of files
    kind = None
    if resource.endswith('.cab'):
        kind = LvfsDownloadKind.FIRMWARE
    elif resource.endswith('.xml.gz.asc'):
        kind = LvfsDownloadKind.SIGNING
    elif resource.endswith('.xml.gz'):
        kind = LvfsDownloadKind.METADATA
    if kind:
        try:
            db = LvfsDatabase(os.environ)
            clients = LvfsDatabaseClients(db)
            clients.increment(_get_client_address(),
                              kind,
                              resource,
                              request.headers.get('User-Agent'))
        except CursorError as e:
            pass

    return send_from_directory('static/', resource)

if __name__ == '__main__':
    if not 'OPENSHIFT_APP_DNS' in os.environ:
        app.debug = True
    app.run()
