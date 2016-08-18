#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os
import hashlib
import math
import calendar
import datetime
import ConfigParser
from StringIO import StringIO

from flask import Blueprint, session, request, flash, url_for, redirect, \
     render_template, escape

import cabarchive
import appstream
from affidavit import NoKeyError
from db import LvfsDatabase, CursorError
from db_clients import LvfsDatabaseClients, LvfsDownloadKind
from db_eventlog import LvfsDatabaseEventlog
from db_firmware import LvfsDatabaseFirmware, LvfsFirmware, LvfsFirmwareMd
from db_users import LvfsDatabaseUsers, _password_hash
from inf_parser import InfParser
from config import DOWNLOAD_DIR, CABEXTRACT_CMD
from util import _qa_hash, _upload_to_cdn, create_affidavit
from metadata import metadata_update_qa_group, metadata_update_targets

def sizeof_fmt(num, suffix='B'):
    """ Generate user-visible size """
    if type(num) not in (int, long):
        return "???%s???" % num
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

def _password_check(value):
    """ Check the password for suitability """
    success = True
    if len(value) < 8:
        success = False
        flash('The password is too short, the minimum is 8 characters')
    if len(value) > 40:
        success = False
        flash('The password is too long, the maximum is 40 characters')
    if value.lower() == value:
        success = False
        flash('The password requires at least one uppercase character')
    if value.isalnum():
        success = False
        flash('The password requires at least one non-alphanumeric character')
    return success

def _email_check(value):
    """ Do a quick and dirty check on the email address """
    if len(value) < 5 or value.find('@') == -1 or value.find('.') == -1:
        flash('Invalid email address')
        return False
    return True

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
    """ Gets user IP address """
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
    if 'username' not in session:
        return False
    if 'qa_group' not in session:
        return False
    if 'qa_capability' not in session:
        return False
    if 'is_locked' not in session:
        return False
    return True

################################################################################

lvfs = Blueprint('lvfs', __name__, url_prefix='/lvfs', template_folder='templates/lvfs')

@lvfs.errorhandler(401)
def error_permission_denied(msg=None):
    """ Error handler: Permission Denied """
    _event_log("Permission denied: %s" % msg, is_important=True)
    flash("Permission denied: %s" % msg)
    return render_template('error.html'), 401

@lvfs.errorhandler(402)
def error_internal(msg=None, errcode=402):
    """ Error handler: Internal """
    _event_log("Internal error: %s" % msg, is_important=True)
    flash("Internal error: %s" % msg)
    return render_template('error.html'), errcode

@lvfs.route('/')
def index():
    """
    The main page that shows existing firmware and also allows the
    user to add new firmware.
    """
    if 'username' not in session:
        return redirect(url_for('.login'))

    return render_template('index.html')

@lvfs.route('/newaccount')
def new_account():
    """ New account page for prospective vendors """
    return render_template('new-account.html')

@lvfs.route('/metadata')
def metadata():
    """
    Show all metadata available to this user.
    """

    # security check
    if not _check_session():
        return redirect(url_for('.login'))

    # show static lists based on QA group
    qa_url = 'firmware-%s.xml.gz' % _qa_hash(session['qa_group'])
    qa_disp = 'firmware-%s&hellip;.xml.gz' % _qa_hash(session['qa_group'])[0:8]
    return render_template('metadata.html',
                           qa_group=session['qa_group'],
                           qa_url=qa_url,
                           qa_desc=qa_disp)

@lvfs.route('/devicelist')
def device_list():
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

                # show name
                html += '<li><a href="/lvfs/device/%s">%s</a></li>\n' % (md.guid, md.name)
        html += '</ul>\n'
    return render_template('devicelist.html', dyncontent=html)

@lvfs.route('/upload', methods=['GET', 'POST'])
def upload():
    """ Upload a .cab file to the LVFS service """

    # only accept form data
    if request.method != 'POST':
        return redirect(url_for('.index'))

    # security check
    if not _check_session():
        return redirect(url_for('.login'))

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
        return error_internal('File too large, limit is 50Mb', 413)
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
        return error_internal("A firmware file with hash %s already exists" % fwid, 422)

    # parse the file
    arc = cabarchive.CabArchive()
    try:
        if os.path.exists(CABEXTRACT_CMD):
            arc.set_decompressor(CABEXTRACT_CMD)
        arc.parse(data)
    except cabarchive.CorruptionError as e:
        return error_internal('Invalid file type: %s' % str(e), 415)
    except cabarchive.NotSupportedError as e:
        return error_internal('The file is unsupported: %s' % str(e), 415)

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
        if tmp != 'Firmware':
            return error_internal('The inf file Version:Class was invalid')
        try:
            tmp = cfg.get('Version', 'ClassGuid')
        except ConfigParser.NoOptionError as e:
            return error_internal('The inf file Version:ClassGuid was missing')
        if tmp != '{f2e7dd72-6468-4e36-b6f1-6488f42c1b52}':
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
        component = appstream.Component()
        try:
            component.parse(str(cf.contents))
            component.validate()
        except appstream.ParseError as e:
            return error_internal('The metadata %s could not be parsed: %s' % (cf, str(e)))
        except appstream.ValidationError as e:
            return error_internal('The metadata %s file did not validate: %s' % (cf, str(e)))

        # check the file does not have any missing request.form
        if cf.contents.find('FIXME') != -1:
            return error_internal("The metadata file was not complete; "
                                  "Any FIXME text must be replaced with the correct values.")

        # check the firmware provides something
        if len(component.provides) == 0:
            return error_internal("The metadata file did not provide any GUID.")
        if len(component.releases) == 0:
            return error_internal("The metadata file did not provide any releases.")

        # check the inf file matches up with the .xml file
        if fw_version_inf and fw_version_inf != component.releases[0].version:
            return error_internal("The inf Firmware_AddReg[HKR->FirmwareVersion] "
                                  "'%s' did not match the metainfo.xml value '%s'."
                                  % (fw_version_inf, component.releases[0].version))

        # check the guid and version does not already exist
        try:
            items = db_firmware.get_items()
        except CursorError as e:
            return error_internal(str(e))
        for item in items:
            for md in item.mds:
                if md.guid == component.provides[0].value and md.version == component.releases[0].version:
                    return error_internal("A firmware file for this version already exists", 422)

        # check the ID hasn't been reused by a different GUID
        for item in items:
            for md in item.mds:
                if md.cid == component.id and not md.guid == component.provides[0].value:
                    return error_internal("The %s ID has already been used by GUID %s" % (md.cid, md.guid), 422)

        # add to array
        apps.append(component)

    # only save if we passed all tests
    basename = os.path.basename(fileitem.filename)
    new_filename = fwid + '-' + basename

    # add these after parsing in case multiple components use the same file
    asc_files = {}

    # fix up the checksums and add the detached signature
    for component in apps:

        # ensure there's always a container checksum
        release = component.releases[0]
        csum = release.get_checksum_by_target('content')
        if not csum:
            csum = appstream.Checksum()
            csum.target = 'content'
            csum.filename = 'firmware.bin'
            component.releases[0].add_checksum(csum)

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
            if not csum.filename in asc_files:
                try:
                    affidavit = create_affidavit()
                except NoKeyError as e:
                    return error_internal('Failed to sign archive: ' + str(e))
                cff = cabarchive.CabFile(fw_data.filename + '.asc',
                                         affidavit.create(fw_data.contents))
                asc_files[csum.filename] = cff
        else:
            # check this file is signed by something we trust
            try:
                affidavit = create_affidavit()
                affidavit.verify(fw_data.contents)
            except NoKeyError as e:
                return error_internal('Failed to verify archive: ' + str(e))

    # add all the .asc files to the archive
    for key in asc_files:
        arc.add_file(asc_files[key])

    # export the new archive and get the checksum
    cab_data = arc.save(compressed=True)
    checksum_container = hashlib.sha1(cab_data).hexdigest()

    # dump to a file
    if not os.path.exists(DOWNLOAD_DIR):
        os.mkdir(DOWNLOAD_DIR)
    fn = os.path.join(DOWNLOAD_DIR, new_filename)
    open(fn, 'wb').write(cab_data)

    # dump to the CDN
    _upload_to_cdn(new_filename, StringIO(cab_data))

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
    for component in apps:
        md = LvfsFirmwareMd()
        md.fwid = fwid
        md.cid = component.id
        md.name = component.name
        md.summary = component.summary
        md.developer_name = component.developer_name
        md.metadata_license = component.metadata_license
        md.project_license = component.project_license
        md.url_homepage = component.urls['homepage']
        md.description = component.description
        md.checksum_container = checksum_container

        # from the provide
        prov = component.provides[0]
        md.guid = prov.value

        # from the release
        rel = component.releases[0]
        md.version = rel.version
        md.release_description = rel.description
        md.release_timestamp = rel.timestamp
        md.release_installed_size = rel.size_installed
        md.release_download_size = rel.size_download
        md.release_urgency = rel.urgency

        # from the first screenshot
        if len(component.screenshots) > 0:
            ss = component.screenshots[0]
            if ss.caption:
                md.screenshot_caption = ss.caption
            if len(ss.images) > 0:
                im = ss.images[0]
                if im.url:
                    md.screenshot_url = im.url

        # from the content checksum
        csum = component.releases[0].get_checksum_by_target('content')
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

    # ensure up to date
    try:
        if target != 'private':
            metadata_update_qa_group(fwobj.qa_group)
        if target == 'stable':
            metadata_update_targets(['stable', 'testing'])
        elif target == 'testing':
            metadata_update_targets(['testing'])

    except NoKeyError as e:
        return error_internal('Failed to sign metadata: ' + str(e))
    except CursorError as e:
        return error_internal('Failed to generate metadata: ' + str(e))

    return redirect(url_for('.firmware_id', fwid=fwid))

@lvfs.route('/device')
def device():
    """
    Show all devices -- probably only useful for the admin user.
    """

    # security check
    if not _check_session():
        return redirect(url_for('.login'))
    if session['username'] != 'admin':
        return error_permission_denied('Unable to view devices')

    # get all firmware
    try:
        db = LvfsDatabase(os.environ)
        db_firmware = LvfsDatabaseFirmware(db)
        items = db_firmware.get_items()
    except CursorError as e:
        return error_internal(str(e))

    # get all the guids we can target
    devices = []
    seen_guid = {}
    for item in items:
        for md in item.mds:
            if md.guid in seen_guid:
                continue
            seen_guid[md.guid] = 1
            devices.append(md.guid)

    return render_template('devices.html', devices=devices)

@lvfs.route('/device/<guid>')
def device_guid(guid):
    """
    Show information for one device, which can be seen without a valid login
    """

    # get all firmware
    try:
        db = LvfsDatabase(os.environ)
        db_firmware = LvfsDatabaseFirmware(db)
        items = db_firmware.get_items()
    except CursorError as e:
        return error_internal(str(e))

    # get all the guids we can target
    firmware_items = []
    for item in items:
        for md in item.mds:
            if md.guid != guid:
                continue
            firmware_items.append(item)
            break

    return render_template('device.html', items=firmware_items)

@lvfs.route('/firmware')
def firmware(show_all=False):
    """
    Show all previsouly uploaded firmware for this user.
    """

    # security check
    if not _check_session():
        return redirect(url_for('.login'))

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
        return render_template('firmware.html', dyncontent=html)

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
    return render_template('firmware.html', dyncontent=html)

@lvfs.route('/firmware_all')
def firmware_all():
    return firmware(True)

@lvfs.route('/firmware/<fwid>/delete')
def firmware_delete(fwid):
    """ Confirms deletion of firmware """
    return render_template('firmware-delete.html', fwid=fwid), 406

@lvfs.route('/firmware/<fwid>/modify', methods=['GET', 'POST'])
def firmware_modify(fwid):
    """ Modifies the update urgency and release notes for the update """

    if request.method != 'POST':
        return redirect(url_for('.firmware'))

    # security check
    if not _check_session():
        return redirect(url_for('.login'))

    # find firmware
    try:
        db = LvfsDatabase(os.environ)
        db_firmware = LvfsDatabaseFirmware(db)
        fwobj = db_firmware.get_item(fwid)
    except CursorError as e:
        return error_internal(str(e))
    if not fwobj:
        return error_internal("No firmware %s" % fwid)

    # set new metadata values
    for md in fwobj.mds:
        if 'urgency' in request.form:
            md.release_urgency = request.form['urgency']
        if 'description' in request.form:
            txt = request.form['description']
            if txt.find('<p>') == -1:
                txt = appstream.utils.import_description(txt)
            try:
                appstream.utils.validate_description(txt)
            except appstream.ParseError as e:
                return error_internal("Failed to parse %s: %s" % (txt, str(e)))
            md.release_description = txt

    # modify
    try:
        db_firmware.update(fwobj)
    except CursorError as e:
        return error_internal(str(e))

    # log
    _event_log('Changed update description on %s' % fwid)

    return redirect(url_for('.firmware_id', fwid=fwid))

@lvfs.route('/firmware/<fwid>/delete_force')
def firmware_delete_force(fwid):
    """ Delete a firmware entry and also delete the file from disk """

    # security check
    if not _check_session():
        return redirect(url_for('.login'))

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
    for loc in [DOWNLOAD_DIR]:
        path = os.path.join(loc, item.filename)
        if os.path.exists(path):
            os.remove(path)

    # update everything
    try:
        metadata_update_qa_group(item.qa_group)
        if item.target == 'stable':
            metadata_update_targets(targets=['stable', 'testing'])
        elif item.target == 'testing':
            metadata_update_targets(targets=['testing'])
    except NoKeyError as e:
        return error_internal('Failed to sign metadata: ' + str(e))
    except CursorError as e:
        return error_internal('Failed to generate metadata: ' + str(e))

    _event_log("Deleted firmware %s" % fwid)
    return redirect(url_for('.firmware'))

@lvfs.route('/firmware/<fwid>/promote/<target>')
def firmware_promote(fwid, target):
    """
    Promote or demote a firmware file from one target to another,
    for example from testing to stable, or stable to testing.
     """

    # security check
    if not _check_session():
        return redirect(url_for('.login'))

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
        metadata_update_qa_group(item.qa_group)
        if target == 'stable':
            metadata_update_targets(['stable', 'testing'])
        elif target == 'testing':
            metadata_update_targets(['testing'])
    except NoKeyError as e:
        return error_internal('Failed to sign metadata: ' + str(e))
    except CursorError as e:
        return error_internal('Failed to generate metadata: ' + str(e))
    return redirect(url_for('.firmware_id', fwid=fwid))

@lvfs.route('/firmware/<fwid>')
def firmware_id(fwid):
    """ Show firmware information """

    # security check
    if not _check_session():
        return redirect(url_for('.login'))

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

    html = '<table class="aligned">'
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
        html += '<table class="aligned">'
        html += '<tr><th>ID</th><td>%s</td></tr>' % md.cid
        html += '<tr><th>Device GUID</th><td><code>%s</code></td></tr>' % md.guid
        html += '<tr><th>Version</th><td>%s</td></tr>' % md.version
        html += '<tr><th>Installed Size</th><td>%s</td></tr>' % sizeof_fmt(md.release_installed_size)
        html += '<tr><th>Download Size</th><td>%s</td></tr>' % sizeof_fmt(md.release_download_size)
        if md.screenshot_caption:
            html += '<tr><th>Screenshot Caption</th><td>%s</td></tr>' % md.screenshot_caption
        if md.screenshot_url:
            html += '<tr><th>Screenshot URL</th><td>%s</td></tr>' % md.screenshot_url
        html += '</table>'

        # show editable update details
        html += '<h2>Update Details</h2>\n'

        # show urgency and update description
        if item.target == 'stable' or not session['qa_capability']:
            html += '<table class="history">\n'
            urgency = md.release_urgency
            if not urgency:
                urgency = 'unknown'
            html += '<tr><th>Release Urgency</th><td>%s</td></tr>\n' % urgency
            html += '<tr><th>Update Description</th><td>%s</td></tr>\n' % md.release_description
            html += '</table>\n'
        else:
            html += '<table class="history">\n'
            html += '<form method="post" action="/lvfs/firmware/%s/modify">\n' % fwid
            urgency_states = []
            urgency_states.append('unknown')
            urgency_states.append('low')
            urgency_states.append('medium')
            urgency_states.append('high')
            urgency_states.append('critical')
            html += '<tr><th>Release Urgency</th><td>\n'
            html += '<select name="urgency" class="fixedwidth" required>\n'
            for state in urgency_states:
                selected = ''
                if state == md.release_urgency:
                    selected = "selected"
                html += '<option value="%s" %s>%s</option>\n' % (state, selected, state)
            html += '</select>\n'
            html += '</td></tr>\n'

            url = 'http://www.freedesktop.org/software/appstream/docs/chap-Metadata.html#tag-description'
            desc = '<textarea name="description" cols="64" rows="5">%s</textarea>\n' % md.release_description
            desc += '<p>Unformatted text will be automatically converted to '
            desc += '<a href="%s">AppStream XML description markup</a>.</p>' % url
            html += '<tr><th>Update Description</th><td>%s</td></tr>\n' % desc
            html += '<tr><th>&nbsp;</th><td><input type="submit" value="Save update details"/></td></tr>\n'
            html += '</form>\n'
            html += '</table>\n'

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

    return render_template('firmware-details.html', dyncontent=html)

@lvfs.route('/analytics')
def analytics():
    """ A analytics screen to show information about users """

    # security check
    if not _check_session():
        return redirect(url_for('.login'))
    if session['username'] != 'admin':
        return error_permission_denied('Unable to view analytics')

    # add days
    db = LvfsDatabase(os.environ)
    db_clients = LvfsDatabaseClients(db)
    data_md = db_clients.get_stats_for_month(LvfsDownloadKind.METADATA)
    data_fw = db_clients.get_stats_for_month(LvfsDownloadKind.FIRMWARE)
    data_asc = db_clients.get_stats_for_month(LvfsDownloadKind.SIGNING)
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
    data_md = db_clients.get_stats_for_year(LvfsDownloadKind.METADATA)
    data_fw = db_clients.get_stats_for_year(LvfsDownloadKind.FIRMWARE)
    data_asc = db_clients.get_stats_for_year(LvfsDownloadKind.SIGNING)
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
    html += '<h2>Firmware Downloads by User Agent</h2>'
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
    return render_template('analytics.html', dyncontent=html)

@lvfs.route('/login', methods=['GET', 'POST'])
def login():
    """ A login screen to allow access to the LVFS main page """
    if request.method != 'POST':
        return render_template('login.html')

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
        _event_log('Failed login attempt for %s' % request.form['username'])
        flash('Incorrect username or password')
        return render_template('login.html')
    if not item.is_enabled:
        # log failure
        _event_log('Failed login attempt for %s (user disabled)' % request.form['username'])
        flash('User account is disabled')
        return render_template('login.html')

    # this is signed, not encrypted
    session['username'] = item.username
    session['qa_capability'] = item.is_qa
    session['qa_group'] = item.qa_group
    session['is_locked'] = item.is_locked

    # log success
    _event_log('Logged on')
    return redirect(url_for('.index'))

@lvfs.route('/logout')
def logout():
    # remove the username from the session
    session.pop('username', None)
    return redirect(url_for('.index'))

@lvfs.route('/eventlog')
@lvfs.route('/eventlog/<start>')
@lvfs.route('/eventlog/<start>/<length>')
def eventlog(start=0, length=20):
    """
    Show an event log of user actions.
    """
    # security check
    if not _check_session():
        return redirect(url_for('.login'))
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
        html += '<td class="history">%s</td>' % escape(item.message)
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
    return render_template('eventlog.html', dyncontent=html)

def _update_metadata_from_fn(fwobj, fn):
    """
    Re-parses the .cab file and updates the database version.
    """

    # load cab file
    arc = cabarchive.CabArchive()
    try:
        if os.path.exists(CABEXTRACT_CMD):
            arc.set_decompressor(CABEXTRACT_CMD)
        arc.parse_file(fn)
    except cabarchive.CorruptionError as e:
        return error_internal('Invalid file type: %s' % str(e))

    # parse the MetaInfo file
    cf = arc.find_file("*.metainfo.xml")
    if not cf:
        return error_internal('The firmware file had no valid metadata')
    component = appstream.Component()
    try:
        component.parse(str(cf.contents))
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
    fwobj.mds[0].release_description = component.releases[0].description
    fwobj.mds[0].description = component.description
    if driver_ver:
        fwobj.version_display = driver_ver[1]
    db = LvfsDatabase(os.environ)
    db_firmware = LvfsDatabaseFirmware(db)
    db_firmware.update(fwobj)
    return None

@lvfs.route('/user/<username>/modify', methods=['GET', 'POST'])
def user_modify(username):
    """ Change details about the current user """

    # only accept form data
    if request.method != 'POST':
        return redirect(url_for('.profile'))

    # security check
    if not _check_session():
        return redirect(url_for('.login'))
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
    if not _password_check(password):
        return redirect(url_for('.profile')), 400

    # check email
    email = request.form['email']
    if not _email_check(email):
        return redirect(url_for('.profile'))

    # check pubkey
    pubkey = ''
    if 'pubkey' in request.form:
        pubkey = request.form['pubkey']
        if pubkey:
            if len(pubkey) > 0:
                if not pubkey.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"):
                    flash('Invalid GPG public key')
                    return redirect(url_for('.profile')), 400

    # verify name
    name = request.form['name']
    if len(name) < 3:
        flash('Name invalid')
        return redirect(url_for('.profile')), 400
    try:
        db_users.update(session['username'], password, name, email, pubkey)
    except CursorError as e:
        return error_internal(str(e))
    #session['password'] = _password_hash(password)
    _event_log('Changed password')
    flash('Updated profile')
    return redirect(url_for('.profile'))

@lvfs.route('/user/add', methods=['GET', 'POST'])
def useradd():
    """ Add a user [ADMIN ONLY] """

    # only accept form data
    if request.method != 'POST':
        return redirect(url_for('.profile'))

    # security check
    if not _check_session():
        return redirect(url_for('.login'))
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
        return error_internal('Already a entry with that username', 422)

    # verify password
    password = request.form['password_new']
    if not _password_check(password):
        return redirect(url_for('.userlist')), 302

    # verify email
    email = request.form['email']
    if not _email_check(email):
        return redirect(url_for('.userlist')), 302

    # verify qa_group
    qa_group = request.form['qa_group']
    if len(qa_group) < 3:
        flash('QA group invalid')
        return redirect(url_for('.userlist')), 302

    # verify name
    name = request.form['name']
    if len(name) < 3:
        flash('Name invalid')
        return redirect(url_for('.userlist')), 302

    # verify username
    username_new = request.form['username_new']
    if len(username_new) < 3:
        flash('Username invalid')
        return redirect(url_for('.userlist')), 302
    try:
        db_users.add(username_new, password, name, email, qa_group)
    except CursorError as e:
        #FIXME
        pass
    _event_log("Created user %s" % username_new)
    flash('Added user')
    return redirect(url_for('.userlist')), 201

@lvfs.route('/user/<username>/delete')
def user_delete(username):
    """ Delete a user """

    # security check
    if not _check_session():
        return redirect(url_for('.login'))
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
        flash("No entry with username %s" % username)
        return redirect(url_for('.userlist')), 400
    try:
        db_users.remove(username)
    except CursorError as e:
        return error_internal(str(e))
    _event_log("Deleted user %s" % username)
    flash('Deleted user')
    return redirect(url_for('.userlist')), 201

def usermod(username, key, value):
    """ Adds or remove a capability to a user """

    # security check
    if not _check_session():
        return redirect(url_for('.login'))
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
    return redirect(url_for('.userlist'))

@lvfs.route('/user/<username>/enable')
def user_enable(username):
    return usermod(username, 'enabled', True)

@lvfs.route('/user/<username>/disable')
def user_disable(username):
    return usermod(username, 'enabled', False)

@lvfs.route('/user/<username>/lock')
def user_lock(username):
    return usermod(username, 'locked', True)

@lvfs.route('/user/<username>/unlock')
def user_unlock(username):
    return usermod(username, 'locked', False)

@lvfs.route('/user/<username>/promote')
def user_promote(username):
    return usermod(username, 'qa', True)

@lvfs.route('/user/<username>/demote')
def user_demote(username):
    return usermod(username, 'qa', False)

@lvfs.route('/userlist')
def userlist():
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
    return render_template('userlist.html', dyncontent=html)

@lvfs.route('/profile')
def profile():
    """
    Allows the normal user to change details about the account,
    """

    # security check
    if not _check_session():
        return redirect(url_for('.login'))
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
    return render_template('profile.html',
                           vendor_name=item.display_name,
                           contact_email=item.email,
                           pubkey=item.pubkey)

@lvfs.route('/metadata_rebuild')
def metadata_rebuild():
    """
    Forces a rebuild of all metadata.
    """

    # security check
    if not _check_session():
        return redirect(url_for('.login'))
    if session['username'] != 'admin':
        return error_permission_denied('Only admin is allowed to force-rebuild metadata')

    # update metadata
    try:
        metadata_update_qa_group(None)
        metadata_update_targets(['stable', 'testing'])
    except NoKeyError as e:
        return error_internal('Failed to sign metadata: ' + str(e))
    except CursorError as e:
        return error_internal('Failed to generate metadata: ' + str(e))
    return redirect(url_for('.metadata'))
