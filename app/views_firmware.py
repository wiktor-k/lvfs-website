#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os

from flask import session, request, url_for, redirect, render_template, flash
from flask.ext.login import login_required

import appstream

from app import app, db

from .affidavit import NoKeyError
from .db import CursorError
from .hash import _qa_hash
from .metadata import _metadata_update_group, _metadata_update_targets
from .models import FirmwareRequirement
from .util import _event_log, _error_internal, _error_permission_denied, _get_chart_labels_months, _get_chart_labels_days, _validate_guid

@app.route('/lvfs/firmware')
def firmware(show_all=False):
    """
    Show all previsouly uploaded firmware for this user.
    """

    # get all firmware
    try:
        items = db.firmware.get_all()
    except CursorError as e:
        return _error_internal(str(e))

    session_group_id = None
    if 'group_id' in session:
        session_group_id = session['group_id']
    session_username = None
    if 'username' in session:
        session_username = session['username']

    # group by the firmware name
    names = {}
    for item in items:
        # admin can see everything
        if session_username != 'admin':
            if item.group_id != session_group_id:
                continue
        if len(item.mds) == 0:
            continue
        name = item.mds[0].developer_name + ' ' + item.mds[0].name
        if not name in names:
            names[name] = []
        names[name].append(item)

    # only show one version in each state
    for name in sorted(names):
        targets_seen = {}
        for item in names[name]:
            if len(item.mds) == 0:
                continue
            key = item.target + item.mds[0].cid
            if key in targets_seen:
                item.is_newest_in_state = False
            else:
                item.is_newest_in_state = True
                targets_seen[key] = item

    return render_template('firmware.html',
                           fw_by_name=names,
                           names_sorted=sorted(names),
                           group_id=session_group_id,
                           show_all=show_all)

@app.route('/lvfs/firmware_all')
def firmware_all():
    return firmware(True)

@app.route('/lvfs/firmware/<firmware_id>/delete')
def firmware_delete(firmware_id):
    """ Confirms deletion of firmware """
    return render_template('firmware-delete.html', firmware_id=firmware_id), 406

@app.route('/lvfs/firmware/<firmware_id>/modify', methods=['GET', 'POST'])
@login_required
def firmware_modify(firmware_id):
    """ Modifies the update urgency and release notes for the update """

    if request.method != 'POST':
        return redirect(url_for('.firmware'))

    # find firmware
    try:
        fwobj = db.firmware.get_item(firmware_id)
    except CursorError as e:
        return _error_internal(str(e))
    if not fwobj:
        return _error_internal("No firmware %s" % firmware_id)

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
                return _error_internal("Failed to parse %s: %s" % (txt, str(e)))
            md.release_description = txt

    # modify
    try:
        db.firmware.update(fwobj)
    except CursorError as e:
        return _error_internal(str(e))

    # log
    _event_log('Changed update description on %s' % firmware_id)

    return redirect(url_for('.firmware_show', firmware_id=firmware_id))

@app.route('/lvfs/firmware/<firmware_id>/modify_requirements', methods=['GET', 'POST'])
@login_required
def firmware_modify_requirements(firmware_id):
    """ Modifies the update urgency and release notes for the update """

    if request.method != 'POST':
        return redirect(url_for('.firmware'))

    # find firmware
    try:
        fwobj = db.firmware.get_item(firmware_id)
    except CursorError as e:
        return _error_internal(str(e))
    if not fwobj:
        return _error_internal("No firmware %s" % firmware_id)

    # set new metadata values
    for md in fwobj.mds:
        if 'requirements' in request.form:
            req_txt = request.form['requirements']
            req_txt = req_txt.replace('\n', ',')
            req_txt = req_txt.replace('\r', '')
            md.requirements = []
            for req in req_txt.split(','):
                req = req.strip()
                if len(req) == 0:
                    continue
                if len(req.split('/')) != 4:
                    return _error_internal("Failed to parse %s" % req)
                fwreq = FirmwareRequirement(req[0], req[1], req[2], req[3])
                md.requirements.append(fwreq)

    # modify
    try:
        db.firmware.update(fwobj)
    except CursorError as e:
        return _error_internal(str(e))

    # log
    _event_log('Changed requirements on %s' % firmware_id)

    return redirect(url_for('.firmware_show', firmware_id=firmware_id))

@app.route('/lvfs/firmware/<firmware_id>/delete_force')
@login_required
def firmware_delete_force(firmware_id):
    """ Delete a firmware entry and also delete the file from disk """

    # check firmware exists in database
    try:
        item = db.firmware.get_item(firmware_id)
    except CursorError as e:
        return _error_internal(str(e))
    if not item:
        return _error_internal("No firmware file with hash %s exists" % firmware_id)
    if session['group_id'] != 'admin' and item.group_id != session['group_id']:
        return _error_permission_denied("No QA access to %s" % firmware_id)

    # only QA users can delete once the firmware has gone stable
    if not session['qa_capability'] and item.target == 'stable':
        return _error_permission_denied('Unable to delete stable firmware as not QA')

    # delete id from database
    try:
        db.firmware.remove(firmware_id)
    except CursorError as e:
        return _error_internal(str(e))

    # delete file
    path = os.path.join(app.config['DOWNLOAD_DIR'], item.filename)
    if os.path.exists(path):
        os.remove(path)

    # update everything
    try:
        _metadata_update_group(item.group_id)
        if item.target == 'stable':
            _metadata_update_targets(targets=['stable', 'testing'])
        elif item.target == 'testing':
            _metadata_update_targets(targets=['testing'])
    except NoKeyError as e:
        return _error_internal('Failed to sign metadata: ' + str(e))
    except CursorError as e:
        return _error_internal('Failed to generate metadata: ' + str(e))

    _event_log("Deleted firmware %s" % firmware_id)
    return redirect(url_for('.firmware'))

@app.route('/lvfs/firmware/<firmware_id>/promote/<target>')
@login_required
def firmware_promote(firmware_id, target):
    """
    Promote or demote a firmware file from one target to another,
    for example from testing to stable, or stable to testing.
     """

    # check is QA
    if not session['qa_capability']:
        return _error_permission_denied('Unable to promote as not QA')

    # check valid
    if target not in ['stable', 'testing', 'private', 'embargo']:
        return _error_internal("Target %s invalid" % target)

    # check firmware exists in database
    try:
        item = db.firmware.get_item(firmware_id)
    except CursorError as e:
        return _error_internal(str(e))
    if session['group_id'] != 'admin' and item.group_id != session['group_id']:
        return _error_permission_denied("No QA access to %s" % firmware_id)
    try:
        db.firmware.set_target(firmware_id, target)
    except CursorError as e:
        return _error_internal(str(e))
    # set correct response code
    _event_log("Moved firmware %s to %s" % (firmware_id, target))

    # update everything
    try:
        _metadata_update_group(item.group_id)
        if target == 'stable':
            _metadata_update_targets(['stable', 'testing'])
        elif target == 'testing':
            _metadata_update_targets(['testing'])
    except NoKeyError as e:
        return _error_internal('Failed to sign metadata: ' + str(e))
    except CursorError as e:
        return _error_internal('Failed to generate metadata: ' + str(e))
    return redirect(url_for('.firmware_show', firmware_id=firmware_id))

@app.route('/lvfs/firmware/<firmware_id>')
@login_required
def firmware_show(firmware_id):
    """ Show firmware information """

    # get details about the firmware
    try:
        item = db.firmware.get_item(firmware_id)
    except CursorError as e:
        return _error_internal(str(e))
    if not item:
        return _error_internal('No firmware matched!')

    # we can only view our own firmware, unless admin
    group_id = item.group_id
    if group_id != session['group_id'] and session['group_id'] != 'admin':
        return _error_permission_denied('Unable to view other vendor firmware')
    if not group_id:
        embargo_url = '/downloads/firmware.xml.gz'
        group_id = 'None'
    else:
        embargo_url = '/downloads/firmware-%s.xml.gz' % _qa_hash(group_id)

    cnt_fn = db.clients.get_firmware_count_filename(item.filename)
    return render_template('firmware-details.html',
                           fw=item,
                           qa_capability=session['qa_capability'],
                           orig_filename='-'.join(item.filename.split('-')[1:]),
                           embargo_url=embargo_url,
                           group_id=group_id,
                           cnt_fn=cnt_fn,
                           firmware_id=firmware_id)

@app.route('/lvfs/firmware/<firmware_id>/analytics/year')
@login_required
def firmware_analytics_year(firmware_id):
    """ Show firmware analytics information """

    # get details about the firmware
    try:
        item = db.firmware.get_item(firmware_id)
    except CursorError as e:
        return _error_internal(str(e))
    if not item:
        return _error_internal('No firmware matched!')

    # we can only view our own firmware, unless admin
    group_id = item.group_id
    if group_id != session['group_id'] and session['group_id'] != 'admin':
        return _error_permission_denied('Unable to view other vendor firmware')

    data_fw = db.clients.get_stats_for_fn(12, 30, item.filename)
    return render_template('firmware-analytics-year.html',
                           fw=item,
                           firmware_id=firmware_id,
                           graph_labels=_get_chart_labels_months()[::-1],
                           graph_data=data_fw[::-1])

@app.route('/lvfs/firmware/<firmware_id>/analytics')
@app.route('/lvfs/firmware/<firmware_id>/analytics/clients')
@login_required
def firmware_analytics_clients(firmware_id):
    """ Show firmware clients information """

    # get details about the firmware
    try:
        item = db.firmware.get_item(firmware_id)
    except CursorError as e:
        return _error_internal(str(e))
    if not item:
        return _error_internal('No firmware matched!')

    # we can only view our own firmware, unless admin
    group_id = item.group_id
    if group_id != session['group_id'] and session['group_id'] != 'admin':
        return _error_permission_denied('Unable to view other vendor firmware')
    clients = db.clients.get_all_for_filename(item.filename)
    return render_template('firmware-analytics-clients.html',
                           fw=item,
                           firmware_id=firmware_id,
                           clients=clients)

@app.route('/lvfs/firmware/<firmware_id>/analytics/month')
@login_required
def firmware_analytics_month(firmware_id):
    """ Show firmware analytics information """

    # get details about the firmware
    try:
        item = db.firmware.get_item(firmware_id)
    except CursorError as e:
        return _error_internal(str(e))
    if not item:
        return _error_internal('No firmware matched!')

    # we can only view our own firmware, unless admin
    group_id = item.group_id
    if group_id != session['group_id'] and session['group_id'] != 'admin':
        return _error_permission_denied('Unable to view other vendor firmware')

    data_fw = db.clients.get_stats_for_fn(30, 1, item.filename)
    return render_template('firmware-analytics-month.html',
                           fw=item,
                           firmware_id=firmware_id,
                           graph_labels=_get_chart_labels_days()[::-1],
                           graph_data=data_fw[::-1])

# get the right component
def _item_filter_by_cid(item, cid):
    for md in item.mds:
        if md.cid == cid:
            return md

@app.route('/lvfs/firmware/<firmware_id>/component/<cid>')
@app.route('/lvfs/firmware/<firmware_id>/component/<cid>/<page>')
@login_required
def firmware_component_show(firmware_id, cid, page='overview'):
    """ Show firmware component information """

    # get firmware component
    try:
        fwobj = db.firmware.get_item(firmware_id)
    except CursorError as e:
        return _error_internal(str(e))
    if not fwobj:
        return _error_internal('No firmware matched!')
    md = _item_filter_by_cid(fwobj, cid)
    if not md:
        return _error_internal('No component matched!')

    # we can only view our own firmware, unless admin
    group_id = fwobj.group_id
    if group_id != session['group_id'] and session['group_id'] != 'admin':
        return _error_permission_denied('Unable to view other vendor firmware')

    return render_template('firmware-md-' + page + '.html',
                           md=md,
                           fw=fwobj,
                           qa_capability=session['qa_capability'],
                           firmware_id=firmware_id)

@app.route('/lvfs/firmware/<firmware_id>/component/<cid>/requires/remove/hwid/<hwid>')
@login_required
def firmware_component_requires_remove_hwid(firmware_id, cid, hwid):

    # get firmware component
    try:
        fwobj = db.firmware.get_item(firmware_id)
    except CursorError as e:
        return _error_internal(str(e))
    if not fwobj:
        return _error_internal('No firmware matched!')
    md = _item_filter_by_cid(fwobj, cid)
    if not md:
        return _error_internal('No component matched!')

    # we can only modify our own firmware, unless admin
    group_id = fwobj.group_id
    if group_id != session['group_id'] and session['group_id'] != 'admin':
        return _error_permission_denied('Unable to modify other vendor firmware')

    # remove hwid
    fwreq = md.find_fwreq('hardware', hwid)
    md.requirements.remove(fwreq)

    # modify
    try:
        db.firmware.update(fwobj)
    except CursorError as e:
        return _error_internal(str(e))

    # log
    _event_log('Removed HWID %s on %s' % (hwid, firmware_id))
    return redirect(url_for('.firmware_component_show',
                            firmware_id=firmware_id,
                            cid=cid,
                            page='requires'))

@app.route('/lvfs/firmware/<firmware_id>/component/<cid>/requires/add/hwid', methods=['POST'])
@login_required
def firmware_component_requires_add_hwid(firmware_id, cid):
    """ Modifies the update urgency and release notes for the update """

    # get firmware component
    try:
        fwobj = db.firmware.get_item(firmware_id)
    except CursorError as e:
        return _error_internal(str(e))
    if not fwobj:
        return _error_internal('No firmware matched!')
    md = _item_filter_by_cid(fwobj, cid)
    if not md:
        return _error_internal('No component matched!')

    # we can only modify our own firmware, unless admin
    group_id = fwobj.group_id
    if group_id != session['group_id'] and session['group_id'] != 'admin':
        return _error_permission_denied('Unable to modify other vendor firmware')

    # check we have data
    if 'hwid' not in request.form:
        return _error_internal('No hwid specified!')

    # add hwid
    hwid = request.form['hwid']
    fwreq = md.find_fwreq('hardware', hwid)
    if fwreq:
        flash('%s has already been added' % hwid, 'warning')
    elif not _validate_guid(hwid):
        flash('%s was not a valid GUID' % hwid, 'danger')
    else:
        fwreq = FirmwareRequirement('hardware', hwid)
        md.requirements.append(fwreq)
        try:
            db.firmware.update(fwobj)
        except CursorError as e:
            return _error_internal(str(e))
        _event_log('Added HWID %s on %s' % (hwid, firmware_id))
    return redirect(url_for('.firmware_component_show',
                            firmware_id=firmware_id,
                            cid=cid,
                            page='requires'))

@app.route('/lvfs/firmware/<firmware_id>/component/<cid>/requires/set/<kind>/<value>', methods=['POST'])
@login_required
def firmware_component_requires_set(firmware_id, cid, kind, value):
    """ Modifies the update urgency and release notes for the update """

    # get firmware component
    try:
        fwobj = db.firmware.get_item(firmware_id)
    except CursorError as e:
        return _error_internal(str(e))
    if not fwobj:
        return _error_internal('No firmware matched!')
    md = _item_filter_by_cid(fwobj, cid)
    if not md:
        return _error_internal('No component matched!')

    # we can only modify our own firmware, unless admin
    group_id = fwobj.group_id
    if group_id != session['group_id'] and session['group_id'] != 'admin':
        return _error_permission_denied('Unable to modify other vendor firmware')

    # check we have data
    if 'compare' not in request.form:
        return _error_internal('No compare specified!')
    if 'version' not in request.form:
        return _error_internal('No version specified!')

    # modify hwid, removing or creating as required
    fwreq = md.find_fwreq(kind, value)
    if request.form['compare'] == '':
        if fwreq:
            md.requirements.remove(fwreq)
    else:
        if not fwreq:
            fwreq = FirmwareRequirement(kind, value)
            md.requirements.append(fwreq)
        fwreq.compare = request.form['compare']
        fwreq.version = request.form['version']
    try:
        db.firmware.update(fwobj)
    except CursorError as e:
        return _error_internal(str(e))
    _event_log('Changed %s/%s requirement on %s' % (kind, value, firmware_id))
    return redirect(url_for('.firmware_component_show',
                            firmware_id=firmware_id,
                            cid=cid,
                            page='requires'))
