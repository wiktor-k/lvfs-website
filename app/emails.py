#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

from flask_mail import Message

from app import app, mail

from .decorators import async

@async
def send_async_email(app2, msg):
    with app2.app_context():
        mail.send(msg)

def send_email(subject, recipient, text_body):
    if 'MAIL_SUPPRESS_SEND' in app.config and app.config['MAIL_SUPPRESS_SEND']:
        _event_log('Not sending email to %s' % recipient)
        return
    msg = Message(subject, recipients=[recipient])
    msg.body = text_body
    send_async_email(app, msg)
