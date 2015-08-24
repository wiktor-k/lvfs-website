#!/usr/bin/python
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2
import os

STATIC_DIR = 'static'
UPLOAD_DIR = 'uploads'
DOWNLOAD_DIR = 'downloads'
KEYRING_DIR = 'gnupg'
if 'OPENSHIFT_PYTHON_DIR' in os.environ:
    virtenv = os.environ['OPENSHIFT_PYTHON_DIR'] + '/virtenv/'
    virtualenv = os.path.join(virtenv, 'bin/activate_this.py')
    try:
        execfile(virtualenv, dict(__file__=virtualenv))
    except IOError:
        pass
    STATIC_DIR = os.path.join(os.environ['OPENSHIFT_REPO_DIR'], 'static')
    UPLOAD_DIR = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'uploads')
    DOWNLOAD_DIR = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'downloads')
    KEYRING_DIR = os.path.join(os.environ['OPENSHIFT_DATA_DIR'], 'gnupg')

from wsgiref.simple_server import make_server
from Cookie import SimpleCookie
import cgi
import hashlib
import MySQLdb as mdb

import cabarchive
import appstream
from affidavit import Affidavit, NoKeyError

class LvfsWebsite(object):
    """ A helper class """

    def __init__(self):
        """ Ininitalize the object """
        self.username = ''
        self.password = '' # hashed
        self.qa_group = ''
        self.qa_capability = False
        self.fields = None
        self.qs_get = None
        self.db = None
        self.client_address = None
        self.session_cookie = SimpleCookie()
        self.response_code = None
        self.content_type = 'text/html'

    def _event_log(self, msg, username=None, is_important=False):
        """ Adds an item to the event log """
        if not self.db:
            print "No database, ignoring: %s" % msg
            return
        if not username:
            username = self.username
        cur = self.db.cursor()
        try:
            cur.execute("INSERT INTO event_log (username, addr, message, is_important) "
                        "VALUES (%s, %s, %s, %s);",
                        (username, self.client_address, msg, is_important,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))

    def create_affidavit(self):
        """ Create an affidavit that can be used to sign files """

        # create signing object
        cur = self.db.cursor()
        cur.execute("SELECT email FROM users WHERE username='admin'")
        key_uid = cur.fetchone()
        return Affidavit(key_uid[0], KEYRING_DIR)

    def _password_hash(self, value):
        """ Generate a salted hash of the password string """
        salt = 'lvfs%%%'
        return hashlib.sha1(salt + value).hexdigest()

    def _qa_hash(self, value):
        """ Generate a salted hash of the QA group """
        salt = 'vendor%%%'
        return hashlib.sha1(salt + value).hexdigest()

    def _password_check(self, value):
        """ Check the password for suitability """
        if len(value) < 8:
            return 'The password is too short, the minimum is 8 character'
        if len(value) > 40:
            return 'The password is too long, the maximum is 40 character'
        if value.lower() == value:
            return 'The password requires at least one uppercase character'
        if value.isalnum():
            return 'The password requires at least one non-alphanumeric character'
        return None

    def _email_check(self, value):
        """ Do a quick and dirty check on the email address """
        if len(value) < 5 or value.find('@') == -1 or value.find('.') == -1:
            return 'Invalid email address'
        return None

    def _format_cursor_error(self, cur, e):
        ''' return an HTML error string of the cursor error '''
        return cgi.escape(cur._last_executed) + '&#10145; ' + cgi.escape(str(e))

    def _set_response_code(self, rc):
        """ Set the response code if not already set """
        if self.response_code:
            return
        self.response_code = rc

    def _gen_header(self, title):
        """ Generate a HTML header for all pages """
        html = """
<!DOCTYPE html>
<!-- Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
     Licensed under the GNU General Public License Version 2 -->
<html>
<head>
<title>%s</title>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8"/>
<link rel="stylesheet" href="style.css" type="text/css" media="screen"/>
<link rel="shortcut icon" href="favicon.ico"/>
</head>
<body>
"""
        return html % title

    def _gen_footer(self):
        """ Generate a footer at the bottom of the page """
        html = """
<p class="footer">
 Copyright <a href="mailto:richard@hughsie.com">Richard Hughes 2015</a>
</p>
</body>
</html>
"""
        return html

    def _gen_breadcrumb(self, show_back=True, show_profile=True):
        """ Generate a breadcrumb header at the top of the page """
        html = '<table class="breadcrumb"><tr>'

        # back button
        if show_back:
            html += '<td>'
            html += '<form method=\"get\" action=\"wsgi.py\">'
            html += '<button class="breadcrumb">&lt;</button>'
            html += '</form>'
            html += '</td>\n'

        # profile
        html += '<td class="breadcrumb">'
        if not show_profile:
            html += "User %s" % self.username
        else:
            html += "User <a href=\"wsgi.py?action=profile\">%s</a>" % self.username

        # log out
        html += ' &#10145; <a href="wsgi.py?action=logout\">Log out</a>'
        html += '</td>\n'
        html += '</tr></table>\n'

        return html

    def _action_login(self, error_msg=None):
        """ A login screen to allow access to the LVFS main page """

        html = """
<h1 class="banner">Linux Vendor<br>Firmware Service</h1>
<h2>Please Login</h2>
<p>%s</p>
<form method="post" action="wsgi.py">
<table class="upload">
<tr>
<td><label for="username">Username:</label></td>
<td><input type="text" name="username" required></td>
</tr>
<tr>
<td><label for="password">Password:</label></td>
<td><input type="password" name="password" required></td>
</tr>
</table>
<input type="submit" class="submit" value="Login">
</form>
<p>
 If you are a hardware vendor it's easy to
 <a href="mailto:richard@hughsie.com">request a new account</a>.
 It's also completely free!
</p>
</body>
</html>
"""
        if error_msg == None:
            error_msg = ''
        # set correct response code
        self._set_response_code('401 Unauthorized')
        return self._gen_header('LVFS: Login') + html % error_msg + self._gen_footer()

    def _action_useradd(self):
        """ Add a user [ADMIN ONLY] """

        if self.username != 'admin':
            return self._action_permission_denied('Unable to add user as non-admin')
        if not 'password_new' in self.fields:
            return self._action_permission_denied('Unable to add user an no data')
        if not 'username_new' in self.fields:
            return self._action_permission_denied('Unable to add user an no data')
        if not 'qa_group' in self.fields:
            return self._action_permission_denied('Unable to add user an no data')
        if not 'name' in self.fields:
            return self._action_permission_denied('Unable to add user an no data')
        if not 'email' in self.fields:
            return self._action_permission_denied('Unable to add user an no data')
        cur = self.db.cursor()
        try:
            cur.execute("SELECT is_enabled FROM users WHERE username=%s",
                        (self.fields['username_new'].value,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))
        auth = cur.fetchone()
        if auth:
            self._set_response_code('422 Entity Already Exists')
            return self._action_profile('Already a entry with that username')

        # verify password
        password = self.fields['password_new'].value
        pw_check = self._password_check(password)
        if pw_check:
            self._set_response_code('400 Bad Request')
            return self._action_profile(pw_check)
        pw_hash = self._password_hash(password)

        # verify email
        email = self.fields['email'].value
        email_check = self._email_check(email)
        if email_check:
            self._set_response_code('400 Bad Request')
            return self._action_profile(email_check)

        # verify qa_group
        qa_group = self.fields['qa_group'].value
        if len(qa_group) < 3:
            self._set_response_code('400 Bad Request')
            return self._action_profile('QA group invalid')

        # verify name
        name = self.fields['name'].value
        if len(name) < 3:
            self._set_response_code('400 Bad Request')
            return self._action_profile('Name invalid')

        # verify username
        username_new = self.fields['username_new'].value
        if len(username_new) < 3:
            self._set_response_code('400 Bad Request')
            return self._action_profile('Username invalid')
        try:
            cur.execute("INSERT INTO users (username, password, display_name, email, is_enabled, qa_group) "
                        "VALUES (%s, %s, %s, %s, 1, %s);",
                        (username_new, pw_hash, name, email, qa_group,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))

        self._event_log("Created user %s" % username_new)
        self._set_response_code('201 Created')
        return self._action_profile('Added user')

    def _action_userinc(self, value):
        """ Adds or remove a capability to a user """

        # check admin
        if self.username != 'admin':
            return self._action_permission_denied('Unable to inc user as not admin')
        username_new = self.qs_get.get('username_new', [None])[0]
        if not username_new:
            return self._action_permission_denied('Unable to inc user as no data')

        # get modification type
        key = self.qs_get.get('key', [None])[0]
        if not key:
            return self._action_permission_denied('Unable to inc user as no data')

        # save new value
        cur = self.db.cursor()
        if key == 'qa':
            try:
                cur.execute("UPDATE users SET is_qa=%s WHERE username=%s;",
                            (value, username_new,))
            except mdb.Error, e:
                return self._internal_error(self._format_cursor_error(cur, e))
        elif key == 'enabled':
            try:
                cur.execute("UPDATE users SET is_enabled=%s WHERE username=%s;",
                            (value, username_new,))
            except mdb.Error, e:
                return self._internal_error(self._format_cursor_error(cur, e))
        else:
            return self._action_permission_denied('Unable to change user as key invalid')
        # set correct response code
        self._event_log("Set %s=%s for user %s" % (key, value, username_new))
        self._set_response_code('200 OK')
        return self._action_profile()

    def _action_userdel(self):
        """ Delete a user [ADMIN ONLY] """

        if self.username != 'admin':
            return self._action_permission_denied('Unable to remove user as not admin')
        username_new = self.qs_get.get('username_new', [None])[0]
        if not username_new:
            return self._action_permission_denied('Unable to change user as no data')
        cur = self.db.cursor()
        try:
            cur.execute("SELECT is_enabled FROM users WHERE username=%s;",
                        (username_new,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))
        exists = cur.fetchone()
        if not exists:
            self._set_response_code('400 Bad Request')
            return self._action_profile("No entry with username %s" % username_new)
        try:
            cur.execute("DELETE FROM users WHERE username=%s;",
                        (username_new,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))
        self._event_log("Deleted user %s" % username_new)
        self._set_response_code('200 OK')
        return self._action_profile('Deleted user')

    def _action_usermod(self):
        """ Change details about the current user """

        if not 'password_new' in self.fields:
            return self._action_permission_denied('Unable to change user as no data')
        if not 'password_old' in self.fields:
            return self._action_permission_denied('Unable to change user as no data')
        if not 'name' in self.fields:
            return self._action_permission_denied('Unable to change user as no data')
        if not 'email' in self.fields:
            return self._action_permission_denied('Unable to change user as no data')
        cur = self.db.cursor()
        try:
            pw_hash = self._password_hash(self.fields['password_old'].value)
            cur.execute("SELECT is_enabled FROM users WHERE username=%s AND password=%s;",
                        (self.username, pw_hash,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))
        auth = cur.fetchone()
        if not auth:
            return self._action_login('Incorrect existing password')

        # check password
        password = self.fields['password_new'].value
        pw_check = self._password_check(password)
        if pw_check:
            self._set_response_code('400 Bad Request')
            return self._action_profile(pw_check)
        pw_hash = self._password_hash(password)

        # check email
        email = self.fields['email'].value
        email_check = self._email_check(email)
        if email_check:
            return self._action_profile(email_check)

        # verify name
        name = self.fields['name'].value
        if len(name) < 3:
            self._set_response_code('400 Bad Request')
            return self._action_profile('Name invalid')
        try:
            cur.execute("UPDATE users SET display_name=%s, email=%s, password=%s "
                        "WHERE username=%s;",
                        (name, email, pw_hash, self.username,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))
        self.session_cookie['password'] = pw_hash
        self._event_log('Changed password')
        self._set_response_code('200 OK')
        return self._action_profile('Updated profile')

    def _action_profile(self, msg=''):
        """
        Allows the normal user to change details about the account,
        and also the admin user to add or remove user accounts.
         """

        html = """
<p>%s</p>
<h1>Modify User</h1>
<p>
A good password consists of upper and lower case with numbers.
</p>
<form method="post" action="wsgi.py?action=usermod">
<table>
<tr>
<td>Current Password:</td>
<td><input type="password" name="password_old" required></td>
</tr>
<tr>
<td>New Password:</td>
<td><input type="password" name="password_new" required></td>
</tr>
<tr>
<td>Vendor Name:</td>
<td><input type="text" name="name" value="%s" required></td>
</tr>
<tr>
<td>Contact Email:</td>
<td><input type="text" name="email" value="%s" required></td>
</tr>
</table>
<input type="submit" class="submit" value="Modify">
</form>
"""

        # auth check
        cur = self.db.cursor()
        try:
            cur.execute("SELECT display_name, email FROM users WHERE username = %s"
                        " LIMIT 1;", (self.username,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))
        res = cur.fetchone()
        if not res:
            return self._action_login('Invalid username query')

        # add defaults
        display_name = res[0]
        if not display_name:
            display_name = "Example Name"
        email = res[1]
        if not email:
            email = "info@example.com"

        html = html % (msg, display_name, email)

        admin_html = ''
        if self.username == 'admin':
            admin_html = """
<h1>Userlist</h1>
<table class="history">
<tr>
<th>Username</th>
<th>Password</th>
<th>Name</th>
<th>Email</th>
<th>Group</th>
<th>Actions</th>
</tr>
%s
</table>
"""

            try:
                cur.execute("SELECT username, display_name, email, password, is_enabled, is_qa, qa_group FROM users;")
            except mdb.Error, e:
                return self._internal_error(self._format_cursor_error(cur, e))
            res = cur.fetchall()
            if not res:
                return self._action_login('No users available!')
            userlist = ''
            for e in res:
                if e[0] == 'admin':
                    button = ''
                else:
                    button = "<form method=\"get\" action=\"wsgi.py\">" \
                             "<input type=\"hidden\" name=\"action\" value=\"userdel\"/>" \
                             "<input type=\"hidden\" name=\"username_new\" value=\"%s\"/>" \
                             "<button>Delete</button>" \
                             "</form>" % e[0]
                    if not int(e[4]):
                        button += "<form method=\"get\" action=\"wsgi.py\">" \
                                  "<input type=\"hidden\" name=\"action\" value=\"userinc\"/>" \
                                  "<input type=\"hidden\" name=\"username_new\" value=\"%s\"/>" \
                                  "<input type=\"hidden\" name=\"key\" value=\"%s\"/>" \
                                  "<button>Enable</button>" \
                                  "</form>" % (e[0], 'enabled')
                    else:
                        button += "<form method=\"get\" action=\"wsgi.py\">" \
                                  "<input type=\"hidden\" name=\"action\" value=\"userdec\"/>" \
                                  "<input type=\"hidden\" name=\"username_new\" value=\"%s\"/>" \
                                  "<input type=\"hidden\" name=\"key\" value=\"%s\"/>" \
                                  "<button>Disable</button>" \
                                  "</form>" % (e[0], 'enabled')
                    if not int(e[5]):
                        button += "<form method=\"get\" action=\"wsgi.py\">" \
                                  "<input type=\"hidden\" name=\"action\" value=\"userinc\"/>" \
                                  "<input type=\"hidden\" name=\"username_new\" value=\"%s\"/>" \
                                  "<input type=\"hidden\" name=\"key\" value=\"%s\"/>" \
                                  "<button>+QA</button>" \
                                  "</form>" % (e[0], 'qa')
                    else:
                        button += "<form method=\"get\" action=\"wsgi.py\">" \
                                  "<input type=\"hidden\" name=\"action\" value=\"userdec\"/>" \
                                  "<input type=\"hidden\" name=\"username_new\" value=\"%s\"/>" \
                                  "<input type=\"hidden\" name=\"key\" value=\"%s\"/>" \
                                  "<button>-QA</button>" \
                                  "</form>" % (e[0], 'qa')
                userlist += '<tr>'
                userlist += "<td>%s</td>\n" % e[0]
                userlist += "<td>%s&hellip;</td>\n" % e[3][0:8]
                userlist += "<td>%s</td>\n" % e[1]
                userlist += "<td>%s</td>\n" % e[2]
                userlist += "<td>%s</td>\n" % e[6]
                userlist += "<td>%s</td>\n" % button
                userlist += '</tr>'

            # add new user form
            userlist += "<tr>" \
                        "<form method=\"post\" action=\"wsgi.py?action=useradd\">" \
                        "<td><input type=\"text\" size=\"8\" name=\"username_new\" placeholder=\"username\" required></td>" \
                        "<td><input type=\"password\" size=\"8\" name=\"password_new\" placeholder=\"password\" required></td>" \
                        "<td><input type=\"text\" size=\"14\" name=\"name\" placeholder=\"Example Name\" required></td>" \
                        "<td><input type=\"text\" size=\"14\" name=\"email\" placeholder=\"info@example.com\" required></td>" \
                        "<td><input type=\"text\" size=\"8\" name=\"qa_group\" placeholder=\"example\" required></td>" \
                        "<td><input type=\"submit\" class=\"button\" value=\"Add\"></td>" \
                        "</form>" \
                        "</tr>\n"
            admin_html = admin_html % userlist

            # add event log
            tbldata = """
<h1>Event Log</h1>
<table class="history">
<tr>
<th>Timestamp</th>
<th>Address</th>
<th>User</th>
<th></th>
<th>Message</th>
</tr>
"""

            try:
                cur.execute("SELECT timestamp, username, addr, message, is_important FROM event_log ORDER BY timestamp DESC LIMIT 20;")
            except mdb.Error, e:
                return self._internal_error(self._format_cursor_error(cur, e))
            res = cur.fetchall()
            if not res:
                return self._action_login('No users available!')
            for e in res:
                tbldata += '<tr>'
                tbldata += "<td>%s</td>" % str(e[0]).split('.')[0]
                tbldata += "<td>%s</td>" % e[2]
                tbldata += "<td>%s</td>" % e[1]
                if e[4] == 1:
                    tbldata += "<td>&#x272a;</td>"
                else:
                    tbldata += "<td></td>"
                tbldata += "<td>%s</td>" % e[3]
                tbldata += '</tr>\n'
            tbldata += '</table>'

            admin_html += tbldata

        self._set_response_code('200 OK')
        return self._gen_header('LVFS: Modify User') + self._gen_breadcrumb(show_profile=False) + html + admin_html + self._gen_footer()

    def _action_firmware(self):
        """
        The main page that shows existing firmware and also allows the
        user to add new firmware.
        """

        html = """
<h1>Add New Firmware</h1>
<p>By uploading a firmware file you must agree that:</p>
<ul>
<li>You are legally permitted to submit the firmware</li>
<li>The submitted firmware file is permitted to be mirrored by our site</li>
<li>The firmware installation must complete without requiring user input</li>
<li>Firmware must not engage in malicious activity (e.g. be a virus or to exploit security issues)</li>
</ul>
"""

        html += """
<form action="wsgi.php?action=upload" method="post" enctype="multipart/form-data">
<table class="upload">
"""

        # can the user upload directly to stable
        if self.qa_capability:
            html += """

<tr>
<th width="150px">Target:</th>
<td>
<select name="target" onChange="changeTargetLabel();" id="targetSelection" required>
<option value="private">Private</option>
<option value="embargo">Embargoed</option>
<option value="testing">Testing</option>
<option value="stable">Stable</option>
</select>
</td>
</tr>
"""
        else:
            html += """
<tr>
<th width="150px">Target:</th>
<td>
<select name="target" id="targetSelection" required>
<option value="private">Private</option>
</select>
</td>
</tr>
"""

        # all enabled users can upload
        html += """
<tr><th width="150px">Firmware:</th><td><input type="file" name="file" required/></td></tr>
</table>
<input type="submit" class="submit" value="Upload"/>
</form>
<p>
 Updates normally go through these stages:
 Private &#8594; Embargoed &#8594; Testing &#8594; Stable
</p>
<p id="targetLabel">This user account is restricted to private uploading.</p>
<h1>Existing Firmware</h1>
%s
</table>

<script type="text/JavaScript">
function changeTargetLabel() {
    var combo = document.getElementById("targetSelection");
    var label = document.getElementById("targetLabel");
    if (combo.selectedIndex == 0) {
        label.innerHTML = "The private target keeps the firmware secret and is only downloadable from this admin console.<br>" +
                          "An admin or QA user can move the firmware to either embargo, testing or stable.";
    } else if (combo.selectedIndex == 1) {
        label.innerHTML = "The embargo target makes the firmware available to users knowing <a href=%s>this URL.</a><br>" +
                          "An admin or QA user can move the firmware to testing when the hardware has been released.";
    } else if (combo.selectedIndex == 2) {
        label.innerHTML = "The testing target makes the firmware available to some users.<br>" +
                          "An admin or QA user can move the firmware to stable when testing is complete.";
    } else if (combo.selectedIndex == 3) {
        label.innerHTML = "The stable target makes the firmware available to all users.<br>" +
                          "Make sure the firmware has been carefully tested before using this target.";
    }
}

// Ensure run at startup
changeTargetLabel();
</script>
"""
        # add the firmware files
        cur = self.db.cursor()
        try:
            if self.username == 'admin':
                cur.execute("SELECT filename, hash, target, timestamp, "
                            "md_name, md_version FROM firmware ORDER BY timestamp DESC;")
            else:
                cur.execute("SELECT filename, hash, target, timestamp, "
                            "md_name, md_version FROM firmware "
                            "WHERE qa_group = %s ORDER BY timestamp DESC;", (self.qa_group,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))
        res = cur.fetchall()
        fwlist = ''
        if res and len(res) > 0:
            fwlist += "<table class=\"history\">" \
                      "<tr>" \
                      "<th>Submitted</td>" \
                      "<th>Name</td>" \
                      "<th>Version</td>" \
                      "<th>Target</td>" \
                      "<th></td>" \
                      "</tr>\n"
            for e in res:
                buttons = "<form method=\"get\" action=\"wsgi.py\">" \
                          "<input type=\"hidden\" name=\"action\" value=\"fwshow\"/>" \
                          "<input type=\"hidden\" name=\"id\" value=\"%s\"/>" \
                          "<button>Details</button>" \
                          "</form>" % e[1]
                fwlist += '<tr>'
                fwlist += "<td>%s</td>" % e[3]
                fwlist += "<td>%s</td>" % e[4]
                fwlist += "<td>%s</td>" % e[5]
                fwlist += "<td>%s</td>" % e[2]
                fwlist += "<td>%s</td>" % buttons
                fwlist += '</tr>\n'
        else:
            fwlist += "<p>No firmware available</p>"

        # this is secret enough as you have to know the SHA1 hash
        embargo_url = 'downloads/firmware-%s.xml.gz' % self._qa_hash(self.qa_group)
        html = html % (fwlist, embargo_url)

        return self._gen_header('LVFS: Firmware') + self._gen_breadcrumb(show_back=False) + html + self._gen_footer()

    def _action_permission_denied(self, msg=None):
        """ The user tried to do something they did not have privs for """

        html = """
<h1>Error: Permission Denied</h1>
<p>Sorry Dave, I can't let you do that&hellip;</p>
"""
        # set correct response code
        self._event_log("Permission denied: %s" % msg, is_important=True)
        self._set_response_code('401 Unauthorized')
        return self._gen_header('LVFS: Permission Denied') + self._gen_breadcrumb(show_back=False, show_profile=False) + html + self._gen_footer()

    def _upload_failed(self, msg=''):
        """ The file upload failed for some reason """

        html = """
<h1>Result: Failed</h1>
<p>%s</p>
"""
        html = html % msg
        # set correct response code
        self._set_response_code('400 Bad Request')
        return self._gen_header('LVFS: Upload Failed') + self._gen_breadcrumb() + html + self._gen_footer()

    def _internal_error(self, admin_only_msg=''):
        """ The file upload failed for some reason """

        html = """
<h1>Internal Error</h1>
<p>%s</p>
"""
        if self.username == 'admin':
            html = html % admin_only_msg
        else:
            html = html % 'No failure details available for this privaledge level.'
        # set correct response code
        self._set_response_code('406 Not Acceptable')
        return self._gen_header('LVFS: Internal Error') + self._gen_breadcrumb() + html + self._gen_footer()

    def _upload_success(self):
        """ A file was successfully uploaded to the LVFS """

        html = """
<h1>Result: Success</h1>
 The firmware file was successfully uploaded and the metadata has been updated.
"""
        # set correct response code
        self._set_response_code('201 Created')
        return self._gen_header('LVFS: Upload Success') + self._gen_breadcrumb() + html + self._gen_footer()

    def _action_fwdelete(self):
        """ Delete a firmware entry and also delete the file from disk """

        # get input
        fwid = self.qs_get.get('id', [None])[0]
        if not fwid:
            return self._upload_failed("No ID specified" % fwid)

        # check firmware exists in database
        cur = self.db.cursor()
        try:
            if self.username == 'admin':
                cur.execute("SELECT filename, target FROM firmware WHERE "
                            "hash = %s LIMIT 1;",
                            (fwid,))
            else:
                cur.execute("SELECT filename, target FROM firmware WHERE "
                            "hash = %s AND qa_group = %s LIMIT 1;",
                            (fwid, self.qa_group,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))
        res = cur.fetchone()
        if not res:
            return self._upload_failed("No firmware file with hash %s exists" % fwid)
        filename = res[0]

        # only QA users can delete once the firmware has gone stable
        if not self.qa_capability and res[1] == 'stable':
            return self._action_permission_denied('Unable to delete stable firmware as not QA')

        # delete id from database
        cur = self.db.cursor()
        try:
            if self.username == 'admin':
                cur.execute("DELETE FROM firmware WHERE hash = %s;",
                            (fwid,))
            else:
                cur.execute("DELETE FROM firmware WHERE hash = %s AND qa_group = %s;",
                            (fwid, self.qa_group,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))

        # delete file
        path = os.path.join(UPLOAD_DIR, filename)
        if os.path.exists(path):
            os.remove(path)

        self._event_log("Deleted firmware %s" % fwid)
        self._set_response_code('200 OK')
        return self._action_firmware()

    def _action_fwshow(self):
        """ Show profile information """

        # get input
        fwid = self.qs_get.get('id', [None])[0]
        if not fwid:
            return self._internal_error('No ID specified')

        # get details about the firmware
        cur = self.db.cursor()
        try:
            cur.execute("SELECT qa_group, addr, timestamp, filename, target, "
                        "md_guid, md_version, md_name, md_summary, md_id "
                        "FROM firmware WHERE hash=%s LIMIT 1;", (fwid,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))
        res = cur.fetchone()
        if not res:
            return self._action_login('No firmware matched!')

        # we can only view our own firmware, unless admin
        qa_group = res[0]
        if qa_group != self.qa_group and self.username != 'admin':
            return self._action_permission_denied('Unable to view other vendor firmware')
        if not qa_group:
            embargo_url = 'downloads/firmware.xml.gz'
            qa_group = 'None'
        else:
            embargo_url = 'downloads/firmware-%s.xml.gz' % self._qa_hash(qa_group)
        file_uri = 'downloads/' + res[3]

        buttons = ''
        if self.qa_capability or res[4] == 'private':
            buttons += "<form method=\"get\" action=\"wsgi.py\">" \
                       "<input type=\"hidden\" name=\"action\" value=\"fwdelete\"/>" \
                       "<input type=\"hidden\" name=\"id\" value=\"%s\"/>" \
                       "<button>Delete</button>" \
                       "</form>" % fwid
        if self.qa_capability:
            if res[4] == 'private':
                buttons += "<form method=\"get\" action=\"wsgi.py\">" \
                           "<input type=\"hidden\" name=\"action\" value=\"fwpromote\"/>" \
                           "<input type=\"hidden\" name=\"target\" value=\"embargo\"/>" \
                           "<input type=\"hidden\" name=\"id\" value=\"%s\"/>" \
                           "<button>&#8594; Embargo</button>" \
                           "</form>" % fwid
            elif res[4] == 'embargo':
                buttons += "<form method=\"get\" action=\"wsgi.py\">" \
                           "<input type=\"hidden\" name=\"action\" value=\"fwpromote\"/>" \
                           "<input type=\"hidden\" name=\"target\" value=\"testing\"/>" \
                           "<input type=\"hidden\" name=\"id\" value=\"%s\"/>" \
                           "<button>&#8594; Testing</button>" \
                           "</form>" % fwid
            elif res[4] == 'testing':
                buttons += "<form method=\"get\" action=\"wsgi.py\">" \
                           "<input type=\"hidden\" name=\"action\" value=\"fwpromote\"/>" \
                           "<input type=\"hidden\" name=\"target\" value=\"stable\"/>" \
                           "<input type=\"hidden\" name=\"id\" value=\"%s\"/>" \
                           "<button>&#8594; Stable</button>" \
                           "</form>" % fwid

        html = '<h1>%s</h1>' % res[7]
        html += '<p>%s</p>' % res[8]
        html += '<table class="history">'
        html += '<tr><th>ID</th><td>%s</td></tr>' % res[9]
        html += '<tr><th>Filename</th><td><a href=\"%s\">%s</a></td></tr>' % (file_uri, res[3])
        html += '<tr><th>Device GUID</th><td>%s</td></tr>' % res[5]
        html += '<tr><th>Version</th><td>%s</td></tr>' % res[6]
        html += '<tr><th>Current Target</th><td>%s</td></tr>' % res[4]
        html += '<tr><th>Submitted</th><td>%s</td></tr>' % res[2]
        html += '<tr><th>QA Group</th><td><a href="%s">%s</a></td></tr>' % (embargo_url, qa_group)
        html += '<tr><th>Uploaded from</th><td>%s</td></tr>' % res[1]
        html += '<tr><th>Actions</th><td>%s</td></tr>' % buttons
        html += '</table>'

        # set correct response code
        self._set_response_code('200 OK')
        return self._gen_header('LVFS: Firmware Details') + self._gen_breadcrumb() + html + self._gen_footer()

    def _action_fwpromote(self):
        """
        Promote or demote a firmware file from one target to another,
        for example from testing to stable, or stable to testing.
         """

        # check is QA
        if not self.qa_capability:
            return self._action_permission_denied('Unable to promote as not QA')

        # get input
        fwid = self.qs_get.get('id', [None])[0]
        if not fwid:
            return self._internal_error('No ID specified')
        target = self.qs_get.get('target', [None])[0]
        if not fwid:
            return self._internal_error('No target specified')

        # check valid
        if target not in ['stable', 'testing', 'private', 'embargo']:
            return self._internal_error("Target %s invalid" % target)

        # check firmware exists in database
        cur = self.db.cursor()
        try:
            cur.execute("UPDATE firmware SET target=%s WHERE hash=%s;", (target, fwid,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))
        # set correct response code
        self._event_log("Moved firmware %s to %s" % (fwid, target))

        # update everything
        try:
            self.update_metadata(targets=['stable', 'unstable'], qa_group='')
        except NoKeyError as e:
            return self._upload_failed('Failed to sign metadata: ' + cgi.escape(str(e)))

        return self._action_fwshow()

    def _action_upload(self):
        """ Upload a .cab file to the LVFS service """

        # not correct parameters
        if not 'target' in self.fields:
            return self._upload_failed('No target')
        if not 'file' in self.fields:
            return self._upload_failed('No file')

        # can the user upload directly to stable
        if self.fields['target'].value == 'stable':
            if not self.qa_capability:
                return self._action_permission_denied('Unable to upload to stable as not QA')

        # check size < 50Mb
        fileitem = self.fields['file']
        if not fileitem.file:
            return self._upload_failed('No file object')
        data = fileitem.file.read()
        if len(data) > 50000000:
            self._set_response_code('413 Payload Too Large')
            return self._upload_failed('File too large, limit is 50Mb')
        if len(data) == 0:
            return self._upload_failed('File has no content')
        if len(data) < 1024:
            return self._upload_failed('File too small, mimimum is 1k')

        # parse the file
        arc = cabarchive.CabArchive()
        try:
            arc.parse(data)
        except cabarchive.CorruptionError as e:
            self._set_response_code('415 Unsupported Media Type')
            return self._upload_failed('Invalid file type, expected <code>.cab</code> file')
        except cabarchive.NotSupportedError as e:
            self._set_response_code('415 Unsupported Media Type')
            return self._upload_failed('The cab file has unsupported features')
        except Exception as e:
            return self._upload_failed(str(e))

        # check .inf exists
        cf = arc.find_file("*.inf")
        if not cf:
            return self._upload_failed('The firmware file had no valid inf file')

        # check metainfo exists
        cf = arc.find_file("*.metainfo.xml")
        if not cf:
            return self._upload_failed('The firmware file had no valid metadata')

        # parse the MetaInfo file
        app = appstream.Component()
        try:
            app.parse(str(cf.contents))
            app.validate()
        except appstream.ParseError as e:
            return self._upload_failed('The metadata could not be parsed: ' + cgi.escape(str(e)))
        except appstream.ValidationError as e:
            return self._upload_failed('The metadata file did not validate: ' + cgi.escape(str(e)))

        # check the file does not already exist
        file_id = hashlib.sha1(data).hexdigest()
        cur = self.db.cursor()
        try:
            cur.execute("SELECT * FROM firmware WHERE hash = %s LIMIT 1;", (file_id,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))
        if cur.fetchone():
            self._set_response_code('422 Entity Already Exists')
            return self._upload_failed("A firmware file with hash %s already exists" % file_id)

        # check the guid and version does not already exist
        try:
            cur.execute("SELECT * FROM firmware WHERE md_guid=%s AND md_version=%s LIMIT 1;",
                        (app.provides[0].value, app.releases[0].version,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))
        if cur.fetchone():
            self._set_response_code('422 Entity Already Exists')
            return self._upload_failed("A firmware file for this version already exists")

        # only save if we passed all tests
        basename = os.path.basename(fileitem.filename)
        new_filename = file_id + '-' + basename
        if not os.path.exists(UPLOAD_DIR):
            os.mkdir(UPLOAD_DIR)
        open(os.path.join(UPLOAD_DIR, new_filename), 'wb').write(data)
        print "wrote %i bytes to %s" % (len(data), new_filename)

        # get the contents checksum
        fw_data = arc.find_file('*.bin')
        if not fw_data:
            fw_data = arc.find_file('*.cap')
        if not fw_data:
            return self._upload_failed('No firmware found in the archive: ' + cgi.escape(str(e)))
        checksum_contents = hashlib.sha1(fw_data.contents).hexdigest()

        # add the detached signature
        try:
            affidavit = self.create_affidavit()
            print affidavit
        except NoKeyError as e:
            return self._upload_failed('Failed to sign archive: ' + cgi.escape(str(e)))
        cff = cabarchive.CabFile(fw_data.filename + '.asc',
                                 affidavit.create(fw_data.contents))
        arc.add_file(cff)

        # export the new archive and get the checksum
        cab_data = arc.save(compressed=True)
        checksum_container = hashlib.sha1(cab_data).hexdigest()

        # dump to a file
        if not os.path.exists(DOWNLOAD_DIR):
            os.mkdir(DOWNLOAD_DIR)
        fn = os.path.join(DOWNLOAD_DIR, new_filename)
        open(fn, 'wb').write(cab_data)

        # log to database
        cur = self.db.cursor()
        target = self.fields['target'].value
        try:
            cur.execute("INSERT INTO firmware (qa_group, addr, timestamp, "
                        "filename, hash, target, md_id, md_guid, md_version, "
                        "md_name, md_summary, md_checksum_contents, md_release_description, "
                        "md_release_timestamp, md_developer_name, md_metadata_license, "
                        "md_project_license, md_url_homepage, md_description, "
                        "md_checksum_container) "
                        "VALUES (%s, %s, CURRENT_TIMESTAMP, %s, %s, %s, %s, "
                        "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);",
                        (self.qa_group,
                         self.client_address,
                         new_filename,
                         file_id,
                         target,
                         app.id,
                         app.provides[0].value,
                         app.releases[0].version,
                         app.name,
                         app.summary,
                         checksum_contents,
                         app.releases[0].description,
                         app.releases[0].timestamp,
                         app.developer_name,
                         app.metadata_license,
                         app.project_license,
                         app.urls['homepage'],
                         app.description,
                         checksum_container,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))
        # set correct response code
        self._event_log("Uploaded file %s to %s" % (new_filename, target))
        self._set_response_code('201 Created')

        # ensure up to date
        try:
            self.update_metadata(targets=['stable', 'unstable'], qa_group='')
            if target in ['stable', 'testing']:
                self.update_metadata(targets=[target])
            elif target == 'embargo':
                self.update_metadata(qa_group=self.qa_group)
        except NoKeyError as e:
            return self._upload_failed('Failed to sign metadata: ' + cgi.escape(str(e)))

        return self._upload_success()

    def get_response(self):
        """ Get the correct page using the page POST and GET data """

        # auth check
        if not self.username:
            self._set_response_code('401 Unauthorized')
            return self._action_login()
        cur = self.db.cursor()
        try:
            cur.execute("SELECT is_enabled, is_qa, qa_group FROM users WHERE username = %s AND password = %s"
                        " LIMIT 1;", (self.username, self.password,))
        except mdb.Error, e:
            return self._internal_error(self._format_cursor_error(cur, e))
        auth = cur.fetchone()
        if not auth:
            return self._action_login('Incorrect username or password')
        if not int(auth[0]):
            return self._action_login('User account has been disabled')
        self.qa_capability = int(auth[1])
        self.qa_group = auth[2]

        # perform login-required actions
        action = self.qs_get.get('action', [None])[0]
        if action == 'logout':
            self.session_cookie['username']['Path'] = '/'
            self.session_cookie['username']['max-age'] = -1
            self.session_cookie['password']['Path'] = '/'
            self.session_cookie['password']['max-age'] = -1
            self._event_log('Logged out')
            return self._action_login('Successfully logged out. Log in again to perform any vendor actions.')
        elif action == 'profile':
            return self._action_profile()
        elif action == 'usermod':
            return self._action_usermod()
        elif action == 'useradd':
            return self._action_useradd()
        elif action == 'userdel':
            return self._action_userdel()
        elif action == 'userinc':
            return self._action_userinc(1)
        elif action == 'userdec':
            return self._action_userinc(0)
        elif action == 'upload':
            return self._action_upload()
        elif action == 'fwdelete':
            return self._action_fwdelete()
        elif action == 'fwpromote':
            return self._action_fwpromote()
        elif action == 'fwshow':
            return self._action_fwshow()
        else:
            self.session_cookie['username'] = self.username
            self.session_cookie['username']['Path'] = '/'
            self.session_cookie['username']['max-age'] = 2 * 60 * 60
            self.session_cookie['password'] = self.password
            self.session_cookie['password']['Path'] = '/'
            self.session_cookie['password']['max-age'] = 2 * 60 * 60
            return self._action_firmware()

    def _generate_metadata_kind(self, filename, target=None, qa_group=None):
        """ Generates AppStream metadata of a specific kind """

        cur = self.db.cursor()
        cur.execute("SELECT filename, md_checksum_contents, md_id, "
                    "md_name, md_summary, md_guid, md_description, "
                    "md_release_description, md_url_homepage, "
                    "md_metadata_license, md_project_license, "
                    "md_developer_name, md_release_timestamp, "
                    "md_version, hash, qa_group, target FROM firmware "
                    "WHERE target != 'private';")
        res = cur.fetchall()

        store = appstream.Store('lvfs')
        for r in res:

            # filter
            if target:
                if target != r[16]:
                    continue
            if qa_group:
                if qa_group != r[15]:
                    continue

            # add component
            app = appstream.Component()
            app.id = r[2]
            app.kind = 'firmware'
            app.name = r[3]
            app.summary = r[4]
            app.description = r[6]
            if r[8]:
                app.urls['homepage'] = r[8]
            app.metadata_license = r[9]
            app.project_license = r[10]
            app.developer_name = r[11]

            # add provide
            if r[5]:
                prov = appstream.Provide()
                prov.kind = 'firmware-flashed'
                prov.value = r[5]
                app.add_provide(prov)

            # add release
            if r[13]:
                rel = appstream.Release()
                rel.version = r[13]
                rel.description = r[7]
                if r[12]:
                    rel.timestamp = r[12]
                rel.checksums = []
                rel.location = 'https://secure-lvfs.rhcloud.com/downloads/' + r[0]
                app.add_release(rel)

                # add container checksum
                if r[14]:
                    csum = appstream.Checksum()
                    csum.target = 'container'
                    csum.value = r[14]
                    csum.filename = r[0]
                    rel.add_checksum(csum)

                # add content checksum
                if r[1]:
                    csum = appstream.Checksum()
                    csum.target = 'content'
                    csum.value = r[1]
                    csum.filename = 'firmware.bin'
                    rel.add_checksum(csum)

            # add app
            store.add(app)

        # dump to file
        if not os.path.exists(DOWNLOAD_DIR):
            os.mkdir(DOWNLOAD_DIR)
        filename = os.path.join(DOWNLOAD_DIR, filename)
        store.to_file(filename)

        # create .asc file
        affidavit = self.create_affidavit()
        affidavit.create_detached(filename)

        # log
        if target:
            self._event_log("Generated metadata for %s target" % target)
        if qa_group:
            self._event_log("Generated metadata for %s QA group" % qa_group)

    def update_metadata(self, targets=None, qa_group=None):
        """ Updates metadata """

        # normal metadata
        if targets:
            for target in targets:
                if target == 'stable':
                    filename = 'firmware.xml.gz'
                else:
                    filename = 'firmware-%s.xml.gz' % target
                self._generate_metadata_kind(filename, target=target)

        # each vendor
        if qa_group == '':
            cur = self.db.cursor()
            try:
                cur.execute("SELECT DISTINCT qa_group FROM firmware;")
            except mdb.Error, e:
                return self._internal_error(self._format_cursor_error(cur, e))
            res = cur.fetchall()
            for r in res:
                filename = 'firmware-%s.xml.gz' % self._qa_hash(r[0])
                self._generate_metadata_kind(filename, qa_group=r[0])
        else:
            self._generate_metadata_kind(filename, qa_group=qa_group)

    def _fixup_database(self):
        ''' Fix any database problems automatically '''

        # test firmware list exists
        cur = self.db.cursor()
        try:
            cur.execute("SELECT * FROM firmware LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                CREATE TABLE `firmware` (
                  `qa_group` VARCHAR(40) NOT NULL DEFAULT '',
                  `addr` VARCHAR(40) DEFAULT NULL,
                  `timestamp` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  `filename` VARCHAR(255) DEFAULT NULL,
                  `target` VARCHAR(255) DEFAULT NULL,
                  `hash` VARCHAR(40) DEFAULT NULL,
                  `md_checksum_contents` VARCHAR(40) DEFAULT NULL,
                  `md_checksum_container` VARCHAR(40) DEFAULT NULL,
                  `md_id` VARCHAR(1024) DEFAULT NULL,
                  `md_name` VARCHAR(1024) DEFAULT NULL,
                  `md_summary` VARCHAR(1024) DEFAULT NULL,
                  `md_guid` VARCHAR(36) DEFAULT NULL,
                  `md_description` VARCHAR(4096) DEFAULT NULL,
                  `md_release_description` VARCHAR(4096) DEFAULT NULL,
                  `md_url_homepage` VARCHAR(1024) DEFAULT NULL,
                  `md_metadata_license` VARCHAR(1024) DEFAULT NULL,
                  `md_project_license` VARCHAR(1024) DEFAULT NULL,
                  `md_developer_name` VARCHAR(1024) DEFAULT NULL,
                  `md_release_timestamp` INTEGER DEFAULT NULL,
                  `md_version` VARCHAR(255) DEFAULT NULL
                ) CHARSET=utf8;
            """
            cur.execute(sql_db)

        # FIXME, remove after a few days
        try:
            cur.execute("SELECT md_checksum_container FROM firmware LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                ALTER TABLE `firmware` ADD md_checksum_container VARCHAR(40) DEFAULT NULL;
                ALTER TABLE `firmware` ADD md_checksum_contents VARCHAR(40) DEFAULT NULL;
                ALTER TABLE `firmware` ADD md_release_description VARCHAR(4096) DEFAULT NULL;
                ALTER TABLE `firmware` ADD md_release_timestamp INTEGER DEFAULT NULL;
                ALTER TABLE `firmware` ADD md_developer_name VARCHAR(1024) DEFAULT NULL;
                ALTER TABLE `firmware` ADD md_metadata_license VARCHAR(1024) DEFAULT NULL;
                ALTER TABLE `firmware` ADD md_project_license VARCHAR(1024) DEFAULT NULL;
                ALTER TABLE `firmware` ADD md_url_homepage VARCHAR(1024) DEFAULT NULL;
                ALTER TABLE `firmware` ADD md_description VARCHAR(4096) DEFAULT NULL;
                ALTER TABLE `firmware` ADD md_id VARCHAR(1024) DEFAULT NULL;
                ALTER TABLE `firmware` ADD md_name VARCHAR(1024) DEFAULT NULL;
                ALTER TABLE `firmware` ADD md_summary VARCHAR(1024) DEFAULT NULL;
                ALTER TABLE `firmware` ADD md_guid VARCHAR(36) DEFAULT NULL;
                ALTER TABLE `firmware` ADD md_version VARCHAR(255) DEFAULT NULL;
            """
            cur.execute(sql_db)

        # test user list exists
        try:
            cur.execute("SELECT * FROM users LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                CREATE TABLE `users` (
                  `username` VARCHAR(40) NOT NULL DEFAULT '',
                  `password` VARCHAR(40) NOT NULL DEFAULT '',
                  `display_name` VARCHAR(128) DEFAULT NULL,
                  `email` VARCHAR(255) DEFAULT NULL,
                  `is_enabled` INTEGER DEFAULT 0,
                  `is_qa` INTEGER DEFAULT 0,
                  `qa_group` VARCHAR(40) NOT NULL DEFAULT ''
                ) CHARSET=utf8;
            """
            cur.execute(sql_db)

        # test event log exists
        try:
            cur.execute("SELECT * FROM event_log LIMIT 1;")
        except mdb.Error, e:
            sql_db = """
                CREATE TABLE `event_log` (
                  `timestamp` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  `username` VARCHAR(40) NOT NULL DEFAULT '',
                  `addr` VARCHAR(40) DEFAULT NULL,
                  `message` VARCHAR(1024) DEFAULT NULL,
                  `is_important` INTEGER DEFAULT 0
                ) CHARSET=utf8;
            """
            cur.execute(sql_db)

        # ensure an admin user always exists
        cur.execute("SELECT is_enabled FROM users WHERE username='admin';")
        if not cur.fetchone():
            self._event_log('Creating admin user')
            sql_db = """
                INSERT INTO users (username, password, display_name, email, is_enabled, is_qa, qa_group)
                    VALUES ('admin', 'Pa$$w0rd', 'Admin User', 'sign-test@fwupd.org', 1, 1, '');
            """
            cur.execute(sql_db)

        # convert legacy passwords from strings to hashes
        cur.execute("SELECT username, password FROM users;")
        res = cur.fetchall()
        for l in res:
            if len(l[1]) == 40:
                continue
            cur.execute("UPDATE users SET password=%s WHERE username=%s;",
                        (self._password_hash(l[1]), l[0],))

        # ensure admin has all privs
        cur.execute("UPDATE users SET is_enabled=1, is_qa=1, qa_group='' WHERE username='admin';")

    def init(self, environ):
        """ Set up the website helper with the calling environment """

        # get client address
        if 'HTTP_X_FORWARDED_FOR' in environ:
            self.client_address = environ['HTTP_X_FORWARDED_FOR'].split(',')[-1].strip()
        else:
            self.client_address = environ['REMOTE_ADDR']

        # parse POST data
        if 'POST' == environ['REQUEST_METHOD']:
            self.fields = cgi.FieldStorage(fp=environ['wsgi.input'],
                                           environ=environ)

        # find username / password either from POST or the session cookie
        if self.fields:
            if 'username' in self.fields:
                self.username = self.fields['username'].value
            if 'password' in self.fields:
                self.password = self._password_hash(self.fields['password'].value)
        if environ.has_key('HTTP_COOKIE'):
            print environ['HTTP_COOKIE']
            self.session_cookie.load(environ['HTTP_COOKIE'])
            if not self.username and 'username' in self.session_cookie:
                self.username = self.session_cookie['username'].value
            if not self.password and 'password' in self.session_cookie:
                self.password = self.session_cookie['password'].value
        try:
            if 'OPENSHIFT_MYSQL_DB_HOST' in environ:
                self.db = mdb.connect(environ['OPENSHIFT_MYSQL_DB_HOST'],
                                      environ['OPENSHIFT_MYSQL_DB_USERNAME'],
                                      environ['OPENSHIFT_MYSQL_DB_PASSWORD'],
                                      'secure',
                                      int(environ['OPENSHIFT_MYSQL_DB_PORT']))
            else:
                # mysql -u root -p
                # CREATE DATABASE secure;
                # CREATE USER 'test'@'localhost' IDENTIFIED BY 'test';
                # USE secure;
                # GRANT ALL ON secure.* TO 'test'@'localhost';
                self.db = mdb.connect('localhost', 'test', 'test', 'secure')
            self.db.autocommit(True)
        except mdb.Error, e:
            print "Error %d: %s" % (e.args[0], e.args[1])

        # make sane
        self._fixup_database()

        if self.fields:
            self._event_log('Logged on')

    def finalize(self):
        """ Clean up the website helper """
        if self.db:
            self.db.close()

def static_app(fn, start_response, content_type, download=False):
    """ Return a static image or resource """
    if not download:
        path = os.path.join(STATIC_DIR, fn)
    else:
        path = os.path.join(DOWNLOAD_DIR, fn)
    if not os.path.exists(path):
        start_response('404 Not Found', [('content-type', 'text/plain')])
        return ['Not found: ' + path]
    h = open(path, 'rb')
    content = h.read()
    h.close()
    headers = [('content-type', content_type)]
    start_response('200 OK', headers)
    return [content]

def application(environ, start_response):
    """ Main entry point for wsgi """

    # static file
    fn = os.path.basename(environ['PATH_INFO'])
    if fn.endswith(".css"):
        return static_app(fn, start_response, 'text/css')
    if fn.endswith(".svg"):
        return static_app(fn, start_response, 'image/svg+xml')
    if fn.endswith(".png"):
        return static_app(fn, start_response, 'image/png')
    if fn.endswith(".ico"):
        return static_app(fn, start_response, 'image/x-icon')
    if fn.endswith(".xml.gz"):
        return static_app(fn, start_response, 'application/gzip', download=True)
    if fn.endswith(".cab"):
        return static_app(fn, start_response, 'application/vnd.ms-cab-compressed', download=True)
    if fn.endswith(".xml.gz.asc"):
        return static_app(fn, start_response, 'text/plain', download=True)

    # use a helper class
    w = LvfsWebsite()
    w.qs_get = cgi.parse_qs(environ['QUERY_STRING'])
    w.init(environ)

    response_body = w.get_response()

    # fallback
    if not w.response_code:
        print "WARNING, USING FALLBACK CODE"
        w._set_response_code('200 OK')

    response_headers = [('Content-Type', w.content_type),
                        ('Content-Length', str(len(response_body)))]
    response_headers.extend(("set-cookie", morsel.OutputString())
                            for morsel
                            in w.session_cookie.values())
    print w.response_code, response_headers
    start_response(w.response_code, response_headers)
    w.finalize()

    return [response_body]

if __name__ == '__main__':
    httpd = make_server('localhost', 8051, application)
    httpd.serve_forever()
