Linux Vendor Firmware Service
=============================

This is the website for the Linux Vendor Firmware Service

IMPORTANT: This needs to be hosted over SSL, i.e. with a `https://` prefix.

## How to I use distro packages ##

    yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
    yum install \
      cabextract \
      certbot-apache \
      git \
      httpd \
      mariadb-server \
      mod_wsgi \
      MySQL-python \
      python2-boto3 \
      python2-gnupg \
      python2-mysql \
      python-flask \
      python-flask-login \
      python-flask-wtf

If using RHEL-7 you can get python-flask-login using:

    yum install ftp://fr2.rpmfind.net/linux/fedora/linux/releases/26/Everything/x86_64/os/Packages/p/python-flask-login-0.3.0-6.fc26.noarch.rpm

## How do I start apache server? ##

Save into `/etc/httpd/conf.modules.d/fwupd.org.conf`

    <VirtualHost *>
        ServerName fwupd.org
        WSGIDaemonProcess lvfs user=lvfs group=lvfs threads=5
        WSGIScriptAlias / /home/lvfs/lvfs-website/app.wsgi

        RewriteEngine on
        RewriteCond %{SERVER_NAME} =fwupd.org
        RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]

        <Directory /home/lvfs/lvfs-website>
            WSGIProcessGroup lvfs
            WSGIApplicationGroup %{GLOBAL}
            Require all granted
        </Directory>
    </VirtualHost>

then `service httpd restart` and `chkconfig httpd on`

## How do I generate a SSL certificate ##

If you want to use LetsEncrypt you can just do `certbot --apache` -- you may
have to comment out `WSGIScriptAlias` in the `fwupd.org.conf` file to avoid
a warning during install.

## How do I create the hosting user? ##

    useradd --create-home lvfs
    passwd lvfs
    usermod -G apache lvfs
    mkdir /home/lvfs/downloads
    mkdir /home/lvfs/.aws
    chown lvfs:apache /home/lvfs/ -R
    su -l lvfs
    git clone git@github.com:hughsie/lvfs-website.git

Then add something like this to `lvfs-website/app/lvfs.cfg`:

    import os
    DEBUG = True
    PROPAGATE_EXCEPTIONS = False
    SECRET_KEY = 'FIXME'
    HOST_NAME = 'localhost'
    APP_NAME = 'lvfs'
    IP = 'FIXME'
    PORT = 80
    DOWNLOAD_DIR = '/home/lvfs/downloads'
    KEYRING_DIR = '/home/lvfs/.gnupg'
    CABEXTRACT_CMD = '/usr/bin/cabextract'
    CDN_URI = 'https://s3.amazonaws.com/lvfsbucket'
    CDN_BUCKET = 'lvfsbucket'
    DATABASE_HOST = 'localhost'
    DATABASE_USERNAME = 'dbusername'
    DATABASE_PASSWORD = 'dpassword'
    DATABASE_DB = 'lvfs'
    DATABASE_PORT = 3306

## How do I use the CDN ##

Create a `.aws/credentials` file like:

    [default]
    region=us-east-1
    aws_access_key_id=foo
    aws_secret_access_key=bar

## How do I install the test key? ##

Use the test GPG key (with the initial password of `fwupd`).

    gpg2 --homedir=~/.gnupg --allow-secret-key-import --import contrib/fwupd-test-private.key
    gpg2 --homedir=~/.gnupg --list-secret-keys
    gpg2 --homedir=~/.gnupg --edit-key D64F5C21
    gpg> passwd
    gpg> quit

If passwd cannot be run due to being in a sudo session you can do:

    script /dev/null
    gpg2...

## How do I install the production key? ##

Use the secure GPG key (with the long secret password).

    cd
    mkdir -p gnupg
    gpg2 --homedir=gnupg --allow-secret-key-import --import contrib/fwupd-secret-signing-key.key
    gpg2 --homedir=gnupg --list-secret-keys
    gpg2 --homedir=gnupg --edit-key 4538BAC2
      gpg> passwd
      gpg> quit

## How do I set up the database ##

    service mariadb start
    chkconfig mariadb on

    CREATE DATABASE lvfs;
    CREATE USER 'dbusername'@'localhost' IDENTIFIED BY 'dbpassword';
    USE lvfs;
    GRANT ALL ON lvfs.* TO 'dbusername'@'localhost';
    SOURCE schema.sql

The default admin password is `Pa$$w0rd`

## How do I backup the data ##

To get just the database you can do:

    mysqldump lvfs > backup-`date +%Y%m%d`.sql

## How do I restore from a backup ##

To just restore the database, do:

    mysql
      CREATE DATABASE lvfs;
      use lvfs;
      source backup.sql;

## How do I enable backups using cron ##

FIXME

