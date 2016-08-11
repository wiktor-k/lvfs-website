Linux Vendor Firmware Service
=============================

This is the website for the Linux Vendor Firmware Service

IMPORTANT: This needs to be hosted over SSL, i.e. with a `https://` prefix.

## How do I set up the database ##

    CREATE DATABASE secure;
    CREATE USER 'test'@'localhost' IDENTIFIED BY 'test';
    USE secure;
    GRANT ALL ON secure.* TO 'test'@'localhost';

    CREATE TABLE users (
      username VARCHAR(40) NOT NULL DEFAULT '',
      password VARCHAR(40) NOT NULL DEFAULT '',
      display_name VARCHAR(128) DEFAULT NULL,
      email VARCHAR(255) DEFAULT NULL,
      pubkey VARCHAR(4096) DEFAULT NULL,
      is_enabled TINYINT DEFAULT 0,
      is_qa TINYINT DEFAULT 0,
      qa_group VARCHAR(40) NOT NULL DEFAULT '',
      is_locked TINYINT DEFAULT 0,
      UNIQUE KEY id (username)
    ) CHARSET=utf8;

    INSERT INTO users (username, password, display_name, email, is_enabled, is_qa, is_locked, qa_group)
        VALUES ('admin', '5459dbe5e9aa80e077bfa40f3fb2ca8368ed09b4', 'Admin User', 'sign-test@fwupd.org', 1, 1, 0, 'admin');

    CREATE TABLE firmware (
      qa_group VARCHAR(40) NOT NULL DEFAULT '',
      addr VARCHAR(40) DEFAULT NULL,
      timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      filename VARCHAR(255) DEFAULT NULL,
      target VARCHAR(255) DEFAULT NULL,
      fwid VARCHAR(40) DEFAULT NULL,
      version_display VARCHAR(255) DEFAULT NULL,
      UNIQUE KEY id (fwid)
    ) CHARSET=utf8;

    CREATE TABLE firmware_md (
      fwid VARCHAR(40) DEFAULT NULL,
      checksum_contents VARCHAR(40) DEFAULT NULL,
      checksum_container VARCHAR(40) DEFAULT NULL,
      id TEXT DEFAULT NULL,
      name TEXT DEFAULT NULL,
      summary TEXT DEFAULT NULL,
      guid VARCHAR(36) DEFAULT NULL,
      description TEXT DEFAULT NULL,
      release_description TEXT DEFAULT NULL,
      url_homepage TEXT DEFAULT NULL,
      metadata_license TEXT DEFAULT NULL,
      project_license TEXT DEFAULT NULL,
      developer_name TEXT DEFAULT NULL,
      filename_contents TEXT DEFAULT NULL,
      release_timestamp INTEGER DEFAULT 0,
      version VARCHAR(255) DEFAULT NULL,
      release_installed_size INTEGER DEFAULT 0,
      release_download_size INTEGER DEFAULT 0,
      release_urgency VARCHAR(16) DEFAULT NULL,
      UNIQUE KEY id (fwid,guid)
    ) CHARSET=utf8;

    CREATE TABLE event_log (
      id INT NOT NULL AUTO_INCREMENT,
      timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      username VARCHAR(40) NOT NULL DEFAULT '',
      qa_group VARCHAR(40) DEFAULT NULL,
      addr VARCHAR(40) DEFAULT NULL,
      message TEXT DEFAULT NULL,
      is_important TINYINT DEFAULT 0,
      UNIQUE KEY id (id)
    ) CHARSET=utf8;

    CREATE TABLE clients (
      id INT NOT NULL AUTO_INCREMENT,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      addr VARCHAR(40) DEFAULT NULL,
      filename VARCHAR(256) DEFAULT NULL,
      user_agent VARCHAR(256) DEFAULT NULL,
      UNIQUE KEY id (id)
    ) CHARSET=utf8;

    CREATE TABLE analytics (
      datestr INT DEFAULT 0,
      kind TINYINT DEFAULT 0,
      cnt INT DEFAULT 1,
      UNIQUE (datestr,kind)
    ) CHARSET=utf8;

The default admin password is `Pa$$w0rd`

## How do I install the test key on Openshift? ##

Use the test GPG key (with the initial password of `fwupd`).

    gpg2 --homedir=./gnupg/ --allow-secret-key-import --import contrib/fwupd-test-private.key
    gpg2 --homedir=./gnupg/ --list-secret-keys
    gpg2 --homedir=./gnupg/ --edit-key D64F5C21
    gpg> passwd
    gpg> quit

Speeding up OpenShift
---------------------

Add to python/conf.d/openshift.conf

    RewriteEngine On
    RewriteRule ^downloads/(.+)$ /static/downloads/$1 [L]

## How do I install the production key on Openshift? ##

Use the secure GPG key (with the long secret password).

    export OPENSHIFT_NAMESPACE=lvfs
    export OPENSHIFT_APP=testing
    rhc scp --app ${OPENSHIFT_APP} --namespace ${OPENSHIFT_NAMESPACE} \
        upload backup/app-root/data/gnupg/fwupd-secret-signing-key.key \
        app-root/data
    rhc ssh --app ${OPENSHIFT_APP} --namespace ${OPENSHIFT_NAMESPACE}
      cd app-root/data/
      mkdir -p app-root/data/gnupg
      gpg2 --homedir=app-root/data/gnupg --allow-secret-key-import --import contrib/fwupd-test-private.key
      gpg2 --homedir=app-root/data/gnupg --list-secret-keys
      gpg2 --homedir=app-root/data/gnupg --edit-key 4538BAC2
        gpg> passwd
        gpg> quit

## How do I backup the data ##

To get just the database you can do:

    export OPENSHIFT_NAMESPACE=lvfs
    export OPENSHIFT_APP=secure
    rhc ssh --app ${OPENSHIFT_APP} --namespace ${OPENSHIFT_NAMESPACE}
    mysqldump -h $OPENSHIFT_MYSQL_DB_HOST \
              -P ${OPENSHIFT_MYSQL_DB_PORT:-3306} \
              -u ${OPENSHIFT_MYSQL_DB_USERNAME:-'admin'} \
              --password="$OPENSHIFT_MYSQL_DB_PASSWORD" \
              secure > app-root/data/backup.sql
    rhc scp --app ${OPENSHIFT_APP} \
            --namespace ${OPENSHIFT_NAMESPACE} \
            download . app-root/data/backup.sql

Or, to get a complete backup you can do:

    rhc snapshot save \
            --app ${OPENSHIFT_APP} --namespace ${OPENSHIFT_NAMESPACE}
            --filepath=backup.tar.gz

## How do I restore from a backup ##

If this is a fresh instance you want to set up using:

    export OPENSHIFT_NAMESPACE=lvfs
    export OPENSHIFT_APP=testing
    rhc delete-app --app ${OPENSHIFT_APP} --namespace ${OPENSHIFT_NAMESPACE}
    rhc create-app --type python-3.3 --scaling \
        --app ${OPENSHIFT_APP} --namespace ${OPENSHIFT_NAMESPACE} \
        --from-code https://github.com/hughsie/lvfs-website.git
    rhc cartridge add --app ${OPENSHIFT_APP} \
        --namespace ${OPENSHIFT_NAMESPACE} \
        mysql-5.5
    rhc env set --app ${OPENSHIFT_APP} \
        --namespace ${OPENSHIFT_NAMESPACE} \
        LVFS_CDN_URI=https://s3.amazonaws.com/lvfsbucket
    rhc env set --app ${OPENSHIFT_APP} \
        --namespace ${OPENSHIFT_NAMESPACE} \
        LVFS_URI=https://testing-lvfs.rhcloud.com
    rhc show-app --app ${OPENSHIFT_APP} --namespace ${OPENSHIFT_NAMESPACE}

To just restore the database, do:

    rhc scp --app ${OPENSHIFT_APP} --namespace ${OPENSHIFT_NAMESPACE} \
        upload backup.sql app-root/data
    rhc ssh --app ${OPENSHIFT_APP} --namespace ${OPENSHIFT_NAMESPACE}
    mysql
      CREATE DATABASE secure;
      use secure;
      source app-root/data/backup.sql;

Or, for a full restore do:

    rhc app snapshot restore \
            --app ${OPENSHIFT_APP} --namespace ${OPENSHIFT_NAMESPACE} \
            --filepath=backup.tar.gz

If you're using new-format cab files, cabextract needs to be setup using:

    rhc ssh --app ${OPENSHIFT_APP} --namespace ${OPENSHIFT_NAMESPACE}
      cd app-root/data/
      wget http://www.cabextract.org.uk/cabextract-1.6.tar.gz
      tar xvfz cabextract-1.6.tar.gz
      cd cabextract-1.6 && ./configure --prefix=/tmp && make && cd ..
      rm cabextract-1.6.tar.gz

## How to I use distro packages ##

    pkcon install \
      python3-boto3 \
      python3-flask \
      python3-flask-wtf \
      python3-gnupg \
      python3-PyMySQL
