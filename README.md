Linux Vendor Firmware Service
=============================

This is the website for the Linux Vendor Firmware Service

IMPORTANT: This needs to be hosted over SSL, i.e. with a `https://` prefix.

## How do I set up the database ##

    CREATE DATABASE secure;
    CREATE USER 'test'@'localhost' IDENTIFIED BY 'test';
    USE secure;
    GRANT ALL ON secure.* TO 'test'@'localhost';
    SOURCE schema.sql

The default admin password is `Pa$$w0rd`

## How do I install the test key on Openshift? ##

Use the test GPG key (with the initial password of `fwupd`).

    gpg2 --homedir=./gnupg/ --allow-secret-key-import --import contrib/fwupd-test-private.key
    gpg2 --homedir=./gnupg/ --list-secret-keys
    gpg2 --homedir=./gnupg/ --edit-key D64F5C21
    gpg> passwd
    gpg> quit

## How do I install the production key on Openshift? ##

Use the secure GPG key (with the long secret password).

    export OPENSHIFT_NAMESPACE=lvfs
    export OPENSHIFT_APP=secure
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
              secure > app-root/data/backup-`date +%Y%m%d`.sql
    rhc scp --app ${OPENSHIFT_APP} \
            --namespace ${OPENSHIFT_NAMESPACE} \
            download . app-root/data/backup-`date +%Y%m%d`.sql

Or, to get a complete backup you can do:

    rhc snapshot save \
            --app ${OPENSHIFT_APP} --namespace ${OPENSHIFT_NAMESPACE}
            --filepath=backup.tar.gz

## How do I restore from a backup ##

If this is a fresh instance you want to set up using:

    export OPENSHIFT_NAMESPACE=lvfs
    export OPENSHIFT_APP=secure
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
        LVFS_URI=https://secure-lvfs.rhcloud.com
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
      python2-boto3 \
      python2-gnupg \
      python2-PyMySQL \
      python2-mysql \
      python-flask \
      python-flask-login \
      python-flask-wtf
