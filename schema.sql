DROP TABLE IF EXISTS users;
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

DROP TABLE IF EXISTS firmware;
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

DROP TABLE IF EXISTS firmware_md;
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
  screenshot_url TEXT DEFAULT NULL,
  screenshot_caption TEXT DEFAULT NULL,
  UNIQUE KEY id (fwid,guid)
) CHARSET=utf8;

DROP TABLE IF EXISTS event_log;
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

DROP TABLE IF EXISTS clients;
CREATE TABLE clients (
  id INT NOT NULL AUTO_INCREMENT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  addr VARCHAR(40) DEFAULT NULL,
  filename VARCHAR(256) DEFAULT NULL,
  user_agent VARCHAR(256) DEFAULT NULL,
  UNIQUE KEY id (id)
) CHARSET=utf8;

DROP TABLE IF EXISTS analytics;
CREATE TABLE analytics (
  datestr INT DEFAULT 0,
  kind TINYINT DEFAULT 0,
  cnt INT DEFAULT 1,
  UNIQUE (datestr,kind)
) CHARSET=utf8;
