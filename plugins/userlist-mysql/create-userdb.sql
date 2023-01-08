CREATE TABLE IF NOT EXISTS %sconfig 
       (config_key VARCHAR(64) NOT NULL PRIMARY KEY COLLATE utf8_bin,
       config_val VARCHAR(64)
       ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE %slogins
       (user_id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
       login VARCHAR(64) NOT NULL UNIQUE KEY COLLATE utf8_bin,
       email VARCHAR(128),
       pwdmethod TINYINT NOT NULL DEFAULT 0,
       password VARCHAR(128),
       privileged TINYINT NOT NULL DEFAULT 0,
       invisible TINYINT NOT NULL DEFAULT 0,
       banned TINYINT NOT NULL DEFAULT 0,
       locked TINYINT NOT NULL DEFAULT 0,
       readonly TINYINT NOT NULL DEFAULT 0,
       neverclean TINYINT NOT NULL DEFAULT 0,
       simplereg TINYINT NOT NULL DEFAULT 0,
       regtime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       logintime DATETIME DEFAULT NULL,
       pwdtime DATETIME DEFAULT NULL,
       changetime DATETIME DEFAULT NULL
       ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE %scookies
       (cookie VARCHAR(64) NOT NULL PRIMARY KEY,
       user_id INT UNSIGNED NOT NULL,
       contest_id INT UNSIGNED NOT NULL,
       priv_level TINYINT NOT NULL DEFAULT 0,
       role_id TINYINT NOT NULL DEFAULT 0,
       ip_version TINYINT NOT NULL DEFAULT 4,
       locale_id TINYINT NOT NULL DEFAULT 0,
       recovery TINYINT NOT NULL DEFAULT 0,
       team_login TINYINT NOT NULL DEFAULT 0,
       ip VARCHAR(64) NOT NULL,
       ssl_flag TINYINT NOT NULL DEFAULT 0,
       expire DATETIME NOT NULL,
       is_ws TINYINT NOT NULL DEFAULT 0,
       is_job TINYINT NOT NULL DEFAULT 0,
       FOREIGN KEY (user_id) REFERENCES logins (user_id)
       ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE %scntsregs
       (user_id INT UNSIGNED NOT NULL,
       contest_id INT UNSIGNED NOT NULL,
       status TINYINT NOT NULL DEFAULT 0,
       banned TINYINT NOT NULL DEFAULT 0,
       invisible TINYINT NOT NULL DEFAULT 0,
       locked TINYINT NOT NULL DEFAULT 0,
       incomplete TINYINT NOT NULL DEFAULT 0,
       disqualified TINYINT NOT NULL DEFAULT 0,
       privileged TINYINT NOT NULL DEFAULT 0,
       reg_readonly TINYINT NOT NULL DEFAULT 0,
       createtime TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
       changetime DATETIME DEFAULT NULL,
       PRIMARY KEY (user_id, contest_id),
       FOREIGN KEY (user_id) REFERENCES logins (user_id)
       ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE %susers
       (user_id INT UNSIGNED NOT NULL,
       contest_id INT UNSIGNED NOT NULL,
       cnts_read_only TINYINT NOT NULL DEFAULT 0,
       instnum INT,
       username VARCHAR(512) DEFAULT NULL,
       pwdmethod TINYINT NOT NULL DEFAULT 0,
       password VARCHAR(128) DEFAULT NULL,
       pwdtime DATETIME DEFAULT NULL,
       createtime TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
       changetime DATETIME DEFAULT NULL,
       logintime DATETIME DEFAULT NULL,
       inst VARCHAR(512) DEFAULT NULL,
       inst_en VARCHAR (512) DEFAULT NULL,
       instshort VARCHAR (512) DEFAULT NULL,
       instshort_en VARCHAR (512) DEFAULT NULL,
       fac VARCHAR(512) DEFAULT NULL,
       fac_en VARCHAR (512) DEFAULT NULL,
       facshort VARCHAR (512) DEFAULT NULL,
       facshort_en VARCHAR (512) DEFAULT NULL,
       homepage VARCHAR (512) DEFAULT NULL,
       phone VARCHAR (512) DEFAULT NULL,
       city VARCHAR (256) DEFAULT NULL,
       city_en VARCHAR (256) DEFAULT NULL,
       region VARCHAR (512) DEFAULT NULL,
       area VARCHAR (512) DEFAULT NULL,
       zip VARCHAR (256) DEFAULT NULL,
       street VARCHAR (512) DEFAULT NULL,
       country VARCHAR (256) DEFAULT NULL,
       country_en VARCHAR (256) DEFAULT NULL,
       location VARCHAR (256) DEFAULT NULL,
       spelling VARCHAR (512) DEFAULT NULL,
       printer VARCHAR (256) DEFAULT NULL,
       languages VARCHAR (512) DEFAULT NULL,
       exam_id VARCHAR (256) DEFAULT NULL,
       exam_cypher VARCHAR (256) DEFAULT NULL,
       field0 VARCHAR(256) DEFAULT NULL,
       field1 VARCHAR(256) DEFAULT NULL,
       field2 VARCHAR(256) DEFAULT NULL,
       field3 VARCHAR(256) DEFAULT NULL,
       field4 VARCHAR(256) DEFAULT NULL,
       field5 VARCHAR(256) DEFAULT NULL,
       field6 VARCHAR(256) DEFAULT NULL,
       field7 VARCHAR(256) DEFAULT NULL,
       field8 VARCHAR(256) DEFAULT NULL,
       field9 VARCHAR(256) DEFAULT NULL,
       avatar_store VARCHAR(256) DEFAULT NULL,
       avatar_id VARCHAR(256) DEFAULT NULL,
       avatar_suffix VARCHAR(32) DEFAULT NULL,
       PRIMARY KEY (user_id, contest_id),
       FOREIGN KEY (user_id) REFERENCES logins (user_id)
       ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE %smembers
       (
       serial INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
       user_id INT UNSIGNED NOT NULL,
       contest_id INT UNSIGNED NOT NULL,
       role_id TINYINT NOT NULL,
       createtime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       changetime DATETIME DEFAULT NULL,
       firstname VARCHAR(512) DEFAULT NULL,
       firstname_en VARCHAR(512) DEFAULT NULL,
       middlename VARCHAR(512) DEFAULT NULL,
       middlename_en VARCHAR(512) DEFAULT NULL,
       surname VARCHAR(512) DEFAULT NULL,
       surname_en VARCHAR(512) DEFAULT NULL,
       status TINYINT NOT NULL,
       gender TINYINT NOT NULL,
       grade TINYINT NOT NULL,
       grp VARCHAR(512) DEFAULT NULL,
       grp_en VARCHAR(512) DEFAULT NULL,
       occupation VARCHAR(512) DEFAULT NULL,
       occupation_en VARCHAR(512) DEFAULT NULL,
       discipline VARCHAR(512) DEFAULT NULL,
       email VARCHAR(512) DEFAULT NULL,
       homepage VARCHAR(512) DEFAULT NULL,
       phone VARCHAR(512) DEFAULT NULL,
       inst VARCHAR(512) DEFAULT NULL,
       inst_en VARCHAR(512) DEFAULT NULL,
       instshort VARCHAR(512) DEFAULT NULL,
       instshort_en VARCHAR(512) DEFAULT NULL,
       fac VARCHAR(512) DEFAULT NULL,
       fac_en VARCHAR(512) DEFAULT NULL,
       facshort VARCHAR(512) DEFAULT NULL,
       facshort_en VARCHAR(512) DEFAULT NULL,
       birth_date DATE DEFAULT NULL,
       entry_date DATE DEFAULT NULL,
       graduation_date DATE DEFAULT NULL,
       FOREIGN KEY (user_id) REFERENCES logins (user_id)
       ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE %sejgroups
(
    group_id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    group_name VARCHAR(128) NOT NULL UNIQUE KEY,
    description VARCHAR(512) DEFAULT NULL,
    created_by INT UNSIGNED NOT NULL,
    create_time DATETIME NOT NULL,
    last_change_time DATETIME DEFAULT NULL,
    FOREIGN KEY (created_by) REFERENCES logins(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE %sgroupmembers
(
    group_id INT UNSIGNED NOT NULL,
    user_id INT UNSIGNED NOT NULL,
    rights VARCHAR(512) DEFAULT NULL,
    PRIMARY KEY (group_id, user_id),
    FOREIGN KEY g(group_id) REFERENCES ejgroups(group_id),
    FOREIGN KEY u(user_id) REFERENCES logins(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE %sapikeys
(
    token VARCHAR(64) NOT NULL PRIMARY KEY,
    secret VARCHAR(64) NOT NULL UNIQUE KEY,
    user_id INT UNSIGNED NOT NULL,
    contest_id INT UNSIGNED NOT NULL,
    create_time DATETIME NOT NULL,
    expiry_time DATETIME DEFAULT NULL,
    payload VARCHAR(1024) DEFAULT NULL,
    origin VARCHAR(128) DEFAULT NULL,
    all_contests TINYINT NOT NULL DEFAULT 0,
    role_id TINYINT NOT NULL DEFAULT 0,
    FOREIGN KEY apikeys_user_id_fk(user_id) REFERENCES logins(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

ALTER TABLE %scntsregs ADD INDEX cntsregs_user_id_idx (user_id),
                       ADD INDEX cntsregs_contest_id_idx (contest_id);
ALTER TABLE %susers    ADD INDEX users_user_id_idx (user_id),
                       ADD INDEX users_contest_id_idx (contest_id);
ALTER TABLE %smembers  ADD INDEX members_user_id_idx (user_id),
                       ADD INDEX members_contest_id_idx (contest_id);

ALTER TABLE %sgroupmembers ADD INDEX groupmembers_group_id_idx (group_id),
                           ADD INDEX groupmembers_user_id_idx (user_id);

INSERT INTO %sconfig VALUES ('version', '25');
