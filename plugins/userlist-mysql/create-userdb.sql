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
       username VARCHAR(512),
       pwdmethod TINYINT NOT NULL DEFAULT 0,
       password VARCHAR(128),
       pwdtime DATETIME DEFAULT NULL,
       createtime TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
       changetime DATETIME DEFAULT NULL,
       logintime DATETIME DEFAULT NULL,
       inst VARCHAR(512),
       inst_en VARCHAR (512),
       instshort VARCHAR (512),
       instshort_en VARCHAR (512),
       fac VARCHAR(512),
       fac_en VARCHAR (512),
       facshort VARCHAR (512),
       facshort_en VARCHAR (512),
       homepage VARCHAR (512),
       phone VARCHAR (512),
       city VARCHAR (512),
       city_en VARCHAR (512),
       region VARCHAR (512),
       area VARCHAR (512),
       zip VARCHAR (512),
       street VARCHAR (512),
       country VARCHAR (512),
       country_en VARCHAR (512),
       location VARCHAR (512),
       spelling VARCHAR (512),
       printer VARCHAR (512),
       languages VARCHAR (512),
       exam_id VARCHAR (512),
       exam_cypher VARCHAR (512),
       field0 VARCHAR(512),
       field1 VARCHAR(512),
       field2 VARCHAR(512),
       field3 VARCHAR(512),
       field4 VARCHAR(512),
       field5 VARCHAR(512),
       field6 VARCHAR(512),
       field7 VARCHAR(512),
       field8 VARCHAR(512),
       field9 VARCHAR(512),
       avatar_store VARCHAR(512) DEFAULT NULL,
       avatar_id VARCHAR(512) DEFAULT NULL,
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
       firstname VARCHAR(512),
       firstname_en VARCHAR(512),
       middlename VARCHAR(512),
       middlename_en VARCHAR(512),
       surname VARCHAR(512),
       surname_en VARCHAR(512),
       status TINYINT NOT NULL,
       gender TINYINT NOT NULL,
       grade TINYINT NOT NULL,
       grp VARCHAR(512),
       grp_en VARCHAR(512),
       occupation VARCHAR(512),
       occupation_en VARCHAR(512),
       discipline VARCHAR(512),
       email VARCHAR(512),
       homepage VARCHAR(512),
       phone VARCHAR(512),
       inst VARCHAR(512),
       inst_en VARCHAR(512),
       instshort VARCHAR(512),
       instshort_en VARCHAR(512),
       fac VARCHAR(512),
       fac_en VARCHAR(512),
       facshort VARCHAR(512),
       facshort_en VARCHAR(512),
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

INSERT INTO %sconfig VALUES ('version', '17');
