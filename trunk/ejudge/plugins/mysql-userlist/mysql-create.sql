CREATE TABLE %sconfig
       (config_key VARCHAR(64) NOT NULL PRIMARY KEY,
       config_val VARCHAR(64)
       );

CREATE TABLE %slogins
       (id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
       login VARCHAR(64) NOT NULL UNIQUE KEY,
       email VARCHAR(128),
       pwdmethod TINYINT NOT NULL DEFAULT 0,
       password VARCHAR(64),
       privileged TINYINT NOT NULL DEFAULT 0,
       invisible TINYINT NOT NULL DEFAULT 0,
       banned TINYINT NOT NULL DEFAULT 0,
       locked TINYINT NOT NULL DEFAULT 0,
       readonly TINYINT NOT NULL DEFAULT 0,
       neverclean TINYINT NOT NULL DEFAULT 0,
       simplereg TINYINT NOT NULL DEFAULT 0,
       regtime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       logintime TIMESTAMP DEFAULT 0,
       pwdtime TIMESTAMP DEFAULT 0,
       changetime TIMESTAMP DEFAULT 0
       );

CREATE TABLE %scookies
       (val BIGINT UNSIGNED NOT NULL PRIMARY KEY,
       user_id INT NOT NULL,
       priv_level TINYINT NOT NULL DEFAULT 0,
       role TINYINT NOT NULL DEFAULT 0,
       ipversion TINYINT NOT NULL DEFAULT 4,
       locale_id TINYINT NOT NULL DEFAULT 0,
       recovery TINYINT NOT NULL DEFAULT 0,
       contest_id INT UNSIGNED NOT NULL,
       ip VARCHAR(64) NOT NULL,
       ssl TINYINT NOT NULL DEFAULT 0,
       expire DATETIME NOT NULL,
       FOREIGN KEY (user_id) REFERENCES logins (id)
       );

CREATE TABLE %scntsregs
       (user_id INT UNSIGNED NOT NULL,
       contest_id INT UNSIGNED NOT NULL,
       status TINYINT NOT NULL DEFAULT 0,
       banned TINYINT NOT NULL DEFAULT 0,
       invisible TINYINT NOT NULL DEFAULT 0,
       locked TINYINT NOT NULL DEFAULT 0,
       createtime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       changetime TIMESTAMP DEFAULT 0,
       PRIMARY KEY (user_id, contest_id),
       FOREIGN KEY (user_id) REFERENCES logins (id)
       );

CREATE TABLE %susers
       (user_id INT UNSIGNED NOT NULL,
       contest_id INT UNSIGNED NOT NULL,
       cnts_read_only TINYINT NOT NULL DEFAULT 0,
       username VARCHAR(256),
       pwdmethod TINYINT NOT NULL DEFAULT 0,
       password VARCHAR(64),
       pwdtime TIMESTAMP DEFAULT 0,
       createtime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       changetime TIMESTAMP DEFAULT 0,
       inst VARCHAR(256),
       inst_en VARCHAR (256),
       instshort VARCHAR (256),
       instshort_en VARCHAR (256),
       fac VARCHAR(256),
       fac_en VARCHAR (256),
       facshort VARCHAR (256),
       facshort_en VARCHAR (256),
       homepage VARCHAR (256),
       phone VARCHAR (256),
       city VARCHAR (256),
       city_en VARCHAR (256),
       region VARCHAR (256),
       country VARCHAR (256),
       country_en VARCHAR (256),
       location VARCHAR (256),
       spelling VARCHAR (256),
       printer VARCHAR (256),
       languages VARCHAR (256),
       PRIMARY KEY (user_id, contest_id),
       FOREIGN KEY (user_id) REFERENCES logins (id)
       );

CREATE TABLE %sparticipants
       (
       serial INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
       user_id INT UNSIGNED NOT NULL,
       contest_id INT UNSIGNED NOT NULL,
       role TINYINT NOT NULL,
       createtime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       changetime TIMESTAMP DEFAULT 0,
       firstname VARCHAR(256),
       firstname_en VARCHAR(256),
       middlename VARCHAR(256),
       middlename_en VARCHAR(256),
       surname VARCHAR(256),
       surname_en VARCHAR(256),
       status TINYINT NOT NULL,
       grade TINYINT NOT NULL,
       grp VARCHAR(256),
       grp_en VARCHAR(256),
       occupation VARCHAR(256),
       occupation_en VARCHAR(256),
       email VARCHAR(256),
       homepage VARCHAR(256),
       phone VARCHAR(256),
       inst VARCHAR(256),
       inst_en VARCHAR(256),
       instshort VARCHAR(256),
       instshort_en VARCHAR(256),
       fac VARCHAR(256),
       fac_en VARCHAR(256),
       facshort VARCHAR(256),
       facshort_en VARCHAR(256),
       birth_date TIMESTAMP,
       entry_date TIMESTAMP,
       graduation_date TIMESTAMP,
       FOREIGN KEY (user_id) REFERENCES logins (id)
       );

INSERT INTO %sconfig VALUES ('version', '1');
