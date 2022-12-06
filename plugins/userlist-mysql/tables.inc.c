/* -*- mode: c -*- */

/* Copyright (C) 2008-2022 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

// the number of columns in `cookies' table
enum { COOKIE_WIDTH = 14 };

#define COOKIE_OFFSET(f) XOFFSET(struct userlist_cookie, f)
static struct common_mysql_parse_spec cookie_spec[COOKIE_WIDTH] =
{
  //[0]       cookie BIGINT UNSIGNED NOT NULL PRIMARY KEY,
  { 0, 'u', "cookie", COOKIE_OFFSET(cookie), 0 },
  //[1]       user_id INT NOT NULL,
  { 0, 'd', "user_id", COOKIE_OFFSET(user_id), 0 },
  //[2]       contest_id INT UNSIGNED NOT NULL,
  { 0, 'd', "contest_id", COOKIE_OFFSET(contest_id), 0 },
  //[3]       priv_level TINYINT NOT NULL DEFAULT 0,
  { 0, 'd', "priv_level", COOKIE_OFFSET(priv_level), 0 },
  //[4]       role_id TINYINT NOT NULL DEFAULT 0,
  { 0, 'd', "role_id", COOKIE_OFFSET(role), 0 },
  //[5]       ip_version TINYINT NOT NULL DEFAULT 4,
  { 0, 'D', "ip_version", 0, 0 },
  //[6]       locale_id TINYINT NOT NULL DEFAULT 0,
  { 0, 'd', "locale_id", COOKIE_OFFSET(locale_id), 0 },
  //[7]       recovery TINYINT NOT NULL DEFAULT 0,
  { 0, 'b', "recovery", COOKIE_OFFSET(recovery), 0 },
  //[8]       team_login TINYINT NOT NULL DEFAULT 0,
  { 0, 'b', "team_login", COOKIE_OFFSET(team_login), 0 },
  //[9]       ip VARCHAR(64) NOT NULL,
  { 0, 'I', "ip", COOKIE_OFFSET(ip), 0 },
  //[10]      ssl_flag TINYINT NOT NULL DEFAULT 0,
  { 0, 'b', "ssl_flag", COOKIE_OFFSET(ssl), 0 },
  //[11]      expire DATETIME NOT NULL)
  { 0, 't', "expire", COOKIE_OFFSET(expire), 0 },
  //[12]      is_ws TINYINT NOT NULL DEFAULT 0,
  { 0, 'b', "is_ws", COOKIE_OFFSET(is_ws), 0 },
  //[13]      is_job TINYINT NOT NULL DEFAULT 0,
  { 0, 'b', "is_job", COOKIE_OFFSET(is_job), 0 },
};

// the number of columns in `cntsregs' table
enum { CNTSREG_WIDTH = 12 };

#define CONTEST_OFFSET(f) XOFFSET(struct userlist_contest, f)
static struct common_mysql_parse_spec cntsreg_spec[CNTSREG_WIDTH] =
{
  //[0]    (user_id INT UNSIGNED NOT NULL,
  { 0, 'D', "user_id", 0, 0 },
  //[1]    contest_id INT UNSIGNED NOT NULL,
  { 0, 'd', "contest_id", CONTEST_OFFSET(id), 0 },
  //[2]    status TINYINT NOT NULL DEFAULT 0,
  { 0, 'd', "status", CONTEST_OFFSET(status), 0 },
  //[3]    banned TINYINT NOT NULL DEFAULT 0,
  { 0, 'B', "banned", 0, 0 },
  //[4]    invisible TINYINT NOT NULL DEFAULT 0,
  { 0, 'B', "invisible", 0, 0 },
  //[5]    locked TINYINT NOT NULL DEFAULT 0,
  { 0, 'B', "locked", 0, 0 },
  //[6]    incomplete TINYINT NOT NULL DEFAULT 0,
  { 0, 'B', "incomplete", 0, 0 },
  //[7]    disqualified TINYINT NOT NULL DEFAULT 0,
  { 0, 'B', "disqualified", 0, 0 },
  //[8]    privileged TINYINT NOT NULL DEFAULT 0,
  { 0, 'B', "privileged", 0, 0 },
  //[9]    reg_readonly TINYINT NOT NULL DEFAULT 0,
  { 0, 'B', "reg_readonly", 0, 0 },
  //[10]    createtime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  { 0, 't', "createtime", CONTEST_OFFSET(create_time), 0 },
  //[11]    changetime TIMESTAMP DEFAULT 0,
  { 1, 't', "changetime", CONTEST_OFFSET(last_change_time), 0 },
};

// the number of columns in `logins' table
enum { LOGIN_WIDTH = 16 };

#define LOGIN_OFFSET(f) XOFFSET(struct userlist_user, f)
static struct common_mysql_parse_spec login_spec[LOGIN_WIDTH] =
{
  //[0]    user_id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  { 0, 'e', "user_id", LOGIN_OFFSET(id) },
  //[1]    login VARCHAR(64) NOT NULL UNIQUE KEY
  { 0, 's', "login", LOGIN_OFFSET(login) },
  //[2]    email VARCHAR(128),
  { 1, 's', "email", LOGIN_OFFSET(email) },
  //[3]    pwdmethod TINYINT NOT NULL DEFAULT 0,
  { 0, 'd', "pwdmethod", LOGIN_OFFSET(passwd_method) },
  //[4]    password VARCHAR(64),
  { 1, 's', "password", LOGIN_OFFSET(passwd) },
  //[5]    privileged TINYINT NOT NULL DEFAULT 0,
  { 0, 'b', "privileged", LOGIN_OFFSET(is_privileged) },
  //[6]    invisible TINYINT NOT NULL DEFAULT 0,
  { 0, 'b', "invisible", LOGIN_OFFSET(is_invisible) },
  //[7]    banned TINYINT NOT NULL DEFAULT 0,
  { 0, 'b', "banned", LOGIN_OFFSET(is_banned) },
  //[8]    locked TINYINT NOT NULL DEFAULT 0,
  { 0, 'b', "locked", LOGIN_OFFSET(is_locked) },
  //[9]    readonly TINYINT NOT NULL DEFAULT 0,
  { 0, 'b', "readonly", LOGIN_OFFSET(read_only) },
  //[10]   neverclean TINYINT NOT NULL DEFAULT 0,
  { 0, 'b', "neverclean", LOGIN_OFFSET(never_clean) },
  //[11]   simplereg TINYINT NOT NULL DEFAULT 0,
  { 0, 'b', "simplereg", LOGIN_OFFSET(simple_registration) },
  //[12]   regtime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  { 1, 't', "regtime", LOGIN_OFFSET(registration_time) },
  //[13]   logintime DATETIME DEFAULT NULL,
  { 1, 't', "logintime", LOGIN_OFFSET(last_login_time) },
  //[14]   pwdtime DATETIME DEFAULT NULL,
  { 1, 't', "pwdtime", LOGIN_OFFSET(last_pwdchange_time) },
  //[15]   changetime DATETIME DEFAULT NULL
  { 1, 't', "changetime", LOGIN_OFFSET(last_change_time) },
};

// the number of columns in `users' table
enum { USER_INFO_WIDTH = 48 };

#define USER_INFO_OFFSET(f) XOFFSET(struct userlist_user_info, f)
static struct common_mysql_parse_spec user_info_spec[USER_INFO_WIDTH] =
{
  //[0]    user_id INT UNSIGNED NOT NULL,
  { 0, 'D', "user_id", 0, 0 },
  //[1]    contest_id INT UNSIGNED NOT NULL,
  { 0, 'd', "contest_id", USER_INFO_OFFSET(contest_id), 0 },
  //[2]    cnts_read_only TINYINT NOT NULL DEFAULT 0,
  { 0, 'b', "cnts_read_only", USER_INFO_OFFSET(cnts_read_only), 0 },
  //[3]    instnum INT,
  { 1, 'd', "instnum", USER_INFO_OFFSET(instnum), 0 },
  //[4]    username VARCHAR(512),
  { 1, 's', "username", USER_INFO_OFFSET(name), 0 },
  //[5]    pwdmethod TINYINT NOT NULL DEFAULT 0,
  { 0, 'd', "pwdmethod", USER_INFO_OFFSET(team_passwd_method), 0 },
  //[6]    password VARCHAR(64),
  { 1, 's', "password", USER_INFO_OFFSET(team_passwd), 0 },
  //[7]    pwdtime TIMESTAMP DEFAULT NULL,
  { 1, 't', "pwdtime", USER_INFO_OFFSET(last_pwdchange_time), 0 },
  //[8]    createtime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  { 1, 't', "createtime", USER_INFO_OFFSET(create_time), 0 },
  //[9]    changetime TIMESTAMP DEFAULT NULL,
  { 1, 't', "changetime", USER_INFO_OFFSET(last_change_time), 0 },
  //[10]   logintime TIMESTAMP DEFAULT NULL,
  { 1, 't', "logintime", USER_INFO_OFFSET(last_login_time), 0 },
  //[11]   inst VARCHAR(512),
  { 1, 's', "inst", USER_INFO_OFFSET(inst), 0 },
  //[12]   inst_en VARCHAR (512),
  { 1, 's', "inst_en", USER_INFO_OFFSET(inst_en), 0 },
  //[13]   instshort VARCHAR (512),
  { 1, 's', "instshort", USER_INFO_OFFSET(instshort), 0 },
  //[14]   instshort_en VARCHAR (512),
  { 1, 's', "instshort_en", USER_INFO_OFFSET(instshort_en), 0 },
  //[15]   fac VARCHAR(512),
  { 1, 's', "fac", USER_INFO_OFFSET(fac), 0 },
  //[16]   fac_en VARCHAR (512),
  { 1, 's', "fac_en", USER_INFO_OFFSET(fac_en), 0 },
  //[17]   facshort VARCHAR (512),
  { 1, 's', "facshort", USER_INFO_OFFSET(facshort), 0 },
  //[18]   facshort_en VARCHAR (512),
  { 1, 's', "facshort_en", USER_INFO_OFFSET(facshort_en), 0 },
  //[19]   homepage VARCHAR (512),
  { 1, 's', "homepage", USER_INFO_OFFSET(homepage), 0 },
  //[20]   phone VARCHAR (512),
  { 1, 's', "phone", USER_INFO_OFFSET(phone), 0 },
  //[21]   city VARCHAR (512),
  { 1, 's', "city", USER_INFO_OFFSET(city), 0 },
  //[22]   city_en VARCHAR (512),
  { 1, 's', "city_en", USER_INFO_OFFSET(city_en), 0 },
  //[23]   region VARCHAR (512),
  { 1, 's', "region", USER_INFO_OFFSET(region), 0 },
  //[24]   area VARCHAR (512),
  { 1, 's', "area", USER_INFO_OFFSET(area), 0 },
  //[25]   zip VARCHAR (512),
  { 1, 's', "zip", USER_INFO_OFFSET(zip), 0 },
  //[26]   street VARCHAR (512),
  { 1, 's', "street", USER_INFO_OFFSET(street), 0 },
  //[27]   country VARCHAR (512),
  { 1, 's', "country", USER_INFO_OFFSET(country), 0 },
  //[28]   country_en VARCHAR (512),
  { 1, 's', "country_en", USER_INFO_OFFSET(country_en), 0 },
  //[29]   location VARCHAR (512),
  { 1, 's', "location", USER_INFO_OFFSET(location), 0 },
  //[30]   spelling VARCHAR (512),
  { 1, 's', "spelling", USER_INFO_OFFSET(spelling), 0 },
  //[31]   printer VARCHAR (512),
  { 1, 's', "printer", USER_INFO_OFFSET(printer_name), 0 },
  //[32]   languages VARCHAR (512),
  { 1, 's', "languages", USER_INFO_OFFSET(languages), 0 },
  //[33]   exam_id VARCHAR (512),
  { 1, 's', "exam_id", USER_INFO_OFFSET(exam_id), 0 },
  //[34]   exam_cypher VARCHAR (512),
  { 1, 's', "exam_cypher", USER_INFO_OFFSET(exam_cypher), 0 },
  //[35]   field0 VARCHAR(512),
  { 1, 's', "field0", USER_INFO_OFFSET(field0), 0 },
  //[36]   field1 VARCHAR(512),
  { 1, 's', "field1", USER_INFO_OFFSET(field1), 0 },
  //[37]   field2 VARCHAR(512),
  { 1, 's', "field2", USER_INFO_OFFSET(field2), 0 },
  //[38]   field3 VARCHAR(512),
  { 1, 's', "field3", USER_INFO_OFFSET(field3), 0 },
  //[39]   field4 VARCHAR(512),
  { 1, 's', "field4", USER_INFO_OFFSET(field4), 0 },
  //[40]   field5 VARCHAR(512),
  { 1, 's', "field5", USER_INFO_OFFSET(field5), 0 },
  //[41]   field6 VARCHAR(512),
  { 1, 's', "field6", USER_INFO_OFFSET(field6), 0 },
  //[42]   field7 VARCHAR(512),
  { 1, 's', "field7", USER_INFO_OFFSET(field7), 0 },
  //[43]   field8 VARCHAR(512),
  { 1, 's', "field8", USER_INFO_OFFSET(field8), 0 },
  //[44]   field9 VARCHAR(512),
  { 1, 's', "field9", USER_INFO_OFFSET(field9), 0 },
  //[45]   avatar_store VARCHAR(512),
  { 1, 's', "avatar_store", USER_INFO_OFFSET(avatar_store), 0 },
  //[46]   avatar_id VARCHAR(512),
  { 1, 's', "avatar_id", USER_INFO_OFFSET(avatar_id), 0 },
  //[47]   avatar_suffix VARCHAR(32),
  { 1, 's', "avatar_suffix", USER_INFO_OFFSET(avatar_suffix), 0 },
};

// the number of columns in `members' table
enum { MEMBER_WIDTH = 34 };

#define MEMBER_OFFSET(f) XOFFSET(struct userlist_member, f)
static struct common_mysql_parse_spec member_spec[MEMBER_WIDTH] =
{
  //[0]    serial INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  { 0, 'e', "serial", MEMBER_OFFSET(serial), 0 },
  //[1]    user_id INT UNSIGNED NOT NULL,
  { 0, 'D', "user_id", 0, 0 },
  //[2]    contest_id INT UNSIGNED NOT NULL,
  { 0, 'D', "contest_id", 0, 0 },
  //[3]    role_id TINYINT NOT NULL,
  { 0, 'd', "role_id", MEMBER_OFFSET(team_role), 0 },
  //[4]    createtime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  { 1, 't', "createtime", MEMBER_OFFSET(create_time), 0 },
  //[5]    changetime TIMESTAMP DEFAULT 0,
  { 1, 't', "changetime", MEMBER_OFFSET(last_change_time), 0 },
  //[6]    firstname VARCHAR(512),
  { 1, 's', "firstname", MEMBER_OFFSET(firstname), 0 },
  //[7]    firstname_en VARCHAR(512),
  { 1, 's', "firstname_en", MEMBER_OFFSET(firstname_en), 0 },
  //[8]    middlename VARCHAR(512),
  { 1, 's', "middlename", MEMBER_OFFSET(middlename), 0 },
  //[9]    middlename_en VARCHAR(512),
  { 1, 's', "middlename_en", MEMBER_OFFSET(middlename_en), 0 },
  //[10]   surname VARCHAR(512),
  { 1, 's', "surname", MEMBER_OFFSET(surname), 0 },
  //[11]   surname_en VARCHAR(512),
  { 1, 's', "surname_en", MEMBER_OFFSET(surname_en), 0 },
  //[12]   status TINYINT NOT NULL,
  { 0, 'd', "status", MEMBER_OFFSET(status), 0 },
  //[13]   gender TINYINT NOT NULL,
  { 0, 'd', "gender", MEMBER_OFFSET(gender), 0 },
  //[14]   grade TINYINT NOT NULL,
  { 0, 'd', "grade", MEMBER_OFFSET(grade), 0 },
  //[15]   grp VARCHAR(512),
  { 1, 's', "grp", MEMBER_OFFSET(group), 0 },
  //[16]   grp_en VARCHAR(512),
  { 1, 's', "group_en", MEMBER_OFFSET(group_en), 0 },
  //[17]   occupation VARCHAR(512),
  { 1, 's', "occupation", MEMBER_OFFSET(occupation), 0 },
  //[18]   occupation_en VARCHAR(512),
  { 1, 's', "occupation_en", MEMBER_OFFSET(occupation_en), 0 },
  //[19]   discipline VARCHAR(512),
  { 1, 's', "discipline", MEMBER_OFFSET(discipline), 0 },
  //[20]   email VARCHAR(512),
  { 1, 's', "email", MEMBER_OFFSET(email), 0 },
  //[21]   homepage VARCHAR(512),
  { 1, 's', "homepage", MEMBER_OFFSET(homepage), 0 },
  //[22]   phone VARCHAR(512),
  { 1, 's', "phone", MEMBER_OFFSET(phone), 0 },
  //[23]   inst VARCHAR(512),
  { 1, 's', "inst", MEMBER_OFFSET(inst), 0 },
  //[24]   inst_en VARCHAR(512),
  { 1, 's', "inst_en", MEMBER_OFFSET(inst_en), 0 },
  //[25]   instshort VARCHAR(512),
  { 1, 's', "instshort", MEMBER_OFFSET(instshort), 0 },
  //[26]   instshort_en VARCHAR(512),
  { 1, 's', "instshort_en", MEMBER_OFFSET(instshort_en), 0 },
  //[27]   fac VARCHAR(512),
  { 1, 's', "fac", MEMBER_OFFSET(fac), 0 },
  //[28]   fac_en VARCHAR(512),
  { 1, 's', "fac_en", MEMBER_OFFSET(fac_en), 0 },
  //[29]   facshort VARCHAR(512),
  { 1, 's', "facshort", MEMBER_OFFSET(facshort), 0 },
  //[30]   facshort_en VARCHAR(512),
  { 1, 's', "facshort_en", MEMBER_OFFSET(facshort_en), 0 },
  //[31]   birth_date DATE DEFAULT NULL,
  { 1, 'a', "birth_date", MEMBER_OFFSET(birth_date), 0 },
  //[32]   entry_date DATE DEFAULT NULL,
  { 1, 'a', "entry_date", MEMBER_OFFSET(entry_date), 0 },
  //[33]   graduation_date DATE DEFAULT NULL,
  { 1, 'a', "graduation_date", MEMBER_OFFSET(graduation_date), 0 },
};

enum { USERGROUP_WIDTH = 6 };
#define USERGROUP_OFFSET(f) XOFFSET(struct userlist_group, f)

static struct common_mysql_parse_spec usergroup_spec[USERGROUP_WIDTH] =
{
  //[0] group_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  { 0, 'd', "group_id", USERGROUP_OFFSET(group_id), 0 },
  //[1] group_name VARCHAR(128) NOT NULL UNIQUE KEY,
  { 0, 's', "group_name", USERGROUP_OFFSET(group_name), 0 },
  //[2] description VARCHAR(512) DEFAULT NULL
  { 1, 's', "description", USERGROUP_OFFSET(description), 0 },
  //[3] created_by INT NOT NULL,
  { 0, 'd', "created_by", USERGROUP_OFFSET(created_by), 0 },
  //[4] create_time DATETIME NOT NULL,
  { 1, 't', "create_time", USERGROUP_OFFSET(create_time), 0 },
  //[5] last_change_time DATETIME DEFAULT NULL,
  { 1, 't', "last_change_time", USERGROUP_OFFSET(last_change_time), 0 },
};

enum { USERGROUPMEMBER_WIDTH = 3 };
#define USERGROUPMEMBER_OFFSET(f) XOFFSET(struct userlist_groupmember, f)

static struct common_mysql_parse_spec usergroupmember_spec[] =
{
  //[0] group_id INT NOT NULL,
  { 0, 'd', "group_id", USERGROUPMEMBER_OFFSET(group_id), 0 },
  //[1] user_id INT NOT NULL,
  { 0, 'd', "user_id", USERGROUPMEMBER_OFFSET(user_id), 0 },
  //[2] rights VARCHAR(512) DEFAULT NULL,
  { 1, 's', "rights", USERGROUPMEMBER_OFFSET(rights), 0 },
};

enum { APIKEY_WIDTH = 10 };
#define APIKEY_OFFSET(f) XOFFSET(struct userlist_api_key, f)

static struct common_mysql_parse_spec apikey_spec[] =
{
  //[0] token VARCHAR(64) NOT NULL PRIMARY KEY,
  { 0, 'U', "token", APIKEY_OFFSET(token), NULL },
  //[1] secret VARCHAR(64) NOT NULL PRIMARY KEY,
  { 0, 'U', "secret", APIKEY_OFFSET(secret), NULL },
  //[2] user_id INT NOT NULL,
  { 0, 'd', "user_id", APIKEY_OFFSET(user_id), NULL },
  //[3] contest_id INT UNSIGNED NOT NULL,
  { 0, 'd', "contest_id", APIKEY_OFFSET(contest_id), NULL },
  //[4] create_time DATETIME NOT NULL,
  { 0, 't', "create_time", APIKEY_OFFSET(create_time), NULL },
  //[5] expiry_time DATETIME DEFAULT NULL,
  { 1, 't', "expiry_time", APIKEY_OFFSET(expiry_time), NULL },
  //[6] payload VARCHAR(1024) DEFAULT NULL,
  { 1, 's', "payload", APIKEY_OFFSET(payload), NULL },
  //[7] origin VARCHAR(128) DEFAULT NULL,
  { 1, 's', "origin", APIKEY_OFFSET(origin), NULL },
  //[8] all_contests TINYINT NOT NULL DEFAULT 0,
  { 0, 'd', "all_contests", APIKEY_OFFSET(all_contests), NULL },
  //[9] priv_level TINYINT NOT NULL DEFAULT 0,
  { 0, 'd', "role_id", APIKEY_OFFSET(role), NULL },
};
