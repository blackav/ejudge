#! /usr/bin/python
# $Id$

import ejudge;

clnt = ejudge.Userlist();

val = clnt.adminProcess();
print val;

#val = clnt.login("127.0.0.1", 0, 0, 0, "cher", "***");

#print val['user_id'];

#id = clnt.createUser('zz');
#print id;

print clnt.editField(1, 0, 0, "NN_EMAIL", "cher@ejudge.ru");
print clnt.privRegisterContest(1, 1);
print clnt.changeRegistration(1, 1, None, None, 0);
print clnt.lookupUser("cher", 0);
print clnt.lookupUser("aaa", 0);
print clnt.lookupUserId(22, 0);
print clnt.lookupUserId(5, 0);

del clnt;

