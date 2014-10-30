/* -*- mode: java; coding: utf-8 -*- */
// $Id$

// Copyright (C) 2008-2014 Alexander Chernov <cher@ejudge.ru>

// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

function ssFieldRequest(op, field_id, next_op)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "field_id": field_id
      },
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else {
          // reload this page
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op;
        }
      }
  });
}

function ssFieldRequest2(op, item_id, field_id, next_op)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "item_id": item_id,
        "field_id": field_id
      },
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else {
          // reload this page
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op;
        }
      }
  });
}

function doFieldRequestWithField(op, field_id, next_op)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "field_id": field_id
      },
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else {
          // reload this page
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op + "&field_id=" + field_id;
        }
      }
  });
}

function ssEditField(op, field_id, next_op, value)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "field_id": field_id,
        "value": value
      },
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else if (data.status > 0) {
          // reload this page
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op;
        }
      }
  });
}

function ssEditField2(op, field_id, subfield_id, next_op, value)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "field_id": field_id,
        "subfield_id": subfield_id,
        "value": value
      },
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else if (data.status > 0) {
          // reload this page
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op;
        }
      }
  });
}

function ssEditField3(op, field_id, subfield_id, next_op, value)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "field_id": field_id,
        "subfield_id": subfield_id,
        "value": value
      },
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else if (data.status > 0) {
          // reload this page
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op + "&field_id=" + field_id;
        }
      }
  });
}

function ssEditField4(op, item_id, field_id, next_op, value)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "item_id": item_id,
        "field_id": field_id,
        "value": value
      },
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else if (data.status > 0) {
          // reload this page
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op;
        }
      }
  });
}

function ssEditField5(op, item_id, field_id, subfield_id, next_op, value)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "item_id": item_id,
        "field_id": field_id,
        "subfield_id": subfield_id,
        "value": value
      },
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else if (data.status > 0) {
          // reload this page
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op;
        }
      }
  });
}

function editFileSave(form_id, op, field_id, next_op)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "field_id": field_id
      },
      form : form_id,
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else if (data.status > 0) {
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op;
        }
      }
  });
}

function ssEditFileSave2(form_id, op, item_id, field_id, next_op)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "item_id": item_id,
        "field_id": field_id
      },
      form : form_id,
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else if (data.status > 0) {
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op;
        }
      }
  });
}

function editFileClear(op, field_id, next_op)
{
  doFieldRequestWithField(op, field_id, next_op);
}

function editFileReload(op, field_id, next_op)
{
  doFieldRequestWithField(op, field_id, next_op);
}

function ssLoad1(op)
{
  document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + op;
}

function ssLoad2(op, field_id)
{
  document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + op + "&field_id=" + field_id;
}

function ssLoad3(op, item_id, field_id)
{
  document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + op + "&item_id=" + item_id + "&field_id=" + field_id;
}

function ssFormOp1(form_id, op, next_op)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op
      },
      form : form_id,
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else if (data.status > 0) {
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op;
        }
      }
  });
}

function ssFormOp2(form_id, op, field_id, next_op)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "field_id": field_id
      },
      form : form_id,
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else if (data.status > 0) {
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op;
        }
      }
  });
}

function ssTopLevel()
{
  document.location.href = script_name + "?SID=" + SID;
}

function ssSetValue2(op, field_id, next_op, value)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "field_id": field_id,
        "value": value
      },
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else if (data.status > 0) {
          // reload this page
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op + "&field_id=" + field_id;
        }
      }
  });
}

function ssSetValue3(op, item_id, field_id, next_op, value)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "item_id": item_id,
        "field_id": field_id,
        "value": value
      },
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else if (data.status > 0) {
          // reload this page
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op;
        }
      }
  });
}

function ssSetHiddenMask(hidden_id, op, value)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "value": value
      },
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else {
          dojo.byId(hidden_id).value = value;
        }
      }
  });
}

function ssFormOp3(form_id, op, field_id, next_op)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "field_id": field_id
      },
      form : form_id,
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else if (data.status > 0) {
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op + "&field_id=" + field_id;
        }
      }
  });
}

function ssFieldCmd3(op, field_id, subfield_id, next_op)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "field_id": field_id,
        "subfield_id": subfield_id
      },
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else {
          // reload this page
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op + "&field_id=" + field_id;
        }
      }
  });
}

function ssForgetContest(op)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op
      },
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else {
          // reload this page
          document.location.href = script_name + "?SID=" + SID;
        }
      }
  });
}

function ssCommitContest(action)
{
  document.location.href = script_name + "?SID=" + SID + "&action=" + action;
}

function ssEditPage(op, page)
{
  document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + op + "&page=" + page;
}

function ssPackage(op, pkg)
{
  document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + op + "&package=" + pkg;
}

function ssPackageOp(op, next_op, pkg, item)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "package": pkg,
        "item": item
      },
      handleAs: "json",
      error: function(data, ioargs) {
        alert("Request failed: " + data);
      },
      load: function(data, ioargs) {
        if (data.status < 0) {
          alert("Operation failed: " + data.text);
        } else if (data.status > 0) {
          // reload this page
          document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + next_op + "&package=" + pkg;
        }
      }
  });
}

function ssEditProblem(op, pkg, name)
{
  document.location.href = script_name + "?SID=" + SID + "&action=" + SSERV_CMD_HTTP_REQUEST + "&op=" + op + "&package=" + pkg + "&name=" + name;
}

function markLine(line)
{
  var obj = document.forms["run_comment"].elements["msg_text"];
  if (obj != null) {
    if (obj.value.length != 0 && obj.value.charAt(obj.value.length - 1) != '\n') obj.value += '\n';
  }
  obj.value += "Строка " + line + "\n";
}

function formatViolation()
{
  var obj = document.forms["run_comment"].elements["msg_text"];
  if (obj != null) {
    if (obj.value.length != 0 && obj.value.charAt(obj.value.length - 1) != '\n') obj.value += '\n';
  }
  obj.value += "Нарушение правил оформления программ\n";
}

function ej_change_stat(run_id, status)
{
  if (status == 100) {
    var d = document.getElementById('ej_dd_' + run_id);
    if (d == null) return;
    d.style.display = "none";
    return;
  }

  var form = document.forms["ChangeStatusForm"];
  if (form !== undefined && form != null) {
    form.run_id.value = run_id;
    form.status.value = status;
    form.submit();
  }

  //  document.location.href = self_url + "?SID=" + SID + "&action=CHANGE_STATUS" + "&run_id=" + run_id + "&status=" + status;
}

var ej_valid_statuses =
{
  100 : "No change",
  99 : "Rejudge",
  95 : "Full rejudge",
  0  : "OK",
  9  : "Ignored",
  10 : "Disqualified",
  17 : "Rejected",
  6  : "Check failed",
  11 : "Pending check",
  7  : "Partial solution",
  8  : "Accepted for testing",
  16 : "Pending review",
  1  : "Compilation error",
  2  : "Run-time error",
  3  : "Time-limit exceeded",
  15 : "Wall time-limit exceeded",
  4  : "Presentation error",
  5  : "Wrong answer",
  12 : "Memory limit exceeded",
  13 : "Security violation",
  14 : "Coding style violation"
}

function ej_stat(run_id)
{
  var d = document.getElementById('ej_dd_' + run_id);
  if (d == null) return;
  if (d.style.display == "block") {
    d.style.display = "none";
    return;
  }
  d.style.display = "block";
  if (d.childNodes.length >= 1) {
    return;
  }
  var b = document.createElement("b");
  var t = document.createTextNode("Change result of run " + run_id);
  var a = null;
  b.appendChild(t);
  d.appendChild(b);
  for (var p in ej_valid_statuses) {
    t = document.createElement("div");
    a = document.createAttribute("class");
    a.value = "ej_stat_menu_item";
    t.setAttributeNode(a);
    a = document.createAttribute("onclick");
    a.value = "ej_change_stat(" + run_id + "," + p + ")";
    t.setAttributeNode(a);
    d.appendChild(t);
    t.appendChild(document.createTextNode(ej_valid_statuses[p]));
  }
}

var ej_valid_fields =
{
  0 : "Run ID",
  1 : "Size",
  2 : "Time",
  3 : "Absolute Time",
  4 : "Relative Time",
  5 : "Nsec",
  6 : "User ID",
  7 : "User Login",
  8 : "User Name",
  9 : "Prob ID",
  10 : "Prob Name",
  11 : "Lang ID",
  12 : "Lang Name",
  13 : "IP",
  14 : "SHA1",
  15 : "Score",
  16 : "Test",
  17 : "Score Adj",
  18 : "Result",
  19 : "Variant",
  20 : "Mime Type",
  21 : "Saved Score",
  22 : "Saved Test",
  23 : "Saved Result",
  24 : "UUID",
  25 : "EOLN Type",
  26 : "Storage Flags",
  27 : "Tokens"
}

function ej_field_popup(field_mask)
{
  var d = document.getElementById("ej_field_popup");
  if (d == null) return;
  if (d.style.display == "block") {
    d.style.display = "none";
    return;
  }
  d.style.display = "block";
  if (d.childNodes.length >= 1) {
    return;
  }

  var b = document.createElement("form");
  var a = document.createAttribute("method");
  a.value = "post";
  b.setAttributeNode(a);
  a = document.createAttribute("action");
  a.value = self_url;
  b.setAttributeNode(a);
  d.appendChild(b);

  var h = document.createElement("input");
  a = document.createAttribute("type");
  a.value = "hidden";
  h.setAttributeNode(a);
  a = document.createAttribute("name");
  a.value = "SID";
  h.setAttributeNode(a);
  a = document.createAttribute("value");
  a.value = SID;
  h.setAttributeNode(a);
  b.appendChild(h);
  h = document.createElement("input");
  a = document.createAttribute("type");
  a.value = "hidden";
  h.setAttributeNode(a);
  a = document.createAttribute("name");
  a.value = "action";
  h.setAttributeNode(a);
  a = document.createAttribute("value");
  a.value = "change-run-fields";
  h.setAttributeNode(a);
  b.appendChild(h);

  var t = document.createElement("table");
  a = document.createAttribute("class");
  a.value = "b0";
  t.setAttributeNode(a);
  b.appendChild(t);

  var r = null;
  var e = null;
  var s = null;
  for (var p in ej_valid_fields) {
    r = document.createElement("tr");
    t.appendChild(r);
    e = document.createElement("td");
    a = document.createAttribute("class");
    a.value = "b0";
    r.appendChild(e);
    s = document.createElement("input");
    a = document.createAttribute("type");
    a.value = "checkbox";
    s.setAttributeNode(a);
    a = document.createAttribute("name");
    a.value = "field_" + p;
    s.setAttributeNode(a);
    if (((1 << p) & field_mask) != 0) {
      a = document.createAttribute("checked");
      a.value = "checked";
      s.setAttributeNode(a);
    }
    e.appendChild(s);

    e = document.createElement("td");
    a = document.createAttribute("class");
    a.value = "b0";
    r.appendChild(e);
    e.appendChild(document.createTextNode(ej_valid_fields[p]));
  }

  t = document.createElement("table");
  a = document.createAttribute("class");
  a.value = "b0";
  t.setAttributeNode(a);
  b.appendChild(t);
  r = document.createElement("tr");
  t.appendChild(r);
  e = document.createElement("td");
  a = document.createAttribute("class");
  a.value = "b0";
  r.appendChild(e);
  s = document.createElement("input");
  a = document.createAttribute("type");
  a.value = "submit";
  s.setAttributeNode(a);
  a = document.createAttribute("name");
  a.value = "cancel";
  s.setAttributeNode(a);
  a = document.createAttribute("value");
  a.value = "Cancel";
  s.setAttributeNode(a);
  e.appendChild(s);

  e = document.createElement("td");
  a = document.createAttribute("class");
  a.value = "b0";
  r.appendChild(e);
  s = document.createElement("input");
  a = document.createAttribute("type");
  a.value = "submit";
  s.setAttributeNode(a);
  a = document.createAttribute("name");
  a.value = "set";
  s.setAttributeNode(a);
  a = document.createAttribute("value");
  a.value = "Change";
  s.setAttributeNode(a);
  e.appendChild(s);
  e = document.createElement("td");
  a = document.createAttribute("class");
  a.value = "b0";
  r.appendChild(e);
  s = document.createElement("input");
  a = document.createAttribute("type");
  a.value = "submit";
  s.setAttributeNode(a);
  a = document.createAttribute("name");
  a.value = "reset";
  s.setAttributeNode(a);
  a = document.createAttribute("value");
  a.value = "Set default";
  s.setAttributeNode(a);
  e.appendChild(s);
}
