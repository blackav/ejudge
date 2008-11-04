// $Id$

// Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru>

// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

function doFieldRequest(op, field_id, next_op)
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

function clearField(op, field_id, next_op)
{
  doFieldRequest(op, field_id, next_op);
}

function editField(op, field_id, next_op, value)
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

function editField2(op, field_id, subfield_id, next_op, value)
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

function toggleButton(op, field_id, next_op)
{
  doFieldRequest(op, field_id, next_op);
}

function editFileSave(form_id, op, field_id, next_op)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
        "field_id": field_id,
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

function ssFormOp1(form_id, op, next_op)
{
  dojo.xhrPost({
      url: script_name,
      content: {
        "SID": SID,
        "action": SSERV_CMD_HTTP_REQUEST,
        "op": op,
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
