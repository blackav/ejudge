// Copyright (C) 2008-2015 Alexander Chernov <cher@ejudge.ru>

// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

var clockTimer = null;
var pingTimer = null;

/* if we have compiling/running runs and want to check status update */
var need_reload_check = 0;
/* number of retry to relax */
var reload_check_count = 0;

function setStatusString(string, default_string)
{
  if (string == null) {
    string = default_string;
  }

  loc = document.getElementById("statusString");
  if (loc != null) {
    if (loc.childNodes.length == 1) {
      loc.removeChild(loc.childNodes[0]);
    }
    loc.appendChild(document.createTextNode("/ " + string));
    loc.style.visibility = "visible";            
  }
}

function hideStatusString()
{
  loc = document.getElementById("statusString");
  if (loc != null) {
    if (loc.childNodes.length == 1) {
      loc.removeChild(loc.childNodes[0]);
    }
    loc.style.visibility = "hidden";
  }
}

// handle errors within AJAX communications
function handleError(type, errObj)
{ 
  if (pingTimer != null) {
    pingTimer = window.clearInterval(pingTimer);
    pingTimer = null;
  }

  setStatusString(updateFailedMessage, "STATUS UPDATE FAILED!");

  loc = document.getElementById("statusLine");
  if (loc != null) {
    loc.className = "server_status_error";
  }
  loc = document.getElementById("reloadButton");
  if (loc != null) {
    loc.style.visibility = "visible";
  }
}

//pretty printer
function printTime()
{
  var placeToAdd = document.getElementById("currentTime");

  if(placeToAdd.childNodes.length == 1)
    placeToAdd.removeChild(placeToAdd.childNodes[0]);

  var localTime = document.createTextNode((jsonState.h < 10 ? "0" : "") + jsonState.h + ":" + (jsonState.m < 10 ? "0" : "") + jsonState.m + ":" + (jsonState.s < 10 ? "0" : "") + jsonState.s);
  placeToAdd.appendChild(localTime);

  if (jsonState.r != null) {
    placeToAdd = document.getElementById("remainingTime");
    if (placeToAdd.childNodes.length == 1)
      placeToAdd.removeChild(placeToAdd.childNodes[0]);

    var hh = jsonState.r;
    var ss = hh % 60;
    if (ss < 10) ss = "0" + ss;
    hh = (hh - ss) / 60;
    var mm = hh % 60;
    if (mm < 10) mm = "0" + mm;
    hh = (hh - mm) / 60;
    localTime = document.createTextNode(hh + ":" + mm + ":" + ss);
    placeToAdd.appendChild(localTime);
  }
}

//updates local time for 1 second
function updateLocalTime()
{
  if (jsonState.r != null) {
    jsonState.r--;
    if (jsonState.r < 0) {
      jsonState.r = null;
      document.location.href = script_name + "?SID=" + SID + "&action=" + NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY;
    }
  }

  jsonState.s++;
  if (jsonState.s >= 60) {
    jsonState.s -= 60;
    jsonState.m++;
    if (jsonState.m >= 60) {
      jsonState.m -= 60;
      jsonState.h++;
      if (jsonState.h >= 24) {
        jsonState.h -= 24;
      }
    }
  }
  printTime();
}

function reloadPage()
{
  window.location.reload();
}

function updateTime()
{
  clearInterval(pingTimer);
  jQuery.ajax({
      url : script_name,
      data : {
          "SID": SID,
          "action": NEW_SRV_ACTION_JSON_USER_STATE,
          "x": need_reload_check
      },
      dataType : "json",
      success : function (data) {
          jsonState = data;
          printTime();
          if (jsonState.z != null) {
              setStatusString(testingCompleted, "TESTING COMPLETED");
              loc = document.getElementById("reloadButton");
              if (loc != null) {
                  loc.style.visibility = "visible";
              }
              loc = document.getElementById("statusLine");
              if (loc != null) {
                  loc.className = "server_status_alarm";
              }
              pingTimer = window.setInterval(updateTime, 60000);
          } else if (jsonState.x != null) {
              if (need_reload_check == 0) need_reload_check = 1;
              if (need_reload_check == 2) {
                  pingTimer = window.setInterval(updateTime, 60000);
              } else if (++reload_check_count > 24) {
                  // give up on a bad job...
                  need_reload_check = 2;
                  reload_check_count = 0;
                  loc = document.getElementById("reloadButton");
                  if (loc != null) {
                      loc.style.visibility = "visible";
                  }
                  setStatusString(waitingTooLong, "REFRESH PAGE MANUALLY!");
                  pingTimer = window.setInterval(updateTime, 60000);
              } else {
                  setStatusString(testingInProgressMessage, "TESTING IN PROGRESS...");
                  pingTimer = window.setInterval(updateTime, 5000);
              }
          } else {
              need_reload_check = 0;
              reload_check_count = 0;
              hideStatusString();
              pingTimer = window.setInterval(updateTime, 60000);
          }
      }});
}

function startClock()
{
  clockTimer = window.setInterval(updateLocalTime, 1000);
  if (jsonState.x != null) {
    pingTimer = window.setInterval(updateTime, 5000);
    need_reload_check = 1;
    reload_check_count = 0;
    setStatusString(testingInProgressMessage, "TESTING IN PROGRESS...");
  } else {
    pingTimer = window.setInterval(updateTime, 60000);
  }
}

function submitStatus(type, data, evt)
{
}

function submitAnswer(action, probId, answer, next_action, nextProbId)
{
    jQuery.ajax({
      url: script_name,
      data: {
          "SID": SID,
          "action": action,
          "prob_id": probId,
          "json": 1,
          "file": answer
      },
      dataType: "json",
      error: function(jqxhr, textStatus, errorThrown) {
          alert("Request failed: " + textStatus);
      },
      success: function(data) {
          if (data.status < 0) {
              alert("Operation failed: " + data.text);
          } else {
              if (nextProbId != null) {
                  document.location.href = self_url + "?SID=" + SID + "&action=" + next_action + "&prob_id=" + nextProbId;
              }
          }
      }
  });
}

function displayProblemSubmitForm(action, probId)
{
  document.location.href = script_name + "?SID=" + SID + "&action=" + action + "&prob_id=" + probId;
}

jQuery(document).ready(function()
{
    $(document).ajaxError(function()
    {
	//alert('ErrorEvent: ' + event + ', Data: ' + data);
        handleError();
    });
});

/*
 * Local variables:
 *  c-basic-offset: "2"
 * End:
 */
