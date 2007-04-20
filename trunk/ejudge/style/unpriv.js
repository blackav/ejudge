// $Id$

//update interval (ms) - server
var oInterval = "";

//update interval (ms) - local
var lInterval = "";

//Date object storing current time
var RightNow = "";

var countDownTimer = null;
var reloadTimer = null;

//handling errors within AJAX communications
function handleError(type, errObj)
{ 
  /* FIXME: should not report error
  alert("ERROR: " + errObj.message);
  */
}

//pretty printer
function printTime()
{
  var placeToAdd = document.getElementById("currentTime");

  if(placeToAdd.childNodes.length == 1)
    placeToAdd.removeChild(placeToAdd.childNodes[0]);

  var localTime = document.createTextNode(
                                          /*(RightNow.getDate() < 10 ? "0" : "") + RightNow.getDate() + "/" 
                                            + (RightNow.getMonth() < 10 ? "0" : "") + RightNow.getMonth() + "/" 
                                            + (1900 + RightNow.getYear()) + " " 
                                            +*/ (RightNow.getHours() < 10 ? "0" : "") + RightNow.getHours() + ":" 
                                            + (RightNow.getMinutes() < 10 ? "0" : "") + RightNow.getMinutes() + ":" 
                                            + (RightNow.getSeconds() < 10 ? "0" : "") + RightNow.getSeconds());
  placeToAdd.appendChild(localTime);

  if (countDownTimer != null) {
    placeToAdd = document.getElementById("remainingTime");
    if (placeToAdd.childNodes.length == 1)
      placeToAdd.removeChild(placeToAdd.childNodes[0]);

    var hh = countDownTimer;
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
  RightNow.setSeconds(RightNow.getSeconds() + 1);
  if (countDownTimer != null) {
    countDownTimer = countDownTimer - 1;
    if (countDownTimer < 0) {
      countDownTimer = null;
      document.location.href = self_url + "?SID=" + SID + "&action=" + NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY;
    }
  }
  if (reloadTimer != null) {
    reloadTimer = reloadTimer - 1;
    if (reloadTimer < 0) {
      reloadTimer = null;
      window.location.reload();
    }
  }
  printTime();
}

//parses Time format
function parseAndSetTime(type, data, evt)
{
  var str;

  countDownTimer = null;
  reloadTimer = null;
  if(data != null) {
    if(dojo.dom.firstElement(data).tagName == "t") {
      RightNow = new Date();
      var elem = dojo.dom.firstElement(dojo.dom.firstElement(data));
      while(elem != null) {
        str = dojo.dom.textContent(elem);
        switch(elem.tagName) {
        case "h":
          RightNow.setHours(str);
          break;
        case "m":
          RightNow.setMinutes(str);
          break;
        case "s":
          RightNow.setSeconds(str);
          break;
        case "d":
          RightNow.setDate(str);
          break;
        case "o":
          RightNow.setMonth(str);
          break;
        case "y":
          RightNow.setYear(str);
          break;
        case "r":
          countDownTimer = str;
          break;
        case "x":
          reloadTimer = 5;
          break;
        }
        elem = dojo.dom.nextElement(elem);
      }
      lInterval = window.setInterval("updateLocalTime()",1000);
    }
  }
}

//function which updates the clock state from server
function updateTime()
{
  request = { SID : SID, action : NEW_SRV_ACTION_XML_USER_STATE };
  clearInterval(lInterval);
  dojo.io.bind({
      url: "/cgi-bin/new-client",
      load: parseAndSetTime,
      error: handleError,
      mimetype: "text/xml",
      method: "GET",
      content: request
        });
}

//starting Clock
function startClock()
{
  clearInterval(lInterval);
  /*
  request = { SID : SID, action : NEW_SRV_ACTION_XML_USER_STATE };
  dojo.io.bind({
      url: "/cgi-bin/new-client",
      load: parseAndSetTime,
      error: handleError,
      mimetype: "text/xml",
      method: "GET",
      content: request
        });
  */
  if (window.ActiveXObject) {
    var xmlDoc = new ActiveXObject("Microsoft.XMLDOM");
    xmlDoc.async = "false";
    xmlDoc.loadXML(xmlStateStr);
  } else {
    var domParser = new DOMParser();
    var xmlDoc = domParser.parseFromString(xmlStateStr, "text/xml");
  }
  parseAndSetTime(null, xmlDoc, null);
  oInterval = window.setInterval("updateTime()",60000);
}

function submitStatus(type, data, evt)
{
}

var next_problem_id;
function gotoNextProblem(type, data, evt)
{
  // FIXME: parse the response packet
  if (next_problem_id != null) {
    document.location.href = self_url + "?SID=" + SID + "&action=" + NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT + "&prob_id=" + next_problem_id;
  }
}

function submitAnswer(probId, answer, nextProbId)
{
  //alert("CLICK: " + probId + "," + answer);

  next_problem_id = null;
  if (probId != nextProbId)
    next_problem_id = nextProbId;
  request = { SID : SID, action : NEW_SRV_ACTION_UPDATE_ANSWER, prob_id : probId, file : answer };
  dojo.io.bind({
      url: self_url,
      load: gotoNextProblem,
      error: handleError,
      mimetype: "text/xml",
      method: "GET",
      content: request
        });
}

function displayProblemSubmitForm(probId)
{
  document.location.href = self_url + "?SID=" + SID + "&action=" + NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT + "&prob_id=" + probId;
}
