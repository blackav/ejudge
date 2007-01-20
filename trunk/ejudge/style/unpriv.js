// $Id$

//update interval (ms) - server
var oInterval = "";

//update interval (ms) - local
var lInterval = "";

//Date object storing current time
var RightNow = "";

var countDownTimer = null;

//handling errors within AJAX communications
function handleError(type, errObj)
{ 
  alert("ERROR: " + errObj.message);
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
    if (countDownTimer < 0) countDownTimer = null;
  }
  printTime();
}

//parses Time format
function parseAndSetTime(type, data, evt)
{
  var str;

  countDownTimer = null;
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
  oInterval = window.setInterval("updateTime()",60000);
}
