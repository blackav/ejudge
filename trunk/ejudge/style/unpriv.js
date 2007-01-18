// $Id$

//update interval (ms) - server
var oInterval = "";

//update interval (ms) - local
var lInterval = "";

//Date object storing current time
var RightNow = "";

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
}

//updates local time for 1 second
function updateLocalTime()
{
  RightNow.setSeconds(RightNow.getSeconds() + 1);
  printTime();
}

//parses Time format
function parseAndSetTime(type, data, evt)
{
  if(data != null) {
    if(dojo.dom.getTagName(dojo.dom.firstElement(data)) == "t") {
      RightNow = new Date();
      var elem = dojo.dom.firstElement(dojo.dom.firstElement(data));
      while(elem != null) {
        switch(dojo.dom.getTagName(elem)) {
        case "h":
          RightNow.setHours(dojo.dom.textContent(elem));
          break;
        case "m":
          RightNow.setMinutes(dojo.dom.textContent(elem));
          break;
        case "s":
          RightNow.setSeconds(dojo.dom.textContent(elem));
          break;
        case "d":
          RightNow.setDate(dojo.dom.textContent(elem));
          break;
        case "o":
          RightNow.setMonth(dojo.dom.textContent(elem));
          break;
        case "y":
          RightNow.setYear(dojo.dom.textContent(elem));
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
