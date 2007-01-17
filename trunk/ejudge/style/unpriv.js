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
	alert("ERROR!" + type + "," + errObj.message);
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
  //println("" + data + "/" + type + "/" + evt);

	if(data != null)
	{	
		if(dojo.dom.getTagName(dojo.dom.firstElement(data)) == "time")
		{	
			RightNow = new Date();
			var elem = dojo.dom.firstElement(dojo.dom.firstElement(data));
			while(elem != null)
			{
				switch(dojo.dom.getTagName(elem))
				{
					case "hour":
						RightNow.setHours(dojo.dom.textContent(elem));
						break;
					case "minute":
						RightNow.setMinutes(dojo.dom.textContent(elem));
						break;
					case "second":
						RightNow.setSeconds(dojo.dom.textContent(elem));
						break;
					case "day":
						RightNow.setDate(dojo.dom.textContent(elem));
						break;
					case "month":
						RightNow.setMonth(dojo.dom.textContent(elem));
						break;
					case "year":
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
  request = { SID : SID, action : currentTimeAction };
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
  request = { SID : SID, action : currentTimeAction };
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
