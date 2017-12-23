var fs = require('fs');

var data = fs.readFileSync('/dev/stdin', 'utf8');
var args = data.split(/\s+/);
var a = parseInt(args[0]);
var b = parseInt(args[1]);
console.log(a + b);
