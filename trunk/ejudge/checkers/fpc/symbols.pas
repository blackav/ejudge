{!PASLIB 1.0 Copyright (c) Антон Суханов, 1996}
{Функции работы со строками}

{Дата последнего изменения: 11/11/96}
{$M 16384,0,30000}

unit Symbols;

INTERFACE

function str (x: longint; width: integer): string;
function RealStr (x: real; w, d: integer): string;
function compress (s: string): string;

IMPLEMENTATION

var error: boolean;


function E_Str (x: longint; width: integer; osn: integer; fill: char): string;
const Digits: array [0..15] of char = '0123456789ABCDEF';
var r: string;
    sgn: integer;
begin
   if x < 0 then sgn := 1 else sgn := 0;
   x := abs (x);
   r := '';
   repeat
      r := Digits [x mod osn] + r; x := x div osn;
      dec (width);
   until (x = 0) or (width=0);
   if (sgn = 1) then r := '-' + r;
   while width - sgn > 0 do begin r := fill + r; dec (width) end;
   E_Str := r;
end;

function Str (x: longint; width: integer): string;
begin
   Str := E_Str (x, width, 10, ' ');
end;

procedure FastCompress (var s: string);
var i, j: integer;
begin
   i := 1; while (i<=length(s)) and (s [i] = ' ') do inc (i);
   if i > length (s) then s := ''
   else begin
     j := length (s); while s [j] = ' ' do dec (j);
     s := copy (s, i, j-i+1);
  end;
end;

function Compress (s: string): string;
begin
   FastCompress (s);
   Compress := s;
end;

function RealStr (x: real; w, d: integer): string;
var r: string;
begin
   system.Str (x:w:d, r);
   RealStr := r
end;



BEGIN {Инициализация}

END.