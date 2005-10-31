{ Copyright(c) SPb-IFMO CTD Developers, 2000 }
{ Copyright(c) Anton Sukhanov, 1996 }

{ $Id$ }

{ Evaluating programs support stuff }

{$ifdef VER70}
{$ERROR}
{$ELSE}
{$I-,O+,Q-,R-,S-}
{$endif}

(*
    Program, using testlib running format:
      CHECK <Input_File> <Output_File> <Answer_File> [<Result_File> [-appes]],

    If result file is specified it will contain results.
*)

(*
    Modifications log:
      dd.mm.yyyy  modified by          modification log
      31.10.2005  Alexander Chernov    Adaptation for ejudge.
 
      27.10.2002  Andrew Stankevich    Buffered input (speedup up to 2 times on big files)
                                       BP7.0 compatibility removed
      17.09.2000  Andrew Stankevich    XML correct comments
      01.08.2000  Andrew Stankevich    Messages translated to English
                                       APPES support added   
                                       FAIL name changed
      07.02.1998  Roman Elizarov       Correct EOF processing
      12.02.1998  Roman Elizarov       SeekEoln corrected
                                       eoln added
                                       nextLine added
                                       nextChar is now function
*)

unit testlib;

interface

const 
    EOFCHAR  = #$1A;
    EOFREMAP = ' ';
    NUMBERBEFORE = [#10,#13,' ',#09];
    NUMBERAFTER  = [#10,#13,' ',#09,EOFCHAR];
    LINEAFTER    = [#10,#13,EOFCHAR];
    BLANKS       = [#10,#13,' ',#09];
    EOLNCHAR     = [#10,#13,EOFCHAR];

    BUFFER_SIZE = 1048576;

type 
    Charset = set of char;
    Tmode   = (_INPUT, _OUTPUT, _ANSWER);
    Tresult = (_OK, _WA, _PE,  _FAIL, _DIRT);
              { 
                _OK - accepted, 
                _WA - wrong answer, 
                _PE - output format mismatch,
                _FAIL - when everything fucks up 
                _DIRT - for inner using
              }

    Instream = object
        f: file; { file }
        name: string; { file name }
        mode: Tmode;
        opened: boolean;
        fpos: integer;
        size: integer;

        buffer: array [0..BUFFER_SIZE - 1] of char;
        bpos: integer;
        bsize: integer;

        { for internal usage }
        procedure fillbuffer;
        constructor init(fname: string; m: Tmode);

        function curchar: char; { returns cur }
        procedure skipchar;  { skips current char }
        function nextchar: char;  { moves to next char }

        procedure reset;

        function eof: boolean;
        function seekeof: boolean;

        function eoln: boolean;
        function seekeoln: boolean;

        procedure nextline; { skips current line }

        { Skips chars from given set }
        { Does not generate errors }
        procedure skip(setof: Charset);

        { Read word. Skip before all chars from `before`
          and after all chars from `after`. }
        function readword(before, after: Charset): string;

        { reads integer }
        { _PE if error }
        function readlongint: integer;

        { = readlongint }
        function readinteger: integer;

        { reads real }
        { _PE if error }
        function readreal: extended;

        { same as readword([], [#13 #10]) }
        function readstring: string;

        { for internal usage }
        procedure quit(res: Tresult; msg: string);
        procedure close;

    end;


procedure quit(res: Tresult; msg: string);

var 
    inf, ouf, ans: Instream;
    resultname: string; { result file name }
    appesmode: boolean;

implementation

uses 
    SysUtils;

const
    LIGHTGRAY = $07;    
    LIGHTRED  = $0c;    
    LIGHTCYAN = $0b;    
    LIGHTGREEN = $0a;

procedure textcolor(x: word);
{var
    h: THandle;}
begin
{    h := GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(h, x);}
end;

const 
    outcomes: array[Tresult] of string = (
        'accepted',
        'wrong-answer',
        'presentation-error',
        'fail',
        'fail'
    );

procedure xmlsafewrite(var t: text; s: string);
var
    i: integer;
begin
    for i := 1 to length(s) do
    begin
        case s[i] of
            '&': write(t, '&amp;');
            '<': write(t, '&lt;');
            '>': write(t, '&gt;');
            '"': write(t, '&quot;');
            #0..#31: write(t, '.');
            else
                write(t, s[i]);
        end; { case }
    end;
end;

procedure quit(res: Tresult; msg: string);
var 
    resfile: text;
    errorname: string;

    procedure scr(color: word; msg: string);
    begin
       if resultname = '' then { if no result file }
       begin
          textcolor(color); write(msg); textcolor(LIGHTGRAY);
       end;
    end;

begin
   if (res = _OK) then
   begin
      if not ouf.seekeof then quit(_DIRT, 'Extra information in the output file');
   end;

   case res of
     _FAIL : 
   begin 
      errorname := 'FAIL ';
      scr(LIGHTRED, errorname);
   end;

     _DIRT : 
   begin
      errorname := 'wrong output format ';
      scr(LIGHTCYAN, errorname);
      res := _PE;
   end;

     _PE   : 
   begin
      errorname := 'wrong output format ';
      scr(LIGHTRED, errorname);
   end;

     _OK   : 
   begin
      errorname := 'ok ';
      scr(LIGHTGREEN, errorname);
   end;

     _WA   : 
   begin
      errorname := 'wrong answer ';
      scr(LIGHTRED, errorname);
   end;

   else    
      quit(_FAIL, 'What is the code ??? ');
   end;    

   if resultname <> '' then
   begin
      assign(resfile, resultname); { Create file with result of evaluation }
      rewrite(resfile);
      if ioresult <> 0 then quit(_FAIL, 'Can not write to Result file');
      if appesmode then
      begin
         write(resfile, '<?xml version="1.0" encoding="koi8-r"?>');
         write(resfile, '<result outcome = "', outcomes[res], '">');
         xmlsafewrite(resfile, msg);
         writeln(resfile, '</result>');
      end else  begin
         writeln(resfile, '.Testlib Result Number = ', ord(res));
         writeln(resfile, '.Result name (optional) = ', errorname);
         writeln(resfile, '.Check Comments = ', msg);
      end;
      close(resfile);
      if ioresult <> 0 then quit(_FAIL, 'Can not write to Result file');
    end;

    scr(LIGHTGRAY, msg);
    writeln;

    if res = _FAIL then HALT(ord(res));

    close(inf.f); 
    close(ouf.f); 
    close(ans.f);

    textcolor(LIGHTGRAY);

   if (res = _OK) or (resultname <> '') then halt(0);
   if res=_PE then halt(4);
   if res=_WA then halt(5);
   halt(255);
end;

procedure Instream.fillbuffer;
var
    left: integer;
begin
    left := size - fpos;
    bpos := 0;

    if left = 0 then
    begin
        bsize := 1;
        buffer[0] := EOFCHAR;
    end else begin
        blockread(f, buffer, BUFFER_SIZE, bsize);
        fpos := fpos + bsize;
    end;
end;

procedure Instream.reset;
begin
    if opened then
        close;

    fpos := 0;
    system.reset(f, 1);

    size := filesize(f);

    if ioresult <> 0 then
    begin
        if mode = _OUTPUT then
            quit(_PE, 'File not found: "' + name + '"');
        bsize := 1;
        bpos := 0;
        buffer[0] := EOFCHAR;
    end else begin
        fillbuffer;
    end;

    opened := true;
end;

constructor Instream.init(fname: string; m: Tmode);
begin
    opened := false;
    name := fname;
    mode := m;

    assign(f, fname);

    reset;
end;

function Instream.curchar: char;
begin
    curchar := buffer[bpos];
end;

function Instream.nextchar: char;
begin
    nextchar := buffer[bpos];
    skipchar;
end;

procedure Instream.skipchar;
begin
    if buffer[bpos] <> EOFCHAR then 
    begin
        inc(bpos);
        if bpos = bsize then
            fillbuffer;
    end;
end;

procedure Instream.quit(res: Tresult; msg: string);
begin
    if mode = _OUTPUT then 
        testlib.quit(res, msg)
    else 
        testlib.quit(_FAIL, msg + ' (' + name + ')');
end;

function Instream.readword(before, after: Charset): string;
begin
    while buffer[bpos] in before do skipchar;

    if (buffer[bpos] = EOFCHAR) and not (buffer[bpos] in after) then
        quit(_PE, 'Unexpected end of file');

    result := '';
    while not ((buffer[bpos] in after) or (buffer[bpos] = EOFCHAR))  do
    begin
        result := result + nextchar;
    end;
end;

function Instream.readinteger: integer;
var 
    help: string;
    code: integer;
begin
    while (buffer[bpos] in NUMBERBEFORE) do skipchar;

    if (buffer[bpos] = EOFCHAR) then
        quit(_PE, 'Unexpected end of file - integer expected');

    help := '';
    while not (buffer[bpos] in NUMBERAFTER) do 
        help := help + nextchar;
    val(help, result, code);
    if code <> 0 then quit(_PE, 'Expected integer instead of "' + help + '"');
end;

function Instream.readlongint: integer;
var 
    help: string;
    code: integer;
begin
    while (buffer[bpos] in NUMBERBEFORE) do skipchar;

    if (buffer[bpos] = EOFCHAR) then
        quit(_PE, 'Unexpected end of file - integer expected');

    help := '';
    while not (buffer[bpos] in NUMBERAFTER) do 
        help := help + nextchar;
    val(help, result, code);
    if code <> 0 then quit(_PE, 'Expected integer instead of "' + help + '"');
end;

function Instream.readreal: extended;
var 
    help: string;
    code: integer;
begin
    help := readword (NUMBERBEFORE, NUMBERAFTER);
    val(help, result, code);
    if code <> 0 then quit(_PE, 'Expected real instead of "' + help + '"');
end;

procedure Instream.skip(setof: Charset);
begin
    while (buffer[bpos] in setof) and (buffer[bpos] <> EOFCHAR) do skipchar;
end;

function Instream.eof: boolean;
begin
    eof := buffer[bpos] = EOFCHAR;
end;

function Instream.seekeof: boolean;
begin
    while (buffer[bpos] in BLANKS) do skipchar;
    seekeof := buffer[bpos] = EOFCHAR;
end;

function Instream.eoln: boolean;
begin
    eoln:= buffer[bpos] in EOLNCHAR;
end;

function Instream.seekeoln: boolean;
begin
    skip([' ', #9]);
    seekeoln := eoln;
end;

procedure Instream.nextline;
begin
    while not (buffer[bpos] in EOLNCHAR) do skipchar;
    if buffer[bpos] = #13 then skipchar; 
    if buffer[bpos] = #10 then skipchar; 
end;

function Instream.readstring: string;
begin
    readstring := readword([], LINEAFTER);
    nextline;
end;

procedure Instream.close;
begin
    if opened then system.close(f);
    opened := false;
end;

initialization
    if sizeof(integer) <> 4 then
        quit(_FAIL, '"testlib" unit assumes "sizeof(integer) = 4"');

    if (paramcount < 3) or (paramcount > 5) then
        quit(_FAIL, 'Program must be run with the following arguments: ' +
            '<input-file> <output-file> <answer-file> [<report-file> [<-appes>]]');

    case paramcount of
        3: 
            begin
                resultname := '';
                appesmode := false;
            end;
        4: 
            begin
                resultname := paramstr(4);
                appesmode := false;
            end;
        5: begin
                if uppercase(paramstr(5)) <> '-APPES' then
                    quit(_FAIL, 'Program must be run with the following arguments: ' +
                        '<input-file> <output-file> <answer-file> [<report-file> [<-appes>]]');
                resultname := paramstr(4);
                appesmode := true;
           end;
    end; { case }

    inf.init(paramstr(1), _INPUT);
    ouf.init(paramstr(2), _OUTPUT);
    ans.init(paramstr(3), _ANSWER);
end.
