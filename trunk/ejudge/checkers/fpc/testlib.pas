{TESTLIB: ���������� ��� ����������� ��������}
{Copyright (c) ����� �������}

{������ 1.0 ��� ejudge}
{ $Id$ }

{���� ���������� ���������: 30/03/97}
{�������� ����� ��� ����������: "�������� �����" (30/03/97)}
{������� ReadInteger ����� ��������}

{$A-,B-,D+,E+,F+,G+,I-,L+,N+,O-,P+,Q-,R+,S+,T-,V+,X+,Y+}
{$M 65520, 0, 0}

 (* ������ ������� ����������� ���������, ������������ TESTLIB:

    CHECK <Input_File> <Output_File> <Answer_File> [<Result_File>],

    ��� ���� � ���� Result_File ����� ������� ��������� ��������,
    ���� �� �����.

    ���� ����� ���� � ����������� ��������, �� ����� �� ����� ��
    ������������, � ��� �������� ������ ���� �������!!!

  *)

unit testlib;

(* ================================================================= *)
                              interface
(* ================================================================= *)

const EofChar = #$1A;
      NumberBefore = [#10,#13,' ',#09];
      NumberAfter  = [#10,#13,' ',#09];
      Blanks       = [#10,#13,' ',#09];

type REAL = EXTENDED; {!!!!!!!!}

type CharSet = set of char;
     TMode   = (_Input, _Output, _Answer);
     TResult = (_OK, _WA, _PE, _3, _4, _Fail, _pc, _Dirt);
               {_OK - ��� �����, _PC - �������� �����,
                _WA - �������� �����,
                _PE - ������ ������,
                _Fail - ����� ��� ���������
                _Dirt - ��� ����������� �������������}

     InStream = object
                    cur: char; {������� ������, =EofChar, ���� �����}
                    f: TEXT; {����}
                    name: string; {��� �����}
                    mode: TMode;
                    opened: boolean;

                    {��� ���������� �������������}
                    constructor init (fname: string; m: TMode);

                    function CurChar: char; {������ cur}
                    function ReadChar: char; {������ cur}
                    procedure NextChar;     {��������� �� ����. ������}

                    function seekeof: boolean;
                    function seekEoln: boolean;


                    function eof : boolean;  { == cur = EofChar}

                    {���������� ������� ��������� ���������}
                    {�� ������������ ������}
                    procedure skip (setof: CharSet);

                    {������ ����� (�� ��������). ����� ������ ������������
                     ��� ������� �� Before. ��������� ����� ����� ��������
                     ���� ����� �����, ���� ������ �� After. ���� ReadWord
                     ���������� �� ����� ����� ��� ����� ������, �� �� �
                     ���������� � ������� _PE}
                    {���� ����� ������� �����, ��� �� 255 �������� =>
                     ������� � ������� _PE}
                    function ReadWord (Before, After: CharSet): string;

                    {������ ����� integer}
                    {��� ������ ������� � _PA}
                    function ReadInteger: integer;

                    {������ ������� �����}
                    {��� ������ ������� � _PA}
                    function ReadLongint: longint;

                    {������ ������������}
                    {��� ������ ������� � _PA}
                    function ReadReal: real;

                    {������ ������ (�� �������� #13, #10),
                     ������� �������� ���������� ������ ������ ����. ������}
                    {���� ������ ������� �����, ��� �� 255 �������� =>
                     ������� � ������� _PA}
                    function ReadString: string;

                    {��� ����������� �������������}
                    procedure QUIT (res: TResult; msg: string);
                    procedure close;

                end;


procedure QUIT (res: TResult; msg: string);

var inf, ouf, ans: InStream;
    ResultName: string; {��� ����� ��� ����������}

(* ================================================================= *)
                              implementation
(* ================================================================= *)

{uses crt;}

procedure QUIT (res: TResult; msg: string);
var RESFILE: Text;
    ErrorName: string;

    procedure scr ({color: word; }msg: string);
    begin
       if ResultName = '' then {���� �� ��������� ���� � ���-���}
       begin
          {TextColor (color);} write (erroutput, msg); {TextColor (LightGray);}
       end;
    end;

begin
   if (res = _OK) then
   begin
      ouf.skip (Blanks);
      if not ouf.eof then QUIT (_Dirt, '������ ���������� � �������� �����');
   end;

   case res of
      _Fail: begin {sound (100); delay (30); nosound;}
                   ErrorName := '�����';
                   Scr ({LightRed,} ErrorName);
             end;

      _Dirt: begin
                   ErrorName := 'PE �������� ������ ������';
                   Scr ({LightCyan, }ErrorName);
                   res := _PE;
                   msg := '������ ���������� � �������� �����';
             end;

      _PE: begin
              ErrorName := 'PE �������� ������ ������';
              Scr ({LightRed, }ErrorName);
           end;

      _OK: begin
              ErrorName := 'ok';
              Scr ({LightGreen, }ErrorName);
           end;

      _PC: begin
              ErrorName := 'PC ��������-������ �����';
              Scr ({Yellow, }ErrorName);
           end;

      _WA: begin
              ErrorName := 'WA �������� �����';
              {TextColor (LightRed); }scr ({LightRed, }ErrorName);
           end;

      else QUIT (_Fail, '����������� ��� ???');
   end;

   if ResultName <> '' then
   begin
      assign (RESFILE, ResultName); {������� ���� � ����������� ��������}
      rewrite (ResFile);
      if IORESULT <> 0 then QUIT (_Fail, '���������� ������� ���� �����������');
      writeln (ResFile, '.Testlib Result Number = ', ord (res));
      writeln (ResFile, '.Result name (optional) = ', ErrorName);
      writeln (ResFile, '.Check Comments = ', msg);
      close (ResFile);
      if IORESULT <> 0 then QUIT (_Fail, '���������� ������� ���� �����������');
   end;

   Scr ({LightGray,} ' ' + msg + ' ');
   writeln(erroutput);

   if Res = _Fail then HALT (6);

   close (inf.f); close (ouf.f); close (ans.f);

   {TextColor (LightGray);}

   if (res = _OK) or (ResultName <> '') then HALT (0);
                                        {else HALT (ord (res));}
   if res=_PE then halt(4);
   if res=_WA then halt(5);
   halt(255);
end;

constructor Instream.init (fname: string; m: TMode);
begin
   name := fname;
   mode := m;
   assign (f, fname);
   {$I-} reset (f);
   if IORESULT <> 0 then
   begin
      if mode = _Output then QUIT (_PE, ' ����������� ���� ' + fname);
              (*          else QUIT (_Fail, '����������� ���� '); *)
       cur := EofChar; {��� ������ ������ - �����}
   end
   else
      if system.eof (f) then cur := EofChar
                        else begin cur := ' '; nextchar end;
   opened := true;

end;

function InStream.curchar: char;
begin
   curchar := cur
end;

function InStream.readchar: char;
begin
   readchar := cur;
   nextchar;
end;

procedure InStream.nextchar;
begin
   if cur = EofChar then {������ �� ������}
   else if system.eof (f) then cur := EofChar
   else begin
      {$I-} read (f, cur);
      if IORESULT <> 0 then Quit (_Fail, '������ ������ ' + name);
   end;
end;

procedure InStream.QUIT (res: TResult; msg: string);
begin
   if mode = _Output then TESTLIB.QUIT (res, msg)
   {������ ��� ������ input ��� answer - ��� ������ -Fail}
   else TESTLIB.QUIT (_Fail, msg + ' (' + name + ')');
end;

function InStream.ReadWord (Before, After: CharSet): string;
var i: integer;
    res: string;
begin
   while cur in Before do nextchar;

(*
   if (cur in After) then
      QUIT (_PE, '������ "' + cur +'" ���������: ����� ��� �����');
*)
   if cur = EofChar then QUIT (_PE, ' ����������� ����� �����');

   res := '';
   i:=0;
   while not ((cur IN AFTER) or (cur = EofChar))  do
   begin
      inc (i);
      if i > 255 then QUIT (_PE, ' ������� ������� ������ �� ������� �����');
      res := res + cur;
      nextchar
   end;
   ReadWord := res
end;


function InStream.ReadInteger: integer;
var res: longint;
begin
   res := ReadLongint;
   if (res < -32768) or (res > 32767) then
     QUIT (_PE, ' ������� ������� ����� (��������� �����)');
   ReadInteger := res
end;


function InStream.ReadReal: real;
var help: string;
    res: real;
    code: integer;
begin
   help := ReadWord (NumberBefore, NumberAfter);
   val (help, res, code);
   if code <> 0 then QUIT (_PE, ' ������ "' + help + '" ��������� ������������');
   ReadReal := res
end;

function InStream.ReadLongint: longint;
var help: string;
    res: longint;
    code: integer;
begin
   help := ReadWord (NumberBefore, NumberAfter);
   val (help, res, code);
   if code <> 0 then QUIT (_PE, ' ������ "' + help + '" ��������� ��. �����');
   ReadLongint := res
end;

procedure InStream.skip (setof: CharSet);
begin
   while (cur in setof) and (cur <> eofchar) do nextchar;
end;

function InStream.seekeof: boolean;
begin
   while (cur in Blanks) do nextchar;
   seekeof := cur = EofChar;
end;

function InStream.eof : boolean;
begin
   eof := cur = EofChar
end;

function InStream.seekEoln: boolean;
begin
  while (cur in [' ', #9]) do nextchar;
  if (cur = #13) or (cur = #10) then begin
    nextchar;
    if (cur = #10) or (cur = #13) then nextchar;
    seekEoln := true;
  end else seekEoln := eof;
end;

function InStream.ReadString: string;
var res: string;
begin
   res := ReadWord ([], [#10,#13]);
   nextchar; {���������� ������ #13}

   if cur = #10 then nextchar; {���� �� ��� ����� #10 => ���������� ���}
   readstring := res
end;

procedure InStream.close;
begin
   if opened then system.close (f)
end;

BEGIN {�������������}
   if (ParamCount <> 3) and (ParamCount <> 4) then
      Quit (_fail, '��������� ������ ����������� � �����������: <INPUT-FILE> <OUTPUT-FILE> <ANSWER-FILE> [<Result_File>]');

   if ParamCount = 4 then ResultName := ParamStr (4)
                     else ResultName := '';

   inf.opened := false;
   ouf.opened := false;
   ans.opened := false;

   inf.init (ParamStr (1), _Input);
   ouf.init (ParamStr (2), _Output);
   ans.init (ParamStr (3), _Answer);
END.
