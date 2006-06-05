{TESTLIB: Библиотека для проверяющих программ}
{Copyright (c) Антон Суханов}

{Версия 1.0 для ejudge}
{ $Id$ }

{Дата последнего изменения: 30/03/97}
{Добавлен новый тип результата: "частично верно" (30/03/97)}
{Функция ReadInteger снова работает}

{$A-,B-,D+,E+,F+,G+,I-,L+,N+,O-,P+,Q-,R+,S+,T-,V+,X+,Y+}
{$M 65520, 0, 0}

 (* Формат запуска тестирующей программы, испольщующей TESTLIB:

    CHECK <Input_File> <Output_File> <Answer_File> [<Result_File>],

    при этом в файл Result_File будут записан результат проверки,
    если он задан.

    Если задан файл с результатом проверки, то вывод на экран не
    производится, а код возврата должен быть нулевым!!!

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
               {_OK - все верно, _PC - частично верно,
                _WA - неверный ответ,
                _PE - формат вывода,
                _Fail - когда все сломается
                _Dirt - для внутреннего использования}

     InStream = object
                    cur: char; {текущий символ, =EofChar, если конец}
                    f: TEXT; {файл}
                    name: string; {Имя файла}
                    mode: TMode;
                    opened: boolean;

                    {Для вутреннего использования}
                    constructor init (fname: string; m: TMode);

                    function CurChar: char; {выдает cur}
                    function ReadChar: char; {выдает cur}
                    procedure NextChar;     {Переходит на след. символ}

                    function seekeof: boolean;
                    function seekEoln: boolean;


                    function eof : boolean;  { == cur = EofChar}

                    {Пропускает символы заданного множества}
                    {Не вырабатывает ошибок}
                    procedure skip (setof: CharSet);

                    {Читаем слово (из символов). Перед словом пропускаются
                     все символы из Before. Признаком конца слова является
                     либо конец файла, либо символ из After. Если ReadWord
                     натыкается на конец файла или слово пустое, то он з
                     авершается с ошибкой _PE}
                    {Если слово состоит более, чем из 255 символов =>
                     выходит с ошибкой _PE}
                    function ReadWord (Before, After: CharSet): string;

                    {Читает целое integer}
                    {При ошибке выходит с _PA}
                    function ReadInteger: integer;

                    {Читает длинное целое}
                    {При ошибке выходит с _PA}
                    function ReadLongint: longint;

                    {Читает вещественное}
                    {При ошибке выходит с _PA}
                    function ReadReal: real;

                    {Читает строку (до символов #13, #10),
                     текущей позицией становится первый символ след. строки}
                    {Если строка состоит более, чем из 255 символов =>
                     выходит с ошибкой _PA}
                    function ReadString: string;

                    {Для внутреннего использования}
                    procedure QUIT (res: TResult; msg: string);
                    procedure close;

                end;


procedure QUIT (res: TResult; msg: string);

var inf, ouf, ans: InStream;
    ResultName: string; {Имя файла для результата}

(* ================================================================= *)
                              implementation
(* ================================================================= *)

{uses crt;}

procedure QUIT (res: TResult; msg: string);
var RESFILE: Text;
    ErrorName: string;

    procedure scr ({color: word; }msg: string);
    begin
       if ResultName = '' then {если не создается файл с рез-том}
       begin
          {TextColor (color);} write (erroutput, msg); {TextColor (LightGray);}
       end;
    end;

begin
   if (res = _OK) then
   begin
      ouf.skip (Blanks);
      if not ouf.eof then QUIT (_Dirt, 'Лишняя информация в выходном файле');
   end;

   case res of
      _Fail: begin {sound (100); delay (30); nosound;}
                   ErrorName := 'Облом';
                   Scr ({LightRed,} ErrorName);
             end;

      _Dirt: begin
                   ErrorName := 'PE Неверный формат вывода';
                   Scr ({LightCyan, }ErrorName);
                   res := _PE;
                   msg := 'Лишняя информация в выходном файле';
             end;

      _PE: begin
              ErrorName := 'PE Неверный формат вывода';
              Scr ({LightRed, }ErrorName);
           end;

      _OK: begin
              ErrorName := 'ok';
              Scr ({LightGreen, }ErrorName);
           end;

      _PC: begin
              ErrorName := 'PC Частично-верный ответ';
              Scr ({Yellow, }ErrorName);
           end;

      _WA: begin
              ErrorName := 'WA Неверный ответ';
              {TextColor (LightRed); }scr ({LightRed, }ErrorName);
           end;

      else QUIT (_Fail, 'Неизвестный код ???');
   end;

   if ResultName <> '' then
   begin
      assign (RESFILE, ResultName); {Создаем файл с результатом проверки}
      rewrite (ResFile);
      if IORESULT <> 0 then QUIT (_Fail, 'Невозможно создать файл результатов');
      writeln (ResFile, '.Testlib Result Number = ', ord (res));
      writeln (ResFile, '.Result name (optional) = ', ErrorName);
      writeln (ResFile, '.Check Comments = ', msg);
      close (ResFile);
      if IORESULT <> 0 then QUIT (_Fail, 'Невозможно создать файл результатов');
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
      if mode = _Output then QUIT (_PE, ' Отсутствует файл ' + fname);
              (*          else QUIT (_Fail, 'Отсутствует файл '); *)
       cur := EofChar; {Для других файлов - можно}
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
   if cur = EofChar then {Ничего не делаем}
   else if system.eof (f) then cur := EofChar
   else begin
      {$I-} read (f, cur);
      if IORESULT <> 0 then Quit (_Fail, 'Ошибка чтения ' + name);
   end;
end;

procedure InStream.QUIT (res: TResult; msg: string);
begin
   if mode = _Output then TESTLIB.QUIT (res, msg)
   {Ошибка при чтении input или answer - это только -Fail}
   else TESTLIB.QUIT (_Fail, msg + ' (' + name + ')');
end;

function InStream.ReadWord (Before, After: CharSet): string;
var i: integer;
    res: string;
begin
   while cur in Before do nextchar;

(*
   if (cur in After) then
      QUIT (_PE, 'Вместо "' + cur +'" Ожидалось: слово или число');
*)
   if cur = EofChar then QUIT (_PE, ' Неожиданный конец файла');

   res := '';
   i:=0;
   while not ((cur IN AFTER) or (cur = EofChar))  do
   begin
      inc (i);
      if i > 255 then QUIT (_PE, ' Слишком длинная строка во входном файле');
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
     QUIT (_PE, ' Слишком большое число (ожидалось целое)');
   ReadInteger := res
end;


function InStream.ReadReal: real;
var help: string;
    res: real;
    code: integer;
begin
   help := ReadWord (NumberBefore, NumberAfter);
   val (help, res, code);
   if code <> 0 then QUIT (_PE, ' Вместо "' + help + '" ожидалось вещественное');
   ReadReal := res
end;

function InStream.ReadLongint: longint;
var help: string;
    res: longint;
    code: integer;
begin
   help := ReadWord (NumberBefore, NumberAfter);
   val (help, res, code);
   if code <> 0 then QUIT (_PE, ' Вместо "' + help + '" ожидалось дл. целое');
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
   nextchar; {Проглотили символ #13}

   if cur = #10 then nextchar; {Если за ним стоит #10 => пропускаем его}
   readstring := res
end;

procedure InStream.close;
begin
   if opened then system.close (f)
end;

BEGIN {ИНИЦИАЛИЗАЦИЯ}
   if (ParamCount <> 3) and (ParamCount <> 4) then
      Quit (_fail, 'Программа должна запускаться с параметрами: <INPUT-FILE> <OUTPUT-FILE> <ANSWER-FILE> [<Result_File>]');

   if ParamCount = 4 then ResultName := ParamStr (4)
                     else ResultName := '';

   inf.opened := false;
   ouf.opened := false;
   ans.opened := false;

   inf.init (ParamStr (1), _Input);
   ouf.init (ParamStr (2), _Output);
   ans.init (ParamStr (3), _Answer);
END.
