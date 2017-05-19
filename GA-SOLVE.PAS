PROGRAM GAsolve;

{TITLE:      Genetic Algorithm Solver for Simple Substitution Ciphers      }
{            Copyright (c) 1993 Mark Janssen                               }
{                                                                          }
{ This program is free software; you can redistribute it and/or            }
{ modify it under the terms of the GNU General Public License              }
{ as published by the Free Software Foundation; either version 2           }
{ of the License, or (at your option) any later version.                   }
{                                                                          }
{ This program is distributed in the hope that it will be useful,          }
{ but WITHOUT ANY WARRANTY; without even the implied warranty of           }
{ MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            }
{ GNU General Public License for more details.                             }
{                                                                          }
{ For a copy of the GNU General Public License, write to the Free Software }
{ Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,   }
{ USA or view it on the Internet at www.gnu.org.                           }
{                                                                          }
{SOURCE:     Turbo Pascal 6.0                                              }
{                                                                          }
{PROGRAMMER: Mark Janssen                                                  }
{            Pacific Lutheran University                                   }
{            Tacoma, WA 98447                                              }
{            E-mail:  janssema@plu.edu                                     }
{                                                                          }
{COMMENTS:                                                                 }
{                                                                          }
{    The idea of this program, suggested by Dr. Richard Spillman of PLU,   }
{    was to apply a genetic search algorithm to aid in decrypting text     }
{    encoded with a simple substitution cipher.  Implementation ideas were }
{    contributed by Bob Nelson, Martin Kepner, and Mark Janssen.           }
{    For a more detailed description of the process involved, please       }
{    refer to "Use of a Genetic Algorithm in the Cryptanalysis of Simple   }
{    Substition Ciphers," CRYPTOLOGIA, Volume XVII, Number 1 (Jan 1993).   }
{    Character frequency counts taken from:  CIPHER SYSTEMS, Beker, Henry, }
{    New York, Wiley, c1982                                                }
{                                                                          }
{NOTE:  This program has a lot of room for improvement.                    }

USES Crt,Dos;

{$B-,R-}

CONST
  MakeOutputFile=false;      {make this true if data output file is desired}
  UseMonograms=false;         {this true gives more weight to monogram freq}
  DigramFile='DIGRAMS.DAT';            {file that contains the digram table}
  MaxText=10000;                    {maximum alphanumeric character in file}
  MaxGenes=100;                        {maximum number of genes            }
  NumLines=8;           {# lines of text at bottom of screen should be <=10}
  A=65;

TYPE
  CtType  =RECORD
             Lt:char;
             Ct:integer;
             Loc:byte
           END;
  GeneType=RECORD
             Strg:string[26];
             CFit,RFit,AFit:real
           END;
  GenePool=ARRAY[1..MaxGenes] OF GeneType;

VAR
  InFile,OutFile:text;
  FileName,OutFN,S:string[50];
  CF,CF2          :ARRAY['A'..'Z'] OF integer; {CF2: standard char freq dist}
  Gen             :ARRAY[0..1] OF GenePool; {Contains generation to the next}
  FlArr           :ARRAY[1..MaxText] OF char;          {stores incoming text}
  Count           :ARRAY['A'..'Z'] OF CtType;      {letter frequency of text}
  Di,Digram       :ARRAY['A'..'Z','A'..'Z'] OF integer; {contains digrams #s}
  Pm              :real;                            {probability of mutation}
  Hour,Min,Tmp,
  G,I,J,Total     :word;            {G is # of generations, Total=# of chars}
  NumDi           :longint;         {Number of Digrams in sample digram file}
  NumGenes,GenNum :byte;            {NumGenes is the # of genes in gene pool}
  QueenB,ShowBest :boolean;
  Best            :GeneType;                 {contains the current best gene}


PROCEDURE Initialize(VAR Genes:GenePool);

{This procedure will create the initial string population.}

  VAR
    I,J,R: byte;
    Tmp  : string[26];
    TmpCh: char;

  BEGIN
    Tmp:='ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    Best.CFit:=0;                 {clear best}
    Randomize;
    FOR I:=1 TO NumGenes DO       {fill with random characters}
      BEGIN
        FOR J:=26 DOWNTO 2 DO
          BEGIN
            R:=Succ(random(J));
            TmpCh:=Tmp[J];
            Tmp[J]:=Tmp[R];
            Tmp[R]:=TmpCh
          END;
        Genes[I].Strg:=Tmp
      END
  END;

PROCEDURE LoadDigrams;

{Procedure will load the digram table for standard English text.  First}
{number in file is the total number of Digrams, the rest are counts.   }

  VAR
    I,J   :char;

  BEGIN
    FOR I:='A' TO 'Z' DO CF2[I]:=0;
    write('Loading digram file:  ',DigramFile,' ... ');
    assign(InFile,DigramFile); reset(InFile);
    readln(InFile); readln(InFile);     {skip past first two comment lines}
    readln(InFile,NumDi);       {read in total # of chars used in counting}
    FOR I:='A' TO 'Z' DO        {load digram table}
      FOR J:='A' TO 'Z' DO
        BEGIN
          read(InFile,Di[I,J]);
          CF2[I]:=CF2[I]+Di[I,J]
        END;
    writeln('Done.');
    close(InFile)
  END;

PROCEDURE LoadText;

{Loads the user-entered ciphertext file.  Sorts letters in order of  }
{freqency (saved in Count).  Total is global=number of chars in file.}

  VAR
    I,J,
    LastCh,Ch:char;
    NumCh    :longint; {contains total # of characters used for standard CF}
    Temp     :CtType;

  BEGIN
    write('Enter ciphertext file name:  '); readln(FileName);
    Assign(InFile,FileName); Reset(InFile);
    Total:=0; NumCh:=0;             {total=# of alphabetic chars in file}
    FOR I:='A'TO'Z' DO
      BEGIN
        Count[I].Ct:=0; Count[I].Lt:=I;    {clear monograms}
        NumCh:=NumCh+CF2[I];               {count up standard freq chars}
        FOR J:='A'TO'Z' DO Digram[I,J]:=0  {clear digrams}
      END;
    WHILE (NOT eof(InFile)) AND (Total<MaxText) DO
      BEGIN
        read(InFile,Ch);
        Ch:=Upcase(Ch);
        IF Ch IN ['A'..'Z'] THEN
          BEGIN
            Inc(Total);
            FlArr[Total]:=Ch;
            Inc(Count[Ch].Ct);
            IF Total>1 THEN Inc(Digram[LastCh,Ch]);
            LastCh:=Ch
          END
      END;
    FOR I:='Y'DOWNTO'A' DO            {sort letters in decreasing frequency}
      FOR J:='A'TO I DO
        IF Count[J].Ct<Count[Succ(J)].Ct THEN
          BEGIN
            Temp:=Count[Succ(J)];
            Count[Succ(J)]:=Count[J];
            Count[J]:=Temp
          END;
    FOR I:='A'TO'Z' DO
      BEGIN
        Count[Count[I].Lt].Loc:=Succ(ord(I)-A); {pointer for easy decrypt}
        CF[I]:=round(CF2[I]/NumCh*Total);
        FOR J:='A' TO 'Z' DO
          Di[I,J]:=round(Di[I,J]/NumDi*Pred(Total))
      END;
    clrscr;
    write(FileName);
    gotoxy(40,1); writeln('Total alphabetic characters:  ',Total)
  END;

PROCEDURE Decrypt(Strg:string; All:boolean);

{Procedure will display decoded ciphertext using the key in Strg.}

  VAR
    I,Stop:word;

  BEGIN
    IF NOT All AND (Total>NumLines*80) THEN Stop:=NumLines*80
    ELSE Stop:=Total;
    FOR I:=1 TO Stop DO write(Strg[Count[FlArr[I]].Loc])
  END;

FUNCTION Parent(VAR Genes:GenePool):byte; {selects&returns index of a parent}

  VAR
    Rnd:real;
    I  :byte;

  BEGIN
    Rnd:=random; I:=1;                  {Spin the spinner}
    WHILE Rnd>Genes[I].CFit DO Inc(I);  {find which gene spinner landed on}
    Parent:=I
  END;

PROCEDURE Mutate(VAR Gene:GeneType);

{Procedure returns resulting gene after possible mutation.  Probability}
{of mutation determined by Pm.  Mutation swaps two adjacent characters }
{if Fitness is relatively good else it swaps two random positions.     }

  VAR
    TmpCh    :char;
    I,Swap   :byte;
    PoorGene :boolean;

  BEGIN
    PoorGene:=Gene.Rfit<1/NumGenes; {about the bottom half of the genes}
    FOR I:=1 TO 26 DO
      IF random<Pm THEN
        BEGIN
          TmpCh:=Gene.Strg[I];
          IF PoorGene THEN Swap:=Succ(random(26))
          ELSE Swap:=Succ(I MOD 26);
          Gene.Strg[I]:=Gene.Strg[Swap];
          Gene.Strg[Swap]:=TmpCh
        END
  END;

PROCEDURE Fitness(VAR Genes:GenePool);

{Procedure will calculate the fitness value of all strings in current  }
{generation by doing a digram frequency comparison to standard English.}

  VAR
    H,WrstGene:word;
    TmpErr:longint;
    I,J,K:char;
    Err,AbSum,Sum,Sum2:real;
    TmpStr:string[26];
    Change:boolean;

  BEGIN
    Sum:=0; AbSum:=0; WrstGene:=1; Change:=true;
    FOR H:=1 TO NumGenes DO
      BEGIN
        Err:=0; TmpErr:=0;
        TmpStr:=Genes[H].Strg;    {helps repetitive index lookups}
        FOR I:='A'TO'Z' DO              {calculate error}
        BEGIN  {will calculate and sum geometric distances from average case}
            K:=TmpStr[Count[I].Loc];       {take this out of inner loop, too}
            IF UseMonograms 
            THEN TmpErr:=TmpErr+abs(Count[I].Ct-CF[TmpStr[ord(Succ(I))-A]]);
            FOR J:='A' TO 'Z' DO                {a lot of time spent here!}
              TmpErr:=TmpErr+abs(Di[K,TmpStr[Count[J].Loc]]-Digram[I,J])
          END;
        Err:=1-TmpErr/Total/(2+2*ord(UseMonograms)); { /4 if Ch err used,   }
        AbSum:=AbSum+Err;                            { keeps between 0 and 1}
        Genes[H].AFit:=Err;
        Err:=sqr(sqr(sqr(sqr(Err))));   {amplify differences, but should use}
        Sum:=Sum+Err;                   {better algorithm.  Anyone?}
        Genes[H].CFit:=Err;
        IF Err>Best.CFit THEN  {check see if its better}
          BEGIN                {update new best, if so }
            Best:=Genes[H]; Change:=false;
            IF ShowBest THEN
              BEGIN
                gotoxy(1,15); Decrypt(Best.Strg,false);
                gotoxy(1,3)   {return cursor}
              END
          END
        ELSE IF Err<Genes[WrstGene].CFit THEN WrstGene:=H
      END;
    IF MakeOutputFile THEN
      BEGIN
        write(OutFile,Genes[WrstGene].AFit:0:4,',');
        IF QueenB AND Change
        THEN write(OutFile,(AbSum-Genes[WrstGene].Afit+Best.Afit)/NumGenes:0:4)
        ELSE write(OutFile,AbSum/NumGenes:0:4);
        writeln(OutFile,',',Best.AFit:0:4)
      END;
    IF QueenB AND Change THEN
      BEGIN
        Sum:=Sum-Genes[WrstGene].CFit+Best.CFit; {adjust sums for anticipated}
        AbSum:=AbSum-Genes[WrstGene].AFit+Best.AFit;           {    best gene}
        Genes[WrstGene]:=Best  {inject best back in; worst dies}
      END;
    Sum2:=0;
    FOR H:=1 TO NumGenes DO  {convert to fraction of Sum}
      BEGIN
        Genes[H].RFit:=Genes[H].CFit/Sum; {percentage}
        Sum2:=Sum2+Genes[H].RFit;
        Genes[H].CFit:=Sum2;
        IF H<=10 THEN    {show only first 10 strings}
          BEGIN
            write('Key: ',Genes[H].Strg,' ');
            write('RelFit: ',Genes[H].RFit:0:2,'  ');
            writeln('AbsFit: ',Genes[H].AFit:0:2)
          END
      END;
    writeln('Average absolute fitness:  ',AbSum/NumGenes:0:3)
  END;

PROCEDURE Crossover(Par1,Par2:GeneType; VAR Chd1,Chd2:GeneType);

{This procedure performs the crossover operation on two character strings}
{contained in Par1 and Par2.  Chd1 & 2 get best of both Parent's traits. }

  VAR
    I,J:byte;
    Used:SET of char;
    TmpStr:string[26];

  BEGIN
    Mutate(Par1);   Mutate(Par2);   {do mutation}
    Chd1:=Par1; Chd2:=Par2;
    Used:=[]; J:=1; TmpStr:=Chd2.Strg;
    FOR I:=1 TO 26 DO                 {form Child1 from the left}
      IF (Chd1.Strg[I] IN Used) OR (NOT (TmpStr[I] IN Used))
      AND (abs(count[chr(Pred(I)+A)].Ct-CF[Chd1.Strg[I]])>abs(count[chr(Pred(I)+A)].Ct-CF[TmpStr[I]]))
      THEN
        BEGIN
          IF (TmpStr[I] IN Used) THEN {must find an unused character}
            BEGIN
              WHILE TmpStr[J] IN Used DO Inc(J);
              TmpStr[I]:=TmpStr[J]    {put the unused char in position}
            END;
          Used:=Used+[TmpStr[I]];     {update the Used Set}
          Chd1.Strg[I]:=TmpStr[I]
        END
      ELSE Used:=Used+[Chd1.Strg[I]]; {just need update Used character set}
    Used:=[]; J:=26; TmpStr:=Par1.Strg;
    FOR I:=26 DOWNTO 1 DO               {form Child2 from the right}
      IF (Chd2.Strg[I] IN Used) OR (NOT (TmpStr[I] IN Used))
      AND (abs(count[chr(Pred(I)+A)].Ct-CF[Chd2.Strg[I]])>abs(count[chr(Pred(I)+A)].Ct-CF[TmpStr[I]]))
      THEN
        BEGIN
          IF (TmpStr[I] IN Used) THEN
            BEGIN
              WHILE TmpStr[J] IN Used DO Dec(J);
              TmpStr[I]:=TmpStr[J]
            END;
          Used:=Used+[TmpStr[I]];
          Chd2.Strg[I]:=TmpStr[I]
        END
      ELSE Used:=Used+[Chd2.Strg[I]]
  END;

(****************************************************)

BEGIN
  clrscr;
  writeln('Genetic Algorithm Solver for Simple Substitution Ciphers v2.0');
  writeln;
  write('Enter number of generations (<64k):  ');readln(G);
  write('Enter size of gene pool (<=',MaxGenes,'):  ');readln(NumGenes);
  NumGenes:=NumGenes+(NumGenes MOD 2);  {make it an even number}
  write('Enter probability of mutation (0<Pm<1):  '); readln(Pm);
  write('Keep best gene (Queen Bee) thru each generation (Y/n)?  ');
  IF Upcase(readkey)='N' THEN QueenB:=false ELSE QueenB:=true;
  writeln(QueenB);
  write('Show best decryption after each generation (Y/n)?  ');
  IF Upcase(readkey)='N' THEN ShowBest:=false ELSE ShowBest:=true;
  writeln(ShowBest);

  Initialize(Gen[0]);              {initial gene pool}
  LoadDigrams;             {load digram table into Di}
  LoadText;       {load desired ciphertext into FlArr}
  IF NumGenes>10 THEN BEGIN gotoxy(62,3); write('First 10 keys...') END;
  IF MakeOutputFile THEN
    BEGIN
      GetTime(Hour,Min,Tmp,Tmp);
      Str(Hour,S); IF length(S)=1 THEN S:='0'+S; OutFN:='OUT'+S;
      Str(Min,S);  IF length(S)=1 THEN S:='0'+S; OutFN:=OutFN+S+'.DAT';
      Assign(OutFile,OutFN); Rewrite(OutFile);
      write(OutFile,FileName,',',DigramFile,',Genes=',NumGenes);
      writeln(OutFile,',PM=',Pm:0:3,',QB=',QueenB,',Generations=',G);
      write(OutFile,'  0,')      {first generation is special case}
    END;
  gotoxy(1,3); Fitness(Gen[0]);  {calculate initial fitness values}

  FOR I:=0 TO Pred(G) DO         {Do the generations}
    BEGIN
      GenNum:=I MOD 2;
      gotoxy(1,2); write('Generation: ',I);
      gotoxy(40,2);   writeln('Current Best:  ',Best.AFit:0:4);
      IF MakeOutputFile THEN write(OutFile,Succ(I):3,',');
      FOR J:=0 TO Pred(NumGenes DIV 2) DO
        CrossOver(Gen[GenNum,Parent(Gen[GenNum])],
                  Gen[GenNum,Parent(Gen[GenNum])],
                  Gen[1-GenNum,Succ(J*2)],
                  Gen[1-GenNum,J*2+2]);
      Fitness(Gen[1-GenNum])       {calc fitness values}
    END;

  IF MakeOutputFile THEN Close(OutFile);

  clrscr;
  writeln('Resulting gene pool after ',G,' generations, Pm=',Pm:4:3,', QueenB=',QueenB,':');
  FOR I:=1 TO NumGenes DO
    writeln(Gen[1-GenNum,I].Strg,'  Fit: ',Gen[1-GenNum,I].AFit:0:4);
  writeln; write('Original text: ');
  FOR I:=0 TO 25 DO write(Count[chr(I+A)].Lt);
  writeln; writeln('Overall best:  ',Best.Strg,' Fitness:  ',Best.AFit:0:4);
  writeln; write('Press ENTER for final decryption...'); readln;
  writeln; Decrypt(Best.Strg,true);
END.
