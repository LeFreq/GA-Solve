PROGRAM MakeDi;

{PROGRAM:    MakeDi                                                        }
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
{   This simple program will create a customized digram data file that     }
{ may be useful for cryptanalizing using GA-SOLVE (a genetic algorithm     }
{ solver for the cryptanalysis of simple substitution ciphers).  This      }
{ program could be used, for example, to create a digram statistics file   }
{ for use on a foreign language text (although it will only currently      }
{ count the characters 'A' through 'Z'.                                    }


USES Crt;

CONST NumLines=12; {The number of lines of text to show at bottom of screen}


VAR
  InFile,OutFile :text;
  InFN,OutFN     :string[50];
  Di,Digram      :ARRAY['A'..'Z','A'..'Z'] OF integer; {contains digrams #s}
  Total          :longint;
  I,J,LastCh,Ch  :char;

BEGIN
  clrscr;
  writeln('Make Digram file v1.0');
  writeln;
  write('Enter input file name:  '); readln(InFN);
  Assign(InFile,InFN); Reset(InFile);
  write('Enter output file name: '); readln(OutFN); gotoxy(1,6);
  Assign(OutFile,OutFN); Rewrite(OutFile);
  Total:=0;                 {total=# of alphabetic chars in file}
  FOR I:='A'TO'Z' DO
    FOR J:='A'TO'Z' DO Digram[I,J]:=0;  {clear digrams}
  WHILE NOT eof(InFile) DO
    BEGIN
      read(InFile,Ch);
      Ch:=Upcase(Ch);
      IF Ch IN ['A'..'Z'] THEN
	BEGIN
	  Inc(Total);
	  IF Total<=NumLines*80 THEN write(Ch); {display only first lines}
	  IF Total>1 THEN Inc(Digram[LastCh,Ch]);
	  LastCh:=Ch
	END
    END;
  writeln(OutFile,';Digram file created with program MakeDi');
  writeln(OutFile,';Tabulated from the file ',InFN);
  writeln(OutFile,Pred(Total));    {This is the number of digrams counted}
  FOR I:='A'TO'Z' DO
    BEGIN
      FOR J:='A' TO 'Z' DO write(OutFile,Digram[I,J]:6);
      writeln(OutFile)             {next line}
    END;
  close(OutFile); close(InFile);
  writeln;
  writeln('Total alphabetic characters:  ',Total)
END.
