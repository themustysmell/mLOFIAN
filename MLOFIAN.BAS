DECLARE FUNCTION FindPosition! (StartPosition!, SearchChar$, FirstLogLine$)
DECLARE FUNCTION PleasePressKey! (z!)
DECLARE FUNCTION MemoryDebugInfo! (DebugStepCounter!)
CLS

DebugMessage = 0
StatusOnOff = 0
NoKey = 0 'ask for press key or not  0=ask for "please press a key"
MaxArgs = 4

'##### First check if parameters have been passed

IF LEN(COMMAND$) = 0 OR INSTR(COMMAND$, "/?") >= 1 OR INSTR(COMMAND$, "/h") >= 1 THEN
    PRINT "------------------------------------------------"; CHR$(218); CHR$(196); CHR$(196); CHR$(196); CHR$(191); "--";
    PRINT "| mLOFIAN V1.0 - mTCP (http) LOg FIle ANalyzer  [- o] |"
    PRINT "-------------------------------------------------"; CHR$(192); CHR$(61); CHR$(217); "---"
    PRINT " "
    PRINT "Top 10 listing of visitor IPs and websites visited"
    PRINT " "
    PRINT "Written in and tested with QuickBASIC 4.5"
    PRINT "(c) 03/2025 by Marco Denecke"
    PRINT " "
    PRINT " "
    PRINT "No parameters were found!"
    PRINT " "
    PRINT "Usage: mLOFIAN.exe LogFile [optional parameters]"
    PRINT " "
    PRINT "LogFile      - The mTCP log file to be analyzed (must be specified)"
    PRINT " "
    PRINT "The following optional parameters are all set to 0 (off) by default:"
    PRINT " "
    PRINT "DEBUG=[0|1]  - Messages are displayed during analysis (runtime benchmarks)"
    PRINT "STATUS=[0|1] - A summary of the analysis is also displayed"
    PRINT "NOKEY=[0|1]  - Do not wait for keyboard input. Suitable for batch processing"
    PRINT " "
    END
END IF


'##### If parameters were passed, determine which ones they are
'https://www.pcjs.org/documents/books/mspl13/basic/qblang/

CONST TRUEX = -1, FALSEX = 0
NumArgs = 0
In = FALSEX
Cl$ = COMMAND$
L = LEN(Cl$)

' Go through the command line a character at a time.
FOR I = 1 TO L
    C$ = MID$(Cl$, I, 1)
    'Test for character being a blank or a tab.
    IF (C$ <> " " AND C$ <> CHR$(9)) THEN
        ' Neither blank nor tab.
        ' Test to see if you're already
        ' inside an argument.
        IF NOT In THEN
            ' You've found the start of a new argument.
            ' Test for too many arguments.
            IF NumArgs = MaxArgs THEN EXIT FOR
            NumArgs = NumArgs + 1
            In = TRUEX
        END IF
        ' Add the character to the current argument.
        Args$(NumArgs) = Args$(NumArgs) + C$
    ELSE
        ' Found a blank or a tab.
        ' Set "Not in an argument" flag to FALSE.
        In = FALSEX
    END IF
NEXT I

IF Args$(2) = "DEBUG=1" OR Args$(3) = "DEBUG=1" OR Args$(4) = "DEBUG=1" THEN DebugMessage = 1
IF Args$(2) = "STATUS=1" OR Args$(3) = "STATUS=1" OR Args$(4) = "STATUS=1" THEN StatusOnOff = 1
IF Args$(2) = "NOKEY=1" OR Args$(3) = "NOKEY=1" OR Args$(4) = "NOKEY=1" THEN NoKey = 1

FileName$ = Args$(1)


'##### Define variables

SelectedHttpStatusCode$ = "200" 'Possible HTTP Return codes: 200,301,304,400,401,403,404,414,500
CounterHttpStatus = 0 'Number of log entries found
MaxLenghtOfLogEntry = 0
YearOfLog$ = "" 'Will be determined next...

LineCounter = 1
RowCounter = 0
ArrayCounter = 1 'must be 1. else the first visited site is missing
DebugStepCounter = 1
RTtotal! = 0 'The sum of all runtime measurements

IpStartPosition = 24 'Always the same position
IpEndPosition = 1
IpSearchChar$ = ":" 'The colon between IP and TCP port
IpRange = 1

AdrStartPosition = 1
AdrEndPosition = 1
AdrSearchChar1$ = "GET " 'The characters in front of the website being called.
AdrSearchChar2$ = " H" 'The characters behind the website being called.
AdrRange = 1


'##### Read the first line and extract the year

OPEN FileName$ FOR INPUT AS #1
LINE INPUT #1, CurrentLine$
YearOfLog$ = LEFT$(CurrentLine$, 4)
SEEK #1, 1


'##### Number of Http Status hits, Number of characters of the longest log entry

IF DebugMessage = 1 THEN
    PRINT "[Start analysing log file]"
    DebugStepCounter = MemoryDebugInfo(DebugStepCounter)
END IF

Start! = TIMER
DO WHILE NOT EOF(1)
    LINE INPUT #1, CurrentLine$
    RowCounter = RowCounter + 1
    IF LEFT$(CurrentLine$, 4) = YearOfLog$ AND RIGHT$(CurrentLine$, 3) = SelectedHttpStatusCode$ THEN
        CounterHttpStatus = CounterHttpStatus + 1
        TempLenOfString = LEN(CurrentLine$)
        IF TempLenOfString > MaxLenghtOfLogEntry THEN
            MaxLenghtOfLogEntry = TempLenOfString
        END IF
    END IF
LOOP
SEEK #1, 1
Finish! = TIMER
Runtime! = Finish! - Start!
RTtotal! = RTtotal! + Runtime!

IF DebugMessage = 1 THEN
    PRINT "Runtime of the step [s]: "; Runtime!
    PRINT " "
END IF


'##### Define arrays

DIM DateOfAccess(CounterHttpStatus) AS STRING * 10
DIM TimeOfAccess(CounterHttpStatus) AS STRING * 11
DIM IPofVisitor(CounterHttpStatus) AS STRING * 15
DIM VisitedSite(CounterHttpStatus) AS STRING
DIM HttpStatus(CounterHttpStatus) AS STRING * 3


'##### Main program

IF DebugMessage = 1 THEN
    PRINT "[Next, use the analysis data and grep the log entries]"
    DebugStepCounter = MemoryDebugInfo(DebugStepCounter)
END IF

Start! = TIMER
DO WHILE NOT EOF(1)

    LINE INPUT #1, CurrentLine$

    IF LEFT$(CurrentLine$, 4) = YearOfLog$ AND RIGHT$(CurrentLine$, 3) = SelectedHttpStatusCode$ THEN

        HttpStatus(ArrayCounter) = RIGHT$(CurrentLine$, 3)
        DateOfAccess(ArrayCounter) = MID$(CurrentLine$, 1, 10)
        TimeOfAccess(ArrayCounter) = MID$(CurrentLine$, 12, 11)

        IpRange = FindPosition(IpStartPosition, IpSearchChar$, CurrentLine$)
        IPofVisitor(ArrayCounter) = MID$(CurrentLine$, IpStartPosition, IpRange)
        IpEndPosition = IpStartPosition + IpRange

        AdrStartPosition = 4 + IpEndPosition + FindPosition(IpEndPosition, AdrSearchChar1$, CurrentLine$)

        AdrRange = FindPosition(AdrStartPosition, AdrSearchChar2$, CurrentLine$)
        AdrEndPosition = AdrStartPosition + AdrRange
        VisitedSite(ArrayCounter) = MID$(CurrentLine$, AdrStartPosition, AdrRange)

        LineCounter = LineCounter + 1
        ArrayCounter = ArrayCounter + 1

    ELSE
        LineCounter = LineCounter + 1
    END IF

LOOP
LogFileSizeInByte = LOF(1)
CLOSE #1
Finish! = TIMER
Runtime! = Finish! - Start!
RTtotal! = RTtotal! + Runtime!

IF DebugMessage = 1 THEN
    PRINT "Runtime of the step [s]: "; Runtime!
    PRINT " "
END IF


'##### Identify and count the most visited websites and visitor IPs

'Prepare the arrays

DIM AdrHighScore(CounterHttpStatus) AS STRING
DIM AdrHitCounter(CounterHttpStatus) AS INTEGER

DIM IPHighScore(CounterHttpStatus) AS STRING * 15
DIM IPHitCounter(CounterHttpStatus) AS INTEGER

FOR H = 1 TO CounterHttpStatus
    AdrHitCounter(H) = 0
    AdrHighScore(H) = " "
    IPHitCounter(H) = 0
    IPHighScore(H) = " "
NEXT H


'#####

IF DebugMessage = 1 THEN
    PRINT "[From these log entries, search and count Visited sites + Visitor IPs]"
    DebugStepCounter = MemoryDebugInfo(DebugStepCounter)
END IF

Start! = TIMER
'Search and count visited websites

FOR I = 1 TO CounterHttpStatus
    FOR j = 1 TO CounterHttpStatus
        IF VisitedSite(I) = AdrHighScore(j) AND AdrHitCounter(j) >= 1 THEN
            AdrHitCounter(j) = AdrHitCounter(j) + 1
            EXIT FOR
        END IF
        IF AdrHighScore(j) = " " AND AdrHitCounter(j) = 0 THEN
            AdrHighScore(j) = VisitedSite(I)
            AdrHitCounter(j) = AdrHitCounter(j) + 1
            EXIT FOR
        END IF
    NEXT j
NEXT I

'Search and count ip of visitor

FOR I = 1 TO CounterHttpStatus
    FOR j = 1 TO CounterHttpStatus
        IF IPofVisitor(I) = IPHighScore(j) AND IPHitCounter(j) >= 1 THEN
            IPHitCounter(j) = IPHitCounter(j) + 1
            EXIT FOR
        END IF
        IF AdrHighScore(j) = " " AND IPHitCounter(j) = 0 THEN
            IPHighScore(j) = IPofVisitor(I)
            IPHitCounter(j) = IPHitCounter(j) + 1
            EXIT FOR
        END IF
    NEXT j
NEXT I
Finish! = TIMER
Runtime! = Finish! - Start!
RTtotal! = RTtotal! + Runtime!

IF DebugMessage = 1 THEN
    PRINT "Runtime of the step [s]: "; Runtime!
    PRINT " "
END IF

'#####

IF DebugMessage = 1 THEN
    PRINT "[Sort both arrays - Visited websites and Visitor IPs]"
    DebugStepCounter = MemoryDebugInfo(DebugStepCounter)
END IF

Start! = TIMER
'Sort the array visited websites by hits

FOR count = 1 TO (ArrayCounter - 1)
    FOR counter = 1 TO (ArrayCounter - 1)
        IF AdrHitCounter(counter) < AdrHitCounter(count) THEN
            SWAP AdrHitCounter(count), AdrHitCounter(counter)
            SWAP AdrHighScore(count), AdrHighScore(counter)
        END IF
    NEXT counter
NEXT count

'Sort the array visitor ip by hits

FOR count = 1 TO (ArrayCounter - 1)
    FOR counter = 1 TO (ArrayCounter - 1)
        IF IPHitCounter(counter) < IPHitCounter(count) THEN
            SWAP IPHitCounter(count), IPHitCounter(counter)
            SWAP IPHighScore(count), IPHighScore(counter)
        END IF
    NEXT counter
NEXT count
Finish! = TIMER
Runtime! = Finish! - Start!
RTtotal! = RTtotal! + Runtime!

IF DebugMessage = 1 THEN
    PRINT "Runtime of the step [s]: "; Runtime!
    PRINT " "
END IF

IF DebugMessage = 1 THEN
    PRINT "[All done ... The analysis was completed at:]"
    DebugStepCounter = MemoryDebugInfo(DebugStepCounter)
    PRINT "--> TOTAL RUNTIME was: "; RTtotal!; "[s]"; " or"; RTtotal! / 60; "[min] <--"
    IF NoKey = 0 THEN WaitForInput = PleasePressKey(z)
    CLS
END IF


'##### Check the content of the array AND ignore the last entry

IF StatusOnOff = 1 THEN
    '    For i = 1 To ArrayCounter - 1
    '    Print DateOfAccess(i); " "; TimeOfAccess(i); " "; IPofVisitor(i); " "; VisitedSite(i); " "; HttpStatus(i)
    '    Next i

    PRINT " "
    PRINT "Analysis data and log file details: "
    PRINT " "
    PRINT "Array entries used         : "; ArrayCounter
    '    Print " "
    PRINT "Number of Http "; SelectedHttpStatusCode$; " hits    : "; CounterHttpStatus
    '    Print " "
    PRINT "Max lenght of Log Entry    : "; MaxLenghtOfLogEntry
    '    Print " "
    PRINT "Log file rows total        : "; RowCounter
    PRINT "Size of log file in byte   : "; LogFileSizeInByte
    PRINT "Total duration of analysis : "; RTtotal!; "[s]"; " or"; RTtotal! / 60; "[min]"
    PRINT " "
    'If DebugMessage = 1 Then
    IF NoKey = 0 THEN WaitForInput = PleasePressKey(z)
END IF


'#####

'Output the result of visited websites

IF (ArrayCounter - 1) < 10 THEN
    PRINT "##### TOP "; (ArrayCounter - 1); "most visited websites: #####"
    FOR I = 1 TO ArrayCounter - 1
        PRINT AdrHighScore(I); " "; " -> "; AdrHitCounter(I)
    NEXT I
ELSE
    PRINT "##### TOP 10 most visited websites: #####"
    FOR I = 1 TO 10
        PRINT AdrHighScore(I); " "; " -> "; AdrHitCounter(I)
    NEXT I
END IF

'Output the result of visitor IPs

IF (ArrayCounter - 1) < 10 THEN
    PRINT ""
    PRINT "##### TOP "; (ArrayCounter - 1); "visitor IPs: #####"
    FOR I = 1 TO ArrayCounter - 1
        PRINT IPHighScore(I); " "; " -> "; IPHitCounter(I)
    NEXT I
ELSE
    PRINT ""
    PRINT "##### TOP 10 visitor IPs: #####"
    FOR I = 1 TO 10
        PRINT IPHighScore(I); " "; " -> "; IPHitCounter(I)
    NEXT I
END IF

'#####


END


'#####

FUNCTION FindPosition (StartPosition, SearchChar$, FirstLogLine$)
    TmpPosition = StartPosition
    PositionCounter = 0
    TestPosition = 0
    DO
        TestPosition = INSTR(TmpPosition, FirstLogLine$, SearchChar$)
        IF TestPosition THEN
            PositionCounter = PositionCounter + 1
            TmpPosition = TmpPosition + 1
        ELSE
            EXIT DO
        END IF
    LOOP

    DebugFindPosition = 0

    IF DebugFindPosition = 1 THEN
        PRINT "Given start position    : "; StartPosition
        PRINT "Actual Tmp position     : "; TmpPosition
        PRINT "Actual position counter : "; PositionCounter
        PRINT "Found end position      : "; StartPosition + PositionCounter - 1
        PRINT "Result grepped          : "; MID$(FirstLogLine$, StartPosition, PositionCounter - 1)
    END IF

    FindPosition = (PositionCounter - 1)
END FUNCTION

FUNCTION MemoryDebugInfo (DebugStepCounter)
    PRINT "Step No. :"; DebugStepCounter; "initiated at "; DATE$; " "; TIME$
    'PRINT "Avail. string space: "; FRE(""); "Unused stack space: "; FRE(-2); "Largest array max: "; FRE(-1)
    MemoryDebugInfo = DebugStepCounter + 1
END FUNCTION

FUNCTION PleasePressKey (z)
    PRINT
    PRINT "Press any key to continue ..."
    PRINT
    DO
    LOOP UNTIL INKEY$ <> ""
    PleasePressKey = z
END FUNCTION

