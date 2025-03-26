DECLARE SUB CHARTMD (IPList$(), IPCounter%(), Top!, WID!, X!, Y!)
DECLARE SUB QSort (xHitCounter%(), Von%, Bis%, xHighScore$())
DECLARE FUNCTION FindPosition! (StartPosition!, SearchChar$, FirstLogLine$)
DECLARE FUNCTION PleasePressKey! (z!)
DECLARE FUNCTION MemoryDebugInfo! (DebugStepCounter!)
CLS

DebugMessage = 0
StatusOnOff = 0
NoKey = 0 'ask for press key or not  0=ask for "please press a key"
MaxArgs = 6
mLOFIANversion$ = "2.2"
SortAlgo = 0 '0=Quick, 1=Bubble
SortAlgoName$ = "Quicksort"
TopScore = 10
ShowChart = 0

'##### First check if parameters have been passed

IF LEN(COMMAND$) = 0 OR INSTR(COMMAND$, "/?") >= 1 OR INSTR(COMMAND$, "/h") >= 1 THEN
    PRINT "------------------------------------------------"; CHR$(218); CHR$(196); CHR$(196); CHR$(196); CHR$(191); "--"
    PRINT "| mLOFIAN "; mLOFIANversion$; " - mTCP (http) LOg FIle ANalyzer   [- o] |"
    PRINT "-------------------------------------------------"; CHR$(192); CHR$(61); CHR$(217); "---"
    PRINT "(c) 03/2025 by Marco Denecke"
    PRINT " "
    PRINT "For the evaluation of the mTCP httpserv logs"
    PRINT "Top 10 listing of visitor IPs and websites visited"
    PRINT " "
    PRINT " "
    PRINT "No parameters were found!"
    PRINT " "
    PRINT "Usage: mLOFIAN.exe LogFile [optional parameters]"
    PRINT " "
    PRINT "LogFile      - The mTCP httpserv log file to be analyzed (must be specified)"
    PRINT " "
    PRINT "The following optional parameters are all set to 0 (off) by default:"
    PRINT " "
    PRINT "DEBUG=[0|1]  - Messages are displayed during analysis (runtime benchmarks)"
    PRINT "STATUS=[0|1] - A summary of the analysis is also displayed"
    PRINT "NOKEY=[0|1]  - Do not wait for keyboard input. Suitable for batch processing"
    PRINT "SORT=[0|1]   - Choose sort algorithm. Default QuickSort (=0). Bubble (=1)."
    PRINT "TOP=[>=11]   - For a different top score, specify a number >=11 (default=10)"
    PRINT "CHART=[0|1]  - Shows a bar chart of the TOP 10 visitor IPs"
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
FOR i = 1 TO L
    C$ = MID$(Cl$, i, 1)
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
NEXT i

FOR i = 2 TO MaxArgs
    IF Args$(i) = "DEBUG=1" THEN DebugMessage = 1
    IF Args$(i) = "STATUS=1" THEN StatusOnOff = 1
    IF Args$(i) = "NOKEY=1" THEN NoKey = 1
    IF Args$(i) = "SORT=1" THEN SortAlgo = 1
    IF Args$(i) = "CHART=1" THEN ShowChart = 1
    IF INSTR(COMMAND$, "TOP=") >= 1 THEN
        TopPosition = INSTR(COMMAND$, "TOP=") + 4
        TopScore = VAL(MID$(COMMAND$, TopPosition, 2))
    END IF
NEXT i

FileName$ = Args$(1)


'##### Define variables

SelectedHttpStatusCode$ = "200" 'Possible HTTP Return codes: 200,301,304,400,401,403,404,414,500
CounterHttpStatus = 0 'Number of log entries found
MaxLenghtOfLogEntry = 0
YearOfLog$ = "" 'Will be determined next...

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
'##### Is needed, among other things, for the dimensioning of the upcoming arrays

IF DebugMessage = 1 THEN
    PRINT "[Start analysing of log file (count log entries and log file rows)]"
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
    PRINT "[Next, use the analysis data and extract the log entries from file]"
    DebugStepCounter = MemoryDebugInfo(DebugStepCounter)
END IF

'##### Read and check line by line: Year on the left and http Code 200 on the right
'##### If a match is found, read the line and fill variables/arrays

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

        ArrayCounter = ArrayCounter + 1

    END IF

LOOP

'##### Determine the size of the file in bytes
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

DIM IPHighScore(CounterHttpStatus) AS STRING '### * 15
DIM IPHitCounter(CounterHttpStatus) AS INTEGER

FOR H = 1 TO CounterHttpStatus
    AdrHitCounter(H) = 0
    AdrHighScore(H) = " "
    IPHitCounter(H) = 0
    IPHighScore(H) = " "
NEXT H


'#####

IF DebugMessage = 1 THEN
    PRINT "[Based on extracted log entries, search and count Visited sites + Visitor IPs]"
    DebugStepCounter = MemoryDebugInfo(DebugStepCounter)
END IF

Start! = TIMER
'Search and count visited websites

FOR i = 1 TO CounterHttpStatus
    FOR j = 1 TO CounterHttpStatus
        IF VisitedSite(i) = AdrHighScore(j) AND AdrHitCounter(j) >= 1 THEN
            AdrHitCounter(j) = AdrHitCounter(j) + 1
            EXIT FOR
        END IF
        IF AdrHighScore(j) = " " AND AdrHitCounter(j) = 0 THEN
            AdrHighScore(j) = VisitedSite(i)
            AdrHitCounter(j) = AdrHitCounter(j) + 1
            EXIT FOR
        END IF
    NEXT j
NEXT i

'Search and count ip of visitor

FOR i = 1 TO CounterHttpStatus
    FOR j = 1 TO CounterHttpStatus
        IF IPofVisitor(i) = IPHighScore(j) AND IPHitCounter(j) >= 1 THEN
            IPHitCounter(j) = IPHitCounter(j) + 1
            EXIT FOR
        END IF
        IF AdrHighScore(j) = " " AND IPHitCounter(j) = 0 THEN
            IPHighScore(j) = IPofVisitor(i)
            IPHitCounter(j) = IPHitCounter(j) + 1
            EXIT FOR
        END IF
    NEXT j
NEXT i
Finish! = TIMER
Runtime! = Finish! - Start!
RTtotal! = RTtotal! + Runtime!

IF DebugMessage = 1 THEN
    PRINT "Runtime of the step [s]: "; Runtime!
    PRINT " "
END IF

'#####

IF DebugMessage = 1 THEN
    PRINT "[Sort both arrays to get Top 10 - Visited websites and Visitor IPs]"
    DebugStepCounter = MemoryDebugInfo(DebugStepCounter)
END IF

Start! = TIMER
'Sort both arrays (visited websites) and (visitor ip) by hits

IF SortAlgo = 0 THEN
    QSortBis% = ArrayCounter - 1

    QSort AdrHitCounter%(), 1, QSortBis%, AdrHighScore$()
    QSort IPHitCounter%(), 1, QSortBis%, IPHighScore$()
ELSE
    SortAlgoName$ = "Bubblesort"
    FOR count = 1 TO (ArrayCounter - 1)
        FOR counter = 1 TO (ArrayCounter - 1)
            IF AdrHitCounter(counter) < AdrHitCounter(count) THEN
                SWAP AdrHitCounter(count), AdrHitCounter(counter)
                SWAP AdrHighScore(count), AdrHighScore(counter)
            END IF
            IF IPHitCounter(counter) < IPHitCounter(count) THEN
                SWAP IPHitCounter(count), IPHitCounter(counter)
                SWAP IPHighScore(count), IPHighScore(counter)
            END IF
        NEXT counter
    NEXT count
END IF
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
    PRINT "--> TOTAL RUNTIME was : "; RTtotal!; "[s]"; " or"; RTtotal! / 60; "[min] <--"
    PRINT "--> LOG FILE NAME is  : "; FileName$; " | mLOFIAN Version: "; mLOFIANversion$; "  <--"
    PRINT " "
    IF NoKey = 0 THEN WaitForInput = PleasePressKey(z)
    CLS
END IF


'##### Check the content of the array AND ignore the last entry
IF StatusOnOff = 1 THEN
    '    For i = 1 To ArrayCounter - 1
    '    Print DateOfAccess(i); " "; TimeOfAccess(i); " "; IPofVisitor(i); " "; VisitedSite(i); " "; HttpStatus(i)
    '    Next i

    '##### Display the status if desired

    PRINT " "
    PRINT "Analysis data and log file details: "
    PRINT " "
    PRINT "Name of selected log file   :  "; FileName$
    PRINT "Array entries used          : "; ArrayCounter
    PRINT "Log Entries (Http "; SelectedHttpStatusCode$; " hits) : "; CounterHttpStatus
    PRINT "Max lenght of Log Entry     : "; MaxLenghtOfLogEntry
    PRINT "Log file rows total         : "; RowCounter
    PRINT "Size of log file in byte    : "; LogFileSizeInByte
    PRINT "Total duration of analysis  : "; RTtotal!; "[s]"; " or"; RTtotal! / 60; "[min]"
    PRINT "Used sort algorithm         :  "; SortAlgoName$
    PRINT " "
    PRINT "Runtime values: "
    PRINT " "
    PRINT "   - Log rows processed per second               : "; RowCounter / RTtotal!
    PRINT "   - Log entries (Http "; SelectedHttpStatusCode$; ") processed per second : "; CounterHttpStatus / RTtotal!
    PRINT "     - Bytes processed per second [B/s]          : "; LogFileSizeInByte / RTtotal!
    PRINT "     - Kilobytes processed per second [kB/s]     : "; LogFileSizeInByte / RTtotal! / 1024
    PRINT "     - Megabytes processed per second [MB/s]     : "; LogFileSizeInByte / RTtotal! / 1024 / 1204
    PRINT " "
    PRINT "Used mLOFIAN Version was: "; mLOFIANversion$
    PRINT " "
    IF NoKey = 0 THEN WaitForInput = PleasePressKey(z)
    CLS
END IF


'#####

'Output the result of visited websites

IF (ArrayCounter - 1) < 10 THEN
    PRINT "##### TOP "; (ArrayCounter - 1); "most visited websites: (Log File:"; FileName$; ") #####"
    FOR i = 1 TO ArrayCounter - 1
        PRINT AdrHighScore(i); " "; " -> "; AdrHitCounter(i)
    NEXT i
ELSE
    PRINT "##### TOP "; TopScore; "most visited websites: (Log File:"; FileName$; ") #####"
    FOR i = 1 TO TopScore
        PRINT AdrHighScore(i); " "; " -> "; AdrHitCounter(i)
    NEXT i
END IF

'Output the result of visitor IPs

IF (ArrayCounter - 1) < 10 THEN
    PRINT ""
    PRINT "##### TOP "; (ArrayCounter - 1); "visitor IPs: (Log File:"; FileName$; ") #####"
    FOR i = 1 TO ArrayCounter - 1
        PRINT IPHighScore(i); " "; " -> "; IPHitCounter(i)
    NEXT i
ELSE
    PRINT ""
    PRINT "##### TOP "; TopScore; "visitor IPs:  (Log File:"; FileName$; ") #####"
    FOR i = 1 TO TopScore
        PRINT IPHighScore(i); " "; " -> "; IPHitCounter(i)
    NEXT i
END IF

'Output the TOP 10 Chart of the visitor IPs

IF ShowChart = 1 THEN
    IF NoKey = 0 THEN WaitForInput = PleasePressKey(z)
    CLS
    IF (ArrayCounter - 1) < 10 THEN
        CALL CHARTMD(IPHighScore$(), IPHitCounter%(), (ArrayCounter - 1), 54, 0, 2) '54
    ELSE
        CALL CHARTMD(IPHighScore$(), IPHitCounter%(), 10, 54, 0, 2) '54
    END IF

END IF

'#####


END


'#####


'##########

SUB CHARTMD (IPList$(), IPCounter%(), Top, WID, X, Y)
    ' Inspired by
    ' BARDEMO.BAS
    ' by Douglas Park
    ' Copyright (C) 1995 DOS World Magazine
    ' Published in Issue #19, January 1995, page 60

    'IPList$ the labels for the two bars.
    'IPCounter% are numbers (integers) you wish to compare.  The
    '     largest integer allowed by QBasic is 32767.
    'Top = 10 (or less but never more :)
    'WID% is the maximum width of the longer of the two bars.  If you specify a
    '     value larger than 56, CHART reduces it to 56.
    'X% and Y% are the row and column on the screen where the graph will be
    '     displayed.

    DIM BARLENGTH(11) AS INTEGER
    DIM IPBackup(11) AS INTEGER

    FOR i = 1 TO Top
        IPBackup%(i) = IPCounter%(i) 'Saving the original values
    NEXT i

    KEYNUM = IPCounter%(1) 'Save largest number
    IF WID < KEYNUM THEN 'Adjust to fit display
        DO
            KEYNUM = KEYNUM \ 2:
            FOR i = 1 TO Top
                IPCounter%(i) = IPCounter%(i) \ 2
            NEXT i
        LOOP WHILE WID < KEYNUM
    END IF

    FOR i = 1 TO Top
        BARLENGTH(i) = (IPCounter%(i) * (WID / KEYNUM))
    NEXT i

    LoopCount = 2 'The distance between the bars

    PRINT "A bar chart of the TOP"; Top; "visitor IPs:";

    FOR L = 1 TO Top

        TEMPSTRING$ = ""
        LOCATE (Y + LoopCount), (X + 1): PRINT IPList$(L) 'Write the line title
        FOR i = 1 TO BARLENGTH(L) 'Draw the bar
            TEMPSTRING$ = TEMPSTRING$ + CHR$(178)
        NEXT i

        IF BARLENGTH(L) < BARLENGTH(L + 1) THEN
            FOR i = BARLENGTH(L) + 1 TO BARLENGTH(L + 1)
                TEMPSTRING$ = TEMPSTRING$ + " "
            NEXT i
        END IF

        LOCATE (Y + LoopCount), (X + 20): PRINT TEMPSTRING$; IPBackup%(L)
        LoopCount = LoopCount + 2
    NEXT L

END SUB

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
    'Print
    PRINT "Press any key to continue ..."
    'Print
    DO
    LOOP UNTIL INKEY$ <> ""
    PleasePressKey = z
END FUNCTION

SUB QSort (xHitCounter%(), Von%, Bis%, xHighScore$())

    i% = Von%: j% = Bis% '** Save the beginning and the end
    X% = xHitCounter%((i% + j%) \ 2) '** Determine limit value

    DO
        WHILE xHitCounter%(i%) > X%: i% = i% + 1: WEND '** Search from below
        WHILE xHitCounter%(j%) < X%: j% = j% - 1: WEND '** Search from above
        IF i% <= j% THEN
            SWAP xHitCounter%(i%), xHitCounter%(j%) '** Swap elements
            SWAP xHighScore$(i%), xHighScore$(j%) '** Swap elements

            i% = i% + 1
            j% = j% - 1
        END IF
    LOOP UNTIL i% > j%

    IF j% > Von% THEN QSort xHitCounter%(), Von%, j%, xHighScore$() '** sort lower part
    IF i% < Bis% THEN QSort xHitCounter%(), i%, Bis%, xHighScore$() '** sort upper part

END SUB

