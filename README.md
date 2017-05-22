# Priority
C++ command line utility to query or set CPU, memory and I/O priority (Windows)

<b>How To Compile</b>
- Start Visual Studio command prompt
- Change to directory with Priority.cpp
- compile with
    cl Priority.cpp  

<b>Usage</b>

Priority [<parameter>] [<PID|program>]

Shows (when called without parameters) or changes the CPU, memory and I/O priority and CPU affinity of a running process (memory priority can maximally be set  to normal, I/O priority to high at most).
It is enough to supply a partly process name. 
Only the first found process is processed (see parameter /INSTANCE). 
If no process ID and no program name is supplied, the calling process is processed.

Parameters:
/INSTANCE:n - n. found process with name part is processed (default: 1.).
/INSTANCE:ALL - all found processes with name part are processed.
/LOW /BELOWNORMAL /NORMAL /ABOVENORMAL /HIGH /REALTIME - process gets respective priority./ONLYCPU - only CPU priority is set.
/CPUMASK:n - CPU affinity. Sum of 1=CPU0, 2=CPU1, 4=CPU2, 8=CPU3,... .

<b>Remarks</b>

Since Priority.exe cannot retrieve the process names of 64 bit executables in an WOW64 environment, compile Priority.exe as a 64 bit executable for a 64 bit OS and as a 32 bit executable for a 32 bit OS.
