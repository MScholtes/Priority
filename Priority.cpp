// Kompilieren mit:
// cl Priority.cpp

#define _WIN32_WINNT 0x0601 // Windows 7 und höher
#include <windows.h>
#include <stdio.h>
#include <psapi.h>

// gegen folgende Library linken:
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

// für Microsoft Compiler
#ifdef _MSC_VER
#define strncmpi strnicmp
#endif

// für Borland Compiler
#ifndef NTSTATUS
#define NTSTATUS long
#endif

// 'On Windows Vista, every page of memory has a priority in the range of 0 to 7...'
const DWORD CRITICAL_MEMORY_PRIORITY = 7;
const DWORD HIGH_MEMORY_PRIORITY = 6;
const DWORD NORMAL_MEMORY_PRIORITY = 5;
const DWORD BELOWNORMAL_MEMORY_PRIORITY = 4;
const DWORD LOW_MEMORY_PRIORITY = 3;
const DWORD BELOWLOW_MEMORY_PRIORITY = 2;
const DWORD VERYLOW_MEMORY_PRIORITY = 1;
const DWORD BELOWVERYLOW_MEMORY_PRIORITY = 0;

// I/O Priority	Usage
// 4 - Critical	Memory manager
// 3 - High			Unused
// 2 - Normal		Default priority
// 1 - Low				Default task priority
// 0 - Very low	Background activity
const DWORD CRITICAL_IO_PRIORITY = 4;
const DWORD HIGH_IO_PRIORITY = 3;
const DWORD NORMAL_IO_PRIORITY = 2;
const DWORD LOW_IO_PRIORITY = 1;
const DWORD VERYLOW_IO_PRIORITY = 0;

int SearchProcess(int, char*, DWORD, int, DWORD, DWORD, int);
int privilege(LPTSTR pszPrivilege, BOOL bEnable);
// ermittle Parent-Prozess-ID zu Prozess-ID
DWORD GetParentProcessID(DWORD);
// I/O- und Speicherpriorität ermitteln
int queryPriority(HANDLE, DWORD*, DWORD*);
// I/O- und Speicherpriorität setzen
int setPriority(HANDLE, DWORD, DWORD);

int main(int argc, char* argv[])
{ int rc = 0, iSet = 0, iMode = 0, iInstance = 1;
  DWORD_PTR dwSysMask, dwCPUMask = 0;
  DWORD dwPrioToSet = NORMAL_PRIORITY_CLASS;
  DWORD ProcID = 0;
  char ProcParam[1024] = "";

  if ((argc > 1) && ((stricmp(argv[1], "-?") == 0) || (stricmp(argv[1], "/?") == 0)))
  { printf("Priority.exe                               (c) Markus Scholtes 2002, 2010, 2017\n\n");
    printf("Usage: Priority [<parameter>] [<PID|program>]\n\n");
    printf("Shows (when called without parameters) or changes the CPU, memory and I/O \n");
    printf("priority and CPU affinity of a running process (memory priority can maximally\n");
    printf("be set  to normal, I/O priority to high at most).\n");    
    printf("It is enough to supply a partly process name. Only the first found process is\n");
    printf("processed (see parameter /INSTANCE). If no process ID and no program name is\n");
    printf("supplied, the calling process is processed.\n\n");
		printf("Parameters:\n");
    printf("/INSTANCE:n - n. found process with name part is processed (default: 1.).\n");
    printf("/INSTANCE:ALL - all found processes with name part are processed.\n");
    printf("/LOW /BELOWNORMAL /NORMAL /ABOVENORMAL /HIGH /REALTIME\n");
    printf("                                  - process gets respective priority.\n");
    printf("/ONLYCPU - only CPU priority is set.\n");
    printf("/CPUMASK:n - CPU affinity. Sum of 1=CPU0, 2=CPU1, 4=CPU2, 8=CPU3,... .\n");
    exit(0); }

  // Parameter auswerten
  for (int i = 1; i < argc; i++)
  { if ((argv[i][0] == '/') || (argv[i][0] == '-'))
    { switch (toupper(argv[i][1]))
      { case 'R':
      		if (strncmpi(argv[i]+1, "REALTIME", 8) == 0)
				  { dwPrioToSet = REALTIME_PRIORITY_CLASS;
				    iSet |= 1; }
				  else
				    rc = 1;
				  break;

				case 'H':
					if (strncmpi(argv[i]+1, "HIGH", 4) == 0)
				  { dwPrioToSet = HIGH_PRIORITY_CLASS;
				    iSet |= 1; }
			    else
				    rc = 1;
				  break;

				case 'A':
					if (strncmpi(argv[i]+1, "ABOVENORMAL",11) == 0)
				  { dwPrioToSet = ABOVE_NORMAL_PRIORITY_CLASS;
				    iSet |= 1; }
				  else
				    rc = 1;
				  break;

				case 'N':
					if (strncmpi(argv[i]+1, "NORMAL", 6) == 0)
				  { dwPrioToSet = NORMAL_PRIORITY_CLASS;
				    iSet |= 1; }
				  else
				    rc = 1;
				  break;

				case 'B':
					if (strncmpi(argv[i]+1, "BELOWNORMAL", 11) == 0)
				  { dwPrioToSet = BELOW_NORMAL_PRIORITY_CLASS;
				    iSet |= 1; }
				  else
				    rc = 1;
				  break;

				case 'L':
					if (strncmpi(argv[i]+1, "LOW", 3) == 0)
				  { dwPrioToSet = IDLE_PRIORITY_CLASS;
				    iSet |= 1; }
				  else
				    rc = 1;
				  break;

				case 'O':
					if (strncmpi(argv[i]+1, "ONLYCPU", 7) == 0)
				    iSet |= 4;
			   else
				    rc = 1;
				  break;

				case 'C':
					if (strncmpi(argv[i]+1, "CPUMASK:", 8) == 0)
				  { HANDLE procHandle = GetCurrentProcess();
		        if (!GetProcessAffinityMask(procHandle, &dwCPUMask, &dwSysMask))
				    { fprintf(stderr, "Cannot retrieve CPU count.\n");
				      rc = 2; }
				    else
				    { dwCPUMask = atoi(argv[i] + 9);
				      if (((dwCPUMask | dwSysMask)!=dwSysMask) || (dwCPUMask<1))
				      { fprintf(stderr, "Invalid CPU mask.\n");
				        rc = 2; }
				    }
				    iSet |= 2;
				  }
				  else
				    rc = 1;
				  break;

				case 'I':
					if (strncmpi(argv[i]+1, "INSTANCE:", 9) == 0)
				  { if (strncmpi(argv[i]+10, "ALL", 3) == 0)
				  		iInstance = -1;
				  	else
				  	{
				  		iInstance = atoi(argv[i] + 10);
				    	if (iInstance < 1)
				    	{ fprintf(stderr, "Invalid instance number.\n");
				      	rc = 2;
				    	}
				    }
				  }
				  else
				    rc = 1;
				  break;

				default:
					rc = 1;
				 break;
	    }
    }
    else
    { while (i < argc)
      { if (ProcParam[0] != 0) strcat(ProcParam," ");
        strcat(ProcParam, argv[i]);
        i++; }
    }
  }

  // PID oder Prozessname übergeben?
  for (unsigned int j = 0; (j < strlen(ProcParam)) && (iMode == 0); j++)
  { if ((ProcParam[j] < '0') || (ProcParam[j] > '9')) iMode=1;
  }

  // wenn iMode == 0, dann ProcID
  if (iMode == 0) ProcID=atol(ProcParam);

  if (ProcParam[0] == 0)
  { // ProzessID des aufrufenden Prozesses ermitteln
  	ProcID = GetParentProcessID(GetCurrentProcessId());
  	iMode = 0;
  	if (!rc) printf("Processing calling process...\n");
  }

	if (((iMode == 0) && (iInstance != 1)) || ((iSet & 5) == 4))
  { fprintf(stderr, "Inconsitent parameters.\n");
    return 1; }

  if ((rc) || ((iMode == 0) && (ProcID < 20)))
  { if (rc != 2) fprintf(stderr, "Wrong parameters.\n");
    return 1; }

  if (privilege(SE_DEBUG_NAME, TRUE))
  { fprintf(stderr, "Debug privilege denied.\n");
    exit(1); }

  if (privilege(SE_INC_BASE_PRIORITY_NAME, TRUE))
  { fprintf(stderr, "Privilege to increase base priority denied.\n");
    exit(1); }

  rc = SearchProcess(iMode, ProcParam, ProcID, iSet, dwPrioToSet, dwCPUMask, iInstance);

  privilege(SE_INC_BASE_PRIORITY_NAME, FALSE);
  privilege(SE_DEBUG_NAME, FALSE);
  return rc;
}


// SearchProcess - Suche Prozess mit PID "ProcID" oder Prozessnamenteil "ProzName" (wenn iMode == 1)
int SearchProcess(int iMode, char *ProzName, DWORD ProcID, int iSet, DWORD dwPrior, DWORD dwCPU, int iInstance)
{ DWORD aProcesses[1024], cbNeeded, cProcesses, dwValue;
  char szProcessName[MAX_PATH] = "<unknown>";
  unsigned int i;
  HANDLE hProcess;
  bool bFound = false;
  int iFound = 0;
  int rc = 0;

  // Liste aller laufenden PIDs ermitteln
  if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
  { fprintf(stderr, "Cannot retrieve process list.\n");
    return 1;
  }

  // Anzahl PIDs
  cProcesses = cbNeeded / sizeof(DWORD);

  // Name und PID ausgeben
  for (i = 0; (i < cProcesses) && (!bFound); i++)
  { if (iMode == 1)
    { // Prozess Handle zur PID ermitteln
      hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
      if (hProcess)
      { HMODULE hMod;
        DWORD cbNeeded;

        // Prozessname ermitteln
        if(EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
          GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName));
        if (strncmpi(ProzName, szProcessName, strlen(ProzName)) == 0)
        {
         	iFound++;
         	if ((iFound == iInstance) || (iInstance == -1))
         		bFound = true;
        }
        else
          CloseHandle(hProcess);
      }
    }
    else
      if (ProcID == aProcesses[i])
      { bFound = true;
      	iFound = 1;
        // Prozess Handle zur PID ermitteln
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
        if (hProcess)
        { HMODULE hMod;
          DWORD cbNeeded;

          // Prozessname ermitteln
          if(EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
            GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName));
				}
      }

    if (bFound)
    { if ((iSet & 2) && (dwCPU))
      { if (!SetProcessAffinityMask(hProcess, dwCPU))
        { fprintf(stderr, "Error %d trying to set CPU affinity.\n", GetLastError());
          rc = 1; }
        else
          printf("CPU affinity of %s [%u] set to %d.\n", szProcessName, aProcesses[i], dwCPU);
      }

      if (iSet & 1)
      { if (!SetPriorityClass(hProcess, dwPrior))
        { fprintf(stderr, "Error %d trying to set priority.\n", GetLastError());
          rc = 1; }
        else
        { DWORD dwIOPrio, dwMemPrio;

					printf("Priority of %s [%u] set to CPU ", szProcessName, aProcesses[i]);
          switch (dwPrior)
          { case REALTIME_PRIORITY_CLASS: printf("real time");
          			dwMemPrio = NORMAL_MEMORY_PRIORITY;
          			dwIOPrio = HIGH_IO_PRIORITY;
   			      break;
            case HIGH_PRIORITY_CLASS: printf("high");
          			dwMemPrio = NORMAL_MEMORY_PRIORITY;
          			dwIOPrio = HIGH_IO_PRIORITY;
   			      break;
            case ABOVE_NORMAL_PRIORITY_CLASS: printf("above normal");
          			dwMemPrio = NORMAL_MEMORY_PRIORITY;
          			dwIOPrio = NORMAL_IO_PRIORITY;
   			      break;
            case NORMAL_PRIORITY_CLASS: printf("normal");
          			dwMemPrio = NORMAL_MEMORY_PRIORITY;
          			dwIOPrio = NORMAL_IO_PRIORITY;
   			      break;
            case BELOW_NORMAL_PRIORITY_CLASS: printf("below normal");
          			dwMemPrio = LOW_MEMORY_PRIORITY;
          			dwIOPrio = LOW_IO_PRIORITY;
   			      break;
            case IDLE_PRIORITY_CLASS: printf("low");
          			dwMemPrio = VERYLOW_MEMORY_PRIORITY;
          			dwIOPrio = VERYLOW_IO_PRIORITY;
   			      break;
          }

          if ((iSet & 4) == 0)
          {
	          // Setzen der IO- und Speicherpriorität
	          if (setPriority(hProcess, dwMemPrio, dwIOPrio))
	          { // Fehler beim Setzen der I/O- oder Speicherpriorität
	          	printf(".\n");
	          	rc = 1;
	          }
	          else
	          { // Speicherpriorität
	          	printf(", memory ");
	          	switch (dwMemPrio)
	          	{
								case CRITICAL_MEMORY_PRIORITY: printf("real time (%d)", dwMemPrio);
	     			      break;
								case HIGH_MEMORY_PRIORITY: printf("high (%d)", dwMemPrio);
	     			      break;
								case NORMAL_MEMORY_PRIORITY: printf("normal (%d)", dwMemPrio);
	     			      break;
								case BELOWNORMAL_MEMORY_PRIORITY: printf("below normal (%d)", dwMemPrio);
	     			      break;
								case LOW_MEMORY_PRIORITY: printf("low (%d)", dwMemPrio);
	     			      break;
								case BELOWLOW_MEMORY_PRIORITY: printf("below low (%d)", dwMemPrio);
	     			      break;
								case VERYLOW_MEMORY_PRIORITY: printf("very low (%d)", dwMemPrio);
	     			      break;
								case BELOWVERYLOW_MEMORY_PRIORITY: printf("below very low (%d)", dwMemPrio);
	     			      break;
							}

	          	// I/O-Priorität
	          	printf(", I/O ");
	          	switch (dwIOPrio)
	          	{
								case CRITICAL_IO_PRIORITY: printf("real time (%d)", dwIOPrio);
	     			      break;
								case HIGH_IO_PRIORITY: printf("high (%d)", dwIOPrio);
	     			      break;
								case NORMAL_IO_PRIORITY: printf("normal (%d)", dwIOPrio);
	     			      break;
								case LOW_IO_PRIORITY: printf("low (%d)", dwIOPrio);
	     			      break;
								case VERYLOW_IO_PRIORITY: printf("very low (%d)", dwIOPrio);
	     			      break;
							}
	          printf(".\n");
						}
					}
					else
	          printf(".\n");
        }
      }

      if (iSet == 0)
      { printf("%s [%u]\n", szProcessName, aProcesses[i]);

        dwValue = GetPriorityClass(hProcess);
        if (dwValue == 0)
        { fprintf(stderr, "cannot retrieve priority, Error %d.\n", GetLastError());
          rc = 1; }
        else
        { printf("Priorities: CPU ");
          switch (dwValue)
          { case REALTIME_PRIORITY_CLASS: printf("real time");
   			      break;
            case HIGH_PRIORITY_CLASS: printf("high");
   			      break;
            case ABOVE_NORMAL_PRIORITY_CLASS: printf("above normal");
   			      break;
            case NORMAL_PRIORITY_CLASS: printf("normal");
   			      break;
            case BELOW_NORMAL_PRIORITY_CLASS: printf("below normal");
   			      break;
            case IDLE_PRIORITY_CLASS: printf("low");
   			      break;
          }

          DWORD dwIOPrio, dwMemPrio;
          // Ermitteln der IO- und Speicherpriorität
          if (queryPriority(hProcess, &dwMemPrio, &dwIOPrio))
          { // Fehler beim Ermitteln der IO- oder Speicherpriorität
          	printf("\n");
          	rc = 1;
          }
          else
          { // Speicherpriorität
          	printf(", memory ");
          	switch (dwMemPrio)
          	{
							case CRITICAL_MEMORY_PRIORITY: printf("real time (%d)", dwMemPrio);
     			      break;
							case HIGH_MEMORY_PRIORITY: printf("high (%d)", dwMemPrio);
     			      break;
							case NORMAL_MEMORY_PRIORITY: printf("normal (%d)", dwMemPrio);
     			      break;
							case BELOWNORMAL_MEMORY_PRIORITY: printf("below normal (%d)", dwMemPrio);
     			      break;
							case LOW_MEMORY_PRIORITY: printf("low (%d)", dwMemPrio);
     			      break;
							case BELOWLOW_MEMORY_PRIORITY: printf("below low (%d)", dwMemPrio);
     			      break;
							case VERYLOW_MEMORY_PRIORITY: printf("very low (%d)", dwMemPrio);
     			      break;
							case BELOWVERYLOW_MEMORY_PRIORITY: printf("below very low (%d)", dwMemPrio);
     			      break;
						}

          	// I/O-Priorität
          	printf(", I/O ");
          	switch (dwIOPrio)
          	{
							case CRITICAL_IO_PRIORITY: printf("realtime (%d)", dwIOPrio);
     			      break;
							case HIGH_IO_PRIORITY: printf("high (%d)", dwIOPrio);
     			      break;
							case NORMAL_IO_PRIORITY: printf("normal (%d)", dwIOPrio);
     			      break;
							case LOW_IO_PRIORITY: printf("low (%d)", dwIOPrio);
     			      break;
							case VERYLOW_IO_PRIORITY: printf("very low (%d)", dwIOPrio);
     			      break;
						}
	          printf("\n");
					}
        }

        DWORD_PTR dwCPUMask, dwSysMask;
        if (!GetProcessAffinityMask(hProcess, &dwCPUMask, &dwSysMask))
        { fprintf(stderr, "Cannot retrieve CPU affinity, error %d.\n", GetLastError());
          rc = 1; }
        else
          printf("CPU affinity: %d\n", dwCPUMask);
      }

      CloseHandle(hProcess);
    }
    if (iInstance == -1) bFound = false;
  }

	if (iInstance == -1)
    printf("Found %d process(es) with name part \"%s\".\n", iFound, ProzName);
	else
  {	if (iFound != iInstance)
  	{ if (iMode == 1)
  		{
      	if (iInstance > 1) fprintf(stderr, "%d. instance of ", iInstance);
	      fprintf(stderr, "process with name part \"%s\" not found.\n", ProzName);
  	  }
    	else
      	fprintf(stderr, "Process with ID %d not found.\n", ProcID);
	    return 1;
  	}
  }

  return rc;
}


int privilege(LPTSTR pszPrivilege, BOOL bEnable)
{ HANDLE hToken;
  TOKEN_PRIVILEGES tp;

  // ermittle den Prozess Token
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken))
    return 1;

  // ermittle die luid
  if (!LookupPrivilegeValue(NULL, pszPrivilege, &tp.Privileges[0].Luid))
    return 1;

  tp.PrivilegeCount=1;

  if (bEnable)
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  else
    tp.Privileges[0].Attributes = 0;

  // Privileg für Prozess ermöglichen/sperren
  if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, 0))
    return 1;

  if (!CloseHandle(hToken)) return 1;

  return 0;
}

// ab hier Prozessmanagement zum Ermitteln der Parentprozess-ID (mit NtQueryInformationProcess)
// und zum Setzen der IO- und Speicherpriorität (mit NtSetInformationProcess)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef void (NTAPI *PPS_POST_PROCESS_INIT_ROUTINE) (VOID);

#ifdef _WIN64
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved3[520];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved4[136];
    ULONG SessionId;
} PEB, *PPEB;
#else
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved4[104];
    PVOID Reserved5[52];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
} PEB, *PPEB;
#endif

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
  	PVOID AffinityMask; // in Wintern.l:
  	PVOID BasePriority; //    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID InheritedFromUniqueProcessId; // in Wintern.l: PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0x00,
    ProcessWow64Information = 0x1A,
    ProcessIoPriority = 0x21,
    ProcessPagePriority = 0x27
} PROCESSINFOCLASS;

typedef NTSTATUS (NTAPI *_NtQueryInformationProcess)(
  IN HANDLE ProcessHandle,
  IN PROCESSINFOCLASS ProcessInformationClass,
  OUT PVOID ProcessInformation,
  IN ULONG ProcessInformationLength,
  OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS (NTAPI *_NtSetInformationProcess)(
	IN HANDLE process,
	ULONG infoClass,
	void* data,
	ULONG dataSize
);


// ermittle Parent-Prozess-ID zu Prozess-ID
DWORD GetParentProcessID(DWORD dwId)
{ LONG status;
  DWORD dwParentPID = (DWORD) -1;
  HANDLE hProcess;
  PROCESS_BASIC_INFORMATION pbi;

  // Funktionsadresse von "NtQueryInformationProcess()" dynamisch aus NTDLL.DLL laden
  _NtQueryInformationProcess fncNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandle("ntdll"), "NtQueryInformationProcess");

  // hat geklappt?
  if (!fncNtQueryInformationProcess)
  { // nein -> Fehler
    fprintf(stderr, "Loading of DLL NTDLL.DLL failed.\n");
    return (DWORD)-1;
  }

  // Hole Prozess-Handle
  hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwId);
  if (!hProcess)
  { // Fehler
  	fprintf(stderr, "Error retrieving the process handle.\n");
    return (DWORD)-1;
  }

  // Information über Prozess ermitteln
  status = fncNtQueryInformationProcess(hProcess, ProcessBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

  // Bei Erfolg Prozess-ID des parents lesen
  if (!status) dwParentPID = (DWORD)pbi.InheritedFromUniqueProcessId;
//  if (!status) dwParentPID = (DWORD)pbi.Reserved3;
  else
  	fprintf(stderr, "Error retrieving the ID of the parent process.\n");

  // Handle freigeben
  CloseHandle(hProcess);

  // Prozess-ID zurückgeben
  return dwParentPID;
}


// I/O- und Speicherpriorität ermitteln
int queryPriority(HANDLE hProcess, DWORD* dwMemPrio, DWORD* dwIOPrio)
{ NTSTATUS result;
	ULONG len;

  // Funktionsadresse von "NtQueryInformationProcess()" dynamisch aus NTDLL.DLL laden
  _NtQueryInformationProcess fncNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandle("ntdll"), "NtQueryInformationProcess");

  // hat geklappt?
  if (!fncNtQueryInformationProcess)
  { // nein -> Fehler
    fprintf(stderr, "Loading of DLL NTDLL.DLL failed.\n");
    return -1;
  }
	// Speicherpriorität ermitteln
	result = fncNtQueryInformationProcess(hProcess, ProcessPagePriority, dwMemPrio, sizeof(DWORD), &len);
	if (result != 0 || len != sizeof(DWORD))
	{ fprintf(stderr, "\nError %x retrieving the memory priority.\n", result);
		return -1;
	}

	// I/O-Priorität ermitteln
	result = fncNtQueryInformationProcess(hProcess, ProcessIoPriority, dwIOPrio, sizeof(DWORD), &len);
	if (result != 0 || len != sizeof(DWORD))
	{ fprintf(stderr, "\nError %x retrieving the I/O priority.\n", result);
		return -1;
	}

	return 0;
}

// I/O- und Speicherpriorität setzen
int setPriority(HANDLE hProcess, DWORD dwMemPrio, DWORD dwIOPrio)
{ NTSTATUS result;

  // Funktionsadresse von "NtQueryInformationProcess()" dynamisch aus NTDLL.DLL laden
  _NtSetInformationProcess fncNtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(GetModuleHandle("ntdll"), "NtSetInformationProcess");

  // hat geklappt?
  if (!fncNtSetInformationProcess)
  { // nein -> Fehler
    fprintf(stderr, "Loading of DLL NTDLL.DLL failed.\n");
    return -1;
  }
	// Speicherpriorität ermitteln
	result = fncNtSetInformationProcess(hProcess, ProcessPagePriority, &dwMemPrio, sizeof(DWORD));
	if (result != 0)
	{ fprintf(stderr, "\nError %x setting the memory priority.\n", result);
		return -1;
	}

	// I/O-Priorität ermitteln
	result = fncNtSetInformationProcess(hProcess, ProcessIoPriority, &dwIOPrio, sizeof(DWORD));
	if (result != 0)
	{ fprintf(stderr, "\nError %x setting the I/O priority.\n", result);
		return -1;
	}

	return 0;
}
