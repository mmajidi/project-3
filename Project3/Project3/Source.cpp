#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <tlhelp32.h>
#include <time.h>
#include <string>


typedef NTSTATUS (NTAPI *_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
    );

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PROCESS_BASIC_INFORMATION
{
    LONG ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

PVOID GetPebAddress(HANDLE ProcessHandle)
{
    _NtQueryInformationProcess NtQueryInformationProcess =
        (_NtQueryInformationProcess)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    PROCESS_BASIC_INFORMATION pbi;

    NtQueryInformationProcess(ProcessHandle, 0, &pbi, sizeof(pbi), NULL);

    return pbi.PebBaseAddress;
}


	

int main(int argc, char* argv[]) 
{

    HANDLE hSnap;

    PROCESSENTRY32 pe;

	DWORD dwWritten; // number of bytes written to file
	HANDLE hFile;  //for Writefile func


	int pid;
    HANDLE processHandle;
    PVOID pebAddress;
    PVOID rtlUserProcParamsAddress;
    UNICODE_STRING commandLine;
    WCHAR *commandLineContents;
	char aaa[100];
	    time_t now;

	// time

	//struct tm *newtime;
 //       char am_pm[] = "AM";
 //       time_t long_time;

 //       time( &long_time );                /* Get time as long integer. */
 //       newtime = localtime( &long_time ); /* Convert to local time. */

 //       if( newtime->tm_hour > 12 )        /* Set up extension. */
 //               strcpy( am_pm, "PM" );
 //       if( newtime->tm_hour > 12 )        /* Convert from 24-hour */
 //               newtime->tm_hour -= 12;    /*   to 12-hour clock.  */
 //       if( newtime->tm_hour == 0 )        /*Set hour to 12 if midnight. */
 //               newtime->tm_hour = 12;


		if ( argc <= 1 || *argv == NULL  )
		{
			argc =1;
			argv[1] = "a";
printf (" insert to argument");		}
   //time

    hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

    if (hSnap==INVALID_HANDLE_VALUE)

         return 1;


    pe.dwSize=sizeof(pe);

    if (Process32First(hSnap, &pe))

		//time

			        
	




    

	for (int i = 0; i < atoi(argv[1]) ; ++i)
	{

	now = time (0);
	strftime(aaa, 100, "%Y-%m-%d %H %M %S.000", localtime (&now));

	char s1[200]= "D:\\code\\";
	char s2[100]= ".txt";

strcat(s1 , aaa);
strcat(s1 , s2);


	hFile=CreateFile(s1,GENERIC_WRITE,FILE_SHARE_WRITE,0,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);

 while (Process32Next(hSnap,&pe))
 {
          MODULEENTRY32 me;

          HANDLE hMod;

		  pid = pe.th32ProcessID;

          if (pe.th32ProcessID==0)

     continue;


          hMod=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pe.th32ProcessID); 

          if (hMod==INVALID_HANDLE_VALUE) 

     continue;


		  if ((processHandle = OpenProcess(
        PROCESS_QUERY_INFORMATION | /* required for NtQueryInformationProcess */
        PROCESS_VM_READ, /* required for ReadProcessMemory */
        FALSE, pid)) == 0)
    {
        printf("Could not open process!\n");
        return GetLastError();
    }

    pebAddress = GetPebAddress(processHandle);

    /* get the address of ProcessParameters */
    if (!ReadProcessMemory(processHandle, (PCHAR)pebAddress + 0x10,
        &rtlUserProcParamsAddress, sizeof(PVOID), NULL))
    {
        printf("Could not read the address of ProcessParameters!\n");
        return GetLastError();
    }

    /* read the CommandLine UNICODE_STRING structure */
    if (!ReadProcessMemory(processHandle, (PCHAR)rtlUserProcParamsAddress + 0x40,
        &commandLine, sizeof(commandLine), NULL))
    {
        printf("Could not read CommandLine!\n");
        return GetLastError();
    }

    /* allocate memory to hold the command line */
    commandLineContents = (WCHAR *)malloc(commandLine.Length);

    /* read the command line */
    if (!ReadProcessMemory(processHandle, commandLine.Buffer,
        commandLineContents, commandLine.Length, NULL))
    {
        printf("Could not read the command line string!\n");
        return GetLastError();
    }


         me.dwSize = sizeof(me); 

         Module32First(hMod, &me);




		 char buffer[4048]; 
		 memset(buffer, '\0', sizeof(buffer));

		 sprintf_s(buffer, "\n====================\nPID:%6d szmodule:%-15s szExePath:%s ParentPID:%6d CommandLine:%.*S\n",pe.th32ProcessID,me.szModule,me.szExePath, pe.th32ParentProcessID, commandLine.Length / 2, commandLineContents);
		 WriteFile(hFile,buffer,strlen(buffer),&dwWritten,0);



		  
		 CloseHandle(processHandle);
		 free(commandLineContents);
         CloseHandle(hMod); 

		

     }

		 	CloseHandle(hFile);

Sleep (atoi(argv[2]));
		}
     CloseHandle(hSnap);
	
	
     return 0;

}