# Windows Debloater

[![made-with-powershell](https://img.shields.io/badge/PowerShell-1f425f?logo=Powershell)](https://microsoft.com/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Script/Utility/Application to debloat Windows 10, to remove Windows pre-installed unnecessary applications, stop some telemetry functions, stop Cortana from being used as your Search Index, disable unnecessary scheduled tasks, and more...

## Disclaimer

**WARNING:** I do **NOT** take responsibility for what may happen to your system! Run scripts at your own risk!
Also, other variants of this repo are not technically "new" versions of this, but they are different in their own respective ways. There are some sites saying that other projects are "new" versions of this, but that is inaccurate.

## How To Run the Windows10Debloater.ps1 file

There are different methods of running the PowerShell script. The methods are as follows:

### First Method

1) Download the .zip file on the main page of the GitHub and extract the .zip file to your desired location
2) Once extracted, open [PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-5.1) (or [PowerShell ISE](https://docs.microsoft.com/en-us/powershell/scripting/windows-powershell/ise/introducing-the-windows-powershell-ise?view=powershell-7)) as an Administrator
3) Enable PowerShell execution
<code>Set-ExecutionPolicy Unrestricted -Force</code>
4) On the prompt, change to the directory where you extracted the files:
  e.g. - `cd c:\temp`
5) Next, to run either script, enter in the following:
  e.g. - `.\Windows10Debloater.ps1`
6) Restart your computer

### Second Method

1) Download the .zip file on the main page of the GitHub and extract the .zip file to your desired location
2) Right-click the PowerShell file that you'd like to run and click on "Run With PowerShell"
3) This will allow the script to run without having to do the above steps but Powershell will ask if you're sure you want to run this script.

Remember this script **NEEDS** to be run as admin in order to function properly.