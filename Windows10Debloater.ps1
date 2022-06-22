<#
.NOTES
   Author	  : lokurapc
   GitHub	  : https://github.com/lokurapc
   Version 0.0.1
#>

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$ErrorActionPreference = 'SilentlyContinue'
$wshell = New-Object -ComObject Wscript.Shell
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Write-Host "You must start this script as an 'Administrator', please read the readme file for more information."
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

$form                            = New-Object system.Windows.Forms.Form
$form.ClientSize                 = New-Object System.Drawing.Point(270,360)
$form.text                       = "Windows Debloater"
$form.StartPosition              = "CenterScreen"
$form.TopMost                    = $false
$form.FormBorderStyle            = 5

$CheckBox1                       = New-Object system.Windows.Forms.CheckBox
$CheckBox1.text                  = "Create Restore Point"
$CheckBox1.AutoSize              = $false
$CheckBox1.width                 = 280
$CheckBox1.height                = 22
$CheckBox1.location              = New-Object System.Drawing.Point(10,4)
$CheckBox1.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$CheckBox2                       = New-Object system.Windows.Forms.CheckBox
$CheckBox2.text                  = "Run O and O Software"
$CheckBox2.AutoSize              = $false
$CheckBox2.width                 = 280
$CheckBox2.height                = 22
$CheckBox2.location              = New-Object System.Drawing.Point(10,26)
$CheckBox2.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$CheckBox3                       = New-Object system.Windows.Forms.CheckBox
$CheckBox3.text                  = "Disable and Unistall Cortana"
$CheckBox3.AutoSize              = $false
$CheckBox3.width                 = 280
$CheckBox3.height                = 22
$CheckBox3.location              = New-Object System.Drawing.Point(10,48)
$CheckBox3.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$CheckBox4                       = New-Object system.Windows.Forms.CheckBox
$CheckBox4.text                  = "Disable and Unistall OneDrive"
$CheckBox4.AutoSize              = $false
$CheckBox4.width                 = 280
$CheckBox4.height                = 22
$CheckBox4.location              = New-Object System.Drawing.Point(10,70)
$CheckBox4.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$CheckBox5                       = New-Object system.Windows.Forms.CheckBox
$CheckBox5.text                  = "Only Essential Tweaks"
$CheckBox5.AutoSize              = $false
$CheckBox5.width                 = 280
$CheckBox5.height                = 22
$CheckBox5.location              = New-Object System.Drawing.Point(10,92)
$CheckBox5.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$CheckBox6                       = New-Object system.Windows.Forms.CheckBox
$CheckBox6.text                  = "Unpin tiles from Start Menu and TaskBar"
$CheckBox6.AutoSize              = $false
$CheckBox6.width                 = 280
$CheckBox6.height                = 22
$CheckBox6.location              = New-Object System.Drawing.Point(10,114)
$CheckBox6.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$CheckBox7                       = New-Object system.Windows.Forms.CheckBox
$CheckBox7.text                  = "Enable NumLock on Startup"
$CheckBox7.AutoSize              = $false
$CheckBox7.width                 = 280
$CheckBox7.height                = 22
$CheckBox7.location              = New-Object System.Drawing.Point(10,136)
$CheckBox7.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$CheckBox8                       = New-Object system.Windows.Forms.CheckBox
$CheckBox8.text                  = "Disable Power Throttling"
$CheckBox8.AutoSize              = $false
$CheckBox8.width                 = 280
$CheckBox8.height                = 22
$CheckBox8.location              = New-Object System.Drawing.Point(10,158)
$CheckBox8.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$CheckBox9                       = New-Object system.Windows.Forms.CheckBox
$CheckBox9.text                  = "Remove MS Store Apps"
$CheckBox9.AutoSize              = $false
$CheckBox9.width                 = 280
$CheckBox9.height                = 22
$CheckBox9.location              = New-Object System.Drawing.Point(10,180)
$CheckBox9.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Button1                         = New-Object system.Windows.Forms.Button
$Button1.text                    = "Check RECOMMEMD Options"
$Button1.width                   = 260
$Button1.height                  = 30
$Button1.location                = New-Object System.Drawing.Point(5,208)
$Button1.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

$Button2                         = New-Object system.Windows.Forms.Button
$Button2.text                    = "RUN CHECKED OPTIONS"
$Button2.width                   = 260
$Button2.height                  = 30
$Button2.location                = New-Object System.Drawing.Point(5,248)
$Button2.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

$Button3                         = New-Object system.Windows.Forms.Button
$Button3.text                    = "Uncheck ALL"
$Button3.width                   = 260
$Button3.height                  = 24
$Button3.location                = New-Object System.Drawing.Point(5,288)
$Button3.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Button4                         = New-Object system.Windows.Forms.Button
$Button4.text                    = "Revert to Default Windows Options"
$Button4.width                   = 260
$Button4.height                  = 24
$Button4.location                = New-Object System.Drawing.Point(5,322)
$Button4.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Form.controls.AddRange(@($CheckBox1,$CheckBox2,$CheckBox3,$CheckBox4,$CheckBox5,$CheckBox6,$CheckBox7,$CheckBox8,$CheckBox9,$Button1,$Button2,$Button3,$Button4))

#----------------------------------------------
#Generated Event Script Blocks
#----------------------------------------------
#Provide Custom Code for events specified

$Button1.Add_Click({
	$CheckBox1.Checked = $true
	$CheckBox2.Checked = $true
	$CheckBox3.Checked = $true
	$CheckBox4.Checked = $true
	$CheckBox5.Checked = $true
	$CheckBox6.Checked = $true
	$CheckBox7.Checked = $true
	$CheckBox8.Checked = $true
	$CheckBox9.Checked = $true
})

$Button2.Add_Click({
	if ( $CheckBox1.Checked -eq $true ) {
		# Create Restore Point
		Write-Host "Creating Restore Point incase something bad happens. Please wait..."
		Enable-ComputerRestore -Drive "C:\"
		Checkpoint-Computer -Description "Before using Windows Debloater"
	}
	if ( $CheckBox2.Checked -eq $true ) {
		# Run O and O Software"
		Write-Host "Running O&O Shutup with Recommended Settings"
		Import-Module BitsTransfer
		Start-BitsTransfer -Source "https://raw.githubusercontent.com/ChrisTitusTech/win10script/master/ooshutup10.cfg" -Destination ooshutup10.cfg
		Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe
		./OOSU10.exe ooshutup10.cfg /quiet
	}
	if ( $CheckBox3.Checked -eq $true ) {
		# Disable and Unistall Cortana
		Write-Host "Disabling Cortana..."
		$Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
		$Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
		$Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
		if (!(Test-Path $Cortana1)) {
			New-Item $Cortana1
		}
		Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0
		if (!(Test-Path $Cortana2)) {
			New-Item $Cortana2
		}
		Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1
		Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1
		if (!(Test-Path $Cortana3)) {
			New-Item $Cortana3
		}
		Set-ItemProperty $Cortana3 HarvestContacts -Value 0
		Write-Host "Uninstalling Cortana..."
		Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
		Start-Sleep -s 2
		Get-AppxPackage -allusers Microsoft.549981C3F5F10 | Remove-AppxPackage
		Write-Host "Disabled and Uninstall Cortana"
	}
	if ( $CheckBox4.Checked -eq $true ) {
		# Disable and Unistall OneDrive
		Write-Host "Disabling OneDrive..."
		if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
		Write-Host "Uninstalling OneDrive..."
		Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
		Start-Sleep -s 2
		$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
		if (!(Test-Path $onedrive)) {
			$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
		}
		Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
		Start-Sleep -s 2
		Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
		Start-Sleep -s 2
		Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
		if (!(Test-Path "HKCR:")) {
			New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
		}
		Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
		Write-Host "Disabled and Unistall OneDrive"
	}
	if ( $CheckBox5.Checked -eq $true ) {
		# Only Essential Tweaks
		Write-Host "Disabling Activity History..."
 	 	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
 	 	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
 	 	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

 	 	Set-ItemProperty -Path "HKLM:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type Hex -Value 00000000
 	 	Set-ItemProperty -Path "HKLM:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type Hex -Value 00000000
 	 	Set-ItemProperty -Path "HKLM:\System\GameConfigStore" -Name "GameDVR_EFSEFeatureFlags" -Type Hex -Value 00000000
 	 	Set-ItemProperty -Path "HKLM:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 00000000

		Write-Host "Disabling Hibernation..."
		Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
 		if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
			New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
 	 	}
 	 	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0

		Write-Host "Disabling Home Groups services..."
		Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
		Set-Service "HomeGroupListener" -StartupType Manual
		Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
		Set-Service "HomeGroupProvider" -StartupType Manual

		Write-Host "Disabling Location Tracking..."
		if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
			New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
		Write-Host "Disabling automatic Maps updates..."
		Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0

		# Set Services to Manual
		Write-Host "Set Services to Manual..."
		$services = @(
            "ALG"                                          # Application Layer Gateway Service(Provides support for 3rd party protocol plug-ins for Internet Connection Sharing)
            "AJRouter"                                     # Needed for AllJoyn Router Service
            "BcastDVRUserService_48486de"                  # GameDVR and Broadcast is used for Game Recordings and Live Broadcasts
            #"BDESVC"                                      # Bitlocker Drive Encryption Service
            #"BFE"                                         # Base Filtering Engine (Manages Firewall and Internet Protocol security)
            #"BluetoothUserService_48486de"                # Bluetooth user service supports proper functionality of Bluetooth features relevant to each user session.
            #"BrokerInfrastructure"                        # Windows Infrastructure Service (Controls which background tasks can run on the system)
            "Browser"                                      # Let users browse and locate shared resources in neighboring computers
            "BthAvctpSvc"                                  # AVCTP service (needed for Bluetooth Audio Devices or Wireless Headphones)
            "CaptureService_48486de"                       # Optional screen capture functionality for applications that call the Windows.Graphics.Capture API.
            "cbdhsvc_48486de"                              # Clipboard Service
            "diagnosticshub.standardcollector.service"     # Microsoft (R) Diagnostics Hub Standard Collector Service
            "DiagTrack"                                    # Diagnostics Tracking Service
            "dmwappushservice"                             # WAP Push Message Routing Service
            "DPS"                                          # Diagnostic Policy Service (Detects and Troubleshoots Potential Problems)
            "edgeupdate"                                   # Edge Update Service
            "edgeupdatem"                                  # Another Update Service
            "EntAppSvc"                                    # Enterprise Application Management.
            "Fax"                                          # Fax Service
            "fhsvc"                                        # Fax History
            "FontCache"                                    # Windows font cache
            #"FrameServer"                                 # Windows Camera Frame Server (Allows multiple clients to access video frames from camera devices)
            "gupdate"                                      # Google Update
            "gupdatem"                                     # Another Google Update Service
            "iphlpsvc"                                     # ipv6(Most websites use ipv4 instead)
            "lfsvc"                                        # Geolocation Service
            #"LicenseManager"                              # Disable LicenseManager (Windows Store may not work properly)
            "lmhosts"                                      # TCP/IP NetBIOS Helper
            "MapsBroker"                                   # Downloaded Maps Manager
            "MicrosoftEdgeElevationService"                # Another Edge Update Service
            "MSDTC"                                        # Distributed Transaction Coordinator
            "ndu"                                          # Windows Network Data Usage Monitor (Disabling Breaks Task Manager Per-Process Network Monitoring)
            "NetTcpPortSharing"                            # Net.Tcp Port Sharing Service
            "PcaSvc"                                       # Program Compatibility Assistant Service
            "PerfHost"                                     # Remote users and 64-bit processes to query performance.
            "PhoneSvc"                                     # Phone Service(Manages the telephony state on the device)
            #"PNRPsvc"                                     # Peer Name Resolution Protocol (Some peer-to-peer and collaborative applications, such as Remote Assistance, may not function, Discord will still work)
            #"p2psvc"                                      # Peer Name Resolution Protocol(Enables multi-party communication using Peer-to-Peer Grouping.  if disabled, some applications, such as HomeGroup, may not function. Discord will still work)iscord will still work)
            #"p2pimsvc"                                    # Peer Networking Identity Manager (Peer-to-Peer Grouping services may not function, and some applications, such as HomeGroup and Remote Assistance, may not function correctly. Discord will still work)
            "PrintNotify"                                  # Windows printer notifications and extentions
            "QWAVE"                                        # Quality Windows Audio Video Experience (audio and video might sound worse)
            "RemoteAccess"                                 # Routing and Remote Access
            "RemoteRegistry"                               # Remote Registry
            "RetailDemo"                                   # Demo Mode for Store Display
            "RtkBtManServ"                                 # Realtek Bluetooth Device Manager Service
            "SCardSvr"                                     # Windows Smart Card Service
            "seclogon"                                     # Secondary Logon (Disables other credentials only password will work)
            "SEMgrSvc"                                     # Payments and NFC/SE Manager (Manages payments and Near Field Communication (NFC) based secure elements)
            "SharedAccess"                                 # Internet Connection Sharing (ICS)
            #"Spooler"                                     # Printing
            "stisvc"                                       # Windows Image Acquisition (WIA)
            #"StorSvc"                                     # StorSvc (usb external hard drive will not be reconized by windows)
            "SysMain"                                      # Analyses System Usage and Improves Performance
            "TrkWks"                                       # Distributed Link Tracking Client
            #"WbioSrvc"                                    # Windows Biometric Service (required for Fingerprint reader / facial detection)
            "WerSvc"                                       # Windows error reporting
            "wisvc"                                        # Windows Insider program(Windows Insider will not work if Disabled)
            #"WlanSvc"                                     # WLAN AutoConfig
            "WMPNetworkSvc"                                # Windows Media Player Network Sharing Service
            "WpcMonSvc"                                    # Parental Controls
            "WPDBusEnum"                                   # Portable Device Enumerator Service
            "WpnService"                                   # WpnService (Push Notifications may not work)
            #"wscsvc"                                      # Windows Security Center Service
            "WSearch"                                      # Windows Search
            "XblAuthManager"                               # Xbox Live Auth Manager (Disabling Breaks Xbox Live Games)
            "XblGameSave"                                  # Xbox Live Game Save Service (Disabling Breaks Xbox Live Games)
            "XboxNetApiSvc"                                # Xbox Live Networking Service (Disabling Breaks Xbox Live Games)
            "XboxGipSvc"                                   # Xbox Accessory Management Service
            #Hp services
            "HPAppHelperCap"
            "HPDiagsCap"
            "HPNetworkCap"
            "HPSysInfoCap"
            "HpTouchpointAnalyticsService"
            #Hyper-V services
            "HvHost"
            "vmicguestinterface"
            "vmicheartbeat"
            "vmickvpexchange"
            "vmicrdv"
            "vmicshutdown"
            "vmictimesync"
            "vmicvmsession"
            #Services that cannot be disabled
            #"WdNisSvc"
        )

        foreach ($service in $services) {
            # -ErrorAction SilentlyContinue is so it doesn't write an error to stdout if a service doesn't exist

            Write-Host "Setting $service StartupType to Manual"
            Get-Service -Name $service -ErrorAction SilentlyContinue | Set-Service -StartupType Manual
        }

		Write-Host "Disabling Storage Sense..."
        Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue

        Write-Host "Disabling Telemetry..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
        Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
        Write-Host "Disabling Application suggestions..."
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
        if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
        Write-Host "Disabling Feedback..."
        if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Disabling Tailored Experiences..."
        if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
            New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
        Write-Host "Disabling Advertising ID..."
        if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
        Write-Host "Disabling Error reporting..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
        Write-Host "Restricting Windows Update P2P only to local network..."
        if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
        Write-Host "Stopping and disabling Diagnostics Tracking Service..."
        Stop-Service "DiagTrack" -WarningAction SilentlyContinue
        Set-Service "DiagTrack" -StartupType Disabled
        Write-Host "Stopping and disabling WAP Push Service..."
        Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
        Set-Service "dmwappushservice" -StartupType Disabled
        Write-Host "Enabling F8 boot menu options..."
        bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
        Write-Host "Disabling Remote Assistance..."
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
        Write-Host "Stopping and disabling Superfetch service..."
        Stop-Service "SysMain" -WarningAction SilentlyContinue
        Set-Service "SysMain" -StartupType Disabled

        # Task Manager Details
        if ((get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuild).CurrentBuild -lt 22557) {
            Write-Host "Showing task manager details..."
            $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
            Do {
                  Start-Sleep -Milliseconds 100
                $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
            } Until ($preferences)
            Stop-Process $taskmgr
            $preferences.Preferences[28] = 0
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
        } else {Write-Host "Task Manager patch not run in builds 22557+ due to bug"}

        Write-Host "Showing file operations details..."
        if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
        Write-Host "Hiding Task View button..."
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
        Write-Host "Hiding People icon..."
        if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0

        Write-Host "Changing default Explorer view to This PC..."
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

        Write-Host "Hiding 3D Objects icon from This PC..."
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

        # Performance Tweaks and More Telemetry
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 00000000
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0000000a
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0000000a
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Type DWord -Value 2000
		Set-ItemProperty -Path "HKLM:\Control Panel\Desktop" -Name "MenuShowDelay" -Type DWord -Value 0
		Set-ItemProperty -Path "HKLM:\Control Panel\Desktop" -Name "WaitToKillAppTimeout" -Type DWord -Value 5000
		Set-ItemProperty -Path "HKLM:\Control Panel\Desktop" -Name "HungAppTimeout" -Type DWord -Value 4000
		Set-ItemProperty -Path "HKLM:\Control Panel\Desktop" -Name "AutoEndTasks" -Type DWord -Value 1
		Set-ItemProperty -Path "HKLM:\Control Panel\Desktop" -Name "LowLevelHooksTimeout" -Type DWord -Value 00001000
		Set-ItemProperty -Path "HKLM:\Control Panel\Desktop" -Name "WaitToKillServiceTimeout" -Type DWord -Value 00002000
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Type DWord -Value 00000001
		Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\Ndu" -Name "Start" -Type DWord -Value 00000004
		Set-ItemProperty -Path "HKLM:\Control Panel\Mouse" -Name "MouseHoverTime" -Type DWord -Value 00000010

		# Network Tweaks
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20

		# Group svchost.exe processes
		$ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $ram -Force

		Write-Host "Disable News and Interests"
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
		# Remove "News and Interest" from taskbar
		Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2

		# Remove "Meet Now" button from taskbar
		if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
			New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
		}

        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1

        Write-Host "Removing AutoLogger file and restricting directory..."
        $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
        if (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
            Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
        }
        icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null

        Write-Host "Stopping and disabling Diagnostics Tracking Service..."
        Stop-Service "DiagTrack"
        Set-Service "DiagTrack" -StartupType Disabled

        Write-Host "Disabling Wi-Fi Sense..."
        if (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
            New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
		
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings"  -Name "SafeSearchMode" -Type DWord -Value 0
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings"  -Name "IsDeviceSearchHistoryEnabled" -Type DWord -Value 0
	}
	if ( $CheckBox6.Checked -eq $true ) {
		# Unpin tiles from Start Menu and TaskBar...
		Write-Host "Unpinning tiles from Start Menu and TaskBar..."
		
		# https://superuser.com/a/1442733
		#Requires -RunAsAdministrator

$START_MENU_LAYOUT = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6" />
        </StartLayoutCollection>
    </DefaultLayoutOverride>
    <CustomTaskbarLayoutCollection PinListPlacement="Replace">
        <defaultlayout:TaskbarLayout>
            <taskbar:TaskbarPinList>
              <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />
            </taskbar:TaskbarPinList>
        </defaultlayout:TaskbarLayout>
    </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
"@

		$layoutFile="C:\Windows\StartMenuLayout.xml"

		#Delete layout file if it already exists
		If(Test-Path $layoutFile)
		{
			Remove-Item $layoutFile
		}

		#Creates the blank layout file
		$START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

		$regAliases = @("HKLM", "HKCU")

		#Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
		foreach ($regAlias in $regAliases){
			$basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
			$keyPath = $basePath + "\Explorer" 
			IF(!(Test-Path -Path $keyPath)) { 
				New-Item -Path $basePath -Name "Explorer"
			}
			Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
			Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
		}

		#Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
		Stop-Process -name explorer
		Start-Sleep -s 5
		$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
		Start-Sleep -s 5

		#Enable the ability to pin items again by disabling "LockedStartLayout"
		foreach ($regAlias in $regAliases){
			$basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
			$keyPath = $basePath + "\Explorer" 
			Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
		}

		#Restart Explorer and delete the layout file
		Stop-Process -name explorer

		# Uncomment the next line to make clean start menu default for all new users
		#Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\

		Remove-Item $layoutFile
	}
	if ( $CheckBox7.Checked -eq $true ) {
		# Enable NumLock on Startup
		Write-Host "Enabling NumLock after startup..."
		if (!(Test-Path "HKU:")) {
			New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
		}
		Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2
	}
	if ( $CheckBox8.Checked -eq $true ) {
		# Disable Power Throttling
		Write-Host "Disable Power Throttling..."
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Type DWord -Value 00000000
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0000001
	}
	if ( $CheckBox9.Checked -eq $true ) {
		# Remove MS Store Apps
		$Bloatware = @(
		# Unnecessary Windows 10 AppX Apps
		"Microsoft.3DBuilder"
		"Microsoft.Microsoft3DViewer"
		"Microsoft.AppConnector"
		"Microsoft.BingFinance"
		"Microsoft.BingNews"
		"Microsoft.BingSports"
		"Microsoft.BingTranslator"
		"Microsoft.BingWeather"
		"Microsoft.BingFoodAndDrink"
		"Microsoft.BingHealthAndFitness"
		"Microsoft.BingTravel"
		"Microsoft.MinecraftUWP"
		"Microsoft.GamingServices"
		# "Microsoft.WindowsReadingList"
		"Microsoft.GetHelp"
		"Microsoft.Getstarted"
		"Microsoft.Messaging"
		"Microsoft.Microsoft3DViewer"
		"Microsoft.MicrosoftSolitaireCollection"
		"Microsoft.NetworkSpeedTest"
		"Microsoft.News"
		"Microsoft.Office.Lens"
		"Microsoft.Office.Sway"
		"Microsoft.Office.OneNote"
		"Microsoft.OneConnect"
		"Microsoft.People"
		"Microsoft.Print3D"
		"Microsoft.SkypeApp"
		"Microsoft.Wallet"
		"Microsoft.Whiteboard"
		"Microsoft.WindowsAlarms"
		"microsoft.windowscommunicationsapps"
		"Microsoft.WindowsFeedbackHub"
		"Microsoft.WindowsMaps"
		"Microsoft.WindowsPhone"
		"Microsoft.WindowsSoundRecorder"
		"Microsoft.XboxApp"
		"Microsoft.ConnectivityStore"
		"Microsoft.CommsPhone"
		"Microsoft.ScreenSketch"
		"Microsoft.Xbox.TCUI"
		"Microsoft.XboxGameOverlay"
		"Microsoft.XboxGameCallableUI"
		"Microsoft.XboxSpeechToTextOverlay"
		"Microsoft.MixedReality.Portal"
		"Microsoft.XboxIdentityProvider"
		"Microsoft.ZuneMusic"
		"Microsoft.ZuneVideo"
		# "Microsoft.YourPhone"
		"Microsoft.Getstarted"
		"Microsoft.MicrosoftOfficeHub"

		# Sponsored Windows 10 AppX Apps
		# Add sponsored/featured apps to remove in the "*AppName*" format
		"*EclipseManager*"
		"*ActiproSoftwareLLC*"
		"*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
		"*Duolingo-LearnLanguagesforFree*"
		"*PandoraMediaInc*"
		"*CandyCrush*"
		"*BubbleWitch3Saga*"
		"*Wunderlist*"
		"*Flipboard*"
		"*Twitter*"
		"*Facebook*"
		"*Royal Revolt*"
		"*Sway*"
		"*Speed Test*"
		"*Dolby*"
		"*Viber*"
		"*ACGMediaPlayer*"
		"*Netflix*"
		"*OneCalendar*"
		"*LinkedInforWindows*"
		"*HiddenCityMysteryofShadows*"
		"*Hulu*"
		"*HiddenCity*"
		"*AdobePhotoshopExpress*"
		"*HotspotShieldFreeVPN*"

		#Optional: Typically not removed but you can if you need to
		"*Microsoft.Advertising.Xaml*"
		#"*Microsoft.MSPaint*"
		#"*Microsoft.MicrosoftStickyNotes*"
		#"*Microsoft.Windows.Photos*"
		#"*Microsoft.WindowsCalculator*"
		#"*Microsoft.WindowsStore*"
		)
		Write-Host "Removing Bloatware"

			foreach ($Bloat in $Bloatware) {
				Get-AppxPackage -Name $Bloat| Remove-AppxPackage
				Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
				Write-Host "Trying to remove $Bloat."
			}

		Write-Host "Finished Removing Bloatware Apps"
	}
	Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	Write-Host "Finished Checked Options"
})

$Button3.Add_Click({
	$CheckBox1.Checked = $false 
	$CheckBox2.Checked = $false
	$CheckBox3.Checked = $false
	$CheckBox4.Checked = $false
	$CheckBox5.Checked = $false
	$CheckBox6.Checked = $false
	$CheckBox7.Checked = $false
	$CheckBox8.Checked = $false
	$CheckBox9.Checked = $false
})

$Button4.Add_Click({
	# Revert to Default Windows Options
	Write-Host "Creating Restore Point incase something bad happens"
	Enable-ComputerRestore -Drive "C:\"
	Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODifY_SETTINGS"

	Write-Host "Enabling Telemetry..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 1
	Write-Host "Enabling Wi-Fi Sense"
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1
	Write-Host "Enabling Application suggestions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 1
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Recurse -ErrorAction SilentlyContinue
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 0
	Write-Host "Enabling Activity History..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 1
	Write-Host "Enable Location Tracking..."
	if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Recurse -ErrorAction SilentlyContinue
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Allow"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 1
	Write-Host "Enabling automatic Maps updates..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 1
	Write-Host "Enabling Feedback..."
	if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
		Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Recurse -ErrorAction SilentlyContinue
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 0
	Write-Host "Enabling Tailored Experiences..."
	if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		Remove-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Recurse -ErrorAction SilentlyContinue
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 0
	Write-Host "Disabling Advertising ID..."
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Recurse -ErrorAction SilentlyContinue
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 0
	Write-Host "Allow Error reporting..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 0
	Write-Host "Allowing Diagnostics Tracking Service..."
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Manual
	Write-Host "Allowing WAP Push Service..."
	Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-Service "dmwappushservice" -StartupType Manual
	Write-Host "Allowing Home Groups services..."
	Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
	Set-Service "HomeGroupListener" -StartupType Manual
	Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
	Set-Service "HomeGroupProvider" -StartupType Manual
	Write-Host "Enabling Storage Sense..."
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" | Out-Null
	Write-Host "Allowing Superfetch service..."
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Manual
	Write-Host "Setting BIOS time to Local Time instead of UTC..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 0
	Write-Host "Enabling Hibernation..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue

	Write-Host "Hiding file operations details..."
	if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
		Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Recurse -ErrorAction SilentlyContinue
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 0
	Write-Host "Showing Task View button..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 1

	Write-Host "Changing default Explorer view to Quick Access..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

	Write-Host "Unrestricting AutoLogger directory"
	$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
	icacls $autoLoggerDir /grant:r SYSTEM:`(OI`)`(CI`)F | Out-Null

	Write-Host "Enabling and starting Diagnostics Tracking Service"
	Set-Service "DiagTrack" -StartupType Automatic
	Start-Service "DiagTrack"

	Write-Host "Hiding known file extensions"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1

	Write-Host "Reset Local Group Policies to Stock Defaults"
	# cmd /c secedit /configure /cfg %windir%\inf\defltbase.inf /db defltbase.sdb /verbose
	cmd /c RD /S /Q "%WinDir%\System32\GroupPolicyUsers"
	cmd /c RD /S /Q "%WinDir%\System32\GroupPolicy"
	cmd /c gpupdate /force
	# Considered using Invoke-GPUpdate but requires module most people won't have installed

	Write-Output "Adjusting visual effects for appearance..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 1
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 400
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](158,30,7,128,18,0,0,0))
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 1
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 1

	Write-Host "Restoring Clipboard History..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Clipboard" -Name "EnableClipboardHistory" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -ErrorAction SilentlyContinue
	Write-Host "Done - Reverted to Stock Settings"

	Write-Host "Default Windows Options Reverted"
})

[void]$Form.ShowDialog()