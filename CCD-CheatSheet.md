*These notes will come handy in exam.*

# Perimeter Defense - Email Security

## Email Spoofing

### SPF - Sender Policy Framework

Check the SPF records of the domain name by checking its DNS TXT records,

```bash
dig <domain> TXT | grep spf
```

#### Mechanisms

Mechanisms display the IP being matched and prefixed with Qualifiers that state what action should be taken if that mechanism (i.e., IP address) is matched. 

| **Mechanism** |        **Example SPF Record**        |                                      **Explanation**                                      |
|:-------------:|:------------------------------------:|:-----------------------------------------------------------------------------------------:|
|      ip4      |     `v=spf1 ip4:10.0.0.1/24`     |                    Authorized server IPs are in the 10.0.0.1/24 range                     |
|       a       |      `v=spf1 a:example.com`      |            Authorized servers' IPs are in the DNS **A** record of example.com             |
|      mx       |     `v=spf1 mx:example.com`      | Authorized servers IPs are the IPs of the servers in the DNS **MX** record of example.com |
|    include    | `v=spf1 include:_spf.domain.com` |  Authorized servers' IPs are in another SPF/TXT record (`_spf.domain.com` in that case)   |
|      all      |           `v=spf1 all`           |                           Authorized servers' IPs match any IP.                           |

#### Qualifiers

Each of the above mechanisms should be prefixed with a qualifier to state the action upon matching the provided IP. 

| **Qualifier** |    **Example SPF Record**     |                             **Explanation**                             |                                  **Action**                                  |
|:-------------:|:-----------------------------:|:-----------------------------------------------------------------------:|:----------------------------------------------------------------------------:|
|   + (pass)    | `v=spf1 +ip4:10.0.0.1/24` |   Pass SPF check If the sender server IP is in the 10.0.0.1/24 range    |              Accept the message (This is an authentic message)               |
|   - (fail)    | `v=spf1 -ip4:10.0.0.1/24` |   Fail SPF check If the sender server IP is in the 10.0.0.1/24 range    |                Reject the message (This is a spoofed message)                |
| ~ (softfail)  | `v=spf1 ~ip4:10.0.0.1/24` | SoftFail SPF checks If the sender server IP is in the 10.0.0.1/24 range | Accept the message but flag it as spam or junk (probably a spoofed message). |
|? (neutral)|`v=spf1 ?ip4:10.0.0.1/24`|Neither pass nor fail If the sender server IP is in the 10.0.0.1/24 range|Accept the message (Not sure whether this is a spoofed or authentic message)|

### DKIM - DomainKeys Identified Mail

DKIM records have a standard format of 

```md
<selector>._domainkey.<domain>.
```

For example, the DKIM public key for cyberdefenders.org is published at  

```md
google._domainkey.cyberdefenders.org
```

and can be queried using  

```bash
dig google._domainkey.cyberdefenders.org TXT | grep DKIM
```

### DMARC - Domain-based Message Authentication, Reporting & Conformance

DMARC records are published as TXT records in the DNS server, just like DKIM and SPF. To check the DMARC record for a domain, we query the DNS server for `_dmarc.<domain>`,

```bash
dig _dmarc.nsa.gov TXT | grep dmarc
```

#### DMARC Record Creation

##### Monitor Mode

To start monitoring and collecting all sending servers, we only need to create a DMARC record with the policy set to **none** and publish it in the DNS server, 

```md
v=DMARC1; p=none; rua=mailto:dmarc-inbox@yourdomain.com
```

##### Receiving Mode

The receiving server/report generators will have to verify that the service provider is waiting for your reports to come by querying the DMARC record at,

```bash
dig <your-company.com>._report._dmarc.<service-provider.com> | grep dmarc
```

---

## Analyzing Artifacts

1. **Visualization Tools** - [URL2PNG](https://www.url2png.com/), [URLScan](https://urlscan.io/), [AbuseIPDB](https://www.abuseipdb.com/), [Criminalip.io](https://www.criminalip.io/en), [ThreatBook.io](https://threatbook.io/), [IPQuality Score](https://www.ipqualityscore.com/), 
2. **URL Reputation Tools** - [VirusTotal](https://www.virustotal.com/gui/), [URLScan](https://urlscan.io/), [URLhaus](https://urlhaus.abuse.ch/), [WannaBrowser](https://www.wannabrowser.net/)
3. **File Reputation Tools** - [VirusTotal](https://www.virustotal.com/gui/), [Talos File Reputation](https://www.talosintelligence.com/talos_file_reputation)
4. **Malware Sandboxing** - [Hybrid Analysis](https://www.hybrid-analysis.com/), [Any.run](https://any.run/), [VirusTotal](https://www.virustotal.com/), [Joe Sandbox](https://www.joesandbox.com/), [Tri.ge](https://tria.ge/).

---
---

# Digital Forensics

## Acquisition

### Memory Acquisition

#### Linux

Determine the kernel version on a Linux machine, you can use the command 

```bash
uname -a
```

Download [LiME](https://github.com/504ensicsLabs/LiME),

```bash
sudo apt update && sudo apt install build-essential git
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src/
make
```

Capture memory using LiME,

```bash
sudo insmod ./lime.ko "path=/home/user/Desktop/dump.mem format=lime timout=0" 
```

#### Windows

We can use various tools like [FTK Imager](https://www.exterro.com/ftk-imager), [Belkasoft](https://belkasoft.com/ram-capturer), [DumpIt](http://www.toolwar.com/2014/01/dumpit-memory-dump-tools.html).

### Checking Disk Encryption

Use a command line tool called "[Encrypted Disk Detector](https://www.magnetforensics.com/resources/encrypted-disk-detector/),"  to detect encrypted drives. 

```powershell
.\EDDv310.exe
```

### Triage Image Acquisition

1. Obtaining Triage Image with [KAPE](https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape) is convenient. 
2. Another tool [CyLR](https://github.com/orlikoski/CyLR), which can acquire triage images on Windows, Linux, and OSX systems. It comes with a list of essential artifacts to collect from each system.

### Disk Acquisition

#### Windows

Using [FTK Imager](https://www.exterro.com/ftk-imager), Disk Images can be acquired. 

#### Linux

**Note: Do not run `dd` on the host system; run it from an external drive and save the output image to the same drive.**

First, determine all mounted disks, and we will specifically choose one of them to image,

```bash
df -h
```

Now, proceed to the acquisition,

```bash
sudo dd if=/dev/sb1 of=/home/user/Desktop/file.img bs=512
```

### Mounting

To mount different image types, use [Arsenal Image Mounter](https://arsenalrecon.com/), [FTK Imager](https://www.exterro.com/ftk-imager).

---

## Windows Disk Forensics

### Windows Event Logs

By default, Windows Event Logs are stored at '`C:\Windows\system32\winevt\logs`' as **.evtx** files.

We can use [Event log explorer](https://eventlogxp.com/) or [Full Event Log view](https://www.nirsoft.net/utils/full_event_log_view.html).

### Artifacts

By default, Windows Event Logs are stored at '`C:\Windows\system32\winevt\logs`' as **.evtx** files.

#### Important Artifacts

|**Live System**|**Dead System**|**Investigation Tool**|
|:---:|:---:|:---:|
|HKEY_LOCAL_MACHINE/SYSTEM|`C:\Windows\System32\config\SYSTEM`|Registry Explorer/RegRipper|
|HKEY_LOCAL_MACHINE/SOFTWARE|`C:\Windows\System32\config\SOFTWARE`|Registry Explorer/RegRipper|
|HKEY_USERS|`C:\Windows\System32\config\SAM`|Registry Explorer/RegRipper|
|HKEY_CURRENT_USER|`C:\Users\<USER>\NTUSER.dat`<br>`C:\Users\<user>\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat`|Registry Explorer/RegRipper|
|Amcache.hve|`C:\Windows\appcompat\Programs\Amcache.hve`|Registry Explorer/RegRipper|
|Event Viewer -> Windows Logs -> SECURITY|`C:\Windows\winevt\Logs\Security.evtx`|Event logs Explorer|
|Event Viewer -> Windows Logs -> SYSTEM|`C:\Windows\winevt\Logs\SYSTEM.evtx`|Event logs Explorer|
|Event Viewer -> Windows Logs -> Application|`C:\Windows\winevt\Logs\Application.evtx`|Event logs Explorer|
|Event viewer -> Applications & service logs -> Microsoft -> Windows -> TaskScheduler -> Operational|`Microsoft-Windows-TaskScheduler%4Operational.evtx`|Event logs Explorer|

#### System Information

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|Windows version and installation date|`SOFTWARE\Microsoft\Windows NT\CurrentVersion`|Registry Explorer/RegRipper|
|Computer Name|`SYSTEM\ControlSet001\Control\ComputerName\ComputerName`|Registry Explorer/RegRipper|
|Timezone|`SYSTEM\ControlSet001\Control\TimeZoneInformation`|Registry Explorer/RegRipper|
|Last Shutdown Time|`SYSTEM\ControlSet001\Control\Windows`|Registry Explorer/RegRipper|

#### Network Information

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|Identify physical cards|`SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards`|Registry Explorer/RegRipper|
|Identify interface configuration (IP address, DHCP Server, DHCP Name Server)|`SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces`|Registry Explorer/RegRipper|
|Connections History (Interfaces lastWrite, lastConnected, dateCreated, DefaultGatewayMac, Type) |`SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` `Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx`<br>`Microsoft-Windows-Sysmon%4Operational.evtx` (Useful to find C2 channel IP address, 3 -> Network connection detected)|WifiHistoryView/Registry Explorer/Event Log Explorer|

#### Users Information

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|Username, creation date ,login date, SID|SAM|Registry Explorer/RegRipper|
|Login, logout, deletion, creation|Security.evtx|Event Log Explorer|
||4624 -> Successful logon event, it shows you the Workstation Name AKA hostname and source network/ip address|Sometimes sysmon event id 1 can find for commands performing network logon|
||4625 -> failed logon event|
||4634 -> Session terminated|
||4647 -> User initiated logoff|
||4672 -> Special privilege logon|
||4648 -> User run program as another user (Runas administrator)|
||4720/4726 -> Account creation/deletion|

#### File Activities - What happened?

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|File name, path, timestamps, actions (i.e rename)|`$MFT, $LogFile, $UsnJrnl:$J` ($J can sometimes be found in $Extend directory)|NTFS Log Tracker|
|Original File name before rename|`Microsoft-Windows-Sysmon%4Operational.evtx` OriginalFileName value|Event Log Explorer|
|Information about deleted files|`$I30`|INDXRipper|

#### File Activities - Who did it?

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|File Creation/Deletion/Command Execution (e.g. whoami, ping)|`Microsoft-Windows-Sysmon%4Operational.evtx`|Event Log Explorer|
||11 -> File created||
||23 -> File Deleted||
|Failed/Succesful object access|Security.evtx|Event Log Explorer|
||4104 -> Scriptblock logging (Logs PowerShell script code when being executed even if it is obfuscated)|Microsoft-Windows-PowerShell%4Operational.evtx has the same event id|
||4656 -> User tried to access an object||
||4660 -> object was deleted||
||4663 -> User accessed the object successfully||
||4658 -> the user closed the opened object (file)||
||5140 -> A Network Share Object Was Accessed||
|Recently used files/folders (may contain files/folders and websites/URLs visited)|NTUSER.dat|Registry Explorer/RegRipper|
||`Software\Microsoft\Office\15.0<Office application>\File MRU`||
||`Software\Microsoft\Office\15.0<Office application>\Place MRU`||
||`Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*`||
||`Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`||
||`Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`|Check event id 13 and filter `RunMRU` for any PowerShell command via Run|
||`Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`||
|Accessed Local/Network folders|ShellBags|ShellBags Explorer|
||NTUSER.dat||
||USRCLASS.dat||
|Accessed Local/Network share files, Startup folder, its path, metadata, timestamps, drive letter|LNK files|LECmd|
||`C:\Users<User>\Appdata\Roaming\Microsoft\Windows\Recent`||
||`C:\Users<User>\Desktop`||
||`C:\Users<User>\AppData\Roaming\Microsoft\Office\Recent\`||
|Frequently accessed files|JumpLists|JumpLists Explorer|
||`C:\Users<User>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`||
||`C:\Users<User>\AppData\Roaming\Microsoft\ Windows\Recent\CustomDestinations`||
|Recover Deleted Files from Recycle Bin|`INFO2/$I`|RBCmd|

#### Connected Devices

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|Vendor ID, Product ID, Serial Number, Device name|`SYSTEM\ControlSet001\Enum\USB`|Registry Explorer/RegRipper|
|Serial Number, First connection time, last connection time, last removal time|`SYSTEM\ControlSet001\USBSTOR`|Registry Explorer/RegRipper|
|USB Label|`SYSTEM\ControlSet001\Enum\SWD\WPDBUSENUM`|Registry Explorer/RegRipper|
|GUID, TYPE, serial number|`SYSTEM\ControlSet001\Control\DeviceClasses`|Registry Explorer/RegRipper|
|VolumeGUID, Volume letter, serial number|`SYSTEM\MountedDevices` (Can also be used to find out USB is mounted to which drive) `SOFTWARE\Microsoft\Windows Portable Devices\Devices` `SOFTWARE\Microsoft\Windows Search\VolumeInfoCache`|Registry Explorer/RegRipper|
|Serial number, first connection time|`setupapi.dev.log`|notepad++|
|Serial number, connections times, drive letter|**SYSTEM.evtx**: 20001 -> a new device is installed|Event Log Explorer|
||**Security.evtx**: 6416 -> new externel device recognized||
||Microsoft-Windows-Ntfs%4Operational.evtx||
|Automation|Registry|USBDeviceForenics (When selecting the input folder, make sure it is C:\Windows\System32\config for Registry-WPDBUSENUM OR Registry-USBSTOR etc.. tabs to be populated. When selecting the input folder, make sure it is C:\Windows\System32\winevt\logs for Win 10 Event Log tab to be populated), USBDetective|
||Event Logs||
||setupapi.dev.log||

#### Execution Activities

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|Windows Services executable, [start type](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree), date added|`SYSTEM\CurrentControlSet\Services`|Registry Explorer/RegRipper|
|Service installation time, Service crashed, stop/start service event|**Security.evtx**: 4697 -> service gets installed|Event Log Explorer|
||**SYSTEM.evtx**: 7034 -> Service crashed||
||7035 -> start/stop requests||
||7036 -> service stoppped/started||
||7045 -> New service was installed (Can be used to check for malicious services started)||
|Autorun applications/Registry-based persistence|`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`|Registry Explorer/RegRipper|
||`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`||
||`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`||
||`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`||
||`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`||
||`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`||
|Frequently run programs, last time, number of execution|UserAssist|UserAssist by Didier Steven|
||`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` (Registry keys ending with EA is executable files and 9F is shortcuts. Clicking onto either of those keys will show the user frequency of running various executables/shortcuts, last run time etc. Focus Time values are in milliseconds, this time is determined based on how long the user is active on that process)||
|Run of older applications on newer system|`SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache` (Only able to view applications details with compatibility mode (properties) turned on.)|ShimCache Parser|
|Files path, md5 & sha1 hash|`Amcache.hve`|Amcache Parser|
|Background applications|`BAM & DAM`|Registry Explorer/RegRipper|
||`SYSTEM\ControlSet001\Services\bam\State\UserSettings`||
|Filename, size, run count, each run timestamp, path|`Prefetch`|WinPrefetchView|
||`C:\Windows\Prefetch`||
|Program network usage, memory usage|`SRUM`|SrumECmd|
||`C:\Windows\System32\sru\SRUDB.dat`||
|Scheduled task|`C:\Windows\Tasks`|Task Scheduler Viewer|
||`Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks`||
||`Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tree`||
||`Security.evtx`|Event Log Explorer|
||4698 -> A scheduled task was created. (Use this to get detailed information if the task scheduled (e.g. Who scheduled it, task name, date scheduled, exec command and etc.)||
||`Microsoft-Windows-TaskScheduler%4Operational.evtx`|Event Log Explorer|
||106 -> Task registered||
||200 -> Action started||
||201 -> Action completed||
||For the list of event ids related to TaskScheduler%4Operational.evtx, refer [here](https://docs.nxlog.co/integrate/windows-task-scheduler.html).||

#### Applications Installed

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|Client-side Applications|`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` `Software\Microsoft\Windows\CurrentVersion\App Paths`|Registry Explorer/RegRipper|
||`C:\ProgramData\Microsoft\Windows\AppRepository\StateRepository-Machine.srd`|DB Browser for SQLite|
||`Application.evtx` look for event id 11707 for successful installations, or event id 1033 (for MSI-based installs)|Event Log Explorer|
||`System.evtx` look for event id 7045 (A service was installed in the system)|Event Log Explorer|

#### Process Activities

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|Process Creation|`Security.evtx`|Event Log Explorer|
||4688 -> A new process has been created (When process such as powershell, cmd, bin files are executed). Corelate this with event id 4104 to see the code contained in powershell file.||
||`Microsoft-Windows-Sysmon%4Operational.evtx`||
||1 -> Process creation, extended information about newly created process.|Good to find for commands encoded in base64 on powershell and cmd executed command|
||10 -> ProcessAccess, reports when a process opens another process. Enables detection of hacking tools reading the memory contents of processes like lsass.exe|

#### Init Activities

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|Malicious DLL loaded into processes every time a specific app is loaded. Attackers attached malicious DLL to applications and persistence happens when user opens the application.|`Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`|Registry Explorer/RegRipper|
|**Initial logged in**|**`Software` hive**|**Registry Explorer/RegRipper**|
|Userinit process is responsible for user initialization, such as running logon scripts and loading the user profile after a user logs on to the system. Malicious DLL is attached and will be loaded into processes every time the user logs on.|`Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`|Registry Explorer/RegRipper|
|Shell registry key in the Windows operating system specifies the shell program run when a user logs in. Attacker maintain persistence by attaching malicious executable and runs alongside the default shell.|`Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`|Registry Explorer/RegRipper|

---

## Windows Memory Forensics with Volatility

### Image Identification

#### imageinfo Plugin

To determine the profile of an image,

```bash
python vol.py -f memory.dmp imageinfo
```
After running this plugin, a list of information related to the system will display, specifically suggested build profile(s), KDBG and image data and time. Suggested build profile(s) may not be always accurate and require testing (see below).

#### kdbgscan Plugin

KDBG is known as Kernel Debugger, used for debugging purposes if the system crashes. To determine the kdbg signature of an image, first ran the command,

```bash
python vol.py -f memory.dmp imageinfo
```

Then identify the profile to be used later in the process, try out each suggested build profile individually using the following command.

```bash
python vol.py -f memory.dmp --profile=<profile> kdbgscan
```

If the output of the command for PsActiveProcessHead and PsLoadedModuleList of discovered processes and modules are 0, the wrong profile is used. Make sure that the Version64 and Build string (NtBuildLab) output values reflect each other. Based on the plugin (kdbgscan) output, copy down actual profile name by matching the suggested profile(s) with Version64 and Build string (Can be found from Version64 minor value OR Build string first few digits before the dot) and the KdCopyDataBlock offset output as we will use it in the next step with any other plugin, *let us say `pslist`*,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> pslist
```

### Processes and DLLs

#### pslist Plugin

To determine the process (offset, name, PID, PPID, # of threads, # of handles (handles are used to interact with other files/processes/registry keys), Sess (good indicator of who triggered the process, each user has a different session number), Wow64 (indicates whether a process is running as a 32-bit process on a 64-bit operating system), Start, Exit) in the memory dump,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> pslist
```
pslist plugin to discover anomalies:
<ol>
  <li>powershell.exe</li>
  <li>cmd.exe</li>
  <li>Unusual process names</li>
  <li>Processes running at time of incident</li>
  <li>Multiple same processes that is supposed to be a singleton process. Example of singleton process includes:</li>
  <ul>
    <li>wininit.exe</li>
    <li>lsass.exe</li>
    <li>services.exe</li>
    <li>spoolsv.exe</li>
  </ul>
</ol>

#### psscan Plugin (Good for finding hidden processes that are not shown in pslist)

To enumerate processes using pool tag scanning,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> psscan
```
pscan plugin to discover anomalies:
<ol>
  <li>Persistence Processes</li>
  <ul>
    <li>schtasks.exe</li>
    <li>reg.exe (Adding registry keys)</li>
    <li>sc.exe, net.exe (Adding a malicious service with autostart)</li>
  </ul>
</ol>

#### dlllist Plugin

To display a process's loaded DLLs,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> dlllist
```

To display the process's loaded DLLs of a particular process with PID XXXX,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> dlllist -p XXXX
```

#### pstree Plugin

To determine the parent-child process like which process is the parent process and which process is the child process,

pstree plugin to discover anomalies:
<ol>
  <li>Run the pstree plugin to check processes relationships and look for:Processes that have cmd or PowerShell as child processes.</li>
  <li>System processes (e.g., services.exe) that have a client-side application as their parent (e.g., explorer.exe).</li>
  <li>Client-side application processes (e.g., calc.exe) which have a system process as their parent (e.g., services.exe)</li>
  <li>Run pstree with -v option and look for: System applications that are running from a location other than C:\Windows\System32\, such as the 'Desktop' and 'Downloads' folders.</li>
  <li>Client-side applications that are running from C:\Windows, or weird folder names.</li>
  <li>Unusual long commands (e.g., a three lines command, usually encoded command.). Also, commands with abnormal arguments such as IP address, port number, or URL.</li>
  <li>A mismatch between the values of the "path" and "audit" fields when running pstree with -v option.</li>
</ol>

Examples of malicious processes:
<ol>
  <li>A web browser (e.g., chrome.exe) spawning a suspicious child process (e.g., mshta.exe)</li>
  <li>An email client (e.g., outlook.exe) spawning a suspicious child process (e.g., regsvr32.exe)</li>
  <li>svchost.exe is running under a process other than services.exe</li>
  <ul>
    <li>svchost.exe will ALWAYS run with a -k parameter because it is required for the service control manager to track and manage services (Use -v for pstree plugin to see the command executed to trigger the process)</li>
  </ul>
  <li>A system process (e.g., services.exe) spawning a client-side application process (e.g., calc.exe)</li>
  <li>Windows explorer process (explorer.exe) spawning system process (e.g., lsass.exe)</li>
</ol>


```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> pstree
```

Use verbose mode of the `pstree` plugin to list detailed information,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> pstree -v
```

#### psxview Plugin

To find the hidden processes (cannot be found in pslist, BUT not all hidden processes are malicious) that are concealed from standard processes,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> psxview
```

#### psinfo Plugin

To find the detailed process information, especially hidden processes,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> psinfo -o <process_offset>
```
Note that the process offset value is based on psxview offset value.

From the above output, it contains the PID, Parent Process & PPID, Creation Time, Virtual Address Descriptor (VAD) (Tracks allocated memory space) and Process Environment Block (PEB) (Tracks command line arg, env var etc.). The VAD and PEB information should match each other, otherwise it increases the odds of being a malicious process. Refer to [this](https://cysinfo.com/detecting-malicious-processes-psinfo-volatility-plugin/) for more use cases.

#### getsids plugin

To find the process privileges and identify the SIDs of the users,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> getsids -o <process_offset>
```

Popular SIDs:
<ol>
  <li>S-1-5-32-544: Administrators group</li>
  <li>S-1-5-32-545: Users Group</li>
  <li>S-1-5-32-546: Guests group</li>
  <li>S-1-1-0: Everyone group</li>
  <li>S-1-5-21-domain-512: Domain Admins group for the domain</li>
  <li>S-1-5-18: Local System account</li>
  <li>S-1-5-19: Local Service account</li>
  <li>S-1-5-20: Network Service account</li>
  <li>S-1-5-21-domain-500: Administrator account for the local machine</li>
  <li>S-1-5-21-domain-1001: User account in the domain</li>
</ol>

For more info on account SIDs, click [here](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers#well-known-sids)

#### handles Plugin

To find open handles in a process,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> handles
```

To find open handles of a particular process with PID XXXX,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> handles -p XXXX
```

#### privs Plugin

To display which process privileges are present, enabled, and/or enabled by default,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> privs
```

#### consoles Plugin

To detect the commands that attackers typed into cmd.exe,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> consoles
```

#### cmdscan Plugin

To detect the commands that attackers entered through a console shell, cmd.exe.

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> cmdscan
```

#### ldrmodules Plugin

To list the DLLs in WoW64 processes,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> ldrmodules
```

### Networking

#### netscan Plugin

To find the network-relevant connection information,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> netscan
```

The above output will be similar to netstat command ran on live machine. Note that for UDP connections, the Foreign Address and State will be defaulted (ip addr is \*:\* and state is blanked) as it is a connectionless protocol.

What to look out for in the output:
<ol>
  <li>Suspicious processes for an application not installed on the subject system. Use psinfo to further investigate the suspected process. E.g. msteams is not installed in the system BUT appeared in the output. Use psinfo to check on the pid of teams.exe</li>
</ol>
Note: It is normal to see PID with -1 as the plugin could not obtain the process ID, process name, and creation time. This is a common occurrence because sometimes the memory parts that contain that information may get overwritten by other applications or functions.

#### connscan Plugin

To detect connections that have since been terminated, or active ones,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> connscan
```

### Registry 

#### hivelist Plugin

To list all registry hives in memory, their virtual space along with the full path, use the following plugin,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> hivelist
```

#### printkey Plugin

To detect the persistence techniques in Registry key, utilize the following plugin,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> printkey -K <registry-key>
```

plugin output:
<ul>
  <li><b>1. Hive path:</b> hive path determine if the configuration stored is specific to a particular user or applies to the entire machine.</li>
  <ul>
    <li>Hives in "\SystemRoot" indicate that the configuration applies to all users.</li>
    <li>Hives in the current user's profile directory (e.g., "C:\Users\username\NTUSER.DAT") indicate that the configuration only applies to that user.</li>
  </ul>
  <li><b>2. Key name and type:</b> "(S)" means that the key is a stable registry key permanently stored on the hard drive. If the key is marked as "(V)," it is a temporary/volatile registry key that exists only in memory. Volatile keys store system settings that frequently change, while stable keys are used for configuration data that needs to persist between system restarts. It makes sense that attackers will be interested in stable keys as their objective is to achieve persistence.</li>
  <li><b>3. Last updated:</b> the date and time when the key was last modified. This information can help establish a timeline of events during the incident.</li>
  <li><b>4. Subkeys:</b> contain a list of subkeys that exist under the inspected (parent) key, if any, along with their type, stable (S) or volatile (V).</li>
  <li>The "Values" section displays key content/values. It's broken down into:</li>
  <ul>
    <li><b>5. Value name:</b> usually the application name.</li>
    <li><b>6. Value data:</b> the key content. Usually, an executable or a command line.</li>
    <li><b>7. Value type:</b> Stable or volatile, similar to registry keys.</li>
    <li><b>8. Value data type:</b> the data type. For a complete list of possible types, please check out Registry value types by Microsoft. Knowing the data type will help you figure out the proper way to decode it.</li>
  </ul>
</ul>

#### winesap Plugin

To automate the inspecting persistence-related registry keys, utilize the following plugin,

```bash
volatility -f <memory_dump> --profile=<profile> -g <offset> winesap
```

Use the following parameter to display suspicious entries,

```bash
volatility -f <memory_dump> --profile=<profile> -g <offset> winesap --match
```

### File System

#### mftparser Plugin

To extract MFT entries in memory, utilize the following plugin,

```bash
volatility -f <memory_dump> --profile=<profile> -g <offset> mftparser
```

From the above output:
<ol>
  <li>MFT Record Header</li>
  <ol>
    <li><b>Attribute</b> will tell you whether it is a file or directory and whether it is <b>in use</b> (AKA NOT deleted)</li>
    <li><b>Record Number</b> is the sequence number of the record within the Master File Table.</li>
    <li><b>Link count</b> is the number of hard links to the file system file. Hard links are multiple file names that point to the same physical file on a disk. This attribute can be useful in tracking down malicious files that may have been created with a different name but still point to the same underlying content.</li>
  </ol>
  <li>STANDARD_INFORMATION</li>
  <ul>
    <li>Contains the timestamps when the file was created, last modified, last accessed, and last time the MFT record changed and the file's type.</li>
    <li>For file type, <b>Read-only</b>, <b>Hidden</b>, or <b>SYSTEM</b> are suspicious and often given by attackers to the malicious files they drop on the machine to evade detection and bypass security measures. Attackers may give their file the <b>System</b> attribute to protect it from being deleted.</li>
    <li>Here is a list of entries you may find under the <b>type</b> section:</li>
    <ol>
      <li><b>READ ONLY</b>: The file can only be read and not modified.</li>
      <li><b>HIDDEN</b>: The file is hidden from normal directory listings.</li>
      <li><b>SYSTEM</b>: The file is a part of the operating system and is required to function properly.</li>
      <li><b>ARCHIVE</b>: The file has been modified since the last backup.</li>
      <li><b>DEVICE</b>: The file is a device driver.</li>
      <li><b>NORMAL</b>: The file is a regular file and has no special attributes.</li>
      <li><b>TEMPORARY</b>: The file is temporary and may be deleted by the system when no longer needed.</li>
      <li><b>SPARSE FILE</b>: The file has been allocated in a way that optimizes the use of disk space.</li>
      <li><b>REPARSE POINT</b>: The file is a symbolic link or junction point.</li>
      <li><b>COMPRESSED</b>: The file has been compressed to save disk space.</li>
      <li><b>OFFLINE</b>: The file is not currently available on the system and may need to be retrieved from an external source.</li>
      <li><b>NOT CONTENT INDEXED</b>: The Windows Search service does not index the file.</li>
      <li><b>ENCRYPTED</b>: The file has been encrypted to protect its contents.</li>
    </ol>
  </ul>
  <li>FILE_NAME</li>
  <ul>
    <li>Contains the file name and timestamps. The $FN attribute is often used to identify files and directories and their properties.</li>
  </ul>
</ol>

### Process Memory

#### procdump Plugin

To dump the process's executable of a particular process with PID XXXX,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> procdump -p XXXX --dump-dir=/<output-directory>
```

#### memdump Plugin

To dump the memory resident pages of a particular process with PID XXXX,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> memdump -p XXXX --dump-dir=/<output-directory>
```

#### vaddump Plugin

To extract the range of pages described by a VAD node,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> vaddump --dump-dir=/<output-directory>
```

#### dumpfiles Plugin

To extract log files (.evtx) etc. use this plugin,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> dumpfiles --regex .evtx$ --ignore-case --dump-dir=/<output-directory>
```
There will be alot of .vacb and .dat files, use evtxECmd OR evtxdump.pl to format it to csv/xml and can be viewed using timeline explorer.

### Kernel Memory and Objects

#### filescan Plugin

To find all the files in the physical memory,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> filescan
```

### Miscellaneous

#### volshell Plugin

Interactively explore an image,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> volshell
```

#### timeliner Plugin

To create a timeline from various artifacts in memory from the following sources,

```bash
python vol.py -f memory.dmp --profile=<profile> -g <offset> timeliner
```

#### malfind Plugin

To find the hidden or injected DLLs in the memory,

```bash
volatility -f <memory_dump> --profile=<profile> -g <offset> malfind
```

#### yarscan Plugin

To locate any sequence of bytes, or determine the malicious nature of a process with PID XXXX, provided we have included the rule (yara rule file) we created, 

```bash
volatility -f <memory_dump> --profile=<profile> -g <offset> yarascan -y rule.yar -p XXXX
```

---
---

# Threat Hunting

#### Elastic Common Schema (ECS)

|Field|Description|KQL Examples|
|:---:|:---:|:---:|
|event.category|It looks for similar events from various data sources that can be grouped together for viewing or analysis.|event.category: authentication|
|||event.category: process|
|||event.category: network|
|||event.category: (malware or intrusion_detection)|
|event.type|It serves as a sub-categorization that, when combined with the "event.category" field, allows for filtering events to a specific level.|event.type: start|
|||event.type: creation|
|||event.type: access|
|||event.type: deletion|
|event.outcome|It indicates whether the event represents a successful or a failed outcome|event.outcome: success|
|||event.outcome : failure|

#### Common search fields

|Field|Description|KQL Examples|
|:---:|:---:|:---:|
|@timestamp|@timestamp: 2023-01-26|Events that happened in 26th|
||@timestamp <= "2023-01-25"|Events that happened with a date less than or equal to 25th of Jan|
||@timestamp >= "2023-01-26" and @timestamp <= "2023-01-27"|Events that happened between 26th and the 27th of Jan|
|agent.name|agent.name: `DESKTOP-*`|Look for events from the agent name that starts with DESKTOP|
|message|message: powershell|Look for any message with the word powershell|

#### Process Related Fields

|Field|Description|KQL Examples|
|:---:|:---:|:---:|
|process.name|`event.category: process and process.name: powershell.exe`|Look for powershell.exe as a process|
|process.command_line|`event.category: process and process.command_line.text:*whoami*`|Look for a commandline that has whoami on it|
|process.pid|`event.category: process and process.pid: 6360`|Look for process id: 6360|
|process.parent.name|`event.category: process and process.parent.name: cmd.exe`|Looks for cmd.exe as a parent process|
|process.parent.pid|`host.name: DESKTOP-* and event.category: process and process.command_line.text: powershell and process.parent.pid: 12620`|Looks for a process command line that has powershell and the parent process id is 12620 on a hostname that starts with DESKTOP|

#### Network related fields

|Field|Description|KQL Examples|
|:---:|:---:|:---:|
|source.ip|`source.ip: 127.0.0.1`|Looks for any logs originated from the loopback IP address|
|destination.ip|`destination.ip: 23.194.192.66`|Looks for any logs originating to IP 23.194.192.66|
|destination.port|`destination.port: 443`|Looks for any logs originating towards port 443|
|dns.question.name|`dns.question.name: "www.youtube.com"`|Look for any DNS resolution towards www.youtube.com|
|winlog.event_data.QueryName|`event.code: 22 and winlog.event_data.QueryName: *micro*`|Event ID 22 allows you to see the DNS resolution for URLs. Example is used to see for any typosquatting microsoft websites|
|dns.response_code|`dns.response_code: "NXDOMAIN"`|Looks for DNS traffic towards non existing domain names|
|destination.geo.country_name|`destination.geo.country_name: "Canada"`|Looks for any outbound traffic toward Canada|

#### Authentication related fields

|Field|Description|KQL Examples|
|:---:|:---:|:---:|
|user.name|`event.category: "authentication" and user.name: administrator and event.outcome: failure`|Looks for failed login attempt targeting username administrator|
|winlog.logon.type|`event.category : "authentication" and winlog.logon.type: "Network"`|Look for authentication that happened over the network|
||`event.category : "authentication" and winlog.logon.type: "RemoteInteractive"` OR `winlog.event_data.LogonType: 10`|Look for RDP successful authentication|
|winlog.event_data.AuthenticationPackageName|`event.category : "authentication" and event.action: logged-in and winlog.logon.type: "Network" and user.name.text: administrator and event.outcome: success and winlog.event_data.AuthenticationPackageName: NTLM`|Look for successful network authentication events against the user administrator, and the  authentication package is NTLM.|

#### RDP related events
|What To Look For|Where To Find It|Investigation Tool|
|:---:|:---:|:---:|
|To confirm if its RDP, look for event id 261|`Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx`|Event Log Explorer|
|To confirm successful authentication to RDP, look for event if 1149, this may also reveal the source ip of suceeded authentication|`Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx`||
|To check if attacker enabled RDP, look for event id 1. Reg add command `reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0 1`|`Microsoft-Windows-Sysmon%4Operational.evtx`||

---

## Endpoint Threat Hunting

### Detecting Persistence using Scheduled Tasks,

```kql
process.name: schtasks.exe
```

OR
```kql
technique_id=T1053,technique_name=Scheduled Task
```

### Detect PsExec Activity in the Network,

```kql
event.code: 1 and process.name: PsExe*
```

OR if PsExec is not used in your environment, check if EULA for PsExec is accepted. If it is accepted, it would meant that a malicious remote access had happened.
```kql
event.code: 13 AND registry.key: *\\PsExec\\EulaAccepted*
```
OR check via registry key `NTUSER\Software\SysInternals\PsExec\EulaAccepted`
OR Sysmon Event ID 12 OR 13. For 13, filter it with `Task` as the keyword in event log explorer

PSEXESVC temporary service will be created to execute the commands specified in the attacker's command. This service will then utilise named pipes for communication.

To detect named pipes used by PsExec, check Sysmon Event ID 18.

Detecting Credential Dumping Activity (e.g. Mimikatz, procdump) in Network,

```kql
event.code: 10 and winlog.event_data.TargetImage: *lsass.exe*
```
For sysmon event log, filter for event id 10 OR "Credential Dumping", usually attackers will use rundll32.exe to call lsass.exe.

### Detect new SID group (e.g. for mail capabilites)

Indicates a user created a security-enabled global group, output will provide SID, group name, group domain, privileges etc.
```kql
event.code: 4727
```
OR
Indicates a user added a user/group/computer to a security-enabled global group, which can be used for permissions and rights, output will provide SID, group name, group domain, privileges etc.
```kql
event.code: 4728
```

### MITRE Classification
|Example|Classification|
|:---:|:---:|
|Leveraged existing, long-running processes to alter the process hierarchy of new processes and to execute malicious code in the context of these long-running processes.|T1055.002|

### Attackers like to search for specific services/strings
|Command|Example|
|:---:|:---:|
|Commonly piped with tasklist and findstr/Select-String to check for services. Filter for Event ID 1, "findstr" OR "Select-String" OR "Get-Service"|`findstr /I "wrsa opssvc"` OR `Select-String -Path "C:\Logs\application.log" -Pattern "Error"`|

### File Type
|Extensions|Type|
|:---:|:---:|
|.bat,.cmd|Bash Scripts|
|.log|Log Files|
|.ldb|Temporary lock file storing session tokens|

### Disable real-time monitoring
Attackers often do this to cover their tracks by removing real-time monitoring, blue teamers will have a harder time recovering.
- `Set-MpPreference -DisableRealtimeMonitoring $true` effectively blinds blue teamers since logs are useful for recovering.
- Any variatins of auditpol (e.g. `auditpol /clear /y`) can prevent system auditing entirely.
- wevtutil cl <event log name> (e.g. `wevtutil cl System`) wipes clean the event log.

### Executable usually used by attackers
|Executable|
|:---:|
|bitsadmin (Deprecated, older version), certutil (newer version)|
---

## Network Threat Hunting

To detect data exfiltration through DNS,

```kql
agent.type: "packetbeat" and type: dns AND not dns.response_code: "NOERROR"
```

### URLs visited
|Browser|History file location|Remarks|
|:---:|:---:|:---:|
|Edge|`C:\Users\<username>\AppData\Local\Micrsoft\Edge\User Data\Default`|To check where users visited which URLs, goto history file location and put the history file into DB Browser for SQLite OR nirsoft's BrowsingHistoryView|
|Google Chrome|`C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default`|For more information, click [here](https://docs.nxlog.co/integrate/browser-history.html)|
|Mozilla Firefox|`C:\Users\<username>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile folder>`||

---
---

# Few Commands for quick start

### Eric Zimmerman Tools

#### MFTCmd

Extract the `$MFT` file from the `C:\$MFT` directory,

```cmd
MFTECmd.exe -f "/path/to/$MFT" --csv "<output-directory>" --csvf results.csv
```

#### PECmd

Extract the Prefetch directory from the `C:\Windows\Prefetch` path using FTK Imager,

```cmd
PECmd.exe -f "/path/to/Prefetch" --csv "<output-directory>" --csvf results.csv
```

#### LECmd

Extract the LNK file(s) from `C:\Users\$USER$\AppData\Roaming\Microsoft\Windows\Recent` using FTK Imager,

```cmd
LECmd.exe -f "C:\Users\user\AppData\Roaming\Microsoft\Windows\Recent\file.lnk"
```

#### RBCmd

Restore the deleted file from the Recycle Bin,

```cmd
RBCmd.exe -f "path/to/file" --csv "<output-directory>" --csvf results.csv
```

#### WxtCmd

Analyze the Timeline database and parse it into a CSV file using WxtCmd. The file can be found at `C:\Users<user>\AppData\Local\ConnectedDevicesPlatform\<user>\ActivitiesCache.db`

```cmd
WxTCmd.exe -f "C:\Users<user>\AppData\Local\ConnectedDevicesPlatform\<user>\ActivitiesCache.db" --csv "C:\Users\<user>\Desktop" --csvf results.csv
```

#### Amcache Parser

Parsing the AmCache.hve file to identify any suspicious entries or determine the malicious nature. The file can be found at `C:\Windows\appcompat\Programs\Amcache.hve`

```cmd
AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" --csv "C:\Users\<user>\Desktop\" --csvf results.csv
```

#### SrumECmd

Parse the SRUDB.dat file to find the system resource usage, network and process, etc. The file can be found at `C:\Windows\System32\sru\SRUDB.dat`

```cmd
SrumECmd.exe -f "C:\Users\Administrator\Desktop\SRUDB.dat" --csv "C:\Users\<user>\Desktop\" --csvf results.csv
```

#### AppCompatCacheParser

To parse the ShimCache from the registry hive,

```cmd
AppCompatCacheParser.exe -f "</path/to/SYSTEM/hive>" --csv "C:\Users\<user>\Desktop\" --csvf results.csv
```

#### ShimCacheParser

Parse the ShimCache with ShimCacheParser,

```bash
python ShimCacheParser.py -i <SYSTEM-hive> -o results.csv
```

### Hashing the files

#### Windows

Utilizing the great PowerShell, we can find the hash of the file,

```powershell
# generate SHA256 hash by-default
get-filehash <file>

# generate MD5 hash
get-filehash -algorithm MD5 <file>

#  generate SHA1 hash
get-filehash -algorithm SHA1 <file>
```

#### Linux

With Linux terminal, we can find the hash of the file,

```bash
# generate MD5 hash
md5sum <file>

# generate SHA1 hash
sha1sum <file>

# generate SHA256 hash
sha256sum <file>
```

### File Extraction and Analysis

Use Binwalk tool to extract the files and analysis,

```bash
binwalk -e <file>
```

### Bulk Extractor

Use bulk_extractor tool to extract the information without parsing file system,

```bash
bulk_extractor -o dump/ memory.dmp
```

### Strings Command

To print the strings of printable characters,

```bash
strings <file>
```

### Detecting LOLBin commands used (Via Elastic SIEM)

To detect LOLBin usages, one common remotely executed commands via LOLBin, is through the usage of **/node** and **process call create**

```bash
event.code : "1" and process.command_line : */node* and process.command_line : *process call create*
```
The result should show WMIC.exe and cmd.exe BUT WMIC.exe uses it as a LOLBin, refer [here](https://lolbas-project.github.io/#wmi)

#### MSSQL

|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|Username, creation date ,login date, SID|SAM|Registry Explorer/RegRipper|
|Login, logout, deletion, creation|Application.evtx|Event Log Explorer|
||15457 -> Configuration option '%ls' changed from %ld to %ld. Run the RECONFIGURE statement to install.|
||18455 -> Login succeeded for user '%.*ls'.%.*ls|
||18456 -> Login failed for user '%.*ls'.%.*ls|
||For more info, goto https://learn.microsoft.com/en-us/sql/relational-databases/errors-events/database-engine-events-and-errors-18000-to-18999?view=sql-server-ver17|

For KQL queries on MSSQL, use

```kql
event.provider : "MSSQL$SQLEXPRESS"
```

#### log4shell
In the event where sysmon log is gone.
|**What To Look For**|**Where To Find It**|**Investigation Tool**|
|:---:|:---:|:---:|
|To see what attacker's IP address and URL was visited, especially `log4shell.huntress.com` payload as it can be used to detect vCenter instance is vulnerable|`C:\ProgramData\VMware\vCenterServer\runtime\VMwareSTSService\logs\websso.log`|Notepad|

---
---

# Tools Utilized

Here is the list of all the tools utilized during the completion of the Certification. More tools can be added in coming future.

|**Tool Name**|**Resource Link**|**Purpose**|
|:---:|:---:|:---:|
|LiME|https://github.com/504ensicsLabs/LiME|Memory Acquisition on Linux devices.|
|FTK Imager|https://www.exterro.com/ftk-imager|Memory Acquisition on range of devices.|
|Belkasoft|https://belkasoft.com/ram-capturer|Memory Acquisition.|
|DumpIt|http://www.toolwar.com/2014/01/dumpit-memory-dump-tools.html|Memory Acquisition.|
|Encrypted Disk Detector|https://www.magnetforensics.com/resources/encrypted-disk-detector/|Quickly checks for encrypted volumes on a system.|
|KAPE|https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape|Used for fast acquisition of data.|
|CyLR|https://github.com/orlikoski/CyLR|Forensics artifacts collection tool.|
|dd|https://man7.org/linux/man-pages/man1/dd.1.html|Used to create a disk image of a Linux OS.|
|Arsenal Image Mounter|https://arsenalrecon.com/|Used to mount different image types.|
|Event log explorer|https://eventlogxp.com/|Used for Windows event log analysis.|
|Full Event Log view|https://www.nirsoft.net/utils/full_event_log_view.html|Used to display a table that details all events from the event logs of Windows.|
|Volatility|https://www.volatilityfoundation.org/<br> https://github.com/volatilityfoundation/volatility/wiki/Command-Reference/<br> https://wongkenny240.gitbook.io/computerforensics/memory-analysis/volatility/<br> https://blog.onfvp.com/post/volatility-cheatsheet/|Used for Memory Analysis.|
|AbuseIPDB|https://www.abuseipdb.com/|Detect abusive activity of IP address.|
|IPQuality Score|https://www.ipqualityscore.com/|checks for IP addresses reputation.|
|Any.run|https://app.any.run/|Malware Sandbox.|
|VirusTotal|https://www.virustotal.com/gui/home/upload|Malware Sandbox.|
|Tria.ge|https://tria.ge/|Malware Sandbox.|
|EZ Tools|https://ericzimmerman.github.io/#!index.md|Set of digital forensics tools.|
|NTFS Log Tracker|https://sites.google.com/site/forensicnote/ntfs-log-tracker|Used to parse `$LogFile`, `$UsnJrnl:$J` of NTFS and carve `UsnJrnl` record in multiple files.|
|UserAssist|https://blog.didierstevens.com/programs/userassist/|Used to display a table of programs executed on a Windows machine, run count, last execution date & time.|
|R-Studio|https://www.r-studio.com/Data_Recovery_Download.shtml|Used to recover lost files.|
|Wireshark|https://www.wireshark.org/|Used for Network Traffic analysis.|
||For filtering, use ~ for finding content containing specified value||
||Filter for `tls` to check for C2 Comms and use Statistics to check where the huge bulk of traffic (in bytes) goes to. Top few communications should be marked as suspicious.||
||Find and type `download` then search for info consisting (application/x-msdownload) etc where suspicious download occurs||
||Look for application/octet-stream as it can be exploit traffic. This type of traffic is usually bin data associated with executable files.||
||To find URL that was redirected to the malicious site, filter base on the malicious site IP address or `http.host==<malicious site name>` then find and type `Referer`.||
||From dhcp traffic, you can find out the hostname of the client leasing IP address||
||From http traffic, you can identify the source operating system. See User-Agent field||
||To check ephemeral public key provided by the server during the TLS handshake in the session, take the session id and filter based on `tls.handshake.session_id == <session id>` then search for `Pubkey`. The value could be found in Handshake Protocol: Server Key Exchange > EC Diffie-Hellman Server Params > Pubkey||
|CobaltStrikeParser|https://github.com/Sentinel-One/CobaltStrikeParser|A python parser for CobaltStrike Beacon's configuration.|
|Suricata|https://suricata.io/|A popular open-source IDS.|
|RITA|https://github.com/activecm/rita|An open source framework for detecting C2 through network traffic analysis.|
|Sysmon|https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon|Windows system service and device driver that logs system activity to Windows Event Log.|
|Velociraptor|https://www.rapid7.com/products/velociraptor/|Used for collecting collect, monitor, and hunt on a single endpoint, a group of endpoints, or an entire network.|
|Gophish|https://getgophish.com/|Open-Source, advanced Phishing Simulation framework.|
|Epoch & Unix Timestamp Conversion Tools|https://www.epochconverter.com/|Convert epoch to human-readable date and vice versa.|
|OSSEC|https://www.ossec.net/|A powerful host-based intrusion detection system.|
|Nessus|https://www.tenable.com/downloads/nessus?loginAttempted=true|Popular Vulnerability Assessment Scanner.|
|Microsoft Sentinel|https://azure.microsoft.com/en-in/products/microsoft-sentinel/|A cloud native SIEM solution|
|Open Threat Exchange (OTX)|https://otx.alienvault.com/|Open Threat Intelligence Community|
|Canary Tokens|https://canarytokens.org/generate|Used for tracking anything.|
|Elastic SIEM|https://www.elastic.co/security/siem|Used for aggregating data, logging, monitoring.|
|Yara|https://virustotal.github.io/yara/|Used by malware researchers to identify and classify malware sample.|
|SQLite Browser|https://sqlitebrowser.org/|A high quality, visual, open source tool to create, design, and edit database files compatible with SQLite.|
|RegRipper|https://github.com/keydet89/RegRipper3.0|Used to surgically extract, translate, and display information from Registry-formatted files via plugins in the form of Perl-scripts.|
|Binwalk|https://github.com/ReFirmLabs/binwalk|Used for for analyzing, reverse engineering, and extracting firmware images.|
|MFTDump.py|https://github.com/mcs6502/mftdump/blob/master/mftdump.py|Used for parsing and displaying Master File Table (MFT) files.|
|Prefetchruncounts.py|https://github.com/dfir-scripts/prefetchruncounts|Used for Parsing and extracting a sortable list of basic Windows Prefetch file information based on "last run" timestamps.|
|parseMFT|https://pypi.org/project/parseMFT/#files|Parse the $MFT from an NTFS filesystem.|
|Brim|https://www.brimdata.io/|Used for network troubleshooting and security incident response.|
||`event_type=="alert"` is a good start to check for signatures and filter out traffic|
||`event_type=="alert" alert.severity==1` is another one to filter for only the critical alerts|
||`<command> alert.severity==1 \| count() by alert.signature` is related to above to focus only on specific critical signatures, good to use for pivot to values (right click the record)|
|NetworkMiner|https://www.netresec.com/?page=networkminer|Used to extract artifacts, such as files, images, emails and passwords, from captured network traffic in PCAP files.|
|Autopsy|https://www.autopsy.com/download/|Used for analyzing forensically-sound images.|
|Capa-Explorer|https://github.com/mandiant/capa|Used to identify capabilities in executable files.|
|IDA|https://hex-rays.com/ida-free/|Used for Reverse engineering the binary samples.|
|TurnedOnTimesView|https://www.nirsoft.net/utils/computer_turned_on_times.html|Used to analyze the windows event logs and detect time ranges that a computer was turned on.|
|USB Forensic Tracker|http://orionforensics.com/forensics-tools/usb-forensic-tracker|Used to extracts USB device connection artefacts from a range of locations.|
|WinDbg|https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools|Used for debugging.|
|Outlook Forensics Wizard|https://forensiksoft.com/outlook-forensics.html|Used to open, search, analyze, & export outlook data files of any size.|
||pst files are usually found in `C:\Users\<Username>\Documents\Outlook Files\`|`.pst` files are related to outlook and 4n6 Outlook Forensics Wizard can be used to analyse the files|
|FakeNet|https://github.com/mandiant/flare-fakenet-ng|Used for dynamic network analysis. After running the fakenet.exe file, it will open a cmd and listens for traffic. Execute the malicious file and allow FakeNet to pick up outgoing traffic to malicious IP addresses|
|oletools|https://github.com/decalage2/oletools|Set of tools used for malware analysis, forensics, and debugging.|
|oleid.py|Can be used to identify whats inside the document/file|Example: To check if xls file contains a vba macro|
|olevba.py|Can be used to examine the vba embedded within the xls file||
|scdbg|http://sandsprite.com/blogs/index.php?uid=7&pid=152|Used to display to the user all of the Windows API the shellcode attempts to call.|
|Resource Hacker|http://angusj.com/resourcehacker|A freeware resource compiler & decompiler for Windows applications.|
|Hashcat|https://hashcat.net/hashcat/|Used to crack the hashes to obtain plain-text password.|
|John The Ripper|https://www.openwall.com/john/|Used to crack the hashes to obtain plain-text password.|
|Bulk Extractor|https://downloads.digitalcorpora.org/downloads/bulk_extractor/|Used to extract useful information without parsing the file system.|
|jq|https://stedolan.github.io/jq/download|A command line JSON processor|
|AWS-CLI|https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html|Used to interact with AWS via Command Line.|
|HindSight|https://github.com/obsidianforensics/hindsight|Used for Web browser forensics for Google Chrome/Chromium|
|xxd|https://linux.die.net/man/1/xxd|Creates a HEX dump of a file/input|
|ShimCacheParser|https://github.com/mandiant/ShimCacheParser|Used to parse the Application Compatibility Shim Cache stored in the Windows registry|
|File Signatures for malware analysis|https://www.garykessler.net/library/file_sigs_GCK_latest.html|Used for reference on the list of file signatures. These file signatures appear at start of the hex dump.|
|Pesec|https://pev.sourceforge.io/doc/manual/en_us/ch06s08.html|To check for security features in PE files|
|Microsoft-Windows-Windows Defender%4Operational|https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus|For Windows Defender related events|
||1116 OR 1015 -> The antimalware platform detected malware or other potentially unwanted software.||
|MSSQL Logs|`<Drive Name>\MSSQL15.MSSQLSERVER\MSSQL\Log\ERRORLOG`|Useful to check which MSSQL account has attempted to logon, IP address initiating it and the configurations changed|
|jd GUI|https://java-decompiler.github.io/|Good to view class files. To obtain class files, upload the jar file to jd GUI. Upon uploading, it will expand to multiple directories containing class files. E.g. `log4j-core-<version number>.jar`|
