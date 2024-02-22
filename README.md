# Configuration Hardening Assessment PowerShell Script (CHAPS)
CHAPS is a PowerShell script for checking system security settings where additional software and assessment tools, such as Microsoft Policy Analyzer, cannot be installed. The purpose of this script is to run it on a server or workstation to collect configuration information about that system. The information collected can then be used to provide recommendations (and references) to improve the security of the individual system and systemic issues within the organization's Windows environment. Examples of environments where this script is useful include Industrial Control System (ICS) environments where systems cannot be modified. These systems include Engineer / Operator workstations, Human Machine Interface (HMI) systems, and management servers that are deployed in production environments.

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## How To Use

Step 1: Preparing for Execution
Ensure you have CHAPS and PowerSploit scripts downloaded into the same directory.
Open a terminal and navigate to that directory.
Start a Python3 web server by running ```python3 -m http.server 8181```. This serves the scripts from another system on the network.


Step 2: Running CHAPS on the Target System
On the target system, open a CMD.exe window as an Administrator.
Run powershell.exe -exec bypass to launch a PowerShell prompt.
If using a PowerShell terminal, execute ```Set-ExecutionPolicy Bypass -scope Process``` to allow script execution.
After  run the following command to execute the ```chaps.ps1``` script.
Execute the CHAPS script with:
vbnet
```Copy code
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/chaps/chaps.ps1')
```

Step 3: Running CHAPS PowerSploit Checks
For additional checks using PowerSploit, disable the system's anti-virus.
Run the following commands ``` chaps-powershell.ps1```  to import and execute PowerSploit scripts:
vbnet
```Copy code
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/PowerSploit/Recon/PowerView.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/PowerSploit/Exfiltration/Get-GPPPassword.ps1') ```


Step 4: Reviewing Output
Outputs of each script will be written to the user's Temp directory.
Copy these files for review, then delete them. Restart the system's anti-virus if necessary.


Step 5: Utilizing CHAPS Assessment Guide
Refer to the provided CHAPS Assessment Guide to discuss findings and recommendations with system administrators or your team.
By following these steps, you can effectively assess and enhance system security configurations within your Windows environment using CHAPS.

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**System Configuration Checks**

# System Info Command:
  *  Run systeminfo to gather system information for further analysis.

# Administrator Rights:
  * Check if the user has administrator privileges, essential for some checks to work effectively. Uncomment the error suppression line if needed.

# System Information:

     * System Version
     * User and Path Information
     * IPv4 and IPv6 addresses
     * Windows AutoUpdate configuration
     * Check for missing Critical and Important Updates
     * BitLocker Disk Encryption status
     * AlwaysInstallElevated Registry Keys check

#PowerShell Event Log Settings:

  * Verify PowerShell Commandline, Module, Script Block, and Invocation Logging statuses.
  * Check PowerShell Protected Event Logging.

# Windows Event Log Configurations:

  * Review maximum log file settings for critical logs.

# PowerShell Configuration Settings:

  * Determine PowerShell version and restrictions.
  * Check installed .NET versions.

# Cached Credentials:

* Assess the number of Cached Credentials configured.

# Remote Access Configurations:

 * Check RDP settings for remote connections.
 * Verify WinRM configuration and Firewall rules.
 * Local Administrator Accounts: Ensure only necessary users are members of the Local Administrator group.

# CHAPS PowerSploit Security Checks:

 * Utilize PowerSploit for additional system information gathering. Disable anti-malware temporarily.

# Secure Baseline Checks -Securing Windows Workstations:

    * Assess AppLocker, EMET, LAPS deployment, and Group Policy settings.
    * Verify disabling of Net Session Enumeration, WPAD, LLMNR, Windows Browser Protocol, NetBIOS, Windows Scripting, WDigest, SMBv1.
    * Check for blocking untrusted fonts, enabling Credential/Device Guard, securing LanMan Authentication, and restricting RPC Clients.
    * Configure NTLM session security.




**Practical video**
 https://drive.google.com/file/d/1eMYiDbOvsFilK5w6u1F75bde3lJUDRpv/view?usp=drive_link


-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Collaborators
Special thanks to collaborators who contributed to troubleshooting and enhancing the CHAPS project, including h1k0r.
