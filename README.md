The Configuration Hardening Assessment PowerShell Script (CHAPS) is a tool designed for checking system security settings in environments where additional software installations are restricted. It is particularly useful in environments like Industrial Control System (ICS) setups, where modifying systems can be challenging due to operational constraints. CHAPS collects configuration information from servers or workstations, enabling administrators to assess security postures and make necessary improvements.

Here's a breakdown of its features and usage:

Features:
System Configuration Checks:

Retrieves system information such as version, user details, IP addresses, Windows AutoUpdate status, BitLocker encryption, and more.
Checks PowerShell event log settings, Windows event log configurations, PowerShell configuration settings, cached credentials, remote access configurations, and local administrator accounts.
CHAPS PowerSploit Security Checks:

Utilizes PowerSploit for additional system information gathering.
Requires disabling anti-malware protection temporarily.
Secure Baseline Checks:

Implements security measures based on the Securing Windows Workstations baseline.
Checks settings related to AppLocker, EMET, LAPS, Group Policy, Net Session Enumeration, WPAD, LLMNR, Windows Scripting, SMBv1, and more.
Usage:
CHAPS is executed via PowerShell and should be PowerShell-version independent.
It can be run within an ICS environment without writing scripts to the system being reviewed.
To run, serve the script from a webserver on the network and execute it on the target system using PowerShell commands provided.
Additional PowerSploit scripts can be imported and executed for further analysis.
Collaborators:
The project acknowledges collaboration with individuals like "h1k0r" for troubleshooting and feature additions.
TODO:
There are outlined issues and potential improvements listed in the script, including handling errors gracefully, testing in domain environments, fixing version-specific checks, and implementing new checks.
The script also notes future enhancements like domain tests, non-PowerShell versions, and integration of additional security checks.
CHAPS serves as a comprehensive tool for assessing and improving system security configurations in restricted environments, providing valuable insights and recommendations for system administrators.
