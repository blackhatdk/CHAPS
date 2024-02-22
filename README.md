Configuration Hardening Assessment PowerShell Script (CHAPS)
CHAPS is a PowerShell script designed to assess system security settings in environments where installing additional software or assessment tools like Microsoft Policy Analyzer isn't feasible. Here's how to use it effectively:

Step 1: Preparing for Execution
Ensure you have CHAPS and PowerSploit scripts downloaded into the same directory.
Open a terminal and navigate to that directory.
Start a Python3 web server by running python3 -m http.server 8181. This serves the scripts from another system on the network.
Step 2: Running CHAPS on the Target System
On the target system, open a CMD.exe window as an Administrator.
Run powershell.exe -exec bypass to launch a PowerShell prompt.
If using a PowerShell terminal, execute Set-ExecutionPolicy Bypass -scope Process to allow script execution.
Execute the CHAPS script with:
vbnet
Copy code
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/chaps/chaps.ps1')
Step 3: Running CHAPS PowerSploit Checks
For additional checks using PowerSploit, disable the system's anti-virus.
Run the following commands to import and execute PowerSploit scripts:
vbnet
Copy code
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/PowerSploit/Recon/PowerView.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/PowerSploit/Exfiltration/Get-GPPPassword.ps1')
...
Step 4: Reviewing Output
Outputs of each script will be written to the user's Temp directory.
Copy these files for review, then delete them. Restart the system's anti-virus if necessary.
Step 5: Utilizing CHAPS Assessment Guide
Refer to the provided CHAPS Assessment Guide to discuss findings and recommendations with system administrators or your team.
By following these steps, you can effectively assess and enhance system security configurations within your Windows environment using CHAPS.

Collaborators
Special thanks to collaborators who contributed to troubleshooting and enhancing the CHAPS project, including h1k0r.
