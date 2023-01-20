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
<https://i.imgur.com/Zdxicjj.png>
