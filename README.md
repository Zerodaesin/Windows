# Windows
#find out what OS we are connected to
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# hostname/ user
hostname
echo %username%

#
net users
net user user1

#network interface
ipconfig /all

route print
arp -A

active network connections and the firewall rules
netstat -ano

#netsh firewall commmands only availabe after OS XP SP2
netsh firewall show state
netsh firewall show config

#scheduled tasks
schtasks /query /fo LIST /v

#running processes to started services
tasklist /SVC

#windows services started
net start

#driver installs
DRIVERQUERY

#Security patch list
wmic qfe get Caption,Description,HotFixID,InstalledOn

directories that contain the configuration files (however it is a good idea to check the entire OS):
c:\sysprep.inf
c:\sysprep\sysprep.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml


