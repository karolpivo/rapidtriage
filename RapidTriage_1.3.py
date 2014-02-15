#
#		RapidTriage.py
#		Version: 1.2
#		Trenton Bond - trent.bond@gmail.com
#		02-14-2014
#
#		Description:
#		This script is meant to provide a framework for incident handlers
#		and system administrators to quickly gather incident discovery data for 
#		Windows, FreeBSD, OSX, and Linux systems into the user specified <filename>.
#		The script has been organized so that commands or log files used to collect the
#		information can be easily modified or removed as necessary. The script also
#		allows the user to select sections to be chosen at runtime. Finally, if necessary, the
#		the results file can be hashed "<filename>-hash" to help ensure the integrity of the
#		results file.
#

import sys,subprocess,os,time,hashlib
from optparse import OptionParser,OptionGroup

######################
#	User Interface
######################

# Setup command line options and arguments
parser=OptionParser(usage='Usage: python %prog [argument(s)] -o <filename>')
parser.add_option('-o',help='specified file will contain the results of RapidTriage',dest='outfile')
group1 = OptionGroup(parser, "Arguments (one or more system areas required)")
group1.add_option('-a','--all_areas',action='store_true', help='collect information from all areas', dest='allchecks')
group1.add_option('-f','--filesystem',action='store_true', help='collect filesystem related information', dest='filesystem')
group1.add_option('-l','--log_events',action='store_true', help='collect histories and log data', dest='logs')
group1.add_option('-n','--net_stats',action='store_true', help='collect network stats and config information', dest='network')
group1.add_option('-p','--process',action='store_true', help='collect process, service, and module information', dest='process')
group1.add_option('-t','--sched_tasks',action='store_true', help='collect scheduled task information', dest='tasks')
group1.add_option('-u','--user',action='store_true', help='collect user account and configuration information', dest='user')
parser.add_option_group(group1)
group2 = OptionGroup(parser, "Optional")
group2.add_option('-m','--md5sum',action='store_true', help='generate an md5 hash of the results file (<filename>) and place in <filename>-hash', dest='hash')
parser.add_option_group(group2)

# Ensure an outfile has been given at runtim
(options,args)=parser.parse_args()
if (options.outfile is None):
	parser.print_help()
        sys.exit()
# Ensure at least of the required arguments has been chosen at runtime
if not any((options.allchecks, options.network, options.logs, options.process, options.tasks, options.user, options.filesystem)):
	parser.print_help()
        sys.exit()

# Open the user specified outfile 
outputfile=open(options.outfile,"a")


######################
#	Platform Detection
######################

from sys import platform as _platform
if _platform.startswith('linux'):
	os_type="linux"
elif _platform.startswith('freebsd'):
	os_type="freebsd"
elif _platform == "darwin":
	os_type="osx"
elif _platform == "win32":
	os_type="windows"

######################
#	Reporting
######################

# Timestamp Function - Provide a timestamp when necessary
def timestamp():
	now = "["+time.strftime("%H:%M:%S")+"]"
	return now

# Process Commands Function - Execute given commands and write the results to the user specified outfile
def run_cmds(list_cmds):
	for cmd in list_cmds:
		split_cmd=cmd.split("::")
	    	outputfile.write("\n")
	    	outputfile.write(timestamp()+"\t"+split_cmd[0]+":\n")
	    	outputfile.write("===========================================================\n\n")
	    	p = subprocess.Popen(split_cmd[1], stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
		for line in p.stdout.readlines():
			outputfile.write("\t"+line)


#######################
# Collection Engine
#######################

# Collect general system information based on identified operating system type
print "\nGathering General System Information..."
outputfile.write("""
############################################## 
#
#	General System Information	     
#
##############################################
""")

outputfile.write("\n")
outputfile.write("\tSystem Time:\t"+time.asctime()+"\n")

# Below are the specific operating system commands to be run for each OS type
# The format is <Description::Commnand> and both are required. Note the double colon "::" is the separator.
if os_type is "linux":
	cmds = [
	'System Name::hostname',
	'Effective User::whoami',
	'Runlevel::runlevel',
	'System Type::uname -a'
	]
elif os_type is "windows":
        cmds = [
	'System Name::hostname',
	'Effective User::whoami',
	'System Type::for /F "delims== tokens=1-2" %a in (\'wmic os get Caption /format:list^|find "Caption"\') do @echo %b'
	]
elif os_type is "osx":
	cmds = [
	'System Name::hostname',
	'Effective User::whoami',
	'System Type::uname -a'
	]
elif os_type is "freebsd":
	cmds = [
	'System Name::hostname',
	'Effective User::whoami',
	'System Type::uname -a'
	]

# Though we have a definition to execute the given commands, the format for the results in the "General System Information"
# are different from the other sections and thus required the execution for the above commands to be done here. 
for cmd in cmds:
	split_cmd=cmd.split("::")
	outputfile.write("\t"+split_cmd[0]+":\t")
	p = subprocess.Popen(split_cmd[1], stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
	outputfile.write(p.stdout.read())
outputfile.write("\n")

# Linux, FreeBSD, Windows, and OSX General System  Related Commands
#
#	This list can easily be modified to include additional commands. Use the "<description>::<command>" format.
#
#	|	|	|
#	V	V	V
#
if os_type is "linux":
	cmds = [
	'Filesystem Disk Space Usage::df -al',
	'Memory Usage::vmstat -s',
	'Uptime and Load Average::uptime',
	'Enviroment Variables::export'
	]
elif os_type is "windows":
	cmds = [
	'Filesystem Disk Space Usage::wmic logicaldisk get caption, size, freespace',
	'Memory Usage::wmic os get totalvisiblememorysize, freephysicalmemory,totalvirtualmemorysize, freevirtualmemory/format:list',
	'Load Average::wmic path win32_processor get deviceid, loadpercentage',
	'Enviroment Variables::set'
	]
elif os_type is "osx":
	cmds = [
	'Filesystem Disk Space Usage::df -al',
	'Memory Usage::vm_stat',
	'Uptime and Load Average::uptime',
	'Enviroment Variables::env'
	]
elif os_type is "freebsd":
	cmds = [
	'Filesystem Disk Space Usage::df -al',
	'Memory Usage::vmstat -s',
	'Uptime and Load Average::uptime',
	'Enviroment Variables::env'
	]

# Again the format for the results of these commands are different than the rest of the program. This requires the execution of the commands here.
for cmd in cmds:
	split_cmd=cmd.split("::")
	outputfile.write("\t"+split_cmd[0]+":\n")
	outputfile.write("\t=========================\n\n")
	p = subprocess.Popen(split_cmd[1], stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
	for line in p.stdout.readlines():
		outputfile.write("\t"+line)
	outputfile.write("\n")
outputfile.write("\n")

# Collect network information based on identified operating system type
# Make sure the "--check-all" or "--net_stats" arguments have been chosen
if options.allchecks or options.network:
	print "Gathering Network Information..."
	outputfile.write("""
############################################## 
#
#	Network Information		     
#
##############################################
	""")

		# Linux, FreeBSD, Windows, and OSX Network Related Commands
		#
		#	This list can easily be modified to include additional commands. Use the "<description>::<command>" format.
		#
		#	|	|	|
		#	V	V	V
		#
	if os_type is "linux":
		cmds = [
		'Network Interface Configuration::ifconfig -a',
		'Network Interfaces in Promiscuous Mode::ip link |grep PROMISC',
		'Route Table::netstat -rn',
		'Firewall Configuration::iptables -L',
		'ARP Table::arp -e',
		'Listening Ports and Associated Command::lsof -i',
		'Active Network Connections::netstat -natp',
		'Count of Half Open Connections::netstat -ant |grep "svn_recv" |wc -l',
		'Count of Open Connections::netstat -ant |grep "established" |wc -l',
		'/etc/hosts Contents::cat /etc/hosts'
		]
	elif os_type is "windows":
		cmds = [
        	'Network Interface Configuration::ipconfig /all',
        	'Route Table::route print',
        	'Firewall Configuration::netsh advfirewall firewall show rule all',
        	'ARP Table::arp -a',
        	'Listening Ports::netstat -ano |find /i "listening"',
        	'Established Connections::netstat -ano |find /i "established"',
        	'Active/Listening Connections and Associated Command::netstat -anob',
        	'Count of Half Open Connections::netstat -ano |find /i /c "syn_received"',
        	'Count of Open Connections::netstat -ano |find /i /c "established"',
        	'/etc/hosts Contents::type %SystemRoot%\System32\Drivers\etc\hosts',
		'Sessions Open to Other Systems::net use',
		'Local File Shares::net view \\\\127.0.0.1',
		'Available Local Shares::net share',
		'Open Sessions with Local Machine::net session'
        	]
	elif os_type is "osx":
		cmds = [
		'Network Interface Configuration::ifconfig -a',
		'Route Table::netstat -rn',
		'Firewall Configuration::ipfw list',
		'ARP Table::arp -a',
		'Listening Ports and Associated Command::lsof -i |grep -i listen',
		'Active Network Connections::lsof -i tcp',
		'Count of Half Open Connections::netstat -ant |grep -i "svn_recv" |wc -l',
		'Count of Open Connections::netstat -ant |grep -i "established" |wc -l',
		'/etc/hosts Contents::cat /etc/hosts'
		]
	elif os_type is "freebsd":
		cmds = [
		'Network Interface Configuration::ifconfig -a',
		'Route Table::netstat -rn',
		'Firewall Configuration::ipfw list',
		'ARP Table::arp -a',
		'Listening Ports and Associated Command::lsof -i |grep -i listen',
		'Active Network Connections::lsof -i tcp',
		'Count of Half Open Connections::netstat -an |grep -i "svn_recv" |wc -l',
		'Count of Open Connections::netstat -an |grep -i "established" |wc -l',
		'/etc/hosts Contents::cat /etc/hosts'
		]

	run_cmds(cmds)
	outputfile.write("\n")

# Collect process and service information based on identified operating system type
# Make sure the "--check-all" or "--process" arguments have been chosen
if options.allchecks or options.process:
	print "Gathering Process and Service Information..."
	outputfile.write("""
############################################## 
#
# Process, Service, and Module Information	
#
##############################################
	""")

		# Linux, FreeBSD, Windows, and OSX Process, Service, or Kernel Module  Related Commands
		#
		#	This list can easily be modified to include additional commands. Use the "<description>::<command>" format.
		#
		#	|	|	|
		#	V	V	V
		#
	if os_type is "linux":
    		cmds = [
    		'Running Processes::ps -aux',
    		'Open Files Associated with each PID::ps aux |awk \'NR!=1 {print $2}\' |while IFS= read pid; do echo ""; ps $pid; lsof -p $pid; done',
    		'System Service Status::service --status-all',
    		'Installed Packages::rpm -Va |sort',
    		'Installed Kernel Modules::lsmod'
    		]
	elif os_type is "windows":
    		cmds = [
    		'Running Processes::tasklist',
    		'Process - Full Information::wmic process list full',
    		'Services and Their State::sc query',
    		'PIDs mapped to Services::tasklist /svc',
    		'Intsalled Patches and Service Packs::wmic qfe'
    		]
	elif os_type is "osx":
		cmds = [
		'Running Processes::ps -vx',
		'Open Files Associated with each PID::ps -xv |awk \'NR!=1 {print $1}\' |while IFS= read pid; do echo ""; ps $pid; lsof -p $pid; done',
		'Installed Packages::pkgutil --packages',
		'Loaded Kernel Extensions::kextstat',
		]
	elif os_type is "freebsd":
		cmds = [
		'Running Processes::ps -vx',
		'Installed Packages::pkg_info',
		'Kernel Loaded Drivers::kldstat',
		]
	
	run_cmds(cmds)
	outputfile.write("\n")

# Collect unusual file information based on identified operating system type
# Make sure the "--check-all" or "--filesystem" arguments have been chosen
if options.allchecks or options.filesystem:
	print "Gathering Information on Unusual Files..."
	outputfile.write("""
############################################## 
#
#	Unusual Files, Directories, Registry Keys		
#
##############################################
	""")

		# Linux, FreeBSD, Windows, and OSX Unusual File, Directories, or Registry Key  Related Commands
		#
		#	This list can easily be modified to include additional commands. Use the "<description>::<command>" format.
		#
		#	|	|	|
		#	V	V	V
		#
	if os_type is "linux":
    		cmds = [
    		'Files with SUID/GUID bits set::find / -type f \( -perm +4000 -o -perm +2000 \) -exec ls -l {} \; 2>/dev/null',
    		'Large Files >50M::find / -size +50000k -print',
    		'Suspicious Files "..."::find / -name "..." -print',
    		'Suspicious Files ".."::find / -name ".." -print',
    		'Suspicious Files "."::find / -name "." -print',
    		'Processes using Unlinked Files::lsof +L1',
    		'Suspicious Directories and Files::find / -name "..*"',
    		'Hidden Directories and Files::find / -name ".*"',
    		'Files Modified in the Last 24 Hours::find / -type f -mtime 0 -ls',
    		'Orphaned Files Without a User or Group::find / -nouser -nogroup'
    		]
	elif os_type is "windows":
    		cmds = [
    		'Large Files >50M::for /R c:\ %i in (*) do @if %~zi gtr 50000000 echo %i %~zi',
    		'hklm\software\microsoft\windows\currentversion\\run::reg query hklm\software\microsoft\windows\currentversion\\run',
    		'hklm\software\microsoft\windows\currentversion\\runonce::reg query hklm\software\microsoft\windows\currentversion\\runonce',
    		'hklm\software\microsoft\windows\currentversion\\runonceex::reg query hklm\software\microsoft\windows\currentversion\\runonceex',
    		'hkcu\software\microsoft\windows\currentversion\\run::reg query hkcu\software\microsoft\windows\currentversion\\run',
    		'hkcu\software\microsoft\windows\currentversion\\runonce::reg query hkcu\software\microsoft\windows\currentversion\\runonce',
    		'hkcu\software\microsoft\windows\currentversion\\runonceex::reg query hkcu\software\microsoft\windows\currentversion\\runonceex'
    		]
	elif os_type is "osx":
    		cmds = [
    		'Files with SUID/GUID bits set::find / -type f \( -perm +4000 -o -perm +2000 \) -exec ls -l {} \; 2>/dev/null',
    		'Large Files >50M::find / -size +50000k -print',
    		'Suspicious Files "..."::find / -name "..." -print',
    		'Suspicious Files ".."::find / -name ".." -print',
    		'Suspicious Files "."::find / -name "." -print',
    		'Processes using Unlinked Files::lsof +L1',
    		'Suspicious Directories and Files::find / -name "..*"',
    		'Hidden Directories and Files::find / -name ".*"',
    		'Files Modified in the Last 24 Hours::find / -type f -mtime 0 -ls',
    		'Orphaned Files Without a User or Group::find / -nouser -nogroup'
    		]
	elif os_type is "freebsd":
    		cmds = [
    		'Files with SUID/GUID bits set::find / -perm 4000 -o -perm 2000 -ls',
    		'Large Files >50M::find / -size +50000k -print',
    		'Suspicious Files "..."::find / -name "..." -print',
    		'Suspicious Files ".."::find / -name ".." -print',
    		'Suspicious Files "."::find / -name "." -print',
    		'Processes using Unlinked Files::lsof +L1',
    		'Suspicious Directories and Files::find / -name "..*"',
    		'Hidden Directories and Files::find / -name ".*"',
    		'Files Modified in the Last 24 Hours::find / -type f -mtime -1 -ls',
    		'Orphaned Files Without a User or Group::find / -nouser -nogroup'
    		]

	run_cmds(cmds)
	outputfile.write("\n")

# Collect scheduled task information based on identified operating system type
# Make sure the "--check-all" or "--sched_tasks" arguments have been chosen
if options.allchecks or options.tasks:
	print "Gathering Scheduled Task Information..."
	outputfile.write("""
############################################## 
#
#	Scheduled Task Information		
#
##############################################
	""")

		# Linux, FreeBSD, Windows,and OSX Task Related Commands
		#
		#	This list can easily be modified to include additional commands. Use the "<description>::<command>" format.
		#
		#	|	|	|
		#	V	V	V
		#
	if os_type is "linux":
    		cmds = [
    		'Cron Jobs Scheduled by Root::crontab -u root -l',
    		'/etc/crontab Contents::cat /etc/crontab',
    		'Systemwide Cron Jobs::ls -la /etc/cron.*'
    		]
	elif os_type is "windows":
    		cmds = [
    		'Scheduled Tasks::schtasks',
    		'Startup Items::wmic startup list full'
    		]
	elif os_type is "osx":
    		cmds = [
    		'Cron Jobs Scheduled by Root::crontab -u root -l',
    		'/etc/crontab Contents::cat /etc/crontab',
    		'Systemwide Cron Jobs::ls -la /etc/cron.*; ls -la /var/cron/tabs/'
    		]		
	elif os_type is "freebsd":
    		cmds = [
    		'Cron Jobs Scheduled by Root::crontab -u root -l',
    		'/etc/crontab Contents::cat /etc/crontab',
    		'Systemwide Cron Jobs::ls -la /etc/cron.*; ls -la /var/cron/tabs/'
    		]		

	run_cmds(cmds)
	outputfile.write("\n")

# Collect user information based on identified operating system type
# Make sure the "--check-all" or "--user" arguments have been chosen
if options.allchecks or options.user:
	print "Gathering Account and User Information..."
	outputfile.write("""
############################################## 
#
#	Account and User Information		
#
##############################################
	""")

		# Linux, FreeBSD, Windows, and OSX Account Related Commands
		#
		#	This list can easily be modified to include additional commands. Use the "<description>::<command>" format.
		#
		#	|	|	|
		#	V	V	V
		#
	if os_type is "linux":
    		cmds = [
    		'Currently Logged In Users::w',
    		'Last Logged In Users::last',
    		'Failed Login Attempts::lastb',
    		'/etc/passwd Contents::cat /etc/passwd| sort -nk3 -t:',
    		'Accounts with UID 0::getent passwd |egrep \':0+\'',
    		'/etc/group Contents:: cat /etc/group'
    		]
	if os_type is "windows":
    		cmds = [
    		'Local Accounts and Security Settings::wmic useraccount',
    		'Accounts in the Local Administrators Group::net localgroup administrators'
    		]
	if os_type is "osx":
    		cmds = [
    		'Currently Logged In Users::w',
    		'Last Logged In Users::last',
    		'User Accounts::dscacheutil -q user',
    		'Groups:: dscacheutil -q group'
    		]
	if os_type is "freebsd":
    		cmds = [
    		'Currently Logged In Users::w',
    		'Last Logged In Users::last',
    		'/etc/passwd Contents::cat /etc/passwd| sort -nk3 -t:',
    		'Accounts with UID 0::getent passwd |egrep \':0+\'',
    		'/etc/group Contents:: cat /etc/group'
    		]

	run_cmds(cmds)
	outputfile.write("\n")

# Collect log and history information based on identified operating system type
# Make sure the "--check-all" or "--log_events" arguments have been chosen
if options.allchecks or options.logs:
	print "Gathering History Files and Log Data..."
	outputfile.write("""
############################################## 
#
#	History Files and Log Data	     
#
##############################################
	""")

	if os_type is "linux":
		# Linux History Collecting Commands
		#
		#	This list can easily be modified to include additional commands. Use the "<description>::<command>" format.
		#
		#	|	|	|
		#	V	V	V
		#
    		cmds = [
    		'Bash History::bash -i -c "history -r; history"'
    		]
    		run_cmds(cmds)
    		outputfile.write("\n")

		# There are several more history files and log files that we need to collect. The formatting of these files is such
		# that we cant use the command execution definition. The commands and formatting have to be done here.
    		
		outputfile.write(timestamp()+"\tOther History Files and Their Contents:\n")
    		outputfile.write("===========================================================\n\n")
    		p = subprocess.Popen('find / -name .*history', stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
    		for line in p.stdout.readlines():
			if "find:" not in line:
	    			outputfile.write("\n"+line+"\n")
	    			r = subprocess.Popen('cat '+line, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
	    			for line in r.stdout.readlines():
	    				outputfile.write("\t"+line)
	    	outputfile.write("\n")

    		outputfile.write(timestamp()+"\tLast 100 Lines of Log File Contents:\n")
    		outputfile.write("===========================================================\n\n")
		# Linux Log Files
		#
		#	This list can easily be modified to include the locations of other log files. Include full path to file.
		#
		#	|	|	|
		#	V	V	V
		#
    		log_files = [
    		'/var/log/auth.log',
    		'/var/log/auth.log.1',
    		'/var/log/daemon.log',
    		'/var/log/daemon.log.1',
    		'/var/log/kern.log',
    		'/var/log/kern.log.1',
    		'/var/log/mysql.log',
    		'/var/log/mysql.log.1',
    		'/var/log/syslog',
    		'/var/log/apache2/access.log',
    		'/var/log/apache2/access.log.1',
		'/var/log/secure',
		'/var/log/messages'
    		]
    		for file in log_files:
	    		outputfile.write("\n"+file+"\n")
	    		r = subprocess.Popen('tail -100 '+file, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
	    		for line in r.stdout.readlines():
	    			outputfile.write("\t"+line)
	    	outputfile.write("\n")

	if os_type is "windows":
		# Windows Log Files
		#
		#	This list can easily be modified to include the locations of other log files.
		# 	A list of available Windows log files can be found with "wevtutil el".
		#
		#	|	|	|
		#	V	V	V
		#

    		outputfile.write(timestamp()+"\tLast 100 Events from Log Files:\n")
    		outputfile.write("===========================================================\n\n")
    		log_files = [
    		'Security',
    		'Application',
    		'System'
    		]
    		for file in log_files:
	    		outputfile.write("\n Log File - "+file+"\n")
    			r = subprocess.Popen('wevtutil qe '+file+' /rd:true /c:100 /e:Events /f:text', stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
    			for line in r.stdout.readlines():
    				outputfile.write("\t"+line)
    		outputfile.write("\n")

	if os_type is "osx":
		# OSX History Collecting Commands
		#
		#	This list can easily be modified to include additional commands. Use the "<description>::<command>" format.
		#
		#	|	|	|
		#	V	V	V
		#
    		cmds = [
    		'Bash History::bash -i -c "history -r; history"',
    		'Last 1000 Lines of Syslog::syslog |tail -n 1000'
    		]
    		run_cmds(cmds)
    		outputfile.write("\n")

		# There are several more history files and log files that we need to collect. The formatting of these files is such
		# that we cant use the command execution definition. The commands and formatting have to be done here.

    		outputfile.write(timestamp()+"\tOther History Files and Their Contents:\n")
    		outputfile.write("===========================================================\n\n")
    		p = subprocess.Popen('find / -name .*history', stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
    		for line in p.stdout.readlines():
			if "find:" not in line:
	    			outputfile.write("\n"+line+"\n")
	    			r = subprocess.Popen('cat '+line, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
	    			for line in r.stdout.readlines():
	    				outputfile.write("\t"+line)
	    	outputfile.write("\n")

    		outputfile.write(timestamp()+"\tLast 100 Lines of Other Log File Contents:\n")
    		outputfile.write("===========================================================\n\n")
		# OSX Log Files
		#
		#	This list can easily be modified to include the locations of other log files. Include the full path.
		#
		#	|	|	|
		#	V	V	V
		#

    		log_files = [
    		'/var/log/system.log'
    		]
    		for file in log_files:
	    		outputfile.write("\n"+file+"\n\n")
	    		r = subprocess.Popen('tail -100 '+file, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
	    		for line in r.stdout.readlines():
	    			outputfile.write("\t"+line)
	    	outputfile.write("\n")

	if os_type is "freebsd":
		# FreeBSD History Collecting Commands
		#
		#	This list can easily be modified to include additional commands. Use the "<description>::<command>" format.
		#
		#	|	|	|
		#	V	V	V
		#
    		cmds = [
    		'Bash History::bash -i -c "history -r; history"'
    		'C Shell History::csh -i -c "history -r; history"'
    		]
    		run_cmds(cmds)
    		outputfile.write("\n")

		# There are several more history files and log files that we need to collect. The formatting of these files is such
		# that we cant use the command execution definition. The commands and formatting have to be done here.
    		
		outputfile.write(timestamp()+"\tOther History Files and Their Contents:\n")
    		outputfile.write("===========================================================\n\n")
    		p = subprocess.Popen('find / -name .*history', stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
    		for line in p.stdout.readlines():
			if "find:" not in line:
	    			outputfile.write("\n"+line+"\n")
	    			r = subprocess.Popen('cat '+line, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
	    			for line in r.stdout.readlines():
	    				outputfile.write("\t"+line)
	    	outputfile.write("\n")

    		outputfile.write(timestamp()+"\tLast 100 Lines of Log File Contents:\n")
    		outputfile.write("===========================================================\n\n")
		# FreeBSD Log Files
		#
		#	This list can easily be modified to include the locations of other log files. Include full path to file.
		#
		#	|	|	|
		#	V	V	V
		#
    		log_files = [
    		'/var/log/auth.log',
		'/var/log/security',
		'/var/log/userlog',
		'/var/log/messages'
    		]
    		for file in log_files:
	    		outputfile.write("\n"+file+"\n")
	    		r = subprocess.Popen('tail -100 '+file, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
	    		for line in r.stdout.readlines():
	    			outputfile.write("\t"+line)
	    	outputfile.write("\n")

#Close the user specified outfile
outputfile.close()

######################
# Reporting - Result Hash
######################

#MD5 hash the output file
if options.hash:
	hashfile=open(options.outfile+"-hash","a")
	results=open(options.outfile,'rb')
	hashresults=results.read()
	results.close()
	md5 = hashlib.md5()
	md5.update(hashresults)
	md5sum=md5.hexdigest()
	hashfile.write(md5sum)
	hashfile.close()

