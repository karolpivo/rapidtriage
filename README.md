# rapidtriage

This project was exported from code.google.com/p/rapidtriage due to Google closing down Google Code.

RapidTriage was developed by Trenton Bond - trent.bond@gmail.com. All credits go to Trent.

# Introduction 
RapidTriage quickly collects critical information from key areas of the operating system to assist information security incident handlers in determining whether or not there has been compromise. Often this process of collecting information is manual and time consuming particularly when multiple systems are suspect. RapidTriage may be deployed to many systems and the results analyzed relative to each other to help the incident handler prioritize where to focus their containments efforts. Frequently, the incident handler does not have immediate access or authorization to the systems in question and getting it setup can be time consuming. RapidTriage can be quickly provided to authorized system administrators to collect the critical information many times used to help identify a compromise. Beside speed to deploy and overcoming access barriers, the other major benefits of using RapidTriage include:

- Ability to add/modify collection commands or event sources as necessary
- Consistent results and output format
- Ability to choose specific operating system areas to collect from
- Single collection script to maintain for multiple operating systems

# Details

```
Usage: python RapidTriage.py [argument(s)] -o <filename>

Options:
  -h, --help           show this help message and exit
  -o OUTFILE           specified file will contain the results of RapidTriage

  Arguments (one or more system areas required):
    -a, --all_areas    collect information from all areas
    -f, --filesystem   collect filesystem related information
    -l, --log_events   collect histories and log data
    -n, --net_stats    collect network stats and config information
    -p, --process      collect process, service, and module information
    -t, --sched_tasks  collect scheduled task information
    -u, --user         collect user account and configuration information

  Optional:
    -m, --md5sum       generate an md5 hash of the results file (<filename>)
                       and place in <filename>-hash
```

###Supported Python Version: 

- 2.7

###Supported Operating Systems

- Linux (2.6.x)
- Mac (OSX 10.2.x)
- Windows 7
- FreeBSD 9

Note: Python is not installed by default in Windows. For suspect Windows systems where Python is not installed considering using the “py2exe” “Distutils” extension to convert RapidTriage into an executable Windows program. Then have the system administrators execute the RapidTriage.exe program to collect the desired information.

    RapidTriage.exe [aflnptu] [options] -o <filename>

#Changing what is collected and how:

Many sections of the script include lists of commands and a description. To add or modify the commands that are used to collect information simply use the following format:

    <description>::<command>

Make sure to modify the list corresponding to the appropriate operating system type. For example, to modify the network information collected for a Linux system find and change the network "cmds" list using the above syntax:
```
############################################## 
#
#       Network Information                  
#
##############################################

                # Linux, Windows,and OSX Network Related Commands
                #
                #       This list can easily be modified to include additional commands. Use 
                #      the "<description>::<command>" format when adding or modifying.
                #
                #       |       |       |
                #       V       V       V
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
```
