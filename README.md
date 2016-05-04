Linux Process Monitoring
========================

### procmon ###

Procmon creates a log of every single command that is executed on a Linux system.  This is not a security tool, procmon filters out commands run as root since the kernel is always very busy doing important things.  The goal is to monitor what tools and languages users are running.  

procmon uses the cn_proc interface to the Linux Kernel. procmon receives every single kernel exec call issued and writes the contents of /proc/pid/cmdline to a log file along with the UID of the process.  The cn_proc interface uses a socket interface and the messages are queued so nothing is dropped.  The data is super cool with lots of detail about what processes are run. Simple commands like "make" are exploded into all the small processes along with the huge command line argument list for gcc. The linux command line can be 4k in size and every bit of it is being logged by procmon.  Command line tools like ps and top truncate the command line strings.  On  a busy system procmon can produce a firehose worth of data, multiply this by a few hundred nodes and the data is no longer usable by humans.  It is expected that the output will be managed by Splunk or Elasticsearch for analysis.  

procmon uses rsyslog to write its output to /var/log/procmon. A rsyslogd configuration file is part of the package. procmon writes its data in JSON format. The JSON output from procmon is designed to be ingested by Splunk or Elasticsearch. Monitor the size of your output file and adjust the frequency of the output truncation. A logrotate configuration file is part of the download.

procmon is written as daemon for non systemd Linux systems. The process must run
as root. 

### Performance ###
procmon is proving to be very efficient. After one week on a live system the CPU 
utilization of procmon is 0.05%. The compiled C code is only 13KB in size. 

### HPC Cluster Use ###
Job schedulers do an excellent job of logging every job run on a cluster but the 
accounting data does not have enough detail to understand "what" applications 
are running on a cluster.  Typical cluster jobs are wrapper scripts. These wrapper 
scripts obfuscate the names of the actual executables that are bing run on a cluster. 
Collecting every user process can bring real insight into what scientific software 
and their versions are running on your cluster.

### Install ###
Build the binary with make procmon then run "install".
Procmon installs its own logrotate and rsyslog configuration files. Edit /etc/logrotate.d/procmon
to customize the amount of data kept on the local system.


### Author ###
John Dey
Feb 2016

