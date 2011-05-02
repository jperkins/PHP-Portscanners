
# TCP Port Scanner #

## refactor ##

- verify that set_time_limit() is required
- deal with exceptions thrown by fsockopen

- validate we've received a valid dotted quad ip addy (only IPv4 for now)
- validate that the starting port number is between 1 and 1024
- validate that the ending port number is between 1 and 1024
- validate that the ending port number is before the starting point number

- modify to allow for hostname to be supplied and we'll do the ip lookup
- modify to accept IPv6 addresses
- modify to accept an array of target ips
- modify to accept a range of target ips

- introduce a log object (roll in the debug console output?)
- give log object a debug flag that will output to STDOUT as well as a logfile
- modify output to direct to the log object


## done ##

- filename extensions changed to .php
- class name and formatting
- method names, visibility and formatting
- variable names and formatting
    - minPort => startPort
    - maxPort => endPort
    - ports => openPorts


# UDP Port Scanner



