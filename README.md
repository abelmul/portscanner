# Port Scanner

The following project is an implementation of a port scanner using `C`. A Port Scanner is a tool
which is used in order to determine what specific ports are open within a system. Security experts
could then use this information to guide them in designing exploits. The following sections breifly
discuss how to build and run the system.

## Build

A `makefile` is included thus in order to build the project just do:

`make portscanner`

## Run

`./prtsc [options] [target_ip]`

[might need `sudo` privilages to run some of the options]

where `[target_ip]` is the ip adress of the machine to be scanned.
The `options` are breifly discussed in the next sub-section.

### Options

The following options maybe specified inorder to specify which kind of scanning techinque is to be used.
The project implements 4 scanning techinques. They can be specified as follows:

`-sT` : This specifies the TCP connect scanning mode. In this mode super user privilages are not needed
inorder to carry out scans, as a full TCP connection is estabilished and the details are handled by the OS.

`-sS` : This specifies a SYN scan, in which a TCP packect with the SYN flag on is sent and the tool waits for a SYN/ACK response.
If one is recieved indicating that the port is `open`, a RST is sent back inorder not to trigger a denial of service attack.
Otherwise if a RST is recieved the port is `closed`. No response might indicate that the port might be filtered. This type of scan requires super user privilages, as raw sockets are used.

`-sU` : This option specifies a UDP scan. This works by sending a UDP packet to every port, if no response is received after retransmissions, the port is classified as `open`. 

`-sF` : This option specifies a FIN scan. In this type of scan, a TCP packet with the FIN bit on is sent. If a RST is recieved the port is considered `closed`. If no response is recieved the it is labelled as `open|filtered`. This type of scan requires super user privilages, as raw sockets are used.

###