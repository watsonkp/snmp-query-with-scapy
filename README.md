# Fetch fan speeds and temperatures from a Dell server using SNMP

A Scapy script to repeatedly query fan speeds and temperatures using SNMP. This was an interesting experiment with SNMP and scapy, but a patch from Dell removed my use case.

Dell mibs used for OIDs are from [Dell Support site for device](https://www.dell.com/support/home/en-ca/drivers/driversdetails?driverid=jm9xj&oscode=ws19l&productcode=poweredge-r240).
Standard RFC 2511 OIDs are from a Debian package described in their [wiki](https://wiki.debian.org/SNMP) and end up in /usr/share/snmp/mibs-downloader/mibrfcs/.
