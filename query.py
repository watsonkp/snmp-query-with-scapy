from time import sleep
from datetime import datetime
from scapy.all import sr1,IP,UDP,SNMP,SNMPget,SNMPvarbind,snmpwalk,load_mib,conf,SNMPnext,ASN1_OID

# OID
# OS Name: 1.3.6.1.4.1.674.10892.5.1.3.6.0
# OID groups on page 9

dst = '10.42.0.143'
root_oid = '1.3.6.1.4.1.674.10892'
system_information_root_oid = '1.3.6.1.4.1.674.10892.5.1.3'
temperature_probe_table_root_oid = '1.3.6.1.4.1.674.10892.5.4.700.20'
temperature_probe_reading_oid = '1.3.6.1.4.1.674.10892.5.4.700.20.1.6'
temperature_probe_location_name_oid = '1.3.6.1.4.1.674.10892.5.4.700.20.1.8'

# Reference
# https://scapy.readthedocs.io/en/latest/advanced_usage.html

def walk(root_oid):
	oid = root_oid
	values = []
	while True:
		response = sr1(IP(dst=dst)/UDP(dport=161)/SNMP(version=1, community='public', PDU=SNMPnext(varbindlist=[SNMPvarbind(oid=oid)])), verbose=0)

		if response is None:
			print('No answer')
			break

		next_oid = response[SNMPvarbind].oid.val

		if next_oid[:len(root_oid)] != root_oid:
			break
		value = response[SNMPvarbind].value
		values.append((next_oid, value))

		oid = response[SNMPvarbind].oid
	return values

def filter_values(prefix, values):
	return [value
			for value in values
			if value[0][:len(prefix)] == prefix]

# Dell mibs from:
# https://www.dell.com/support/home/en-ca/drivers/driversdetails?driverid=jm9xj&oscode=ws19l&productcode=poweredge-r240
# RFC 2511 from /usr/share/snmp/mibs-downloader/mibrfcs/
load_mib('mibs/*')

while True:
	coolingDeviceReadings = walk(conf.mib.coolingDeviceReading)
	coolingDeviceLocationNames = walk(conf.mib.coolingDeviceLocationName)
	temperatureProbeTable = walk(temperature_probe_table_root_oid)

	temperature_readings = filter_values(temperature_probe_reading_oid, temperatureProbeTable)
	temperature_locations = filter_values(temperature_probe_location_name_oid, temperatureProbeTable)

	cooling_devices = {}
	for reading in coolingDeviceReadings:
		suffix = reading[0][len(conf.mib.coolingDeviceReading):]
		device = cooling_devices.get(suffix, {})
		device['value'] = reading[1].val
		cooling_devices[suffix] = device
	for name in coolingDeviceLocationNames:
		suffix = name[0][len(conf.mib.coolingDeviceLocationName):]
		device = cooling_devices.get(suffix, {})
		device['name'] = name[1].val
		cooling_devices[suffix] = device
	fans = '\n'.join([f"{device['name'].decode('utf-8')}: {device['value']}" for device in cooling_devices.values()])

	temperature_probes = {}
	for reading in temperature_readings:
		suffix = reading[0][len(temperature_probe_reading_oid):]
		device = temperature_probes.get(suffix, {})
		device['value'] = reading[1].val
		temperature_probes[suffix] = device
	for name in temperature_locations:
		suffix = name[0][len(temperature_probe_location_name_oid):]
		device = temperature_probes.get(suffix, {})
		device['name'] = name[1].val
		temperature_probes[suffix] = device
	temperatures = '\n'.join([f"{probe['name'].decode('utf-8')}: {probe['value'] / 10}" for probe in temperature_probes.values()])

	# TODO: https://docs.python.org/3/howto/curses.html
	print(datetime.now())
	print(temperatures + '\n\n' + fans + '\n')

	sleep(5)
