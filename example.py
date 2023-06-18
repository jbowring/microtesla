import network
import microtesla

wlan = network.WLAN(network.STA_IF)
wlan.active(True)
wlan.connect('ssid', 'password')
while not wlan.isconnected():
    pass

tesla = microtesla.MicroTesla()
vehicle = tesla.get_vehicle_list()[0]

print(vehicle)
print(tesla.get_vehicle_data(vehicle['id_s']))

