import network
import microtesla

wlan = network.WLAN(network.STA_IF)
wlan.active(True)
wlan.connect('ssid', 'password')
while not wlan.isconnected():
    pass

tesla = microtesla.MicroTesla()
vehicle = tesla.get_vehicle_list()[0]

print(f'"{vehicle["display_name"]}" is {vehicle["state"]}')

try:
    print(tesla.get_vehicle_data(vehicle['id_s']))
except microtesla.VehicleUnavailable as exception:
    print('Vehicle unavailable:', exception)
