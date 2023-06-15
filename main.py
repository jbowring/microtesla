import microtesla

tesla = microtesla.MicroTesla()
vehicle_list = tesla.get_vehicle_list()
print(tesla.get_vehicle_data(vehicle_list[0]['id'])['charge_state']['battery_level'])
