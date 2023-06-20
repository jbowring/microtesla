# microtesla

### Barebones MicroPython implementation of the unofficial Tesla API
Hugely inspired by the full-featured [TeslaPy](https://github.com/tdorssers/TeslaPy) Python library. Many thanks to those who have spent their time discovering the undocumented API endpoints.

This is a stripped-down version of TeslaPy that (for now) just returns vehicle data. This library has been written for and tested on the Raspberry Pi Pico W; your mileage may vary with other MicroPython ports.

## Usage
Include `microtesla.py` in your sources directory and import the module with `import microtesla`. See [example section](#example) below for reference.

### Authentication
When the module is first called, you will be asked to authenticate with the Tesla API by copy/pasting a URL into a browser, signing in, and copy/pasting the resulting URL back into the MicroPython terminal. This process only needs to be completed once as the module saves the OAuth refresh token for use following a reboot.

Example terminal printout during first login flow:
```
>>> Open this URL: https://auth.tesla.com/oauth2/v3/authorize?code_challenge=HIuhIuh78G7G78VvikAnannsadsaO87k3kjkBzDdDD&response_type=code&client_id=ownerapi&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fauth.tesla.com%2Fvoid%2Fcallback&scope=openid+email+offline_access
>>> Enter URL after authentication: <paste here>
```
After signing in, the browser will redirect to a dummy page `https://auth.tesla.com/void/callback` and show a _Page Not Found_ error. This is expected; paste the full URL into the MicroPython terminal.

### API access
Two API endpoints are exposed by the module:

* `get_vehicle_summary` Top-level information about a vehicle, such as the display name, VIN, online/offline status, ID, colour etc.

* `get_vehicle_data` Most of the information returned by `get_vehicle_summary` plus:
  * Vehicle configuration: _seat/trim types, ludicrous mode, sun roof, charge port type, performance package etc._
  * Charge state: _battery level, charger power, battery heater, charge rate, time until fully charged, range etc._
  * Climate state: _heaters, defrost settings, inside/outside temperatures etc._
  * Drive state: _navigation info, GPS info, speed, power etc._
  * Vehicle state: _software updates, odometer, remote start, TPMS, locked/unlocked, media playback, dashcam, speed limit etc._
  * GUI settings: _distance/time/range/power/temperature units etc._

See full (unofficial) documentation at [tesla-api.timdorr.com](https://tesla-api.timdorr.com).

A `VehicleUnavailable` exception will be raised if the vehicle is offline when data is requested.

## Example
```python
import microtesla

tesla = microtesla.MicroTesla()
vehicle = tesla.get_vehicle_list()[0]

print(f'"{vehicle["display_name"]}" is {vehicle["state"]}')

try:
    print(tesla.get_vehicle_summary(vehicle['id']))
    print(tesla.get_vehicle_data(vehicle['id']))
except microtesla.VehicleUnavailable as exception:
    print('Vehicle unavailable:', exception)
```