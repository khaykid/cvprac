import urllib3
urllib3.disable_warnings()
from cvprac.cvp_client import CvpClient
from rich.tree import Tree
from rich import print
import yaml

# CVP connection settings
CVP_HOSTS = ['10.18.148.95']
# CVP_HOSTS = ['10.18.163.120']
USERNAME = 'cvpadmin'
PASSWORD = 'cvpadmin123!'
CONTAINER = 'Firewalls'

# Initialize CVP client
client = CvpClient()

'''
Validate the configlets for devices in a container,
Create the Reconciliation Configlet,
Apply it to the device
Result = all devices should be in compliance
Author: Khay Kid Chow (June 2025)
'''

# Connect to CVP — token is automatically handled
client.connect(CVP_HOSTS, USERNAME, PASSWORD)

# List of : {Device Name, MAC}
device_info = [
  {"name": device["fqdn"], "macAddress": device["systemMacAddress"]}
  for device in client.api.get_devices_in_container(CONTAINER)
]

print (device_info)

for info in device_info:
  print (f"Validating Configlets for {info["name"]}")
  device_mac = info["macAddress"]
  device_short_name = info["name"]
  reconcile_configlet_name = f"{device_short_name} RECONCILE"
  device = client.api.get_device_by_name( device_short_name )

  try:
    # get configlet list
    configlets = client.api.get_configlets_by_device_id(device_mac)
  except Exception as e:
    print( f"Error getting configlets for device {info['name']}: {e}" )

  configlet_key_list = [configlet['key'] for configlet in configlets]

  try:
    # validate configlets
    result = client.api.validate_configlets_for_device(device_mac, configlet_key_list, 'validateConfig')
    # print (result)
  except Exception as e:
    print( f"Error validating configlets for device {info['name']}: {e}" )

  if result['reconciledConfig']:
    print ("Reconcile needed")

    # check if old reconcile exists
    rec_configlet = [
      configlet for configlet in configlets 
      if configlet['name']==reconcile_configlet_name
    ]

    # exists - remove it first
    if rec_configlet:
      print ("Found old reconcile configlet")
      configlet_name_key = [
        {"name": reconcile_configlet_name, "key": rec_configlet[0]['key']}
      ]
      try:
        client.api.remove_configlets_from_device(
          "Remove Reconcile", device, configlet_name_key
        )
        print ("Old reconcile configlet removed from device")
      except Exception as e:
        print( f"Error removing configlets from device {info['name']}: {e}" )

      try:
        client.api.delete_configlet( reconcile_configlet_name, rec_configlet[0]['key'] )
        print ("Old reconcile configlet deleted")
      except Exception as e:
        print( f"Error deleting old reconcile configlets for device {info['name']}: {e}" )

      # run validate again without the old reconcile configlet
      configlets = [
        configlet for configlet in configlets 
        if configlet['name']!=reconcile_configlet_name
      ]
      configlet_key_list = [configlet['key'] for configlet in configlets]

      try:
        # validate configlets
        result = client.api.validate_configlets_for_device(device_mac, configlet_key_list, 'validateConfig')
      except Exception as e:
        print( f"Error validating configlets for device {info['name']}: {e}" )

    # need to create a new reconcile configlet
    if result['reconciledConfig']:
      print ("Need to create a new reconcile configlet")

      # create configlet
      try:
        new_configlet_key = client.api.add_configlet(reconcile_configlet_name, result['reconciledConfig']['config'])
        print (f"Reconciliation created: {reconcile_configlet_name}")
      except Exception as e:
        print( f"Error creating new reconcile configlets for device {info['name']}: {e}" )

      # apply configlet to device
      configlet_name_key = [
          {"name": reconcile_configlet_name, "key": new_configlet_key}
      ]

      try:
        client.api.apply_configlets_to_device(
          "Management Configs", device, configlet_name_key
        )
        print (f"Reconciliation applied to device")
      except Exception as e:
        print( f"Error applying new reconcile configlets to device {info['name']}: {e}" )
        
    else:
      print ("No reconciliation after deleting old reconcile configlet")

  else:
    print ("No Reconciliation")


tasks = client.api.get_tasks_by_status("Pending")
if tasks:
  print ("Execute Tasks")
  for task in tasks:
    client.api.execute_task(task["workOrderId"])
