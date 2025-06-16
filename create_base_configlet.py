import urllib3
urllib3.disable_warnings()
from cvprac.cvp_client import CvpClient
from rich.tree import Tree
from rich import print
import yaml

# CVP connection settings
# CVP_HOSTS = ['10.18.148.95']
CVP_HOSTS = ['10.18.163.120']
USERNAME = 'cvpadmin'
PASSWORD = 'cvpadmin123!'

# Initialize CVP client
client = CvpClient()

'''
Create Base Configlets for all Devices in Tenant 
based on their Running Config
'''

# Connect to CVP — token is automatically handled
client.connect(CVP_HOSTS, USERNAME, PASSWORD)

# List of : {Device Name, MAC}
device_info = [
  {"name": device["fqdn"], "macAddress": device["systemMacAddress"]}
  for device in client.api.get_devices_in_container("Tenant")
]

print (device_info)

for info in device_info:
  print (f"Creating Base Configlet for {info["name"]}")
  try:
    device_mac = info["macAddress"]
    device_short_name = info["name"]
    dev_mgmt = f"{device_short_name} Base"

    # get running config
    get_config = client.api.get_device_configuration( device_mac )

    # create configlet
    client.api.add_configlet(dev_mgmt, get_config)

    # apply configlet to device
    device_name = client.api.get_device_by_name( device_short_name )
    mgmt_configlet = client.api.get_configlet_by_name(dev_mgmt)
    mgmt_configlet_key = [
        {"name": mgmt_configlet["name"], "key": mgmt_configlet["key"]}
    ]
    client.api.apply_configlets_to_device(
        "Management Configs", device_name, mgmt_configlet_key
    )
  except Exception as e:
      print(
          f"Error creating or applying configlet for device {info['name']}: {e}"
      )

print ("Execute Tasks")
tasks = client.api.get_tasks_by_status("Pending")
for task in tasks:
    client.api.execute_task(task["workOrderId"])
