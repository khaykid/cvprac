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

# Connect to CVP — token is automatically handled
client.connect(CVP_HOSTS, USERNAME, PASSWORD)

device_list = [
  {"deviceName": device["fqdn"]}
  for device in client.api.get_devices_in_container("Undefined")
]

print (device_list)

print ("Move Devices to Tenant")
for device in device_list:
  try:
    device_info = client.api.get_device_by_name( device["deviceName"] )
    new_container = client.api.get_container_by_name("Tenant")
    client.api.move_device_to_container(
      "python", device_info, new_container
    )
  except Exception as e:
    print( f"Error moving device {device['deviceName']}: {e}" )

print ("Execute Tasks")
tasks = client.api.get_tasks_by_status("Pending")
for task in tasks:
    client.api.execute_task(task["workOrderId"])

