import urllib3
urllib3.disable_warnings()
from cvprac.cvp_client import CvpClient

# CVP connection settings
CVP_HOSTS = ['10.18.148.95']
USERNAME = 'cvpadmin'
PASSWORD = 'cvpadmin123!'

# Initialize CVP client
client = CvpClient()

# Connect to CVP — token is automatically handled
client.connect(CVP_HOSTS, USERNAME, PASSWORD)

# Verify connection and list devices
inventory = client.api.get_inventory()
print("Managed devices:")
for device in inventory:
    print(f"• {device['hostname']} ({device['ipAddress']}) ({device['key']})")