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

# Initialize CVP client
client = CvpClient()

# Connect to CVP — token is automatically handled
client.connect(CVP_HOSTS, USERNAME, PASSWORD)

# Verify connection and list devices
containers = client.api.get_containers()
# print (containers)


''' calculate children containers '''
# dict of lists to map containers to subcontainer
children = {}
root = ""

''' add children to the dict '''
def add_children(p, c):
  if p not in children.keys():
    # initialize
    children[p] = []
  children[p].append(c)
  return

for container in containers['data']:
  # print (container['Name'])
  c = container['Name']
  p = container['parentName']
  if not p:
    # root
    root = c
  else:
    add_children(p, c)

''' get the devices '''
inventory = client.api.get_inventory()
for device in inventory:
  p = device['containerName']
  c = device['hostname']
  add_children(p, c)


''' recursively print branches '''
def make_branches(tree, p):
  if p in children.keys() and len(children[p]) != 0:
    for c in children[p]:
      branch = tree.add(c)
      make_branches(branch, c)
  return

tree = Tree(root)
make_branches(tree, root)
print(tree)



''' dump inventory in YAML '''
# print (
#   yaml.dump(inventory)
# )

