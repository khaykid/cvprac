from rich.tree import Tree
from rich import print

tree = Tree("Root")
branch1 = tree.add("Branch 1")
branch1.add("Leaf 1.1")
branch1.add("Leaf 1.2")
branch2 = tree.add("Branch 2")
branch2.add("Leaf 2.1")
print(tree)