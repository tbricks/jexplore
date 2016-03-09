import sys

try:
  import gdb
except ImportError:
  print("Error: only usable from within gdb")
  sys.exit(0)
