# jexplore

import sys
import warnings

true = True
false = False

class heap:

  def __init__(self, chunksize=2097152):
    self.chunksize = chunksize
    self.sections = {}
    self.threads = {}

class run:

  def __init__(self, mapbits):
    self.mapbits = mapbits

  def is_allocated(self):
    if (self.mapbits & 0x1 != 0):
      return true
    else:
      return false

  def is_large(self):
    if (self.mapbits & 0x2 != 0):
      return true
    else:
      return false

  def is_decommitted(self):
    if (self.mapbits & 0x4 != 0):
      return true
    else:
      return false

  def is_unzeroed(self):
    if (self.mapbits & 0x8 != 0):
      return true
    else:
      return false

  def is_dirty(self):
    if (self.mapbits & 0x10 != 0):
      return true
    else:
      return false
