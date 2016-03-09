# jexplore

import os
import sys
import warnings
import math
import re
import pdb

sys.path.append('.')
sys.path.append('./jexplore')

from gdbwrap import *
import jemalloc
import documentation

true = True
false = False

heap = jemalloc.heap()

def is_chunk_aligned(ptr):
  try:
    bit = gdb.execute("p (({}&je_chunksize_mask)||0x00000)==0x0".format(ptr), to_string = true).split()[2]
  except RuntimeError:
    print("Error type: {}, Description: {}".format(sys.exc_info()[0], sys.exc_info()[1]))
    sys.exit(0)

  return bool(bit)

def validate_chunk(ptr, silent = true):

  chunk = gdb.execute("p/x (((uintptr_t){})&~je_chunksize_mask)".format(ptr), to_string = true).split()[2]
  lg = math.log(int(ptr,16),2)
  lg_floor = math.floor(lg)

  try:
    gdb.execute("p/x $ptr=%s" % (chunk), to_string = true)
    gdb.execute("p $lg_floor=%d" %(lg_floor), to_string = true)
    chunks_rtree = gdb.execute("p/x je_chunks_rtree", to_string = true).split()[2]
    start_level = gdb.execute("p $start_level = je_chunks_rtree->start_level[$lg_floor>>macro_LG_RTREE_BITS_PER_LEVEL]", to_string = true).split()[2] # 4
    height = gdb.execute("p $height = je_chunks_rtree->height", to_string = true).split()[2]
    next_node = gdb.execute("p $next_node = je_chunks_rtree.levels[$start_level].subtree", to_string = true).split()[4]
    next_subkey = gdb.execute("p $next_subkey = (($ptr>>(((size_t)(1) << (macro_LG_SIZEOF_PTR + 3))-\
    je_chunks_rtree.levels[$start_level].cumbits)) & (((size_t)(1) << \
    je_chunks_rtree.levels[$start_level].bits)-1))", to_string = true).split()[2] # 6

    if not silent:
      print("je_chunks_rtree start_level {} {}".format(chunks_rtree, start_level))
      print("next_node next_subkey {} {}".format(next_node, next_subkey))

    if (next_node == "0x0"):
      freed = true
    else:
      freed = false

      for i in range(int(start_level)+1,int(height)):
        next_node = gdb.execute("p $next_node = $next_node[$next_subkey]->child", to_string = true).split()[4]
        if (next_node == '0x0'):
          freed = true
          break
        next_subkey = gdb.execute("p $next_subkey = (($ptr>>(((size_t)(1) << (macro_LG_SIZEOF_PTR + 3))-\
        je_chunks_rtree.levels[%d].cumbits)) & (((size_t)(1) << \
        je_chunks_rtree.levels[%d].bits)-1))" % (i,i), to_string = true).split()[2]

        if not silent:
          print("next_node next_subkey {} {}".format(next_node, next_subkey))

    if (freed == false):
      extent_node = gdb.execute("p $extent_node=$next_node[$next_subkey]->val", to_string = true).split()[4]
    else:
      extent_node = "0x0" 

  except RuntimeError:
    print("Error type: {}, Description: {}".format(sys.exc_info()[0], sys.exc_info()[1]))
    sys.exit(0)

  if (extent_node == "0x0"):
    return (chunk, "0x0", "0x0")
  else:
    try:
      achun = gdb.execute("p $extent_node->en_achunk", to_string = true).split()[2]
      arena = gdb.execute("p $extent_node->en_arena", to_string = true).split()[4]
    except RuntimeError:
      print("Error type: {}, Description: {}".format(sys.exc_info()[0], sys.exc_info()[1]))
      sys.exit(0)

  if achun == "true":
    return (chunk, arena, extent_node)

  return (chunk, "0x0", extent_node)

####### exported gdb commands ######

class je_help(gdb.Command):
  '''Details about the commands provided by je_analyzer'''

  def __init__(self):
    gdb.Command.__init__(self, "je_help", gdb.COMMAND_OBSCURE)

  def invoke(self, arg, from_tty):
    print(documentation.text)

class je_threads(gdb.Command):
  '''Give info on thread caches'''

  def __init__(self):
    gdb.Command.__init__(self, "je_threads", gdb.COMMAND_OBSCURE)

    global heap

    try:
      infos = gdb.execute("info threads", to_string = true)
      for info in infos.splitlines():
        m = re.match(".*([0-9]+).*(0x[0-9a-fA-F]*) \(LWP ([0-9]*)\).*", info)
        if m is None:
          continue
        idx = m.group(1)
        threadp = m.group(2)
        pid = m.group(3)
        
        gdb.execute("thread {}".format(idx), to_string = true)
        tsd = gdb.execute("p je_tsd_tls", to_string = true)
        m = re.match(".*tcache = (0x[0-9a-fA-F]+).*thread_allocated = ([0-9]+).*thread_deallocated = ([0-9]+).*", tsd)
        if m is None:
          print("The core file seems corrupted, TLS data is not available for thread {}".format(pid))
          return

        heap.threads[idx] = {"thread pointer":threadp, "pid":pid, "tcache":m.group(1), "talloc":m.group(2), "tfree":m.group(3)}

    except RuntimeError:
      print("Error type: {}, Description: {}".format(sys.exc_info()[0], sys.exc_info()[1]))
      sys.exit(0)

  def invoke(self, arg, from_tty):
    global heap
    for t,p in heap.threads.items():
      print("Thread #{}".format(t))
      for p,v in p.items():
        print("\t{}: {}".format(p, v))

class je_scan_sections(gdb.Command):
  '''Evaluate which sections belong to heap'''

  def __init__(self):
    gdb.Command.__init__(self, "je_scan_sections", gdb.COMMAND_OBSCURE)

    global heap
    try:
      heap.chunksize = int(gdb.execute("p je_chunksize", to_string = true).split()[2])
    except RuntimeError:
      print("Error type: {}, Description: {}".format(sys.exc_info()[0], sys.exc_info()[1]))
      sys.exit(0)

  def invoke(self, arg, from_tty):
    if len(arg) < 1:
      step = 16
    arg = arg.split()
    step = int(arg[0])
    
    #check all mappings with RW 
    try:
      sections = gdb.execute("maint info sections", to_string = true)
    except RuntimeError:
      print("Error type: {}, Description: {}".format(sys.exc_info()[0], sys.exc_info()[1]))
      sys.exit(0)

    global heap
      
    for section in sections.splitlines():
      if re.search("ALLOC LOAD HAS_CONTENTS$", section) != None:
        beg, end, *misc = re.findall("0x[0-9a-fA-F]*", section)

        if beg in heap.sections:
          continue

        ptr = (int(beg, 16) & ~(heap.chunksize-1))
        if (ptr != int(beg, 16)):
          continue

        print("Potential heap section: {} {}".format(beg, end))

        while (ptr < int(end, 16)):
            chunk, arena, extent_node = validate_chunk(hex(ptr), silent = true)

            if extent_node != "0x0":
              heap.sections[beg] = end
              break
            else:
              ptr += heap.chunksize*step

    if not heap.sections:
      print("No chunks detected in \"maint info sections\" with step {}".format(step))
    else:
      print("Chunks detected in following sections:")

    for b,e in heap.sections.items():
      print("{} {}".format(b,e))

class je_dump_chunks(gdb.Command):
  '''Iterate through the chunks in the given heap mapping'''

  def __init__(self):
    gdb.Command.__init__(self, "je_dump_chunks", gdb.COMMAND_OBSCURE)

  def invoke(self, arg, from_tty):
    arg = arg.split() 
    if len(arg) >= 3:
      beg = arg[0]
      end = arg[1]
      fil = arg[2]
    else:
      print("Please supply begin and end addresses for the section and the destination file")
      return

    global heap

    if beg not in heap.sections:
      print("Run je_scan_sections to find the correct section first")
      return

    ptr = (int(beg, 16) & ~(heap.chunksize-1))
    f = open(fil, "w+")

    csz = heap.chunksize

    while (ptr < int(end, 16)):
      chunk, arena, extent_node = validate_chunk(hex(ptr), silent=True)

      if extent_node != "0x0":
        try:
          if arena != "0x0":
            ind = gdb.execute("p ((arena_t*)%s)->ind" % (arena), to_string = true).split()[2]
            f.write("Chunk {}->{} (extent_node_t*){}: Arena #{} (arena_t*){}\n".format(hex(ptr),\
              hex(ptr+csz), extent_node, ind, arena))
          else:
            size = gdb.execute("p ((extent_node_t*)%s)->en_size" % (extent_node), to_string = true).split()[2]
            f.write("Chunk {}->{} (extent_node_t*){}: Huge allocation of size {}\n".format(hex(ptr),\
              hex(ptr+csz), extent_node, size))

        except RuntimeError:
          print("Error type: {}, Description: {}".format(sys.exc_info()[0], sys.exc_info()[1]))
          sys.exit(0)

      ptr += heap.chunksize

    f.close()

class je_ptr(gdb.Command):

  def __init__(self):
    gdb.Command.__init__(self, "je_ptr", gdb.COMMAND_OBSCURE)

  def invoke(self, arg, from_tty):
    if len(arg) < 1:
      print("Give a ptr argument")
      return

    arg = arg.split()
    ptr = arg[0]
    
    global heap
    csz = heap.chunksize

    chunk, arena, extent_node = validate_chunk(ptr, silent=true)

    if extent_node == "0x0":
      print("{} points to freed Chunk {} +{} ((extent_node_t*){})".format(ptr, chunk, hex(int(ptr,16)-int(chunk,16)), extent_node))
      return

    # check if the allocation doest not belong to arena
    if arena == "0x0":
      print("{} points to allocated Chunk {} +{} ((extent_node_t*){})".format(ptr, chunk, hex(int(ptr,16)-int(chunk,16)), extent_node))
      return

    # large or small allocation
    try:
      gdb.execute("p/x $ptr=%s" % (ptr), to_string = true)
      chunk = gdb.execute("p/x $chunk=((uintptr_t)$ptr&~je_chunksize_mask)", to_string = true).split()[2] # 0x1fffff
      pageind = gdb.execute("p $pageind=((uintptr_t)$ptr - (uintptr_t)$chunk) >> macro_LG_PAGE", to_string = true).split()[2] # 12
      mapbits = int(gdb.execute("p/x $mapbits=((arena_chunk_t*)$chunk)->map_bits[$pageind-je_map_bias].bits", \
      to_string = true).split()[2], 16) # 13
      rpageind = gdb.execute("p $rpageind = $pageind - ($mapbits >> macro_CHUNK_MAP_RUNIND_SHIFT)", to_string = true).split()[2] # 13
      rpages = gdb.execute("p/x $rpages=((uintptr_t)$chunk + ($rpageind << macro_LG_PAGE))", to_string = true).split()[2] # 12
    except RuntimeError:
      print("Error type: {}, Description: {}".format(sys.exc_info()[0], sys.exc_info()[1]))
      sys.exit(0)

    r = jemalloc.run(mapbits)
    if (not r.is_allocated()):
      print("{} points to freed Run page {} +{} ((arena_map_bits_t){})".format(ptr, rpages, hex(int(ptr, 16)-int(rpages, 16)), mapbits))
      return

    if (r.is_large()):
      try:
        chunk_map_ss = int(gdb.execute("p macro_CHUNK_MAP_SIZE_SHIFT", to_string = true).split()[2]) # 1
        chunk_map_sm = int(gdb.execute("p macro_CHUNK_MAP_SIZE_MASK", to_string = true).split()[2]) # 0xffffffffffffe000
        tcache_maxsz = int(gdb.execute("p 1<<je_opt_lg_tcache_max", to_string = true).split()[2])
        large_pad    = int(gdb.execute("p large_pad", to_string = true).split()[2])
      except RuntimeError:
        print("Error type: {}, Description: {}".format(sys.exc_info()[0], sys.exc_info()[1]))
        sys.exit(0)

      if chunk_map_ss == 0:
        size = (mapbits & chunk_map_sm)
      elif chunk_map_ss > 0:
        size = (mapbits & chunk_map_sm) >> chunk_map_ss
      else:
        size = (mapbits & chunk_map_sm) << -chunk_map_ss

      if size - large_pad > tcache_maxsz:
        print("{} points to allocated Run page {} +{} ((arena_map_bits_t){})".format(ptr, rpages, hex(int(ptr, 16)-int(rpages, 16)), mapbits))
        return

      try:
        sg = int(gdb.execute("p macro_LG_SIZE_CLASS_GROUP", to_string = True).split()[2]) # 2
        qu = int(gdb.execute("p macro_LG_QUANTUM", to_string = True).split()[2]) # 4
        nt = int(gdb.execute("p macro_NTBINS", to_string = True).split()[2]) # 1
      except RuntimeError:
        print("Error type: {}, Description: {}".format(sys.exc_info()[0], sys.exc_info()[1]))
        sys.exit(0)

      x = math.floor(math.log(size<<1-1,2))
      shift = x - (sg + qu)
      grp = shift << sg
      lg_delta = x - sg - 1
      delta_inverse_mask = -1<<lg_delta
      mod = ((((size-1) & delta_inverse_mask) >> lg_delta)) & ((1 << sg) - 1)
      ind = nt + grp + mod

      for t,v in heap.threads.items():
        try:
          avail = gdb.execute("p ((tcache_t*){})->tbins[{}]->avail".format(v["tcache"], ind), to_string = true).split()[4]
          ncached = gdb.execute(" p ((tcache_t*){})->tbins[{}]->ncached".format(v["tcache"], ind), to_string = true).split()[2]
          for i in reversed(range(1, int(ncached)+1)):
            p = gdb.execute("x/gx {} - {}*sizeof(void*)".format(avail, i), to_string = true).split()[1] 
            if int(ptr, 16) == int(p, 16):
              print("{} points to cached Run page {} +{} thread #{} tbin index {})".format(ptr, rpages, hex(int(ptr,16)-int(rpages, 16)), t, ind))
              return
        except RuntimeError:
          print("Error type: {}, Description: {}".format(sys.exc_info()[0], sys.exc_info()[1]))
          sys.exit(0)

      print("{} points to allocated Run page {} +{} ((arena_map_bits_t){})".format(ptr, rpages, hex(int(ptr,16)-int(rpages,16)), mapbits))
      return

    # so it's a small allocation
    try:
      miscelm = gdb.execute("p/x $miscelm=((arena_chunk_map_misc_t *)((uintptr_t)$chunk+(uintptr_t)je_map_misc_offset)+$rpageind-je_map_bias)", \
      to_string = true).split()[2] # 4096 13
      run = gdb.execute("p/x $run=&((arena_chunk_map_misc_t*)$miscelm)->run", to_string = true).split()[2]
      bitmap = gdb.execute("p/x $bitmap=((arena_run_t*)$run)->bitmap", to_string = true).split()[2]
      binind = gdb.execute("p $binind=($mapbits&macro_CHUNK_MAP_BININD_MASK)>>macro_CHUNK_MAP_BININD_SHIFT", to_string = true).split()[2] # 0x1fe0 5
      bin_info = gdb.execute("p $bin_info = &je_arena_bin_info[$binind]", to_string = true).split()[4]
      diff = gdb.execute("p $diff=(unsigned)((uintptr_t)$ptr-(uintptr_t)$rpages-((arena_bin_info_t*)$bin_info)->reg0_offset)", \
      to_string = true).split()[2]       
      interval = gdb.execute("p $interval = ((arena_bin_info_t*)$bin_info)->reg_interval", to_string = true).split()[2]
      regind = gdb.execute("p $regind = $diff/$interval", to_string = true).split()[2]
      goff = gdb.execute("p $goff=$regind>>macro_LG_BITMAP_GROUP_NBITS", to_string = true).split()[2] # 6
      g = gdb.execute("p/x $g=((bitmap_t*)$bitmap)[$goff]", to_string = true).split()[2]
      bit = gdb.execute("p $bit=(!($g&(1LU<<($regind&macro_BITMAP_GROUP_NBITS_MASK))))", to_string = true).split()[2] # 63
    except RuntimeError:
      print("Error type: {}, Description: {}".format(sys.exc_info()[0], sys.exc_info()[1]))
      sys.exit(0)

    region = int(ptr, 16) - int(diff) + (int(regind) * int(interval))
    if (bit == 'false' or bit == '0'):
      print("{} points to freed Region {} +{} ((arena_bin_info_t*){})".format(ptr, hex(region), hex(int(ptr,16)-region), bin_info))
      sys.exit(0)
  
    for t,v in heap.threads.items():
      try:
        avail = gdb.execute("p ((tcache_t*){})->tbins[{}]->avail".format(v["tcache"], binind), to_string = true).split()[4]
        ncached = gdb.execute(" p ((tcache_t*){})->tbins[{}]->ncached".format(v["tcache"], binind), to_string = true).split()[2]
        for i in reversed(range(1, int(ncached)+1)):
          p = gdb.execute("x/gx {} - {}*sizeof(void*)".format(avail, i), to_string = true).split()[1] 
          if region == int(p, 16):
            print("{} points to cached Region {} +{} thread #{} ((arena_bin_info_t*){})".format(ptr, hex(region), hex(int(ptr,16)-region), t, bin_info))
            return
      except RuntimeError:
        print("Error type: {}, Description: {}".format(sys.exc_info()[0], sys.exc_info()[1]))
        sys.exit(0)
    
    print("{} points to allocated Region {} +{} ((arena_bin_info_t*){})".format(ptr, hex(region), hex(int(ptr,16)-region), bin_info))
    return
    

class je_chunk(gdb.Command):

  def __init__(self):
    gdb.Command.__init__(self, "je_chunk", gdb.COMMAND_OBSCURE)

  def invoke(self, arg, from_tty):

    if len(arg) < 1:
      return

    arg = arg.split()
    ptr = arg[0]

    chunk, arena, extent_node = validate_chunk(ptr, silent = true)

    global heap
    csz = heap.chunksize

    if extent_node != "0x0":
      if arena != "0x0":
        print("Chunk {}->{} ((extent_node_t*){}): Arena ((arena_t*){})".format(chunk, hex(int(chunk, 16)+csz), extent_node, arena))
      else:
        print("Chunk {}->{} ((extent_node_t*){}): Contains a huge allocation".format(chunk, hex(int(chunk, 16)+csz), extent_node, arena))
    else:
      print("Chunk {}->{} ((extent_node_t*){}): Not allocated)".format(chunk, hex(int(chunk, 16)+csz), extent_node))

    return

class je_run(gdb.Command):

  def __init__(self):
    gdb.Command.__init__(self, "je_run", gdb.COMMAND_OBSCURE)

  def invoke(self, arg, from_tty):
    
    if len(arg) < 1:
      return

    arg = arg.split()
    ptr = arg[0]

    try:
      gdb.execute("p/x $ptr=%s" % (ptr), to_string = true)
      chunk = gdb.execute("p/x $chunk=((uintptr_t)$ptr&~je_chunksize_mask)", to_string = true).split()[2] # 0x1fffff
      pageind = gdb.execute("p $pageind=((uintptr_t)$ptr - (uintptr_t)$chunk) >> macro_LG_PAGE", to_string = true).split()[2] # 12
      mapbits = int(gdb.execute("p/x $mapbits=((arena_chunk_t*)$chunk)->map_bits[$pageind-je_map_bias].bits", \
      to_string = true).split()[2], 16) # 13
      rpageind = gdb.execute("p $rpageind = $pageind - ($mapbits >> macro_CHUNK_MAP_RUNIND_SHIFT)", to_string = true).split()[2] # 13
      rpages = gdb.execute("p/x $rpages=((uintptr_t)$chunk + ($rpageind << macro_LG_PAGE))", to_string = true).split()[2] # 12
      miscelm = gdb.execute("p/x $miscelm=((arena_chunk_map_misc_t *)((uintptr_t)$chunk+(uintptr_t)je_map_misc_offset)+$rpageind-je_map_bias)", \
      to_string = true).split()[2] # 4096 13
      run = gdb.execute("p/x $run=&((arena_chunk_map_misc_t*)$miscelm)->run", to_string = true).split()[2]
      chunk_map_ss = int(gdb.execute("p macro_CHUNK_MAP_SIZE_SHIFT", to_string = true).split()[2]) # 1
      chunk_map_sm = int(gdb.execute("p macro_CHUNK_MAP_SIZE_MASK", to_string = true).split()[2])  # 0xffffffffffffe000
      tcache_maxsz = int(gdb.execute("p 1<<je_opt_lg_tcache_max", to_string = true).split()[2])
      large_pad    = int(gdb.execute("p large_pad", to_string = true).split()[2])
    except RuntimeError:
      print("Error type: {}, Description: {}".format(sys.exc_info()[0], sys.exc_info()[1]))
      sys.exit(0)

    r = jemalloc.run(mapbits)

    if chunk_map_ss == 0:
      size = (mapbits & chunk_map_sm)
    elif chunk_map_ss > 0:
      size = (mapbits & chunk_map_sm) >> chunk_map_ss
    else:
      size = (mapbits & chunk_map_sm) << -chunk_map_ss

    print("Run {}->{} ((arena_run_t*){}): allocated {}, large {}, decommitted {}, unzeroed {}, dirty {}".format(
      rpages, hex(int(rpages, 16)+size), run, r.is_allocated(), r.is_large(), r.is_decommitted(), r.is_unzeroed(), r.is_dirty()))

    return

class je_region(gdb.Command):

  def __init__(self):
    gdb.Command.__init__(self, "je_region", gdb.COMMAND_OBSCURE)

  def invoke(self, arg, from_tty):

    if len(arg) < 1:
      return
    arg = arg.split()
    ptr = arg[0]

    try:
      gdb.execute("p/x $ptr=%s" % (ptr), to_string = true)
      chunk = gdb.execute("p/x $chunk=((uintptr_t)$ptr&~je_chunksize_mask)", to_string = true).split()[2]
      pageind = gdb.execute("p $pageind=((uintptr_t)$ptr - (uintptr_t)$chunk) >> macro_LG_PAGE", to_string = true).split()[2]
      mapbits = int(gdb.execute("p/x $mapbits=((arena_chunk_t*)$chunk)->map_bits[$pageind-je_map_bias].bits", \
      to_string = true).split()[2], 16)
    except RuntimeError:
      print("Error type: {}, Description: {}".format(sys.exc_info()[0], sys.exc_info()[1]))
      sys.exit(0)
    
    r = jemalloc.run(mapbits)

    if (not r.is_allocated()) or r.is_large():
        print("No region for this pointer")
        return

    try:
      rpageind = gdb.execute("p $rpageind = $pageind - ($mapbits >> macro_CHUNK_MAP_RUNIND_SHIFT)", to_string = true).split()[2]
      rpages = gdb.execute("p/x $rpages=((uintptr_t)$chunk + ($rpageind << macro_LG_PAGE))", to_string = true).split()[2]
      miscelm = gdb.execute("p/x $miscelm=((arena_chunk_map_misc_t *)((uintptr_t)$chunk+(uintptr_t)je_map_misc_offset)+$rpageind-je_map_bias)", \
      to_string = true).split()[2]
      run = gdb.execute("p/x $run=&((arena_chunk_map_misc_t*)$miscelm)->run", to_string = true).split()[2]
      bitmap = gdb.execute("p/x $bitmap=((arena_run_t*)$run)->bitmap", to_string = true).split()[2]
      binind = gdb.execute("p $binind=($mapbits&macro_CHUNK_MAP_BININD_MASK)>>macro_CHUNK_MAP_BININD_SHIFT", to_string = true).split()[2]
      bin_info = gdb.execute("p $bin_info = &je_arena_bin_info[$binind]", to_string = true).split()[4]
      diff = gdb.execute("p $diff=(unsigned)((uintptr_t)$ptr-(uintptr_t)$rpages-((arena_bin_info_t*)$bin_info)->reg0_offset)", \
      to_string = true).split()[2]       
      interval = gdb.execute("p $interval = ((arena_bin_info_t*)$bin_info)->reg_interval", to_string = true).split()[2]
      size = gdb.execute("p $interval = ((arena_bin_info_t*)$bin_info)->reg_size", to_string = true).split()[2]
      regind = gdb.execute("p $regind = $diff/$interval", to_string = true).split()[2]
      goff = gdb.execute("p $goff=$regind>>macro_LG_BITMAP_GROUP_NBITS", to_string = true).split()[2]
      g = gdb.execute("p/x $g=((bitmap_t*)$bitmap)[$goff]", to_string = true).split()[2]
      bit = gdb.execute("p $bit=(!($g&(1LU<<($regind&macro_BITMAP_GROUP_NBITS_MASK))))", to_string = true).split()[2]
    except RuntimeError:
      print("Error type: {}, Description: {}".format(sys.exc_info()[0], sys.exc_info()[1]))
      sys.exit(0)

    region = int(ptr, 16) - int(diff) + (int(regind) * int(interval))
    print("Region {}->{} ((arena_bin_info_t*){}): allocated {}".format(hex(region), hex(region+int(size, 16)), bin_info, bool(bit)))

    return

je_help()
je_ptr()
je_chunk()
je_run()
je_region()
je_threads()
je_scan_sections()
je_dump_chunks()