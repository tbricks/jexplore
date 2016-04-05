# Jexplore

jexplore - is a bundle of python scripts which help to unveil the state of underlying structures in jemalloc 4.0.4 allocator.

# Install

* Add macrolist.c to the list of jemalloc src files
```ln -s jexplore/macrolist.c jemalloc/src/macrolist.c```
* Add macrolist.h to the list of jemalloc headers
```ln -s jexplore/macrolist.h include/jemalloc/internal/macrolist.h```
* Change include/jemalloc/internal/jemalloc_internal.h by adding
```#include "jemalloc/internal/macrolist.h"``` before ```#undef JEMALLOC_H_EXTERNS```
* Change jemalloc Makefile variable
```C_SRCS += $(srcroot)src/macrolist.c```
* Rebuild jemalloc
* Add ```source /PATH/TO/jexplore/jexplore.py``` to your .gdbinit file. Or type it directly in a new gdb session
* By default scripts work with python3, for python2.6 support switch to python26 upstream branch

# Documentation

Read the complete documention in documentation.py file.

Basic commands are: 
- je_help - print help from documentation.py
- je_init - define jemalloc macroses if they were not resolved when starting gdb session
- je_threads - print thread specific data
- je_ptr ptr - check internal jemalloc structures associated with this pointer 
- je_chunk ptr - check the chunk associated with this pointer (huge)
- je_run ptr - check the run associated with this pointer (large)
- je_region ptr - check the region associated with this pointer (small)
- je_scan_sections step - detect heap sections in mmap of the process
- je_dump_chunks beg end file - dump chunks to the file from the section identified by beg and end addr.
- je_search /size-char max-count string - search string in detected heap sections (flags like gdb find)
  
