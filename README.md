# Jexplore

jexplore - is a bundle of python scripts which help to unveil the state of underlying structures in jemalloc 4x allocator.

# Install

* Add macrolist.c to the list of jemalloc src files
```ln -s jexplore/macrolist.c jemalloc/src/macrolist.c```
* Change jemalloc Makefile variable
```C_SRCS += $(srcroot)src/macrolist.c```
* Rebuild jemalloc
* Add ```source jexplore/jexplore.py``` to your .gdbinit file. Or type it directly in a new gdb session.

# Documentation

Read the complete documention in documentation.py file
Basic commands are: je_ptr ptr, je_chunk ptr, je_run ptr, je_region ptr, je_threads, je_scan_sections
