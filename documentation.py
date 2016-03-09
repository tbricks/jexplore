text = """
DOCUMENTATION

jexplore - is a bundle of python scripts which help to unveil the state of underlying structures in jemalloc allocator.

An area of jemalloc managed memory is divided into equal sized chunks (p je_chunksize). Huge allocation regions are memory regions managed by jemalloc chunks. Apart from the huge size class, jemalloc also has the small and large size classes for end user allocations (both managed by arenas). An arena is a structure that manages the memory areas which jemalloc divides into chunks. Arenas can span more than one chunk. Arenas are used to mitigate lock contention problems between threads. Therefore, allocations and deallocations from a thread always happen on the same arena. Theoretically, the number of arenas is in direct relation to the need for concurrency in memory allocation (In practice, related to the # of CPUs). A chunk is broken into several runs. Each run is actually a set of one or more contiguous pages (but a run cannot be smaller than one page). Therefore, they are aligned to multiples of the page size. The runs themselves may be non-contiguous but they are as close as possible due to the tree search heuristics implemented by jemalloc. Each run either stores a large allocation or holds regions of a specific size for small allocations. To keep track about different runs of specific size class bins are used. So, a specific bin may be associated with several runs, however a specific run can only be associated with a specific bin.

To sum up.

Huge allocations (size > je_chunksize) are stored in chunks
Large allocations (size > macro_LG_PAGE) are stored in runs (which are stored in chunks)
Small allocations are stored in regions (which are stored in runs, which are stored in chunks)

Do not forget to compile with macrolist.c. jemalloc 4.0.4

The following is the list of the commands:

je_help
Prints this message.

je_ptr  ptr
For the given pointer checks associated internal structures: chunks, runs, regions (in that order). The process of selecting substructures continues until the last allocated substructure is found.

Pointers do not have to only point to the beginning of the allocated object. For example, if the given pointer points to some offset from the beginning of the small object, the beginning of the allocated region will be printed plus the offset value. 

The offset value is rubbish for huge objects if jemalloc was compiled with oblivious cache (p config_cache_oblivious), since the objects are allocated in the beginning of the run plus some random value.

KNOWN BUGS:

If the pointer points to huge object plus some value larger than chunk size, the allocation will not be found!
(What about a really big 'large' allocations).

Thread caches are supported for small allocations.

KNOWN BUGS:

In caches of large allocations are found pointers of different allocated size.

je_scan_sections step
Scan sections of underlying core dump file in search of jemalloc managed sections. Filter sections based on flags first (e.g. read-write). Then reject sections, not aligned as chunks. Then scan the rest of the sections with given step (by default 16) until the first chunk is found (or not).

je_dump_chunks beg end file
beg - beginning address
end - end addresss
For the sections found first with je_scan_section dump their content to file on the chunks level.

je_chunk ptr
Print info on chunk associated with given pointer

je_run ptr
Print info on run associated with given pointer

je_region ptr
Print info on region assiciated with given pointer
"""
