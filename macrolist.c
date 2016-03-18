#define	JEMALLOC_MACROLIST_C_
#include "jemalloc/internal/jemalloc_internal.h"

static int volatile macro_LG_RTREE_BITS_PER_LEVEL = LG_RTREE_BITS_PER_LEVEL;
static int volatile macro_LG_SIZEOF_PTR = LG_SIZEOF_PTR;
static int volatile macro_LG_PAGE = LG_PAGE;
static int volatile macro_CHUNK_MAP_RUNIND_SHIFT = CHUNK_MAP_RUNIND_SHIFT;
static int volatile macro_CHUNK_MAP_BININD_MASK = CHUNK_MAP_BININD_MASK;
static int volatile macro_CHUNK_MAP_BININD_SHIFT = CHUNK_MAP_BININD_SHIFT;
static int volatile macro_LG_BITMAP_GROUP_NBITS = LG_BITMAP_GROUP_NBITS;
static int volatile macro_BITMAP_GROUP_NBITS_MASK = BITMAP_GROUP_NBITS_MASK;
static int volatile macro_CHUNK_MAP_SIZE_SHIFT = CHUNK_MAP_SIZE_SHIFT;
static int volatile macro_NTBINS = NTBINS;
static int volatile macro_LG_SIZE_CLASS_GROUP = LG_SIZE_CLASS_GROUP;
static int volatile macro_LG_QUANTUM = LG_QUANTUM;
static long volatile macro_CHUNK_MAP_SIZE_MASK = CHUNK_MAP_SIZE_MASK;
//static int macro_LG_TINY_MAXCLASS = LG_TINY_MAXCLASS; 
