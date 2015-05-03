#define HAVE_DEBUG

#ifdef HAVE_DEBUG
# define DEBUG(x) printf x
#else
# define DEBUG(x) do {} while (0)
#endif

