/* config.h.  Generated by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define to the default daemon name to check for axfr. */
#define AXFR_DAEMON "axfr"

/* Define to the default daemon prefix to check for axfr. */
#define AXFR_DAEMON_PREFIX "axfr-"

/* Define this to enable BIND8 like NSTATS & XSTATS. */
/* #undef BIND8_STATS */

/* Define to the default maximum message length with EDNS. */
#define CF_EDNS_MAX_MESSAGE_LEN 4096

/* Define to the default facility for syslog. */
#define CF_FACILITY LOG_DAEMON

/* Define to the default nsd identity. */
#define CF_IDENTITY "unindentified server"

/* Define to the maximum interfaces to serve. */
#define CF_MAX_INTERFACES 8

/* Define to the backlog to be used with listen. */
#define CF_TCP_BACKLOG 5

/* Define to the default maximum simultaneous tcp connections. */
#define CF_TCP_MAX_CONNECTIONS 8

/* Define to the default maxium message length. */
#define CF_TCP_MAX_MESSAGE_LEN 16384

/* Define to the default tcp port. */
#define CF_TCP_PORT 53

/* Define to the default tcp timeout. */
#define CF_TCP_TIMEOUT 120

/* Define to the default maximum udp message length. */
#define CF_UDP_MAX_MESSAGE_LEN 512

/* Define to the default udp port. */
#define CF_UDP_PORT 53

/* Define to the NSD version to answer version.server query. */
#define CF_VERSION PACKAGE_STRING

/* Define this to disable axfr. */
/* #undef DISABLE_AXFR */

/* Define this to enable DNSSEC support. */
/* #undef DNSSEC */

/* Define to 1 if you have the `alarm' function. */
#define HAVE_ALARM 1

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the `basename' function. */
#define HAVE_BASENAME 1

/* Define to 1 if you have the `bzero' function. */
#define HAVE_BZERO 1

/* Define to 1 if your system has a working `chown' function. */
#define HAVE_CHOWN 1

/* Define to 1 if you have the `dup2' function. */
#define HAVE_DUP2 1

/* Define to 1 if you have the `endpwent' function. */
#define HAVE_ENDPWENT 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* Define to 1 if you have the `gethostname' function. */
#define HAVE_GETHOSTNAME 1

/* Define to 1 if you have the `getpagesize' function. */
#define HAVE_GETPAGESIZE 1

/* Define to 1 if you have the `inet_ntoa' function. */
#define HAVE_INET_NTOA 1

/* Define to 1 if you have the `inet_pton' function. */
#define HAVE_INET_PTON 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if your system has a working `malloc' function. */
#define HAVE_MALLOC 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have a working `mmap' system call. */
#define HAVE_MMAP 1

/* Define to 1 if you have the `munmap' function. */
#define HAVE_MUNMAP 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the `select' function. */
#define HAVE_SELECT 1

/* Define to 1 if you have the `socket' function. */
#define HAVE_SOCKET 1

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
/* #undef HAVE_STDINT_H */

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strcasecmp' function. */
#define HAVE_STRCASECMP 1

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strncasecmp' function. */
#define HAVE_STRNCASECMP 1

/* Define to 1 if you have the `strtol' function. */
#define HAVE_STRTOL 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have <sys/wait.h> that is POSIX.1 compatible. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the <vfork.h> header file. */
/* #undef HAVE_VFORK_H */

/* Define to 1 if `fork' works. */
#define HAVE_WORKING_FORK 1

/* Define to 1 if `vfork' works. */
#define HAVE_WORKING_VFORK 1

/* Define this to enable IPv6 support. */
#define INET6 

/* Define to use hosts_access() from -lwrap. */
/* #undef LIBWRAP */

/* Define to log incoming notifies with syslog. */
#define LOG_NOTIFIES 

/* Define to the maximum message length to pass to syslog. */
#define MAXSYSLOGMSGLEN 512

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "nsd-bugs@nlnetlabs.nl"

/* Define to the full name of this package. */
#define PACKAGE_NAME "NSD"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "NSD 1.1a"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "nsd"

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.1a"

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to use red-black tree methods. */
#define USE_HEAP_RBTREE 

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* Define to `unsigned' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef uid_t */

/* Define as `fork' if `vfork' does not work. */
/* #undef vfork */
