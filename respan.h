/*
 * © 2019 The Johns Hopkins University Applied Physics Laboratory LLC.
 * All Rights Reserved. 
 *
 * AUTHOR: Troy D. Hanson
 * LICENSE: MIT
 * PACKAGE: fluxcap
 */

#ifndef RESPAN_H
#define RESPAN_H

#if defined __cplusplus
extern "C" {
#endif

#define MODES x(none) x(erspan) x(pcap)
#define x(a) mode_ ## a,
typedef enum { MODES } io_mode;
#undef x

#define RESPAN_VERSION "0.1"
#define FILE_MAX 250 /* instead of FILENAME_MAX or PATH_MAX */
#define FILE_PATTERN "%Y%m%d%H%M%S"
#define MAX_PKT 65536

#if defined __cplusplus
 }
#endif

#endif /* RESPAN_H */
