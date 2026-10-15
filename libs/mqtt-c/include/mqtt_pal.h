/*
 * Freestanding MQTT-C platform-abstraction port for ruptor. MQTT-C requires the integrator to supply mqtt_pal.h for
 * their platform (the upstream one only selects between POSIX/Windows/TLS backends) -- this is that port, NOT a change
 * to the library: src/mqtt.c and the real include/mqtt.h stay pristine. No sockets, no threads, no TLS: the fuzzer is
 * the broker and delivers the PUBLISH bytes directly, so the send/recv/mutex/time surfaces are inert stubs that only
 * need to compile and link (the vulnerable parse path -- mqtt_unpack_fixed_header / mqtt_unpack_publish_response --
 * never reaches them).
 */
#ifndef MQTT_PAL_H
#define MQTT_PAL_H

#include <stdint.h>
#include <stddef.h>

typedef long ssize_t;
typedef uint32_t mqtt_pal_time_t;
typedef int mqtt_pal_socket_handle;
typedef int mqtt_pal_mutex_t;

#define MQTT_PAL_HTONS(s) ((uint16_t)((((uint16_t)(s) & 0x00FFu) << 8) | (((uint16_t)(s) & 0xFF00u) >> 8)))
#define MQTT_PAL_NTOHS(s) MQTT_PAL_HTONS(s)
#define MQTT_PAL_TIME()   ((mqtt_pal_time_t)0)

#define MQTT_PAL_MUTEX_INIT(mtx_ptr)   ((void)(mtx_ptr))
#define MQTT_PAL_MUTEX_LOCK(mtx_ptr)   ((void)(mtx_ptr))
#define MQTT_PAL_MUTEX_UNLOCK(mtx_ptr) ((void)(mtx_ptr))

ssize_t mqtt_pal_sendall(mqtt_pal_socket_handle fd, const void *buf, size_t len, int flags);
ssize_t mqtt_pal_recvall(mqtt_pal_socket_handle fd, void *buf, size_t bufsz, int flags);

#endif /* MQTT_PAL_H */
