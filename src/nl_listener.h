#ifndef _WIOMW_NL_LISTENER_H_
#define _WIOMW_NL_LISTENER_H_

typedef struct _nl_listener_closure_struct* nl_listener_closure;

void* nl_listener(void* closure);

#endif
