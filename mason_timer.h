
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/string.h>

//#include "mason.h"

/*
 * Defining this for debugging messages for Timer
 */
#define MASON_TIMER_DEBUG 0

/* @param mason_fi - Pointer to FSM instance.
 * @param timer_list - Standard linux timer
 * @param expire_event - Event, to trigger if timer expires.
 * @param event_arg - Generic argument, provided to expiry function.
 */
typedef struct 
{
	char name[16];
	int data;
} mason_fsm_instance;

static inline void mason_event(mason_fsm_instance *mason_fi, int event, void * arg)
{
	//function to be executed for the event to be triggered
}

typedef struct 
{
	mason_fsm_instance  *mason_fi;
	struct timer_list mason_tl;
	int expire_event;
	void *event_arg;
} mason_timer;

/**
 * Initializes a timer for the mason FSM.
 */
extern void mason_set_timer(mason_fsm_instance *fsm_instance, mason_timer *timr);

/**
 * Removes an existing timer .
 */
extern void mason_del_timer(mason_timer *timr);

/**
 * Adds and starts a timer to a mason FSM instance.
 * 
 * @param timer    The timer to be added. The field fi of that timer
 *                 must have been set to point to the instance.
 * @param millisec Duration, after which the timer should expire.
 * @param event    Event, to trigger if timer expires.
 * @param arg      Generic argument, provided to expiry function.
 *
 * @return         0 on success, -1 if timer is already active.
 */
extern int mason_add_timer(mason_timer *timr, int msec, int event, void *arg);

/**
 *  * Modifies a timer .
 *   
 */
extern void mason_modtimer(mason_timer *timr, int msec);

/*
 * Function executed after timeout
 */
extern void mason_expire_timer(unsigned long timer_pointer);

