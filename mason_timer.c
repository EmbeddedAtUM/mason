/*
 *  mason timeout implementation
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/timer.h>

//#include "mason.h"
#include "mason_timer.h"


void mason_expire_timer(unsigned long timer_pointer)
{
	mason_timer *timr = (mason_timer *)timer_pointer;
#if MASON_TIMER_DEBUG
	printk(KERN_INFO "Timer has expired\n");
#endif
	mason_event(timr->mason_fi, timr->expire_event, timr->event_arg);
}

void mason_set_timer(mason_fsm_instance *fsm_instance, mason_timer *timr)
{
	timr->mason_fi = fsm_instance;
	timr->mason_tl.function = (void *)mason_expire_timer;
	timr->mason_tl.data = (unsigned long)timr;
#if MASON_TIMER_DEBUG
	printk(KERN_INFO "Creating the timer\n");
#endif
	init_timer(&timr->mason_tl);
}

void mason_del_timer(mason_timer *timr)
{
#if MASON_TIMER_DEBUG
	printk(KERN_INFO "Deleting the timer\n");
#endif
	del_timer(&timr->mason_tl);
}

int mason_add_timer(mason_timer *timr, int msec, int event, void *arg)
{
	timr->expire_event = event;
	timr->event_arg = arg;	
	timr->mason_tl.expires = jiffies + msecs_to_jiffies(msec) ;
	
#if MASON_TIMER_DEBUG
	printk(KERN_INFO "Adding the timer\n");
#endif
	add_timer(&timr->mason_tl);
	return 0;
}

void mason_mod_timer(mason_timer *timr, int msec)
{
#if MASON_TIMER_DEBUG
	printk(KERN_INFO "Modifying the timer\n");
#endif
	mod_timer(&timr->mason_tl, jiffies + msecs_to_jiffies(msec));
}

static int init_mason_timer(void)
{
	printk(KERN_INFO "Loading the mason timer module\n");
	return 0;
}	

static void cleanup_mason_timer(void)
{
	printk(KERN_INFO "Unloading the mason timer module\n");
}	

module_init(init_mason_timer);
module_exit(cleanup_mason_timer);






