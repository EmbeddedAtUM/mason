/* 
 * Filename : create_rsst.c
 * Author : inreddyp<inreddyp@umich.edu>
 * Created: 11/21/2010
 *
 * Description: Kernel module for creating rsst pkts
 */

#include <linux/module.h>	
#include <linux/kernel.h>	
#include <linux/init.h>		
#include <linux/err.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/time.h>
#include <net/net_namespace.h>

#include "create_rsst.h"

#define DRIVER_AUTHOR "Indu <inreddyp@umich.edu>"
#define DRIVER_DESC   "Create RSST Packet"

#define MAX_PACKET_SIZE 1500


static const char DEV_NAME[]  = "lo";

static struct pkt_size_info get_required_pkt_size_info(struct id_table *table, int initial_participant)
{
	size_t pkt_size = 0;
	int participant = initial_participant;
	struct rssi_obs * tmp_rssi_obs;
	struct pkt_size_info required_pkt_size;
	
	while(table->ids[participant])
	{
		/* storing the feasible pkt_size */
		required_pkt_size.pkt_size = pkt_size;

		/* initializing a temporary struct to store packet id and rssi */
		tmp_rssi_obs = (table->ids[participant])->head;
		
		while (tmp_rssi_obs) 
		{
			/* senderid */
			pkt_size  = pkt_size + sizeof(table->ids[participant]->id);
			/* pkt_id and rssi */
			pkt_size = pkt_size + sizeof(tmp_rssi_obs->pkt_id);
			pkt_size = pkt_size + sizeof(tmp_rssi_obs->rssi);

			tmp_rssi_obs = tmp_rssi_obs->next;
		}
		
		if ( (pkt_size > MAX_PACKET_SIZE))
			break;

		/* Going to the next participant */
		participant += 1;
		if (participant > MAX_PARTICIPANTS)
			break;
	}

	required_pkt_size.final_participant = participant - 1;

	if ( participant == initial_participant )
		printk(KERN_INFO "Maximum allowed packet size is not sufficient to allocate rsst information even from one sender\n");

	return required_pkt_size;
}

void insert_rsst_data(struct sk_buff *skb, struct id_table *table, int initial_participant, int final_participant)
{
	int participant;
	struct rssi_obs * tmp_rssi_obs;
	struct pkt_id_and_rssi *tmp_pkt_rssi;

	/* Temporary struct to put senderid, pkt_id and rssi into skb->data*/
	tmp_pkt_rssi = ( struct pkt_id_and_rssi *) skb->data;

	for (participant = initial_participant; participant <= final_participant; participant++)
	{
		tmp_rssi_obs = table->ids[participant]->head;
		while (tmp_rssi_obs)
		{
			/* storing information for one packet - senderid, pkt_id and rssi*/
			tmp_pkt_rssi->id = table->ids[participant]->id;
			tmp_pkt_rssi->pkt_id = tmp_rssi_obs->pkt_id;
			tmp_pkt_rssi->rssi = tmp_rssi_obs->rssi;

			/* Going to the next packet*/
			tmp_rssi_obs = tmp_rssi_obs->next;
			tmp_pkt_rssi++;
		}
	}
}

struct sk_buff * create_rsst_pkt(struct id_table *table, struct create_rsst_st *state)
{
	int initial_participant = 0, final_participant;
	struct sk_buff *skb ;
	struct net_device *mason_dev;
	struct pkt_size_info required_pkt_size;

	mason_dev = dev_get_by_name(&init_net, DEV_NAME);
	if (!mason_dev) {
	  printk(KERN_ERR "Failed to find net_device for Mason Rate Test\n");
	  return NULL;
	}
	
	if (table == NULL )
	{	
		printk(KERN_ERR "id table is null\n");
		return NULL;
	}

	/* Return Null if all the required packets are already created */
	if (table->ids[state->start_participant] == NULL || state->start_participant > MAX_PARTICIPANTS)
		return NULL;

	if ( state->start_participant )
		initial_participant = state->start_participant;

	required_pkt_size = get_required_pkt_size_info(table, initial_participant);
	final_participant = required_pkt_size.final_participant;
	
	if (final_participant < initial_participant)
	{
		printk(KERN_ERR "Maximum allowed packet size is not sufficient\n");
		return NULL;
	}
	

	skb = alloc_skb( (required_pkt_size.pkt_size) + LL_ALLOCATED_SPACE(mason_dev),GFP_KERNEL);
  
	if (!skb) 
	{
    		printk(KERN_ERR "Failed to allocate skbuff for Mason RT msg");
		return NULL; 
  	}
    

	skb->dev = mason_dev;
  
	skb_reserve(skb, LL_RESERVED_SPACE(mason_dev));  /* reserve for L2 header */
	skb_reset_network_header(skb);  
  
	// place the rsst data
	skb_put(skb, required_pkt_size.pkt_size);
	
	insert_rsst_data(skb, table, initial_participant, final_participant);

	state->start_participant = final_participant + 1;
	return (skb);  
}

static int __init mason_create_rsst_init(void)
{

	printk(KERN_INFO "Loading Mason Create Rsst Module\n");
	return 0;
}

static void __exit mason_create_rsst_exit(void)
{
	printk(KERN_INFO "Unloading Mason Create Rsst Module\n");
}

module_init(mason_create_rsst_init);
module_exit(mason_create_rsst_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);	
MODULE_DESCRIPTION(DRIVER_DESC);

