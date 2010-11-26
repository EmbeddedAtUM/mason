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
//static struct logfile mason_log;


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

		/* senderid and count */
		pkt_size  = pkt_size + sizeof(struct id_and_count);

		/* initializing a temporary struct to store packet id and rssi */
		tmp_rssi_obs = (table->ids[participant])->head;
		
		while (tmp_rssi_obs) 
		{
			/* pkt_id and rssi */
			pkt_size = pkt_size + sizeof(struct pkt_id_and_rssi);
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

/* information stored in the form [senderid][count][pkt_id][rssi][pkt_id][rssi]...[senderid][count][pkt_id][rssi]..*/
void log_rsst_data(struct sk_buff *skb)
{
	struct mason_hdr *hdr;
	struct pkt_id_and_rssi *tmp_pkt_rssi;
	struct id_and_count *tmp_id_cnt;

	int i, participant, rssi_count, position = 0;
	int len = mason_log.length;
	char * pos = mason_log.buffer + len;

	// ***Need to be uncommented***** 
	//hdr = mason_hdr(skb);
	//
	
	hdr = (struct mason_hdr*)skb->data;
	len += sprintf(pos,"Identity: %d\n",hdr->id );
	pos = pos + len;

	hdr++;
	tmp_pkt_rssi = (struct pkt_id_and_rssi *)hdr;

	while( (char *)skb_tail_pointer(skb) >= (char *) tmp_pkt_rssi )
	{
		tmp_id_cnt = (struct id_and_count *)tmp_pkt_rssi ;

		participant = tmp_id_cnt->id;
		rssi_count = tmp_id_cnt->rssi_obs_count;

		tmp_id_cnt++;
		tmp_pkt_rssi = ( struct pkt_id_and_rssi*) tmp_id_cnt;

		/* Loop over all the packets*/
		for(i = 0; i<rssi_count; i++)
		{
			len += sprintf(pos,"Received: time_or_position: %d packet_id: %d sender_id: %d\n",position,tmp_pkt_rssi->pkt_id,tmp_pkt_rssi->rssi);
			pos = pos + len;
			position++;
			tmp_pkt_rssi++;
		}
		tmp_pkt_rssi++;
	}

	mason_log.length = len;

}

/* Receiving data at the initiator from one member of receiver set and storing into the data structure receiver_info */
/*
void get_rsst_data(struct sk_buff *skb, receiver_info *rcv_info)
{
	int participant,rssi_count,i;
	struct rssi_obs *tmp_rssi_obs;
	struct masonhdr *hdr;
	struct id_table table;
	struct pkt_id_and_rssi *tmp_pkt_rssi;
	struct id_and_count *tmp_id_cnt;

	hdr = mason_hdr(skb);
	rcv_info->receiver_id = hdr->id;
	hdr++;
	tmp_pkt_rssi = (struct pkt_id_and_rssi *)hdr;

	while( skb->tail != (char *)tmp_pkt_rssi )
	{
		tmp_id_cnt = (struct id_and_count *)tmp_pkt_rssi ;

		participant = tmp_id_cnt->id;
		rssi_count = tmp_id_cnt->rssi_obs_count;

		// storing sender(participant) information
		table.ids[participant] = kmalloc(sizeof(struct masonid), GFP_KERNEL);
		table.ids[participant]->id = participant;
		table.ids[participant]->rssi_obs_count = rssi_count;

		tmp_id_cnt++;

		tmp_pkt_rssi = ( struct pkt_id_and_rssi*) tmp_id_cnt;

		// storing first packet information
		tmp_rssi_obs = kmalloc(sizeof(struct rssi_obs), GFP_KERNEL);
		tmp_rssi_obs->pkt_id = tmp_pkt_rssi->pkt_id;
		tmp_rssi_obs->rssi = tmp_pkt_rssi->rssi;
		table.ids[participant]->head = tmp_rssi_obs;

		// For further packets
		for(i = 1; i<rssi_count; i++)
		{
			tmp_pkt_rssi++;
			
			tmp_rssi_obs->next = kmalloc(sizeof(struct rssi_obs), GFP_KERNEL);
			tmp_rssi_obs = tmp_rssi_obs->next;

			tmp_rssi_obs->pkt_id = tmp_pkt_rssi->pkt_id;
			tmp_rssi_obs->rssi = tmp_pkt_rssi->rssi;
		}
		tmp_pkt_rssi++;
	}
	rcv_info->tbl = &table;
}
*/


void insert_rsst_data(struct sk_buff *skb, struct id_table *table, int initial_participant, int final_participant)
{
	int participant;
	struct rssi_obs * tmp_rssi_obs;
	struct pkt_id_and_rssi *tmp_pkt_rssi;
	struct id_and_count *tmp_id_cnt;

	/* Temporary struct to put pkt_id and rssi into skb->data*/
	tmp_pkt_rssi = ( struct pkt_id_and_rssi*) skb->data;

	for (participant = initial_participant; participant <= final_participant; participant++)
	{
		tmp_id_cnt = ( struct id_and_count *)tmp_pkt_rssi;

		/* storing the client id and count*/
		tmp_id_cnt->id = table->ids[participant]->id;
		tmp_id_cnt->rssi_obs_count = table->ids[participant]->rssi_obs_count;

		tmp_id_cnt++;

		tmp_rssi_obs = table->ids[participant]->head;
		tmp_pkt_rssi = ( struct pkt_id_and_rssi *)tmp_id_cnt; 

		while (tmp_rssi_obs)
		{
			/* storing information for one packet - pkt_id and rssi*/
			tmp_pkt_rssi->pkt_id = tmp_rssi_obs->pkt_id;
			tmp_pkt_rssi->rssi = tmp_rssi_obs->rssi;

			/* Going to the next packet*/
			tmp_rssi_obs = tmp_rssi_obs->next;
			tmp_pkt_rssi++;
		}
	}
}

struct sk_buff * create_rsst_pkt(struct rnd_info *rnd, struct create_rsst_st *state)
{
	int initial_participant = 0, final_participant;
	struct sk_buff *skb ;
	struct pkt_size_info required_pkt_size;
	struct id_table *table = rnd->tbl;

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

	/* creating a new skbuff using 'create_mason_packet' in mason.c */
	//Need to be uncommented when including mason.c
	//skb = create_mason_packet(rnd, required_pkt_size.pkt_size);

	/* place the rsst data */
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

