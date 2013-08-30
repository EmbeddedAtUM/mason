/*
 * Copyright 2010, 2011 The Regents of the University of Michigan
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

/* mason_dissector.c --- 
 * 
 * Filename: mason_dissector.c
 * Author: David Bild <drbild@umich.edu>
 * Created: 04/01/2011
 * 
 * Description: Wireshark protocol dissector plugin for Mason.
 *
 * Some code copied from the Wireshark developer documentation
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/column-utils.h>

#include "../kernel/include/if_mason.h"     /* Mason specific defs */

#define VERSION_MASK     0xE0
#define GET_MASON_VERSION(val) ((val) >> 5)
#define TYPE_MASK        0x1E
#define GET_MASON_TYPE(val)    (((val) << 3) >> 4)
#define SIG_MASK         0x01
#define GET_MASON_SIG(val)     (((unsigned char)(val)) & SIG_MASK)

#define RSA_FSTR "%02x%02x%02x%02x%02x%02x..."
#define RSA_VARG(ptr,off)  tvb_get_guint8((ptr), (off)),	\
    tvb_get_guint8((ptr), (off)+1),				\
    tvb_get_guint8((ptr), (off)+2),				\
    tvb_get_guint8((ptr), (off)+3),				\
    tvb_get_guint8((ptr), (off)+4),				\
    tvb_get_guint8((ptr), (off)+5)				\

static const value_string mason_type_names[] = {
  {0, "INIT"},
  {1, "PAR"},
  {2, "PARACK"},    
  {3, "PARLIST"},
  {4, "TXREQ"},
  {5, "MEAS"},
  {6, "RSSTREQ"},
  {7, "RSST"},
  {8, "ABORT"},
  {0, NULL}
};

/* Handle to this dissector */
static dissector_handle_t mason_handle;

/* Protocol */
static int proto_mason = -1;

/* Header fields */
static int hf_mason_version   = -1;
static int hf_mason_type      = -1;
static int hf_mason_sig       = -1;
static int hf_mason_rssi      = -1;
static int hf_mason_rnd_id    = -1;
static int hf_mason_sender_id = -1;
static int hf_mason_pkt_uid   = -1;

/* Type-specific fields */
static int hf_mason_init_pubkey        = -1;
static int hf_mason_par_pubkey         = -1;
static int hf_mason_parack_id          = -1;
static int hf_mason_parack_pubkey      = -1;
static int hf_mason_parlist_startid    = -1;
static int hf_mason_parlist_count      = -1;
static int hf_mason_parlist_par_pubkey = -1;
static int hf_mason_txreq_id           = -1;
static int hf_mason_rsstreq_id         = -1;
static int hf_mason_rsst_frag          = -1;
static int hf_mason_rsst_len           = -1;
static int hf_mason_rsst_data          = -1;

/* Type-specific subtrees */
static gint ett_mason   = -1;
static gint ett_init    = -1;
static gint ett_par     = -1;
static gint ett_parack  = -1;
static gint ett_parlist = -1;
static gint ett_parlist_data = -1;
static gint ett_parlist_par  = -1;
static gint ett_txreq   = -1;
static gint ett_meas    = -1;
static gint ett_rsstreq = -1;
static gint ett_rsst    = -1;

static void __attribute__((__unused__))
show_src_identity(packet_info *pinfo, const gint16 id)
{
  if (0 < id)
    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "%03d (%s)", id, ep_address_to_str(&pinfo->dl_src));
  else if (0 == id) 
    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "Ini (%s)", ep_address_to_str(&pinfo->dl_src));
  else
    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "... (%s)", ep_address_to_str(&pinfo->dl_src));
}

static void __attribute__((__unused__))
show_dst_identity(packet_info *pinfo, const gint16 id)
{
  if (0 < id)
    col_add_fstr(pinfo->cinfo, COL_DEF_DST, "%03d (%s)", id, ep_address_to_str(&pinfo->dl_dst));
  else if (0 == id) 
    col_add_fstr(pinfo->cinfo, COL_DEF_DST, "Ini (%s)", ep_address_to_str(&pinfo->dl_dst));
  else if (-1 == id)
    col_add_fstr(pinfo->cinfo, COL_DEF_DST, "All (%s)", ep_address_to_str(&pinfo->dl_dst));
  else
    col_add_fstr(pinfo->cinfo, COL_DEF_DST, "... (%s)", ep_address_to_str(&pinfo->dl_dst));
}

/* Register the protocol with Wireshark */
void
proto_register_mason(void)
{
  static hf_register_info hf[] = {
    { &hf_mason_version,
      {"Version", "mason.version",
       FT_UINT8, BASE_DEC,
       NULL, VERSION_MASK,
       NULL, HFILL }
    },     
    { &hf_mason_type,
      {"Type", "mason.type",
       FT_UINT8, BASE_DEC,
       VALS(mason_type_names), TYPE_MASK,
       NULL, HFILL }
    },	
    { &hf_mason_sig,
      {"Signed Flag", "mason.signed",
       FT_BOOLEAN, 8,
       NULL, SIG_MASK,
       NULL, HFILL }
    },
    { &hf_mason_rssi,
      {"RSSI", "mason.rssi",
       FT_INT8, BASE_DEC,
       NULL, 0x0,
       NULL, HFILL }
    },
    {&hf_mason_rnd_id,
     {"Round ID", "mason.rnd_id",
      FT_UINT32, BASE_HEX,
      NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_mason_sender_id,
      {"Sender ID", "mason.sender_id",
       FT_UINT16, BASE_DEC,
       NULL, 0x0,
       NULL, HFILL }
    },
    { &hf_mason_pkt_uid,
      {"Packet ID", "mason.packet_id",
       FT_UINT16, BASE_DEC,
       NULL, 0x0,
       NULL, HFILL }
    },
    { &hf_mason_init_pubkey,
      {"Public Key", "mason.init.pubkey",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL }
    },
    { &hf_mason_par_pubkey,
      {"Public Key", "mason.par.pubkey",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL }
    },
    { &hf_mason_parack_id,
      {"Id", "mason.parack.id",
       FT_UINT16, BASE_DEC,
       NULL, 0x0,
       NULL, HFILL }
    },
    { &hf_mason_parack_pubkey,
      {"Public Key", "mason.parack.pubkey",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL }
    },
    { &hf_mason_parlist_startid,
      {"Start Id", "mason.parlist.startid",
       FT_UINT16, BASE_DEC,
       NULL, 0x0,
       NULL, HFILL }
    },
    { &hf_mason_parlist_count,
      {"Count", "mason.parlist.count",
       FT_UINT16, BASE_DEC,
       NULL, 0x0,
       NULL, HFILL }
    },
    { &hf_mason_parlist_par_pubkey,
      {"Public Key", "mason.parlist.par.pubkey",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL }
    },
    { &hf_mason_txreq_id,
      {"Id", "mason.txreq.id",
       FT_UINT16, BASE_DEC,
       NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_mason_rsstreq_id,
      {"Id", "mason.rsstreq.id",
       FT_UINT16, BASE_DEC,
       NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_mason_rsst_frag,
      {"Fragmented", "mason.rsst.frag",
       FT_BOOLEAN, 8,
       NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_mason_rsst_len,
      {"Length", "mason.rsst.len",
       FT_UINT16, BASE_DEC,
       NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_mason_rsst_data,
      {"Data", "mason.rsst.data",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL}
    }
  };
  
  static gint *ett[] = {
    &ett_mason,
    &ett_init,
    &ett_par,
    &ett_parack,
    &ett_parlist,
    &ett_parlist_data,
    &ett_parlist_par,
    &ett_txreq,
    &ett_meas,
    &ett_rsstreq,
    &ett_rsst
  };
  
  proto_mason = proto_register_protocol("Mason Protocol",
					"Mason",
					"mason");

  proto_register_field_array(proto_mason, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

static void 
process_init(tvbuff_t *tvb, packet_info *pinfo, gint *offset, proto_tree *tree)
{
  proto_item *ti = NULL;
  proto_item *init_tree = NULL;
  
  show_dst_identity(pinfo, -1);
  col_append_fstr(pinfo->cinfo, COL_INFO, RSA_FSTR, RSA_VARG(tvb, *offset));

  if (tree) {
    ti = proto_tree_add_text(tree, tvb, 0, 0, "Init");
    init_tree = proto_item_add_subtree(ti, ett_init);
    
    proto_tree_add_item(init_tree, hf_mason_init_pubkey, tvb, *offset, RSA_LEN, FALSE);
  }
}

static void
process_par(tvbuff_t *tvb, packet_info *pinfo, gint *offset, proto_tree *tree)
{
  proto_item *ti = NULL;
  proto_item *par_tree = NULL;
  
  show_src_identity(pinfo, -1); /* Override source address */
  show_dst_identity(pinfo, 0);
  col_append_fstr(pinfo->cinfo, COL_INFO, "        "RSA_FSTR, RSA_VARG(tvb, *offset));

  if (tree) {
    ti = proto_tree_add_text(tree, tvb, 0, 0, "Par");
    par_tree = proto_item_add_subtree(ti, ett_par);
    
    proto_tree_add_item(par_tree, hf_mason_par_pubkey, tvb, *offset, RSA_LEN, FALSE);
  }
}

static void
process_parack(tvbuff_t *tvb, packet_info *pinfo, gint *offset, proto_tree *tree)
{
  proto_item *ti = NULL;
  proto_item *parack_tree = NULL;
  
  guint16 dest_id = tvb_get_ntohs(tvb, *offset);
  show_dst_identity(pinfo, dest_id);
  col_append_fstr(pinfo->cinfo, COL_INFO, "%3d <-> "RSA_FSTR, dest_id, RSA_VARG(tvb, *offset +2));
  
  if (tree) {
    ti = proto_tree_add_text(tree, tvb, 0, 0, "Parack");
    parack_tree = proto_item_add_subtree(ti, ett_parack);

    proto_tree_add_item(parack_tree, hf_mason_parack_id, tvb, *offset, 2, FALSE);    
    proto_tree_add_item(parack_tree, hf_mason_parack_pubkey, tvb, *offset + 2, RSA_LEN, FALSE);
  }
}

static void
process_parlist(tvbuff_t *tvb, packet_info *pinfo, gint *offset, proto_tree *tree)
{
  proto_item *ti = NULL;
  proto_item *parlist_tree = NULL;
  
  proto_item *data_item = NULL;
  proto_item *data_tree = NULL;
  proto_item *par_item = NULL;
  proto_item *par_tree = NULL;

  guint16 start_id = tvb_get_ntohs(tvb, *offset);
  guint16 count = tvb_get_ntohs(tvb, *offset+2);
  
  int i;

  show_dst_identity(pinfo, -1);
  col_append_fstr(pinfo->cinfo, COL_INFO, "%2d partipicants from id %3d", count, start_id);

  if (tree) {
    ti = proto_tree_add_text(tree, tvb, 0, 0, "Parlist");
    parlist_tree = proto_item_add_subtree(ti, ett_parlist);
    
    proto_tree_add_item(parlist_tree, hf_mason_parlist_startid, tvb, *offset, 2, FALSE);
    proto_tree_add_item(parlist_tree, hf_mason_parlist_count, tvb, *offset+2, 2, FALSE);
    data_item = proto_tree_add_text(parlist_tree, tvb, 0, 0, "Participants");
    data_tree = proto_item_add_subtree(data_item, ett_parlist_data);
    
    for (i = 0; i < count; i++) {
      par_item = proto_tree_add_text(data_tree, tvb,
				     *offset+4 + i*RSA_LEN, RSA_LEN,
				     "Participant %3d ("RSA_FSTR")",
				     start_id + i,
				     RSA_VARG(tvb, *offset+4 + i*RSA_LEN));
      par_tree = proto_item_add_subtree(par_item, ett_parlist_par);
      proto_tree_add_text(par_tree, tvb, 0, 0, "Id: %3d", start_id + i);
      proto_tree_add_item(par_tree, hf_mason_par_pubkey, tvb, *offset+4 + i*RSA_LEN, RSA_LEN, FALSE);
    }
  }
}

static void
process_txreq(tvbuff_t *tvb, packet_info *pinfo, gint *offset, proto_tree *tree)
{
  proto_item *ti = NULL;
  proto_item *txreq_tree = NULL;
  
  guint16 dest_id = tvb_get_ntohs(tvb, *offset);
  show_dst_identity(pinfo, dest_id);
  col_append_fstr(pinfo->cinfo, COL_INFO, "-> %3d", dest_id);
  
  if (tree) {
    ti = proto_tree_add_text(tree, tvb, 0, 0, "TxReq");
    txreq_tree = proto_item_add_subtree(ti, ett_txreq);
    
    proto_tree_add_item(txreq_tree, hf_mason_txreq_id, tvb, *offset, 2, FALSE);
  }
}

static void
process_meas(tvbuff_t *tvb,
	     packet_info  *pinfo,
	     gint *offset,
	     proto_tree __attribute__((__unused__)) *tree)
{
  show_dst_identity(pinfo, -1);
  col_append_fstr(pinfo->cinfo, COL_INFO, "<- %3d", tvb_get_ntohs(tvb, *offset-4));
}

static void
process_rsstreq(tvbuff_t *tvb, packet_info *pinfo, gint *offset, proto_tree *tree)
{
  proto_item *ti = NULL;
  proto_item *rsstreq_tree = NULL;
  
  guint16 dest_id = tvb_get_ntohs(tvb, *offset);
  show_dst_identity(pinfo, dest_id);

  if (tree) {
    ti = proto_tree_add_text(tree, tvb, 0, 0, "RSSTReq");
    rsstreq_tree = proto_item_add_subtree(ti, ett_rsstreq);
    
    proto_tree_add_item(rsstreq_tree, hf_mason_rsstreq_id, tvb, *offset, 2, FALSE);
  }
}

static void
process_rsst(tvbuff_t *tvb, packet_info *pinfo, gint *offset, proto_tree *tree)
{
  proto_item *ti = NULL;
  proto_item *rsst_tree = NULL;
  
  guint16 data_len = tvb_get_ntohs(tvb, *offset+1);

  show_dst_identity(pinfo, 0);

  if (tree) {
    ti = proto_tree_add_text(tree, tvb, 0, 0, "RSST");
    rsst_tree = proto_item_add_subtree(ti, ett_rsst);
    
    proto_tree_add_item(rsst_tree, hf_mason_rsst_frag, tvb, *offset, 1, FALSE);
    proto_tree_add_item(rsst_tree, hf_mason_rsst_len, tvb, *offset+1, 2, FALSE);
    proto_tree_add_item(rsst_tree, hf_mason_rsst_data, tvb, *offset+3, data_len, FALSE);
  }
}

static void (*process_table[])(tvbuff_t*, packet_info*, gint*, proto_tree*) = 
{  process_init,
   process_par,
   process_parack,
   process_parlist,
   process_txreq,
   process_meas,
   process_rsstreq,
   process_rsst
};

static void
dissect_mason(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti = NULL;
  proto_item *mason_tree = NULL;

  gint offset = 0;
  guint8 packet_type = GET_MASON_TYPE(tvb_get_guint8(tvb, 0));
  guint16 sender_id  = tvb_get_ntohs(tvb, 6);
  guint32 round_id = tvb_get_ntohl(tvb, 2);

  /* Set the info column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Mason");
  col_clear(pinfo->cinfo, COL_INFO);
  col_add_fstr(pinfo->cinfo, COL_INFO, "%7s (0x%08x): ",
	       val_to_str(packet_type, mason_type_names, "Unknown (0x%02x)"),
	       round_id);
  
  /* Clear the source and address columns. */
  SET_ADDRESS(&pinfo->src, AT_NONE, 0, NULL);
  COPY_ADDRESS(&pinfo->net_dst, &pinfo->dl_dst);
  SET_ADDRESS(&pinfo->dst, AT_NONE, 0, NULL);
  COPY_ADDRESS(&pinfo->net_src, &pinfo->dl_src);

  /* Fill in the source column. The type-specific process_* methods
     can later change this field and set the destination field.  */
  show_src_identity(pinfo, sender_id);
  
  /* Fill in the fields */
  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_mason, tvb, 0, -1, 
					"Mason (%s)",		
					val_to_str(packet_type,		
						   mason_type_names, 
						   "Unknown (0x%02x)"));
    mason_tree = proto_item_add_subtree(ti, ett_mason);
    proto_tree_add_item(mason_tree, hf_mason_version, tvb, 0, 1, FALSE);
    proto_tree_add_item(mason_tree, hf_mason_type, tvb, 0, 1, FALSE);
    proto_tree_add_item(mason_tree, hf_mason_sig, tvb, 0, 1, FALSE);
    proto_tree_add_item(mason_tree, hf_mason_rnd_id, tvb, 2, 4, FALSE);
    proto_tree_add_item(mason_tree, hf_mason_sender_id, tvb, 6, 2, FALSE);
    proto_tree_add_item(mason_tree, hf_mason_pkt_uid, tvb, 8, 2, FALSE);
    proto_tree_add_item(mason_tree, hf_mason_rssi, tvb, 1, 1, FALSE); 

  }

  /* Add subtrees for packet type */
  offset += 10;
  if (packet_type < 8 && process_table[packet_type])
    process_table[packet_type](tvb, pinfo, &offset, mason_tree);   
}

/* Initialize the dissector */
void
proto_reg_handoff_mason(void)
{

  mason_handle = create_dissector_handle(dissect_mason, proto_mason);
  dissector_add_uint("ethertype", ETH_P_MASON, mason_handle);
}
