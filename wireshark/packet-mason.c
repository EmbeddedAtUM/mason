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

static int proto_mason = -1;

static gint ett_mason = -1;

static int hf_mason_version   = -1;
static int hf_mason_type      = -1;
static int hf_mason_sig       = -1;
static int hf_mason_rssi      = -1;
static int hf_mason_rnd_id    = -1;
static int hf_mason_sender_id = -1;
static int hf_mason_pkt_uid   = -1;

static int hf_mason_pub_key  = -1;
static int hf_mason_id       = -1;
static int hf_mason_txreq_id = -1;
static int hf_mason_rsstreq_id = -1;

static void
show_src_identity(packet_info *pinfo, const gint16 id)
{
  if (0 < id)
    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "%03d (%s)", id, ep_address_to_str(&pinfo->dl_src));
  else if (0 == id) 
    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "Ini (%s)", ep_address_to_str(&pinfo->dl_src));
  else
    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "... (%s)", ep_address_to_str(&pinfo->dl_src));
}

static void
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
      {"Packet UID", "mason.packet_id",
       FT_UINT16, BASE_DEC,
       NULL, 0x0,
       NULL, HFILL }
    },
    { &hf_mason_pub_key,
      {"Public Key", "mason.pub_key",
       FT_BYTES, BASE_NONE,
       NULL, 0x0,
       NULL, HFILL }
    },
    { &hf_mason_id,
      {"ID", "mason.id",
       FT_UINT16, BASE_DEC,
       NULL, 0x0,
       NULL, HFILL }
    },
    { &hf_mason_txreq_id,
      {"ID", "mason.txreq.id",
       FT_UINT16, BASE_DEC,
       NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_mason_rsstreq_id,
      {"ID", "mason.rsstreq.id",
       FT_UINT16, BASE_DEC,
       NULL, 0x0,
       NULL, HFILL}
    }
  };
  
  static gint *ett[] = {
    &ett_mason
  };

  proto_mason = proto_register_protocol("Mason Protocol",
					"Mason",
					"mason");

  proto_register_field_array(proto_mason, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

static void
dissect_mason(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8 packet_type = GET_MASON_TYPE(tvb_get_guint8(tvb, 0));
  guint16 sender_id   = tvb_get_ntohs(tvb, 6);
  
  SET_ADDRESS(&pinfo->src, AT_NONE, 0, NULL);
  SET_ADDRESS(&pinfo->dst, AT_NONE, 0, NULL);
  COPY_ADDRESS(&pinfo->net_dst, &pinfo->dl_dst);
  COPY_ADDRESS(&pinfo->net_src, &pinfo->dl_src);
  
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Mason");
  col_clear(pinfo->cinfo, COL_INFO);
  col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s",
	       val_to_str(packet_type, mason_type_names, "Unknown (0x%02x)"));

  /* TODO: Replace all the switch statements in the following code
     with per-type sub-dissectors */

  /* TODO: Proper stateful decoding of source and destination
     addresses by storing the public key<->ID assignments. The
     following decoding assumes the packets are well-formed and
     well-addressed. */

  /* Set the source column display */
  switch(packet_type) {
  case MASON_PAR:
    show_src_identity(pinfo, -1);
    break;
  case MASON_INIT:
  case MASON_PARACK:
  case MASON_PARLIST:
  case MASON_TXREQ:
  case MASON_MEAS:
  case MASON_RSSTREQ:
  case MASON_RSST:
    show_src_identity(pinfo, sender_id);
    break;
  }
  
  /* Set the destination column display */
  switch(packet_type) {
  case MASON_INIT:
    show_dst_identity(pinfo, -1);
    break;
  case MASON_PAR:
    show_dst_identity(pinfo, 0);
    break;
  case MASON_PARLIST:
    show_dst_identity(pinfo, -1);
    break;
  case MASON_PARACK:
  case MASON_TXREQ:
  case MASON_RSSTREQ:
    show_dst_identity(pinfo, tvb_get_ntohs(tvb, 10));
    break;
  case MASON_MEAS:
    show_dst_identity(pinfo, -1);
    break;
  case MASON_RSST:
    show_dst_identity(pinfo, 0);
    break;
  }
  
  if (tree) {
    proto_item *ti = NULL;
    proto_item *mason_tree = NULL;

    ti = proto_tree_add_protocol_format(tree, proto_mason, tvb, 0, -1, 
					"Mason (%s)",		
					val_to_str(packet_type,		
						   mason_type_names, 
						   "Unknown (0x%02x)"));
    mason_tree = proto_item_add_subtree(ti, ett_mason);

    proto_tree_add_item(mason_tree, hf_mason_version, tvb, 0, 1, FALSE);
    proto_tree_add_item(mason_tree, hf_mason_type, tvb, 0, 1, FALSE);
    proto_tree_add_item(mason_tree, hf_mason_sig, tvb, 0, 1, FALSE);
    proto_tree_add_item(mason_tree, hf_mason_rssi, tvb, 1, 1, FALSE);
    proto_tree_add_item(mason_tree, hf_mason_rnd_id, tvb, 2, 4, FALSE);
    proto_tree_add_item(mason_tree, hf_mason_sender_id, tvb, 6, 2, FALSE);
    proto_tree_add_item(mason_tree, hf_mason_pkt_uid, tvb, 8, 2, FALSE);

    switch(packet_type) {
    case MASON_INIT: 
    case MASON_PAR:
      proto_tree_add_item(mason_tree, hf_mason_pub_key, tvb, 10, RSA_LEN, FALSE);
      break;
    case MASON_PARACK:
      proto_tree_add_item(mason_tree, hf_mason_id, tvb, 10, 2, FALSE);
      proto_tree_add_item(mason_tree, hf_mason_pub_key, tvb, 11, RSA_LEN, FALSE);
      break;
    case MASON_PARLIST:
      break;
    case MASON_TXREQ:
      proto_tree_add_item(mason_tree, hf_mason_txreq_id, tvb, 10, 2, FALSE);
      break;
    case MASON_RSSTREQ:
      proto_tree_add_item(mason_tree, hf_mason_rsstreq_id, tvb, 10, 2, FALSE);
      break;
    }
  }
}

/* Initialize the dissector */
void
proto_reg_handoff_mason(void)
{
  static dissector_handle_t mason_handle;
  mason_handle = create_dissector_handle(dissect_mason, proto_mason);
  dissector_add_uint("ethertype", ETH_P_MASON, mason_handle);
}


