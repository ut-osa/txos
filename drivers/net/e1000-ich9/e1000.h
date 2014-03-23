/*******************************************************************************

  Intel PRO/1000 Linux driver
  Copyright(c) 1999 - 2007 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  Linux NICS <linux.nics@intel.com>
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/


/* Linux PRO/1000 Ethernet Driver main header file */

#ifndef _E1000_H_
#define _E1000_H_

#include "kcompat.h"

#include "e1000_api.h"

#define BAR_0		0
#define BAR_1		1
#define BAR_5		5

#define INTEL_E1000_ETHERNET_DEVICE(device_id) {\
	PCI_DEVICE(PCI_VENDOR_ID_INTEL, device_id)}

struct e1000_adapter;

#define E1000_DBG(args...)

#define E1000_ERR(args...) printk(KERN_ERR "e1000: " args)

#define PFX "e1000: "
#define DPRINTK(nlevel, klevel, fmt, args...) \
	(void)((NETIF_MSG_##nlevel & adapter->msg_enable) && \
	printk(KERN_##klevel PFX "%s: %s: " fmt, adapter->netdev->name, \
		__FUNCTION__ , ## args))

#define E1000_MAX_INTR 10

/* TX/RX descriptor defines */
#define E1000_DEFAULT_TXD                  256
#define E1000_MAX_TXD                      256
#define E1000_MIN_TXD                       80
#define E1000_MAX_82544_TXD               4096

#define E1000_DEFAULT_RXD                  256
#define E1000_MAX_RXD                      256
#define E1000_MIN_RXD                       80
#define E1000_MAX_82544_RXD               4096

#ifdef CONFIG_E1000_MQ
#define E1000_MAX_TX_QUEUES                  4
#endif

/* this is the size past which hardware will drop packets when setting LPE=0 */
#define MAXIMUM_ETHERNET_VLAN_SIZE 1522

/* Supported Rx Buffer Sizes */
#define E1000_RXBUFFER_128   128    /* Used for packet split */
#define E1000_RXBUFFER_256   256    /* Used for packet split */
#define E1000_RXBUFFER_512   512
#define E1000_RXBUFFER_1024  1024
#define E1000_RXBUFFER_2048  2048
#define E1000_RXBUFFER_4096  4096
#define E1000_RXBUFFER_8192  8192
#define E1000_RXBUFFER_16384 16384

/* SmartSpeed delimiters */
#define E1000_SMARTSPEED_DOWNSHIFT 3
#define E1000_SMARTSPEED_MAX       15

/* Packet Buffer allocations */
#define E1000_PBA_BYTES_SHIFT 0xA
#define E1000_TX_HEAD_ADDR_SHIFT 7
#define E1000_PBA_TX_MASK 0xFFFF0000

/* Early Receive defines */
#define E1000_ERT_2048 0x100

#define E1000_FC_PAUSE_TIME 0x0680 /* 858 usec */

/* How many Tx Descriptors do we need to call netif_wake_queue ? */
#define E1000_TX_QUEUE_WAKE	16
/* How many Rx Buffers do we bundle into one write to the hardware ? */
#define E1000_RX_BUFFER_WRITE	16	/* Must be power of 2 */

#define AUTO_ALL_MODES            0
#define E1000_EEPROM_82544_APM    0x0004
#define E1000_EEPROM_APME         0x0400

#ifndef E1000_MASTER_SLAVE
/* Switch to override PHY master/slave setting */
#define E1000_MASTER_SLAVE	e1000_ms_hw_default
#endif

#ifdef NETIF_F_HW_VLAN_TX
#define E1000_MNG_VLAN_NONE -1
#endif
/* Number of packet split data buffers (not including the header buffer) */
#define PS_PAGE_BUFFERS MAX_PS_BUFFERS-1

/* wrapper around a pointer to a socket buffer,
 * so a DMA handle can be stored along with the buffer */
struct e1000_buffer {
	struct sk_buff *skb;
	dma_addr_t dma;
	unsigned long time_stamp;
	u16 length;
	u16 next_to_watch;
};

struct e1000_rx_buffer {
	struct sk_buff *skb;
	dma_addr_t dma;
	struct page *page;
};
	
#ifdef CONFIG_E1000_MQ
struct e1000_queue_stats {
	u64 packets;
	u64 bytes;
};
#endif

struct e1000_ps_page { struct page *ps_page[PS_PAGE_BUFFERS]; };
struct e1000_ps_page_dma { u64 ps_page_dma[PS_PAGE_BUFFERS]; };

struct e1000_tx_ring {
	/* pointer to the descriptor ring memory */
	void *desc;
	/* physical address of the descriptor ring */
	dma_addr_t dma;
	/* length of descriptor ring in bytes */
	unsigned int size;
	/* number of descriptors in the ring */
	unsigned int count;
	/* next descriptor to associate a buffer with */
	unsigned int next_to_use;
	/* next descriptor to check for DD status bit */
	unsigned int next_to_clean;
	/* array of buffer information structs */
	struct e1000_buffer *buffer_info;

#ifdef CONFIG_E1000_MQ
	/* for tx ring cleanup - needed for multiqueue */
	spinlock_t tx_queue_lock;
#endif
	spinlock_t tx_lock;
	u16 tdh;
	u16 tdt;
#ifdef CONFIG_E1000_MQ
	struct e1000_queue_stats tx_stats;
#endif
	boolean_t last_tx_tso;
};

struct e1000_rx_ring {
	/* pointer to the descriptor ring memory */
	void *desc;
	/* physical address of the descriptor ring */
	dma_addr_t dma;
	/* length of descriptor ring in bytes */
	unsigned int size;
	/* number of descriptors in the ring */
	unsigned int count;
	/* next descriptor to associate a buffer with */
	unsigned int next_to_use;
	/* next descriptor to check for DD status bit */
	unsigned int next_to_clean;
	/* array of buffer information structs */
	struct e1000_rx_buffer *buffer_info;
	/* arrays of page information for packet split */
	struct e1000_ps_page *ps_page;
	struct e1000_ps_page_dma *ps_page_dma;
	struct sk_buff *rx_skb_top;

	/* cpu for rx queue */
	int cpu;

	u16 rdh;
	u16 rdt;
#ifdef CONFIG_E1000_MQ
	struct e1000_queue_stats rx_stats;
#endif
};

#define E1000_DESC_UNUSED(R) \
	((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->count) + \
	(R)->next_to_clean - (R)->next_to_use - 1)

#define E1000_RX_DESC_PS(R, i)	    \
	(&(((union e1000_rx_desc_packet_split *)((R).desc))[i]))
#define E1000_RX_DESC_EXT(R, i)	    \
	(&(((union e1000_rx_desc_extended *)((R).desc))[i]))
#define E1000_GET_DESC(R, i, type)	(&(((struct type *)((R).desc))[i]))
#define E1000_RX_DESC(R, i)		E1000_GET_DESC(R, i, e1000_rx_desc)
#define E1000_TX_DESC(R, i)		E1000_GET_DESC(R, i, e1000_tx_desc)
#define E1000_CONTEXT_DESC(R, i)	E1000_GET_DESC(R, i, e1000_context_desc)

/* board specific private data structure */

struct e1000_adapter {
	struct timer_list tx_fifo_stall_timer;
	struct timer_list watchdog_timer;
	struct timer_list phy_info_timer;
#ifdef NETIF_F_HW_VLAN_TX
	struct vlan_group *vlgrp;
	u16 mng_vlan_id;
#endif
	u32 bd_number;
	u32 rx_buffer_len;
	u32 wol;
	u32 smartspeed;
	u32 en_mng_pt;
	u16 link_speed;
	u16 link_duplex;
	spinlock_t stats_lock;
#ifdef CONFIG_E1000_NAPI
	spinlock_t tx_queue_lock;
#endif
	atomic_t irq_sem;
	unsigned int total_tx_bytes;
	unsigned int total_tx_packets;
	unsigned int total_rx_bytes;
	unsigned int total_rx_packets;
	/* Interrupt Throttle Rate */
	u32 itr;
	u32 itr_setting;
	u16 tx_itr;
	u16 rx_itr;

	struct work_struct reset_task;
	struct work_struct watchdog_task;
	u8 fc_autoneg;

#ifdef ETHTOOL_PHYS_ID
	struct timer_list blink_timer;
	unsigned long led_status;
#endif

	/* TX */
	struct e1000_tx_ring *tx_ring;      /* One per active queue */
#ifdef CONFIG_E1000_MQ
	struct e1000_tx_ring **cpu_tx_ring; /* per-cpu */
#endif
	unsigned int restart_queue;
	unsigned long tx_queue_len;
	u32 txd_cmd;
	u32 tx_int_delay;
	u32 tx_abs_int_delay;
	u32 gotcl;
	u64 gotcl_old;
	u64 tpt_old;
	u64 colc_old;
	u32 tx_timeout_count;
	u32 tx_fifo_head;
	u32 tx_head_addr;
	u32 tx_fifo_size;
	u8 tx_timeout_factor;
	atomic_t tx_fifo_stall;
	boolean_t pcix_82544;
	boolean_t detect_tx_hung;

	/* RX */
#ifdef CONFIG_E1000_NAPI
	boolean_t (*clean_rx) (struct e1000_adapter *adapter,
			       struct e1000_rx_ring *rx_ring,
			       int *work_done, int work_to_do);
#else
	boolean_t (*clean_rx) (struct e1000_adapter *adapter,
			       struct e1000_rx_ring *rx_ring);
#endif
	void (*alloc_rx_buf) (struct e1000_adapter *adapter,
			      struct e1000_rx_ring *rx_ring,
				int cleaned_count);
	struct e1000_rx_ring *rx_ring;      /* One per active queue */
#ifdef CONFIG_E1000_NAPI
	struct net_device *polling_netdev;  /* One per active queue */
#endif
	int num_tx_queues;
	int num_rx_queues;

	u64 hw_csum_err;
	u64 hw_csum_good;
	u64 rx_hdr_split;
	u32 alloc_rx_buff_failed;
	u32 rx_int_delay;
	u32 rx_abs_int_delay;
	boolean_t rx_csum;
	unsigned int rx_ps_pages;
	u32 gorcl;
	u64 gorcl_old;
	u16 rx_ps_bsize0;


	/* OS defined structs */
	struct net_device *netdev;
	struct pci_dev *pdev;
	struct net_device_stats net_stats;

	/* structs defined in e1000_hw.h */
	struct e1000_hw hw;
	struct e1000_hw_stats stats;
	struct e1000_phy_info phy_info;
	struct e1000_phy_stats phy_stats;

#ifdef ETHTOOL_TEST
	u32 test_icr;
	struct e1000_tx_ring test_tx_ring;
	struct e1000_rx_ring test_rx_ring;
#endif


	int msg_enable;
	/* to not mess up cache alignment, always add to the bottom */
	unsigned long state;
	u32 eeprom_wol;

	u32 *config_space;

	/* hardware capability, feature, and workaround flags */
	struct {
		unsigned int has_smbus:1;
		unsigned int has_manc2h:1;
#ifdef CONFIG_PCI_MSI
		unsigned int has_msi:1;
		unsigned int msi_enabled:1;
#endif
		unsigned int has_intr_moderation:1;
		unsigned int rx_needs_restart:1;
		unsigned int bad_tx_carrier_stats_fd:1;
		unsigned int int_assert_auto_mask:1;
		unsigned int quad_port_a:1;
		unsigned int smart_power_down:1;
#ifdef NETIF_F_TSO
		unsigned int has_tso:1;
#ifdef NETIF_F_TSO6
		unsigned int has_tso6:1;
#endif
		unsigned int tso_force:1;
#endif
	} flags;

};

enum e1000_state_t {
	__E1000_TESTING,
	__E1000_RESETTING,
	__E1000_DOWN
};
#endif /* _E1000_H_ */
