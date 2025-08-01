#ifndef __MTK_AES_ENGINE__
#define __MTK_AES_ENGINE__

#include <crypto/aes.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>

#define MTK_RING_SIZE		128
#define NUM_AES_BYPASS		16 /* Bypass for small packets, must be multiple of AES_BLOCK_SIZE */
#define MTK_QUEUE_LENGTH	20

#define CRYPTO_MODE_ENC	BIT(0)
#define CRYPTO_MODE_CBC	BIT(1)

/* 1. AES Register Offsets */
#define AES_TX_BASE_PTR0	0x000
#define AES_TX_MAX_CNT0		0x004
#define AES_TX_CTX_IDX0		0x008
#define AES_TX_DTX_IDX0		0x00C

#define AES_RX_BASE_PTR0	0x100
#define AES_RX_MAX_CNT0		0x104
#define AES_RX_CALC_IDX0	0x108
#define AES_RX_DRX_IDX0		0x10C

#define AES_INFO		0x200
#define AES_GLO_CFG		0x204
#define AES_RST_IDX		0x208
#define AES_RST_CFG		(AES_RST_IDX)
#define AES_DLY_INT_CFG		0x20C
#define AES_FREEQ_THRES		0x210
#define AES_INT_STATUS		0x220
#define AES_INT_MASK		0x228

/* AES_GLO_CFG bits */
#define AES_PST_DRX_IDX0	(1u<<16)
#define AES_PST_DTX_IDX0	(1u<<0)
#define AES_RX_2B_OFFSET	(1u<<31)
#define AES_RX_ANYBYTE_ALIGN	(1u<<12)
#define AES_DESC_5DW_INFO_EN	(1u<<11)
#define AES_MUTI_ISSUE		(1u<<10)
#define AES_TWO_BUFFER		(1u<<9)
#define AES_32_BYTES		(1u<<8)
#define AES_TX_WB_DDONE		(1u<<6)
#define AES_RX_DMA_BUSY		(1u<<3)
#define AES_TX_DMA_BUSY		(1u<<1)
#define AES_RX_DMA_EN		(1u<<2)
#define AES_TX_DMA_EN		(1u<<0)

#define AES_BT_SIZE_4DWORDS	(0u<<4)
#define AES_BT_SIZE_8DWORDS	(1u<<4)
#define AES_BT_SIZE_16DWORDS	(2u<<4)
#define AES_BT_SIZE_32DWORDS	(3u<<4)

/* AES_INT_STATUS / AES_INT_MASK bits */
#define AES_RX_COHERENT		(1u<<31)
#define AES_RX_DLY_INT		(1u<<30)
#define AES_TX_COHERENT		(1u<<29)
#define AES_TX_DLY_INT		(1u<<28)
#define AES_RX_DONE_INT0	(1u<<16)
#define AES_TX_DONE_INT0	(1u<<0)

#define AES_MASK_INT_ALL	(AES_RX_DLY_INT | AES_RX_DONE_INT0)

#define AES_DLY_INIT_VALUE	0x00008101

/*
 * AES RX Descriptor Format define
 */
struct aes_rxdesc {
	u32 sdp0;
	volatile u32 rxd_info2;
	u32 user_data;
	u32 rxd_info4;
	u32 iv[4];
} __attribute__((aligned(32)));

#define RX2_DMA_SDL0_GET(_x)	(((_x) >> 16) & 0x3fff)
#define RX2_DMA_SDL0_SET(_x)	(((_x) & 0x3fff) << 16)
#define RX2_DMA_LS0		BIT(30)
#define RX2_DMA_DONE		BIT(31)

#define RX4_DMA_ENC		BIT(2)
#define RX4_DMA_UDV		BIT(3)
#define RX4_DMA_CBC		BIT(4)
#define RX4_DMA_IVR		BIT(5)
#define RX4_DMA_KIU		BIT(6)

/*
 * AES TX Descriptor Format define
 */
struct aes_txdesc {
	u32 sdp0;
	volatile u32 txd_info2;
	u32 sdp1;
	u32 txd_info4;
	u32 iv[4];
} __attribute__((aligned(32)));

#define TX2_DMA_SDL1_SET(_x)	((_x) & 0x3fff)
#define TX2_DMA_LS1		BIT(14)
#define TX2_DMA_SDL0_SET(_x)	(((_x) & 0x3fff) << 16)
#define TX2_DMA_LS0		BIT(30)
#define TX2_DMA_DONE		BIT(31)

#define TX4_DMA_ENC		BIT(2)
#define TX4_DMA_UDV		BIT(3)
#define TX4_DMA_CBC		BIT(4)
#define TX4_DMA_IVR		BIT(5)
#define TX4_DMA_KIU		BIT(6)

#define TX4_DMA_AES_128		0
#define TX4_DMA_AES_192		1
#define TX4_DMA_AES_256		2

/**
 * struct mtk_dma_rec - holds the records associated with the ringbuffer
 * @src: Dma address of the source packet
 * @dst: Dma address of the destination
 * @len: Size of the packet
 * @req: holds the async_request
 */
struct mtk_dma_rec {
	dma_addr_t src;
	dma_addr_t dst;
	size_t len;
	struct skcipher_request *req;
};

/**
 * struct mtk_dev - Cryptographic device
 * @base:	pointer to mapped register I/O base
 * @dev:	pointer to device
 * @clk:	pointer to crypto clock
 * @rstc:	pointer to reset controller
 * @irq:	global system and rings IRQ
 * @tx:		pointer to descriptor input-ring
 * @rx:		pointer to descriptor output-ring
 * @phy_tx:	dma address of tx ring
 * @phy_rx:	dma address of rx ring
 * @aes_list:	device list of AES
 * @done_tasklet: tasklet for completed requests
 * @rec_front_idx: ring buffer front index
 * @rec_rear_idx: ring buffer rear index
 * @rec:	dma records
 * @lock:	per-device spinlock
 * @count:	number of active requests
 *
 * Structure storing cryptographic device information.
 */
struct mtk_dev {
	void __iomem *base;
	struct device *dev;
	struct clk *clk;
	struct reset_control *rstc;
	int irq;

	struct aes_txdesc *tx;
	struct aes_rxdesc *rx;
	dma_addr_t phy_tx;
	dma_addr_t phy_rx;

	struct list_head aes_list;

	struct tasklet_struct done_tasklet;
	unsigned int rec_front_idx;
	unsigned int rec_rear_idx;
	struct mtk_dma_rec *rec;
	spinlock_t lock;
	unsigned int count;
};

struct mtk_aes_ctx {
	struct mtk_dev *mtk;
	u8 key[AES_MAX_KEY_SIZE] __attribute__((aligned(16)));
	u32 keylen;
	dma_addr_t phy_key;
	struct crypto_skcipher *fallback;
};

struct mtk_aes_reqctx {
	unsigned long mode;
};

struct mtk_aes_drv {
	struct list_head dev_list;
	spinlock_t lock;
};

static struct mtk_aes_drv mtk_aes = {
	.dev_list = LIST_HEAD_INIT(mtk_aes.dev_list),
	.lock = __SPIN_LOCK_UNLOCKED(mtk_aes.lock),
};

#endif /* __MTK_AES_ENGINE__ */
