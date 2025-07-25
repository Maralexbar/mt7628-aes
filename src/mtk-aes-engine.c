/*
 * For verbose debug messages, compile with DEBUG flag
 * or enable dynamic debug for this module.
 *
 * Example:
 * echo 'file mtk-aes-engine.c +p' > /sys/kernel/debug/dynamic_debug/control
 */
#define DEBUG

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/reset.h>
#include <crypto/skcipher.h>
#include <crypto/internal/skcipher.h>

#include "mtk-aes-engine.h"

static void aes_engine_start(struct mtk_dev *mtk)
{
	u32 reg_val;
	u32 aes_glo_cfg = 0;

	dev_dbg(mtk->dev, "Starting hardware engine...");

	aes_glo_cfg = (AES_TX_DMA_EN | AES_RX_DMA_EN | AES_TX_WB_DDONE |
		       AES_DESC_5DW_INFO_EN | AES_RX_ANYBYTE_ALIGN);

	writel(AES_DLY_INIT_VALUE, mtk->base + AES_DLY_INT_CFG);
	/* Clear any pending interrupts */
	writel(AES_MASK_INT_ALL, mtk->base + AES_INT_STATUS);
	reg_val = readl(mtk->base + AES_INT_STATUS);
	/* Enable interrupts */
	writel(AES_MASK_INT_ALL, mtk->base + AES_INT_MASK);

	aes_glo_cfg |= AES_BT_SIZE_16DWORDS;
	writel(aes_glo_cfg, mtk->base + AES_GLO_CFG);

	dev_dbg(mtk->dev, "AES_GLO_CFG set to 0x%08x", aes_glo_cfg);
}

static void aes_engine_stop(struct mtk_dev *mtk)
{
	int i;
	u32 reg_val;

	dev_dbg(mtk->dev, "Stopping hardware engine...");

	reg_val = readl(mtk->base + AES_GLO_CFG);
	reg_val &= ~(AES_TX_WB_DDONE | AES_RX_DMA_EN | AES_TX_DMA_EN);
	writel(reg_val, mtk->base + AES_GLO_CFG);

	/* Wait for AES engine to stop */
	for (i = 0; i < 50; i++) {
		if (!(readl(mtk->base + AES_GLO_CFG) &
		      (AES_RX_DMA_BUSY | AES_TX_DMA_BUSY))) {
			dev_dbg(mtk->dev, "Engine stopped.");
			break;
		}
		msleep(1);
	}
	if (i == 50)
		dev_warn(mtk->dev, "Timeout waiting for engine to stop!\n");

	/* Disable AES interrupt */
	writel(0, mtk->base + AES_INT_MASK);
}

static int aes_engine_desc_init(struct mtk_dev *mtk)
{
	u32 reg_val;
	int i;
	size_t size;

	dev_dbg(mtk->dev, "Initializing descriptor rings...");

	size = (MTK_RING_SIZE * sizeof(struct aes_txdesc));
	mtk->tx = dma_alloc_coherent(mtk->dev, size, &mtk->phy_tx, GFP_KERNEL);
	if (!mtk->tx)
		return -ENOMEM;

	size = (MTK_RING_SIZE * sizeof(struct aes_rxdesc));
	mtk->rx = dma_alloc_coherent(mtk->dev, size, &mtk->phy_rx, GFP_KERNEL);
	if (!mtk->rx)
		goto err_free_tx;

	size = (MTK_RING_SIZE * sizeof(struct mtk_dma_rec));
	mtk->rec = devm_kzalloc(mtk->dev, size, GFP_KERNEL);
	if (!mtk->rec)
		goto err_free_rx;

	dev_dbg(mtk->dev, "Rings allocated (TX: %pad, RX: %pad)",
		&mtk->phy_tx, &mtk->phy_rx);

	for (i = 0; i < MTK_RING_SIZE; i++)
		mtk->tx[i].txd_info2 |= TX2_DMA_DONE;

	reg_val = readl(mtk->base + AES_GLO_CFG);
	reg_val &= 0x00000ff0;
	writel(reg_val, mtk->base + AES_GLO_CFG);

	writel((u32)mtk->phy_tx, mtk->base + AES_TX_BASE_PTR0);
	writel((u32)MTK_RING_SIZE, mtk->base + AES_TX_MAX_CNT0);
	writel(0, mtk->base + AES_TX_CTX_IDX0);
	writel(AES_PST_DTX_IDX0, mtk->base + AES_RST_CFG);

	writel((u32)mtk->phy_rx, mtk->base + AES_RX_BASE_PTR0);
	writel((u32)MTK_RING_SIZE, mtk->base + AES_RX_MAX_CNT0);
	writel((u32)(MTK_RING_SIZE - 1), mtk->base + AES_RX_CALC_IDX0);

	mtk->rec_rear_idx = 0;
	mtk->rec_front_idx = 0;
	mtk->count = 0;

	writel(AES_PST_DRX_IDX0, mtk->base + AES_RST_CFG);

	dev_dbg(mtk->dev, "Descriptor rings initialized.");
	return 0;

err_free_rx:
	dma_free_coherent(mtk->dev, MTK_RING_SIZE * sizeof(struct aes_rxdesc),
			  mtk->rx, mtk->phy_rx);
	mtk->rx = NULL;
err_free_tx:
	dma_free_coherent(mtk->dev, MTK_RING_SIZE * sizeof(struct aes_txdesc),
			  mtk->tx, mtk->phy_tx);
	mtk->tx = NULL;
	return -ENOMEM;
}

static void aes_engine_desc_free(struct mtk_dev *mtk)
{
	dev_dbg(mtk->dev, "Freeing descriptor rings...");
	writel(0, mtk->base + AES_TX_BASE_PTR0);
	writel(0, mtk->base + AES_RX_BASE_PTR0);

	if (mtk->tx) {
		dma_free_coherent(mtk->dev,
				  MTK_RING_SIZE * sizeof(struct aes_txdesc),
				  mtk->tx, mtk->phy_tx);
		mtk->tx = NULL;
	}

	if (mtk->rx) {
		dma_free_coherent(mtk->dev,
				  MTK_RING_SIZE * sizeof(struct aes_rxdesc),
				  mtk->rx, mtk->phy_rx);
		mtk->rx = NULL;
	}
	dev_dbg(mtk->dev, "Descriptor rings freed.");
}

static int mtk_aes_xmit(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct mtk_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct mtk_aes_reqctx *rctx = skcipher_request_ctx(req);
	struct mtk_dev *mtk = ctx->mtk;
	struct aes_txdesc *txdesc = NULL;
	struct aes_rxdesc *rxdesc = NULL;
	struct mtk_dma_rec *rec;
	u32 aes_txd_info4, info;
	u32 ctr, i;
	unsigned long flags;
	struct scatterlist *sg;
	int nents;

	if (!mtk)
		return -ENODEV;

	spin_lock_irqsave(&mtk->lock, flags);

	if (ctx->keylen == AES_KEYSIZE_256)
		aes_txd_info4 = TX4_DMA_AES_256;
	else if (ctx->keylen == AES_KEYSIZE_192)
		aes_txd_info4 = TX4_DMA_AES_192;
	else
		aes_txd_info4 = TX4_DMA_AES_128;

	if (rctx->mode & CRYPTO_MODE_ENC)
		aes_txd_info4 |= TX4_DMA_ENC;

	if (rctx->mode & CRYPTO_MODE_CBC)
		aes_txd_info4 |= TX4_DMA_CBC | TX4_DMA_IVR;

	nents = sg_nents_for_len(req->src, req->cryptlen);
	if (nents < 0) {
		dev_warn(mtk->dev, "Invalid S/G list for request\n");
		spin_unlock_irqrestore(&mtk->lock, flags);
		return nents;
	}
	dev_dbg(mtk->dev, "Transmitting request %p with %d S/G entries", req, nents);

	for_each_sg(req->src, sg, nents, i) {
		ctr = (mtk->rec_rear_idx + i) % MTK_RING_SIZE;
		txdesc = &mtk->tx[ctr];
		rxdesc = &mtk->rx[ctr];
		rec = &mtk->rec[ctr];
		rec->req = req;
		info = aes_txd_info4;

		if ((rctx->mode & CRYPTO_MODE_CBC) && (i == 0)) {
			memcpy(txdesc->iv, req->iv, AES_BLOCK_SIZE);
			info |= TX4_DMA_KIU;
		}
		txdesc->txd_info4 = info;

		if (i == 0) {
			txdesc->sdp0 = (u32)ctx->phy_key;
			txdesc->txd_info2 = TX2_DMA_SDL0_SET(ctx->keylen);
		} else {
			txdesc->txd_info2 = 0;
		}

		rec->src = sg_dma_address(sg);
		rec->len = sg_dma_len(sg);
		txdesc->sdp1 = (u32)rec->src;
		txdesc->txd_info2 |= TX2_DMA_SDL1_SET(rec->len);

		rec->dst = sg_dma_address(sg_next(req->dst));
		rxdesc->sdp0 = (u32)rec->dst;
		rxdesc->rxd_info2 = RX2_DMA_SDL0_SET(rec->len);

		dev_dbg(mtk->dev, "  desc[%u]: src=%pad, dst=%pad, len=%zu",
			ctr, &rec->src, &rec->dst, rec->len);
	}

	if (txdesc && rxdesc) {
		/* Mark last descriptors */
		txdesc->txd_info2 |= TX2_DMA_LS1;
		rxdesc->rxd_info2 |= RX2_DMA_LS0;
	}

	mtk->rec_rear_idx = (mtk->rec_rear_idx + nents) % MTK_RING_SIZE;
	ctr = mtk->rec_rear_idx;

	spin_unlock_irqrestore(&mtk->lock, flags);

	wmb(); /* Ensure all descriptor changes are written */
	dev_dbg(mtk->dev, "Setting TX_CTX_IDX to %u", ctr);
	writel(ctr, mtk->base + AES_TX_CTX_IDX0);
	return -EINPROGRESS;
}

static void mtk_tasklet_req_done(struct tasklet_struct *t)
{
	struct mtk_dev *mtk = from_tasklet(mtk, t, done_tasklet);
	struct skcipher_request *req;
	struct aes_rxdesc *rxdesc;
	struct mtk_dma_rec *rec;
	unsigned long flags;
	int ctr;
	bool last;

	dev_dbg(mtk, "Tasklet running, checking for completed requests...");
	spin_lock_irqsave(&mtk->lock, flags);

	ctr = mtk->rec_front_idx;

	while (mtk->count > 0) {
		rxdesc = &mtk->rx[ctr];

		if (!(rxdesc->rxd_info2 & RX2_DMA_DONE)) {
			dev_dbg(mtk, "Descriptor %d not done yet", ctr);
			break; /* Not yet processed by hardware */
		}

		last = rxdesc->rxd_info2 & RX2_DMA_LS0;
		rec = &mtk->rec[ctr];
		req = rec->req;

		rxdesc->rxd_info2 &= ~RX2_DMA_DONE;

		if (last) {
			dev_dbg(mtk, "Request %p completed, calling callback", req);
			mtk->count--;
			spin_unlock_irqrestore(&mtk->lock, flags);
			req->base.complete(&req->base, 0);
			spin_lock_irqsave(&mtk->lock, flags);
		}

		ctr = (ctr + 1) % MTK_RING_SIZE;

		if (last)
			break;
	}

	mtk->rec_front_idx = ctr;
	writel((ctr - 1) % MTK_RING_SIZE, mtk->base + AES_RX_CALC_IDX0);

	spin_unlock_irqrestore(&mtk->lock, flags);
}

static irqreturn_t mtk_aes_irq(int irq, void *arg)
{
	struct mtk_dev *mtk = arg;
	u32 reg_val;

	reg_val = readl(mtk->base + AES_INT_STATUS);
	if (!reg_val)
		return IRQ_NONE;

	dev_dbg(mtk->dev, "IRQ received, status: 0x%08x", reg_val);

	/* Disable interrupts, clear status, then schedule tasklet */
	writel(0, mtk->base + AES_INT_MASK);
	writel(reg_val, mtk->base + AES_INT_STATUS);
	tasklet_schedule(&mtk->done_tasklet);
	/* Re-enable interrupts */
	writel(AES_MASK_INT_ALL, mtk->base + AES_INT_MASK);

	return IRQ_HANDLED;
}

static struct mtk_dev *mtk_aes_find_dev(struct mtk_aes_ctx *ctx)
{
	struct mtk_dev *mtk = NULL;
	struct mtk_dev *tmp;

	spin_lock_bh(&mtk_aes.lock);
	if (!ctx->mtk) {
		list_for_each_entry(tmp, &mtk_aes.dev_list, aes_list) {
			mtk = tmp;
			break;
		}
		ctx->mtk = mtk;
	} else {
		mtk = ctx->mtk;
	}
	spin_unlock_bh(&mtk_aes.lock);

	return mtk;
}

static int mtk_aes_crypt(struct skcipher_request *req, unsigned int mode)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct mtk_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct mtk_aes_reqctx *rctx = skcipher_request_ctx(req);
	struct mtk_dev *mtk;
	int ret;
	unsigned long flags;

	mtk = mtk_aes_find_dev(ctx);
	if (!mtk) {
		pr_warn("mtk-aes: crypt() called without initialized device\n");
		return -ENODEV;
	}

	/* Fallback for small requests */
	if (req->cryptlen < NUM_AES_BYPASS) {
		dev_dbg(mtk->dev, "Request len %u < %d, using fallback",
			req->cryptlen, NUM_AES_BYPASS);

		{
			struct skcipher_request *subreq;

			subreq = skcipher_request_alloc(ctx->fallback, GFP_ATOMIC);
			if (!subreq)
				return -ENOMEM;

			skcipher_request_set_tfm(subreq, ctx->fallback);
			skcipher_request_set_callback(subreq, req->base.flags, NULL, NULL);
			skcipher_request_set_crypt(subreq, req->src, req->dst,
						   req->cryptlen, req->iv);
			if (mode & CRYPTO_MODE_ENC)
				ret = crypto_skcipher_encrypt(subreq);
			else
				ret = crypto_skcipher_decrypt(subreq);

			skcipher_request_free(subreq);
			return ret;
		}
	}

	rctx->mode = mode;

	spin_lock_irqsave(&mtk->lock, flags);
	if (mtk->count >= MTK_QUEUE_LENGTH) {
		spin_unlock_irqrestore(&mtk->lock, flags);
		dev_warn_ratelimited(mtk->dev, "HW queue full, returning busy\n");
		return -EBUSY;
	}
	mtk->count++;
	dev_dbg(mtk->dev, "Queued request, count: %u", mtk->count);
	spin_unlock_irqrestore(&mtk->lock, flags);

	return mtk_aes_xmit(req);
}

static int mtk_aes_setkey(struct crypto_skcipher *tfm, const u8 *key,
			  unsigned int keylen)
{
	struct mtk_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct mtk_dev *mtk;
	int ret;

	if (keylen != AES_KEYSIZE_128 && keylen != AES_KEYSIZE_192 &&
	    keylen != AES_KEYSIZE_256)
		return -EINVAL;

	mtk = mtk_aes_find_dev(ctx);
	if (!mtk)
		return -ENODEV;

	dev_dbg(mtk->dev, "Setting %u-bit AES key", keylen * 8);

	memcpy(ctx->key, key, keylen);
	ctx->keylen = keylen;

	if (ctx->phy_key)
		dma_unmap_single(mtk->dev, ctx->phy_key, ctx->keylen,
				 DMA_TO_DEVICE);

	ctx->phy_key = dma_map_single(mtk->dev, ctx->key, ctx->keylen,
				      DMA_TO_DEVICE);
	if (dma_mapping_error(mtk->dev, ctx->phy_key)) {
		dev_err(mtk->dev, "Failed to DMA map key\n");
		ctx->phy_key = 0;
		return -ENOMEM;
	}

	crypto_skcipher_clear_flags(ctx->fallback, CRYPTO_TFM_REQ_MASK);
	crypto_skcipher_set_flags(ctx->fallback, tfm->base.crt_flags &
					      CRYPTO_TFM_REQ_MASK);

	ret = crypto_skcipher_setkey(ctx->fallback, key, keylen);
	if (ret) {
		dev_err(mtk->dev, "Fallback setkey failed: %d\n", ret);
		dma_unmap_single(mtk->dev, ctx->phy_key, ctx->keylen,
				 DMA_TO_DEVICE);
		ctx->phy_key = 0;
	}

	return ret;
}

static int mtk_aes_ecb_encrypt(struct skcipher_request *req)
{
	return mtk_aes_crypt(req, CRYPTO_MODE_ENC);
}

static int mtk_aes_ecb_decrypt(struct skcipher_request *req)
{
	return mtk_aes_crypt(req, 0);
}

static int mtk_aes_cbc_encrypt(struct skcipher_request *req)
{
	return mtk_aes_crypt(req, CRYPTO_MODE_ENC | CRYPTO_MODE_CBC);
}

static int mtk_aes_cbc_decrypt(struct skcipher_request *req)
{
	return mtk_aes_crypt(req, CRYPTO_MODE_CBC);
}

static int mtk_aes_cra_init(struct crypto_tfm *tfm)
{
	struct mtk_aes_ctx *ctx = crypto_tfm_ctx(tfm);
	const char *name = crypto_tfm_alg_name(tfm);

	ctx->fallback = crypto_alloc_skcipher(name, 0, CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(ctx->fallback)) {
		pr_err("mtk-aes: Failed to allocate fallback for %s\n", name);
		return PTR_ERR(ctx->fallback);
	}

	crypto_tfm_set_flags(tfm, CRYPTO_TFM_REQ_FORBID_WEAK_KEYS);
	crypto_skcipher_set_reqsize(__crypto_skcipher_cast(tfm),
				    sizeof(struct mtk_aes_reqctx));
	return 0;
}

static void mtk_aes_cra_exit(struct crypto_tfm *tfm)
{
	struct mtk_aes_ctx *ctx = crypto_tfm_ctx(tfm);
	crypto_free_skcipher(ctx->fallback);
}

static struct skcipher_alg crypto_algs[] = {
	{
		.base.cra_name		= "cbc(aes)",
		.base.cra_driver_name	= "mtk-aes-cbc",
		.base.cra_priority	= 300,
		.base.cra_flags		= CRYPTO_ALG_ASYNC |
					  CRYPTO_ALG_NEED_FALLBACK,
		.base.cra_blocksize	= AES_BLOCK_SIZE,
		.base.cra_ctxsize	= sizeof(struct mtk_aes_ctx),
		.base.cra_alignmask	= 0,
		.base.cra_module	= THIS_MODULE,
		.init			= mtk_aes_cra_init,
		.exit			= mtk_aes_cra_exit,
		.min_keysize		= AES_MIN_KEY_SIZE,
		.max_keysize		= AES_MAX_KEY_SIZE,
		.setkey			= mtk_aes_setkey,
		.encrypt		= mtk_aes_cbc_encrypt,
		.decrypt		= mtk_aes_cbc_decrypt,
	},
	{
		.base.cra_name		= "ecb(aes)",
		.base.cra_driver_name	= "mtk-aes-ecb",
		.base.cra_priority	= 300,
		.base.cra_flags		= CRYPTO_ALG_ASYNC |
					  CRYPTO_ALG_NEED_FALLBACK,
		.base.cra_blocksize	= AES_BLOCK_SIZE,
		.base.cra_ctxsize	= sizeof(struct mtk_aes_ctx),
		.base.cra_alignmask	= 0,
		.base.cra_module	= THIS_MODULE,
		.init			= mtk_aes_cra_init,
		.exit			= mtk_aes_cra_exit,
		.min_keysize		= AES_MIN_KEY_SIZE,
		.max_keysize		= AES_MAX_KEY_SIZE,
		.setkey			= mtk_aes_setkey,
		.encrypt		= mtk_aes_ecb_encrypt,
		.decrypt		= mtk_aes_ecb_decrypt,
	},
};

static int mtk_cipher_alg_register(struct mtk_dev *mtk)
{
	int err;

	INIT_LIST_HEAD(&mtk->aes_list);
	spin_lock_init(&mtk->lock);
	spin_lock(&mtk_aes.lock);
	list_add_tail(&mtk->aes_list, &mtk_aes.dev_list);
	spin_unlock(&mtk_aes.lock);

	err = crypto_register_skciphers(crypto_algs, ARRAY_SIZE(crypto_algs));
	if (err) {
		dev_err(mtk->dev, "Could not register algorithms: %d\n", err);
		list_del(&mtk->aes_list);
		return err;
	}
	dev_info(mtk->dev, "Cipher algorithms registered");
	return 0;
}

static void mtk_cipher_alg_release(struct mtk_dev *mtk)
{
	dev_dbg(mtk->dev, "Unregistering cipher algorithms...");
	spin_lock(&mtk_aes.lock);
	list_del(&mtk->aes_list);
	spin_unlock(&mtk_aes.lock);
	crypto_unregister_skciphers(crypto_algs, ARRAY_SIZE(crypto_algs));
}

static int mtk_aes_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mtk_dev *mtk;
	struct resource *res;
	int ret;

	mtk = devm_kzalloc(dev, sizeof(*mtk), GFP_KERNEL);
	if (!mtk)
		return -ENOMEM;

	mtk->dev = dev;
	platform_set_drvdata(pdev, mtk);

	dev_info(dev, "Probing MediaTek AES accelerator...");

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	mtk->base = devm_ioremap_resource(dev, res);
	if (IS_ERR(mtk->base)) {
		dev_err(dev, "Failed to ioremap registers\n");
		return PTR_ERR(mtk->base);
	}
	dev_dbg(dev, "Registers mapped to %p", mtk->base);

	mtk->rstc = devm_reset_control_get_exclusive(dev, "cryp");
	if (IS_ERR(mtk->rstc)) {
		dev_err(dev, "Failed to get crypto reset controller\n");
		return PTR_ERR(mtk->rstc);
	}
	dev_dbg(dev, "Acquired reset controller");

	mtk->clk = devm_clk_get(dev, "cryp");
	if (IS_ERR(mtk->clk)) {
		dev_err(dev, "Failed to get crypto clock\n");
		return PTR_ERR(mtk->clk);
	}
	dev_dbg(dev, "Acquired clock");

	ret = clk_prepare_enable(mtk->clk);
	if (ret) {
		dev_err(dev, "Failed to enable clock: %d\n", ret);
		return ret;
	}
	dev_dbg(dev, "Clock enabled");

	dev_dbg(dev, "Performing hardware reset...");
	reset_control_assert(mtk->rstc);
	udelay(10);
	reset_control_deassert(mtk->rstc);
	dev_dbg(dev, "Hardware reset complete");

	dev_info(dev, "HW version: 0x%02X", readl(mtk->base + AES_INFO) >> 28);

	mtk->irq = platform_get_irq(pdev, 0);
	if (mtk->irq < 0) {
		dev_err(dev, "Failed to get IRQ number\n");
		ret = mtk->irq;
		goto err_clk_disable;
	}

	ret = devm_request_irq(dev, mtk->irq, mtk_aes_irq, 0, dev_name(dev), mtk);
	if (ret) {
		dev_err(dev, "Failed to request IRQ %d: %d\n", mtk->irq, ret);
		goto err_clk_disable;
	}
	dev_info(dev, "Registered IRQ %d", mtk->irq);

	tasklet_setup(&mtk->done_tasklet, mtk_tasklet_req_done);

	ret = aes_engine_desc_init(mtk);
	if (ret) {
		dev_err(dev, "Failed to initialize descriptors\n");
		goto err_tasklet_kill;
	}

	ret = mtk_cipher_alg_register(mtk);
	if (ret)
		goto err_desc_free;

	aes_engine_start(mtk);

	dev_info(dev, "MTK AES driver initialized successfully.\n");
	return 0;

err_desc_free:
	aes_engine_desc_free(mtk);
err_tasklet_kill:
	tasklet_kill(&mtk->done_tasklet);
err_clk_disable:
	clk_disable_unprepare(mtk->clk);
	dev_err(dev, "Probe failed with error %d\n", ret);
	return ret;
}

static int mtk_aes_remove(struct platform_device *pdev)
{
	struct mtk_dev *mtk = platform_get_drvdata(pdev);

	if (!mtk)
		return -ENODEV;

	dev_info(mtk->dev, "Unloading MTK AES driver...");

	aes_engine_stop(mtk);
	tasklet_kill(&mtk->done_tasklet);
	mtk_cipher_alg_release(mtk);
	aes_engine_desc_free(mtk);
	clk_disable_unprepare(mtk->clk);

	dev_info(mtk->dev, "Driver unloaded.");
	return 0;
}

static const struct of_device_id of_crypto_id[] = {
	{ .compatible = "mediatek,mtk-aes" },
	{},
};
MODULE_DEVICE_TABLE(of, of_crypto_id);

static struct platform_driver mt76x8_aes_driver = {
	.probe  = mtk_aes_probe,
	.remove = mtk_aes_remove,
	.driver = {
		.name           = "mtk-aes",
		.of_match_table = of_crypto_id,
	},
};

module_platform_driver(mt76x8_aes_driver);

MODULE_AUTHOR("Richard van Schagen <vschagen@cs.com>");
MODULE_AUTHOR("Daniel Golle <daniel@makrotopia.org>");
MODULE_DESCRIPTION("MediaTek AES Crypto hardware driver (updated for 6.x)");
MODULE_LICENSE("GPL");
