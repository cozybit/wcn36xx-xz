/*
 * Copyright (c) 2013 Eugene Krasnikov <k.eugene.e@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "txrx.h"

static inline int get_rssi0(struct wcn36xx_rx_bd *bd)
{
	return 100 - ((bd->phy_stat0 >> 24) & 0xff);
}

int wcn36xx_rx_skb(struct wcn36xx *wcn, struct sk_buff *skb)
{
	struct ieee80211_rx_status status;
	struct ieee80211_hdr *hdr;
	struct wcn36xx_rx_bd *bd;
	u16 fc, sn;

	/*
	 * All fields must be 0, otherwise it can lead to
	 * unexpected consequences.
	 */
	memset(&status, 0, sizeof(status));

	bd = (struct wcn36xx_rx_bd *)skb->data;
	buff_to_be((u32 *)bd, sizeof(*bd)/sizeof(u32));
	wcn36xx_dbg_dump(WCN36XX_DBG_RX_DUMP,
			 "BD   <<< ", (char *)bd,
			 sizeof(struct wcn36xx_rx_bd));

	skb_put(skb, bd->pdu.mpdu_header_off + bd->pdu.mpdu_len);
	skb_pull(skb, bd->pdu.mpdu_header_off);

	status.mactime = 10;
	status.freq = WCN36XX_CENTER_FREQ(wcn);
	status.band = WCN36XX_BAND(wcn);
	status.signal = -get_rssi0(bd);
	status.antenna = 1;
	status.rate_idx = 1;
	status.flag = 0;
	status.rx_flags = 0;
	status.flag |= RX_FLAG_IV_STRIPPED |
		       RX_FLAG_MMIC_STRIPPED |
		       RX_FLAG_DECRYPTED;

	wcn36xx_dbg(WCN36XX_DBG_RX, "status.flags=%x status->vendor_radiotap_len=%x\n",
		    status.flag,  status.vendor_radiotap_len);

	memcpy(IEEE80211_SKB_RXCB(skb), &status, sizeof(status));

	hdr = (struct ieee80211_hdr *) skb->data;
	fc = __le16_to_cpu(hdr->frame_control);
	sn = IEEE80211_SEQ_TO_SN(__le16_to_cpu(hdr->seq_ctrl));

	if (ieee80211_is_beacon(hdr->frame_control)) {
		wcn36xx_dbg(WCN36XX_DBG_BEACON, "beacon skb %p len %d fc %04x sn %d\n",
			    skb, skb->len, fc, sn);
		wcn36xx_dbg_dump(WCN36XX_DBG_BEACON_DUMP, "SKB <<< ",
				 (char *)skb->data, skb->len);
	} else {
		wcn36xx_dbg(WCN36XX_DBG_RX, "rx skb %p len %d fc %04x sn %d\n",
			    skb, skb->len, fc, sn);
		wcn36xx_dbg_dump(WCN36XX_DBG_RX_DUMP, "SKB <<< ",
				 (char *)skb->data, skb->len);
	}

	ieee80211_rx_irqsafe(wcn->hw, skb);

	return 0;
}

static void wcn36xx_set_tx_pdu(struct wcn36xx_tx_bd *bd,
			       u32 mpdu_header_len,
			       u32 len,
			       u16 tid)
{
	bd->pdu.mpdu_header_len = mpdu_header_len;
	bd->pdu.mpdu_header_off = sizeof(*bd);
	bd->pdu.mpdu_data_off = bd->pdu.mpdu_header_len +
		bd->pdu.mpdu_header_off;
	bd->pdu.mpdu_len = len;
	bd->pdu.tid = tid;
}

static inline struct wcn36xx_vif *get_vif_by_addr(struct wcn36xx *wcn,
						  u8 *addr)
{
	struct wcn36xx_vif *vif_priv = NULL;
	struct ieee80211_vif *vif = NULL;
	list_for_each_entry(vif_priv, &wcn->vif_list, list) {
			vif = container_of((void *)vif_priv,
				   struct ieee80211_vif,
				   drv_priv);
			if (memcmp(vif->addr, addr, ETH_ALEN) == 0)
				return vif_priv;
	}
	wcn36xx_warn("vif %pM not found\n", addr);
	return NULL;
}

int wcn36xx_tx_setup_mgmt(struct wcn36xx *wcn,
			  struct sk_buff *skb,
			  struct wcn36xx_vif *vif_priv,
			  bool bcast)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	struct wcn36xx_tx_bd *bd;

	bd = wcn36xx_dxe_get_next_bd(wcn, false);
	if (!bd) {
		wcn36xx_err("bd address may not be NULL for BD DXE\n");
		return -EINVAL;
	}

	memset(bd, 0, sizeof(*bd));

	bd->dpu_rf = WCN36XX_BMU_WQ_TX;
	/* SSN always filled by Host */
	bd->pdu.bd_ssn = WCN36XX_TXBD_SSN_FILL_HOST;
	bd->tx_comp = 0;
	bd->sta_index = vif_priv->self_sta_index;
	bd->dpu_desc_idx = vif_priv->self_dpu_desc_index;
	bd->dpu_ne = 1;

	/* default rate for unicast */
	if (ieee80211_is_mgmt(hdr->frame_control))
		bd->bd_rate = (WCN36XX_BAND(wcn) == IEEE80211_BAND_5GHZ) ?
			WCN36XX_BD_RATE_CTRL :
			WCN36XX_BD_RATE_MGMT;
	else if (ieee80211_is_ctl(hdr->frame_control))
		bd->bd_rate = WCN36XX_BD_RATE_CTRL;
	else
		wcn36xx_warn("frame control type unknown\n");

	/*
	 * In joining state trick hardware that probe is sent as
	 * unicast even if address is broadcast.
	 */
	if (vif_priv->is_joining &&
	    ieee80211_is_probe_req(hdr->frame_control))
		bcast = false;

	if (bcast) {
		/* broadcast */
		bd->ub = 1;
		/* No ack needed not unicast */
		bd->ack_policy = 1;
		bd->queue_id = WCN36XX_TX_B_WQ_ID;
	} else {
		bd->queue_id = WCN36XX_TX_U_WQ_ID;
	}

	wcn36xx_set_tx_pdu(bd, ieee80211_is_data_qos(hdr->frame_control) ?
			   sizeof(struct ieee80211_qos_hdr) :
			   sizeof(struct ieee80211_hdr_3addr),
			   skb->len, WCN36XX_TID);

	buff_to_be((u32 *)bd, sizeof(*bd)/sizeof(u32));
	bd->tx_bd_sign = 0xbdbdbdbd;

	return 0;
}

int wcn36xx_tx_setup_data(struct wcn36xx *wcn,
			  struct sk_buff *skb,
			  struct wcn36xx_vif *vif_priv,
			  bool bcast)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	struct ieee80211_vif *vif = NULL;
	struct wcn36xx_tx_bd *bd;
	struct wcn36xx_sta *sta_priv = NULL;
	u8 *qc, tid = 0;

	bd = wcn36xx_dxe_get_next_bd(wcn, true);
	if (!bd) {
		/*
		 * TX DXE are used in pairs. One for the BD and one for the
		 * actual frame. The BD DXE's has a preallocated buffer while
		 * the skb ones does not. If this isn't true something is really
		 * wierd. TODO: Recover from this situation
		 */
		wcn36xx_err("bd address may not be NULL for BD DXE\n");
		return -EINVAL;
	}

	memset(bd, 0, sizeof(*bd));

	bd->dpu_rf = WCN36XX_BMU_WQ_TX;
	bd->bd_rate = WCN36XX_BD_RATE_DATA;
	/* SSN always filled by Host */
	bd->pdu.bd_ssn = WCN36XX_TXBD_SSN_FILL_HOST;
	bd->tx_comp = 0;

	if (!bcast) {
		sta_priv = vif_priv->sta;
		qc = ieee80211_get_qos_ctl(hdr);
		tid = qc[0] & 0xf;
		/* Let FW set the SQN */
		bd->pdu.bd_ssn = WCN36XX_TXBD_SSN_FILL_DPU_QOS;
		bd->queue_id = tid;

		vif = container_of((void *)vif_priv, struct ieee80211_vif,
				   drv_priv);

		if (vif->type == NL80211_IFTYPE_STATION) {
			bd->sta_index = sta_priv->bss_sta_index;
			bd->dpu_desc_idx = sta_priv->bss_dpu_desc_index;
		} else if (vif->type == NL80211_IFTYPE_AP ||
			   vif->type == NL80211_IFTYPE_ADHOC ||
			   vif->type == NL80211_IFTYPE_MESH_POINT) {
			bd->sta_index = sta_priv->sta_index;
			bd->dpu_desc_idx = sta_priv->dpu_desc_index;
		}

		/*
		 * Hacking here: once STA is deleted and added,
		 * it won't able to work with unicast data frame,
		 * so just fall back to lower Tx rate
		 */
		if (sta_priv->is_rejoin_mesh) {
			bd->sta_index = sta_priv->bss_sta_index;
			bd->dpu_desc_idx = sta_priv->bss_dpu_desc_index;
		}
	} else {
		bd->ub = 1;
		bd->ack_policy = 1;
		bd->sta_index = vif_priv->self_sta_index;
		bd->dpu_desc_idx = vif_priv->self_dpu_desc_index;
	}

	bd->dpu_sign = vif_priv->ucast_dpu_signature;

	if (ieee80211_is_nullfunc(hdr->frame_control) ||
	    (sta_priv && !sta_priv->is_data_encrypted))
		bd->dpu_ne = 1;

	wcn36xx_set_tx_pdu(bd, ieee80211_is_data_qos(hdr->frame_control) ?
			   sizeof(struct ieee80211_qos_hdr) :
			   sizeof(struct ieee80211_hdr_3addr),
			   skb->len, tid);

	buff_to_be((u32 *)bd, sizeof(*bd)/sizeof(u32));
	bd->tx_bd_sign = 0xbdbdbdbd;

	return 0;
}

void wcn36xx_ampdu_work(struct work_struct *work)
{
	struct wcn36xx_sta *wcn36xx_sta;
	struct ieee80211_sta *sta;
	int tid;

	wcn36xx_sta = container_of(work, struct wcn36xx_sta, ampdu_work);
	sta = wcn36xx_sta->sta;

	for (tid = 0; tid < WCN36XX_MAX_TIDS; tid++) {
		if (wcn36xx_sta->tid_state[tid] != AGGR_INIT)
			continue;

		ieee80211_start_tx_ba_session(sta, tid, 0);
	}
}

int wcn36xx_tx_frame(struct wcn36xx *wcn,
		     struct sk_buff *skb,
		     bool more_frames)
{
	struct wcn36xx_vif *vif_priv;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	struct wcn36xx_sta *sta_priv = NULL;
	bool dxe_txlow, bcast;

	vif_priv = get_vif_by_addr(wcn, hdr->addr2);
	if (!vif_priv) {
		wcn36xx_err("No VIF for tx frame\n");
		return -EINVAL;
	}

	bcast = is_broadcast_ether_addr(hdr->addr1) ||
		is_multicast_ether_addr(hdr->addr1);

	dxe_txlow = ieee80211_is_data(hdr->frame_control);

	sta_priv = vif_priv->sta;

	if (dxe_txlow) {
		if (wcn36xx_tx_setup_data(wcn, skb, vif_priv, bcast)) {
			wcn36xx_err("Tx BD Data setup problem\n");
			return -EINVAL;
		}
	} else {
		if (wcn36xx_tx_setup_mgmt(wcn, skb, vif_priv, bcast)) {
			wcn36xx_err("Tx BD Mgmt setup problem\n");
			return -EINVAL;
		}
	}

	return wcn36xx_dxe_tx_frame(wcn, vif_priv, skb, dxe_txlow);
}

void wcn36xx_start_queue(struct wcn36xx *wcn)
{
	if (!wcn->stopped)
		return;

	wcn->stopped = false;
	ieee80211_wake_queues(wcn->hw);
}

void wcn36xx_tx_cleanup(struct wcn36xx *wcn)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&wcn->tx_queue)))
		ieee80211_free_txskb(wcn->hw, skb);
}

void wcn36xx_stop_queue(struct wcn36xx *wcn)
{
	if (wcn->stopped)
		return;

	wcn->stopped = true;
	ieee80211_stop_queues(wcn->hw);
}

void wcn36xx_ampdu_check(struct wcn36xx *wcn,
			 struct ieee80211_sta *sta,
			 struct sk_buff *skb)
{
	struct wcn36xx_sta *sta_priv;
	struct ieee80211_hdr *hdr;
	u8 *qc, tid;

	if (!sta || !conf_is_ht(&wcn->hw->conf))
		return;

	hdr = (struct ieee80211_hdr *) skb->data;
	if (!ieee80211_is_data_qos(hdr->frame_control))
		return;

	if (skb_get_queue_mapping(skb) == IEEE80211_AC_VO)
		return;

	qc = ieee80211_get_qos_ctl(hdr);
	tid = qc[0] & IEEE80211_QOS_CTL_TID_MASK;

	sta_priv = (struct wcn36xx_sta *) sta->drv_priv;

	if (sta_priv->tid_state[tid] == AGGR_STOP) {
		sta_priv->tid_state[tid] = AGGR_INIT;
		ieee80211_queue_work(wcn->hw, &sta_priv->ampdu_work);
	}
}

void wcn36xx_tx_work(struct work_struct *work)
{
	struct wcn36xx *wcn;
	struct sk_buff *skb;
	u8 *data_ptr;
	int ret;

	wcn = container_of(work, struct wcn36xx, tx_work);

	while ((skb = skb_dequeue(&wcn->tx_queue))) {
		data_ptr = skb->data;
		ret = wcn36xx_tx_frame(wcn, skb,
				       !skb_queue_empty(&wcn->tx_queue));

		skb_pull(skb, data_ptr - skb->data);

		if (ret == -EBUSY) {
			skb_queue_head(&wcn->tx_queue, skb);
			return;
		}

		if (ret) {
			atomic_dec_return(&wcn->tx_pending);
			ieee80211_free_txskb(wcn->hw, skb);
			return;
		}

		if (atomic_dec_return(&wcn->tx_pending) <=
		    WCN36XX_TX_CT_LO)
			wcn36xx_start_queue(wcn);
	}
}
