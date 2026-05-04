#ifndef ESPNOW_MANAGER_H
#define ESPNOW_MANAGER_H

/*
 * ESP-NOW manager for Arduino UNO R4 WiFi bridge firmware.
 *
 * This module provides init/deinit, peer management, send, and a thread-safe
 * receive queue so that asynchronous ESP-NOW callbacks can be polled from the
 * AT-command task.
 *
 * Design constraints:
 *  - ESP-NOW and the standard WiFi networking stack (STA/AP/TCP/UDP) share the
 *    2.4 GHz radio.  The CAtHandler radio-mode gate in cmds_espnow.h prevents
 *    both from being active at the same time.
 *  - Callbacks are called from the Wi-Fi task; data is pushed into a
 *    FreeRTOS queue and consumed by the AT task.
 *  - Maximum ESP-NOW payload size is ESP_NOW_MAX_DATA_LEN (250 bytes).
 *  - Peer table limited to ESP_NOW_MAX_TOTAL_PEER_NUM entries.
 */

#include <stdint.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "esp_now.h"
#include "WiFi.h"

#define ESPNOW_MAX_PAYLOAD   ESP_NOW_MAX_DATA_LEN   /* 250 bytes */
#define ESPNOW_RX_QUEUE_LEN  8                       /* queued RX packets */

/* One received ESP-NOW packet stored in the RX queue. */
struct EspNowRxEvent {
    uint8_t  src_mac[6];
    uint8_t  data[ESPNOW_MAX_PAYLOAD];
    uint8_t  data_len;
};

/* Last TX completion result (only one slot; polled via +ESPNOWSTATUS?). */
struct EspNowTxResult {
    uint8_t  peer_mac[6];
    bool     success;
    bool     valid;   /* true once at least one send has completed */
};

class EspNowManager {
public:
    EspNowManager() : _initialized(false), _channel(1), _rx_queue(nullptr) {
        memset(&_last_tx, 0, sizeof(_last_tx));
    }

    /* Initialize ESP-NOW.  Puts the radio into STA mode on the requested
     * channel and registers send/receive callbacks.
     * Returns true on success. */
    bool begin(uint8_t channel = 1) {
        if (_initialized) {
            return true;
        }

        _channel = channel;

        /* ESP-NOW requires STA mode; set it before calling esp_now_init(). */
        WiFi.mode(WIFI_STA);
        WiFi.disconnect();

        /* Create the RX queue before registering callbacks so there is
         * always somewhere to push data into. */
        if (_rx_queue == nullptr) {
            _rx_queue = xQueueCreate(ESPNOW_RX_QUEUE_LEN, sizeof(EspNowRxEvent));
            if (_rx_queue == nullptr) {
                return false;
            }
        }

        if (esp_now_init() != ESP_OK) {
            vQueueDelete(_rx_queue);
            _rx_queue = nullptr;
            return false;
        }

        esp_now_register_recv_cb(_onRecv);
        esp_now_register_send_cb(_onSend);

        _initialized = true;
        return true;
    }

    /* Tear down ESP-NOW and release resources. */
    void end() {
        if (!_initialized) {
            return;
        }
        esp_now_deinit();
        _initialized = false;
        _last_tx.valid = false;

        if (_rx_queue != nullptr) {
            vQueueDelete(_rx_queue);
            _rx_queue = nullptr;
        }
    }

    bool isInitialized() const { return _initialized; }
    uint8_t channel() const { return _channel; }

    /* Add a unicast peer.  encrypt=true requires a 16-byte LMK. */
    bool addPeer(const uint8_t mac[6], uint8_t ch, bool encrypt,
                 const uint8_t lmk[16] = nullptr) {
        if (!_initialized) return false;

        esp_now_peer_info_t peer;
        memset(&peer, 0, sizeof(peer));
        memcpy(peer.peer_addr, mac, 6);
        peer.channel = ch;
        peer.encrypt = encrypt;
        if (encrypt && lmk != nullptr) {
            memcpy(peer.lmk, lmk, 16);
        }
        peer.ifidx = WIFI_IF_STA;

        return esp_now_add_peer(&peer) == ESP_OK;
    }

    /* Remove a previously added peer. */
    bool delPeer(const uint8_t mac[6]) {
        if (!_initialized) return false;
        return esp_now_del_peer(mac) == ESP_OK;
    }

    /* Set the primary master key (16 bytes) for encrypted peers. */
    bool setPMK(const uint8_t pmk[16]) {
        if (!_initialized) return false;
        return esp_now_set_pmk(pmk) == ESP_OK;
    }

    /* Send data to a peer.  data_len must be <= ESPNOW_MAX_PAYLOAD.
     * Returns false immediately if the peer is unknown or the send call
     * fails; the actual delivery status is available via lastTxResult(). */
    bool send(const uint8_t mac[6], const uint8_t *data, uint8_t data_len) {
        if (!_initialized) return false;
        if (data_len > ESPNOW_MAX_PAYLOAD) return false;
        return esp_now_send(mac, data, data_len) == ESP_OK;
    }

    /* Number of packets waiting in the RX queue. */
    size_t available() const {
        if (_rx_queue == nullptr) return 0;
        return (size_t)uxQueueMessagesWaiting(_rx_queue);
    }

    /* Pop one received packet.  Returns false when the queue is empty. */
    bool read(EspNowRxEvent &out) {
        if (_rx_queue == nullptr) return false;
        return xQueueReceive(_rx_queue, &out, 0) == pdTRUE;
    }

    /* Return the result of the most recent TX callback. */
    EspNowTxResult lastTxResult() const { return _last_tx; }

    /* --- Singleton accessor -------------------------------------------- */
    static EspNowManager &instance() {
        static EspNowManager mgr;
        return mgr;
    }

private:
    bool              _initialized;
    uint8_t           _channel;
    QueueHandle_t     _rx_queue;
    EspNowTxResult    _last_tx;

    /* ESP-NOW receive callback – called from the Wi-Fi task. */
    static void _onRecv(const uint8_t *mac, const uint8_t *data, int len) {
        EspNowManager &mgr = instance();
        if (mgr._rx_queue == nullptr) return;

        EspNowRxEvent ev;
        memset(&ev, 0, sizeof(ev));
        memcpy(ev.src_mac, mac, 6);
        uint8_t copy_len = (len > ESPNOW_MAX_PAYLOAD) ? ESPNOW_MAX_PAYLOAD
                                                       : (uint8_t)len;
        memcpy(ev.data, data, copy_len);
        ev.data_len = copy_len;

        /* Non-blocking push; drop the packet if the queue is full. */
        xQueueSendFromISR(mgr._rx_queue, &ev, nullptr);
    }

    /* ESP-NOW send-completion callback – called from the Wi-Fi task. */
    static void _onSend(const uint8_t *mac, esp_now_send_status_t status) {
        EspNowManager &mgr = instance();
        memcpy(mgr._last_tx.peer_mac, mac, 6);
        mgr._last_tx.success = (status == ESP_NOW_SEND_SUCCESS);
        mgr._last_tx.valid   = true;
    }
};

#endif /* ESPNOW_MANAGER_H */
