#ifndef CMDS_ESPNOW_H
#define CMDS_ESPNOW_H

/*
 * ESP-NOW AT command handlers for the Arduino UNO R4 WiFi bridge firmware.
 *
 * Commands exposed to the RA4M1 side over Serial1 (the AT interface):
 *
 *   AT+ESPNOWBEGIN[=<channel>]
 *       Initialize ESP-NOW on the given channel (1-13, default 1).
 *       Sets Wi-Fi mode to STA; standard WiFi networking commands will be
 *       rejected while ESP-NOW is active.
 *
 *   AT+ESPNOWEND
 *       Deinitialize ESP-NOW and release the radio back to idle.
 *
 *   AT+ESPNOWADDPEER=<mac>[,<channel>[,<encrypt>[,<lmk_hex>]]]
 *       Add a unicast peer.  mac is colon-separated hex (AA:BB:CC:DD:EE:FF).
 *       channel defaults to the value set in ESPNOWBEGIN.
 *       encrypt is 0 or 1 (default 0).  When encrypt=1, a 32-char hex LMK
 *       must be supplied (16 bytes).
 *
 *   AT+ESPNOWDELPEER=<mac>
 *       Remove a peer from the peer table.
 *
 *   AT+ESPNOWSEND=<mac>,<len>
 *       Send <len> binary bytes to <mac>.  The AT server enters transparent
 *       binary mode and reads exactly <len> bytes from the serial stream
 *       (same pattern as +HCIWRITE / +FS write).
 *       Maximum payload size: 250 bytes (ESP_NOW_MAX_DATA_LEN).
 *
 *   AT+ESPNOWAVAILABLE?
 *       Returns the number of queued received packets.
 *
 *   AT+ESPNOWREAD
 *       Pop one received packet from the queue and return:
 *         <src_mac>|<len>|<binary_payload>
 *       Returns ERROR if the queue is empty.
 *
 *   AT+ESPNOWSTATUS?
 *       Returns: <initialized>,<channel>,<last_tx_mac>,<last_tx_ok>
 *
 *   AT+ESPNOWSETKEY=<pmk_hex>
 *       Set the 16-byte primary master key (32 hex chars).
 *
 *   AT+ESPNOWSETPEERKEY=<mac>,<lmk_hex>
 *       Update the 16-byte LMK for an existing peer (32 hex chars).
 *       The peer must already be in the table; it is re-added with
 *       encryption enabled.
 *
 * Radio-mode mutual exclusion
 * ───────────────────────────
 * The CAtHandler tracks a simple radio_mode enum (RADIO_MODE_NONE,
 * RADIO_MODE_WIFI, RADIO_MODE_ESPNOW).  The existing WiFi commands check
 * this flag and return ERROR when ESP-NOW is active.  Symmetrically,
 * ESPNOWBEGIN returns ERROR when standard WiFi is in use.
 */

#include "at_handler.h"
#include "commands.h"
#include "espnow_manager.h"

/* -------------------------------------------------------------------------- */
/* Small hex-decoding helper used by key/MAC parsing below.                   */
/* -------------------------------------------------------------------------- */
static bool hexCharToByte(char c, uint8_t &out) {
    if (c >= '0' && c <= '9') { out = c - '0';       return true; }
    if (c >= 'a' && c <= 'f') { out = c - 'a' + 10;  return true; }
    if (c >= 'A' && c <= 'F') { out = c - 'A' + 10;  return true; }
    return false;
}

/* Decode a 32-char hex string into 16 bytes.  Returns false on bad input. */
static bool hexTo16Bytes(const std::string &hex, uint8_t out[16]) {
    if (hex.size() != 32) return false;
    for (int i = 0; i < 16; i++) {
        uint8_t hi, lo;
        if (!hexCharToByte(hex[2*i], hi) || !hexCharToByte(hex[2*i+1], lo)) {
            return false;
        }
        out[i] = (hi << 4) | lo;
    }
    return true;
}

/* Parse colon-separated MAC string "AA:BB:CC:DD:EE:FF" into 6 bytes. */
static bool parseMac(const std::string &mac_str, uint8_t mac[6]) {
    if (mac_str.size() != 17) return false;
    for (int i = 0; i < 6; i++) {
        uint8_t hi, lo;
        if (!hexCharToByte(mac_str[3*i],     hi)) return false;
        if (!hexCharToByte(mac_str[3*i + 1], lo)) return false;
        if (i < 5 && mac_str[3*i + 2] != ':')    return false;
        mac[i] = (hi << 4) | lo;
    }
    return true;
}

/* Format a 6-byte MAC into "AA:BB:CC:DD:EE:FF\0" (caller supplies buf[18]). */
static void macToStr(const uint8_t mac[6], char buf[18]) {
    snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* -------------------------------------------------------------------------- */
void CAtHandler::add_cmds_espnow() {
/* -------------------------------------------------------------------------- */

    /* ....................................................................... */
    command_table[_ESPNOW_BEGIN] = [this](auto & srv, auto & parser) {
    /* ....................................................................... */
        switch (parser.cmd_mode) {
            case chAT::CommandMode::Run:
            case chAT::CommandMode::Write: {
                /* Reject if standard WiFi networking is already active. */
                if (radio_mode == RADIO_MODE_WIFI) {
                    return chAT::CommandStatus::ERROR;
                }

                uint8_t channel = 1;
                if (parser.cmd_mode == chAT::CommandMode::Write) {
                    if (parser.args.size() != 1 || parser.args[0].empty()) {
                        return chAT::CommandStatus::ERROR;
                    }
                    int ch = atoi(parser.args[0].c_str());
                    if (ch < 1 || ch > 13) {
                        return chAT::CommandStatus::ERROR;
                    }
                    channel = (uint8_t)ch;
                }

                if (!EspNowManager::instance().begin(channel)) {
                    return chAT::CommandStatus::ERROR;
                }

                radio_mode = RADIO_MODE_ESPNOW;

                srv.write_response_prompt();
                srv.write_line_end();
                return chAT::CommandStatus::OK;
            }
            default:
                return chAT::CommandStatus::ERROR;
        }
    };

    /* ....................................................................... */
    command_table[_ESPNOW_END] = [this](auto & srv, auto & parser) {
    /* ....................................................................... */
        switch (parser.cmd_mode) {
            case chAT::CommandMode::Run: {
                EspNowManager::instance().end();
                radio_mode = RADIO_MODE_NONE;

                srv.write_response_prompt();
                srv.write_line_end();
                return chAT::CommandStatus::OK;
            }
            default:
                return chAT::CommandStatus::ERROR;
        }
    };

    /* ....................................................................... */
    command_table[_ESPNOW_ADDPEER] = [this](auto & srv, auto & parser) {
    /* ....................................................................... */
        switch (parser.cmd_mode) {
            case chAT::CommandMode::Write: {
                if (parser.args.size() < 1 || parser.args.size() > 4) {
                    return chAT::CommandStatus::ERROR;
                }
                if (!EspNowManager::instance().isInitialized()) {
                    return chAT::CommandStatus::ERROR;
                }

                uint8_t mac[6];
                if (!parseMac(parser.args[0], mac)) {
                    return chAT::CommandStatus::ERROR;
                }

                uint8_t channel = EspNowManager::instance().channel();
                if (parser.args.size() >= 2 && !parser.args[1].empty()) {
                    int ch = atoi(parser.args[1].c_str());
                    if (ch < 0 || ch > 13) return chAT::CommandStatus::ERROR;
                    channel = (uint8_t)ch;
                }

                bool encrypt = false;
                if (parser.args.size() >= 3 && !parser.args[2].empty()) {
                    encrypt = (atoi(parser.args[2].c_str()) != 0);
                }

                uint8_t lmk[16] = {0};
                if (encrypt) {
                    if (parser.args.size() < 4 || parser.args[3].empty()) {
                        return chAT::CommandStatus::ERROR;
                    }
                    if (!hexTo16Bytes(parser.args[3], lmk)) {
                        return chAT::CommandStatus::ERROR;
                    }
                }

                if (!EspNowManager::instance().addPeer(mac, channel, encrypt,
                                                       encrypt ? lmk : nullptr)) {
                    return chAT::CommandStatus::ERROR;
                }

                srv.write_response_prompt();
                srv.write_line_end();
                return chAT::CommandStatus::OK;
            }
            default:
                return chAT::CommandStatus::ERROR;
        }
    };

    /* ....................................................................... */
    command_table[_ESPNOW_DELPEER] = [this](auto & srv, auto & parser) {
    /* ....................................................................... */
        switch (parser.cmd_mode) {
            case chAT::CommandMode::Write: {
                if (parser.args.size() != 1 || parser.args[0].empty()) {
                    return chAT::CommandStatus::ERROR;
                }
                if (!EspNowManager::instance().isInitialized()) {
                    return chAT::CommandStatus::ERROR;
                }

                uint8_t mac[6];
                if (!parseMac(parser.args[0], mac)) {
                    return chAT::CommandStatus::ERROR;
                }

                if (!EspNowManager::instance().delPeer(mac)) {
                    return chAT::CommandStatus::ERROR;
                }

                srv.write_response_prompt();
                srv.write_line_end();
                return chAT::CommandStatus::OK;
            }
            default:
                return chAT::CommandStatus::ERROR;
        }
    };

    /* ....................................................................... */
    command_table[_ESPNOW_SEND] = [this](auto & srv, auto & parser) {
    /* ....................................................................... */
        switch (parser.cmd_mode) {
            case chAT::CommandMode::Write: {
                if (parser.args.size() != 2) {
                    return chAT::CommandStatus::ERROR;
                }
                if (!EspNowManager::instance().isInitialized()) {
                    return chAT::CommandStatus::ERROR;
                }

                uint8_t mac[6];
                if (!parseMac(parser.args[0], mac)) {
                    return chAT::CommandStatus::ERROR;
                }

                auto &len_str = parser.args[1];
                if (len_str.empty()) return chAT::CommandStatus::ERROR;
                int data_len = atoi(len_str.c_str());
                if (data_len <= 0 || data_len > ESPNOW_MAX_PAYLOAD) {
                    return chAT::CommandStatus::ERROR;
                }

                /* Binary-transparent read – same pattern as +HCIWRITE. */
                std::vector<uint8_t> payload;
                payload = srv.inhibit_read(data_len);
                size_t offset = payload.size();
                if (offset < (size_t)data_len) {
                    payload.resize(data_len);
                    do {
                        offset += serial->read(payload.data() + offset,
                                               data_len - offset);
                    } while (offset < (size_t)data_len);
                }

                srv.continue_read();

                if (!EspNowManager::instance().send(mac, payload.data(),
                                                    (uint8_t)data_len)) {
                    return chAT::CommandStatus::ERROR;
                }

                srv.write_response_prompt();
                srv.write_line_end();
                return chAT::CommandStatus::OK;
            }
            default:
                return chAT::CommandStatus::ERROR;
        }
    };

    /* ....................................................................... */
    command_table[_ESPNOW_AVAILABLE] = [this](auto & srv, auto & parser) {
    /* ....................................................................... */
        switch (parser.cmd_mode) {
            case chAT::CommandMode::Read: {
                srv.write_response_prompt();
                String av(EspNowManager::instance().available());
                srv.write_str(av.c_str());
                srv.write_line_end();
                return chAT::CommandStatus::OK;
            }
            default:
                return chAT::CommandStatus::ERROR;
        }
    };

    /* ....................................................................... */
    command_table[_ESPNOW_READ] = [this](auto & srv, auto & parser) {
    /* ....................................................................... */
        switch (parser.cmd_mode) {
            case chAT::CommandMode::Run: {
                EspNowRxEvent ev;
                if (!EspNowManager::instance().read(ev)) {
                    return chAT::CommandStatus::ERROR;
                }

                char mac_str[18];
                macToStr(ev.src_mac, mac_str);

                /* Format: <src_mac>|<len>|<binary payload> */
                srv.write_response_prompt();
                srv.write_str(mac_str);
                srv.write_str("|");
                srv.write_str(String(ev.data_len).c_str());
                srv.write_str("|");
                std::vector<uint8_t> payload(ev.data, ev.data + ev.data_len);
                srv.write_vec8(payload);
                srv.write_line_end();
                return chAT::CommandStatus::OK;
            }
            default:
                return chAT::CommandStatus::ERROR;
        }
    };

    /* ....................................................................... */
    command_table[_ESPNOW_STATUS] = [this](auto & srv, auto & parser) {
    /* ....................................................................... */
        switch (parser.cmd_mode) {
            case chAT::CommandMode::Read: {
                EspNowManager &mgr = EspNowManager::instance();
                EspNowTxResult tx  = mgr.lastTxResult();

                char tx_mac[18] = "00:00:00:00:00:00";
                if (tx.valid) {
                    macToStr(tx.peer_mac, tx_mac);
                }

                /* Format: <initialized>,<channel>,<last_tx_mac>,<last_tx_ok> */
                srv.write_response_prompt();
                String status_line =
                    String(mgr.isInitialized() ? 1 : 0) + "," +
                    String(mgr.channel())                + "," +
                    String(tx_mac)                       + "," +
                    String(tx.valid ? (tx.success ? 1 : 0) : -1);
                srv.write_str(status_line.c_str());
                srv.write_line_end();
                return chAT::CommandStatus::OK;
            }
            default:
                return chAT::CommandStatus::ERROR;
        }
    };

    /* ....................................................................... */
    command_table[_ESPNOW_SETKEY] = [this](auto & srv, auto & parser) {
    /* ....................................................................... */
        switch (parser.cmd_mode) {
            case chAT::CommandMode::Write: {
                if (parser.args.size() != 1 || parser.args[0].empty()) {
                    return chAT::CommandStatus::ERROR;
                }
                if (!EspNowManager::instance().isInitialized()) {
                    return chAT::CommandStatus::ERROR;
                }

                uint8_t pmk[16];
                if (!hexTo16Bytes(parser.args[0], pmk)) {
                    return chAT::CommandStatus::ERROR;
                }

                if (!EspNowManager::instance().setPMK(pmk)) {
                    return chAT::CommandStatus::ERROR;
                }

                srv.write_response_prompt();
                srv.write_line_end();
                return chAT::CommandStatus::OK;
            }
            default:
                return chAT::CommandStatus::ERROR;
        }
    };

    /* ....................................................................... */
    command_table[_ESPNOW_SETPEERKEY] = [this](auto & srv, auto & parser) {
    /* ....................................................................... */
        switch (parser.cmd_mode) {
            case chAT::CommandMode::Write: {
                if (parser.args.size() != 2) {
                    return chAT::CommandStatus::ERROR;
                }
                if (!EspNowManager::instance().isInitialized()) {
                    return chAT::CommandStatus::ERROR;
                }

                uint8_t mac[6];
                if (!parseMac(parser.args[0], mac)) {
                    return chAT::CommandStatus::ERROR;
                }

                uint8_t lmk[16];
                if (!hexTo16Bytes(parser.args[1], lmk)) {
                    return chAT::CommandStatus::ERROR;
                }

                /* Re-add the peer with the updated LMK and encryption on. */
                EspNowManager::instance().delPeer(mac); /* ignore result */
                if (!EspNowManager::instance().addPeer(
                        mac, EspNowManager::instance().channel(), true, lmk)) {
                    return chAT::CommandStatus::ERROR;
                }

                srv.write_response_prompt();
                srv.write_line_end();
                return chAT::CommandStatus::OK;
            }
            default:
                return chAT::CommandStatus::ERROR;
        }
    };
}

#endif /* CMDS_ESPNOW_H */
