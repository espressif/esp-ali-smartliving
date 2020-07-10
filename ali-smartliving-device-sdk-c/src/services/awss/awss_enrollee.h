/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifndef __AWSS_ENROLLEE_H__
#define __AWSS_ENROLLEE_H__

#include <stdint.h>
#include "utils_hmac.h"
#include "passwd.h"
#include "os.h"
#include "zconfig_ieee80211.h"

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C"
{
#endif

/* 802.11 management frame def */
#define MGMT_BEACON                         (0x80)
#define MGMT_PROBE_REQ                      (0x40)
#define MGMT_PROBE_RESP                     (0x50)
#define MGMT_SA_POS                         (10)     // source mac pos in management frame header
#define MGMT_FCS_SIZE                       (4)      // FCS length in management frame
#define ZC_PROBE_LEN                        (46)     // Probe frame header length, mgmt header len + FCS len
#define MGMT_HDR_LEN                        (24)     // fc(2) + dur(2) + da(6) + sa(6) + bssid(6) + seq(2)
                                                     // used for recever parse received mgmt frame contents

/* Device limited max length */
#define AES_KEY_LEN                         (16)
#define MAX_DEV_NAME_LEN                    (64)
#define MAX_PK_LEN                          (20)
#define MAX_KEY_LEN                         (32)
#define MAX_TOKEN_LEN                       (32)
#ifdef AWSS_BATCH_DEVAP_ENABLE
#define MAX_ENROLLEE_NUM                    (20) // Registrar Config: max enrollee num supported
#else
#define MAX_ENROLLEE_NUM                    (5) // Registrar Config: max enrollee num supported
#endif

/* ie oui def. */
#define WLAN_OUI_ALIBABA                    (0xD896E0)
#define WLAN_OUI_ALIBABA_ARRAY              {0xD8, 0x96, 0xE0}
#define WLAN_OUI_TYPE_ENROLLEE              (0xAA)          // ProbReqA provision frame from Enrollee
#define WLAN_OUI_TYPE_REGISTRAR             (0xAB)          // ProbRespA provision frame from Registrar
#define WLAN_OUI_TYPE_MODESWITCH            (0xAC)          // ProbReqB awssmode switch frame
#define WLAN_VENDOR_IE_HDR_LEN              (6)             // eid(1) + ie_len(1) + oui(3) + oui_type(1)

/* ie vendor version */
#define WLAN_VENDOR_VER_0                   (0)     // zconfig prob vendor element version 0
#define WLAN_VENDOR_VERSION                 WLAN_VENDOR_VER_0

/* ie vendor device type: alink=0, alink_cloud=1, yoc=8 */
#define WLAN_VENDOR_DEVTYPE_ALINK           (0)
#define WLAN_VENDOR_DEVTYPE_ALINK_CLOUD     (1)
#define WLAN_VENDOR_DEVTYPE_YOC             (8)

/* ie vendor version & device type */
#define DEVICE_TYPE_VERSION_0               ((WLAN_VENDOR_VER_0 << 4) | WLAN_VENDOR_DEVTYPE_ALINK_CLOUD)
#define DEVICE_TYPE_VERSION                 ((WLAN_VENDOR_VERSION << 4) | WLAN_VENDOR_DEVTYPE_ALINK_CLOUD)

/* ie vendor frame type */
#define ENROLLEE_FRAME_TYPE                 (0)
#define REGISTRAR_FRAME_TYPE                (1)
#define AWSSMODE_SWITCH_FRAME_TYPE          (2)

/* fields parse position in vendor ie */
#define IE_POS_EID                          (0)     // element_id position
#define IE_POS_IE_LEN                       (1)     // ie length position
#define IE_POS_OUI                          (2)     // oui start position
#define IE_POS_OUI_TYPE                     (5)     // oui type position
#define IE_POS_VER_DEVTYPE                  (6)     // version&dev_type position

/* verbose log for internal debug */
#define ZERO_AWSS_VERBOSE_DBG               (0)

/* request provision frame(probe request) format, send from enrollee */
struct ieee80211_enrollee_alibaba_ie {
    uint8_t element_id;     /* 221 */
    uint8_t len;            /* len of this struct, exclude element id & len field */
    uint8_t oui[3];         /* D896E0 */
    uint8_t oui_type;       /* 0xAA, device request */

    uint8_t version:4;      /* bit7 - bit4 */
    uint8_t dev_type:4;     /* bit3 - bit0; alink=0, alink_cloud=1, yoc=8 */
    uint8_t dn_len;         /* device name length*/
#ifdef __GNUC__
    uint8_t dev_name[0];    /* device name, unique name for device */
#endif
    uint8_t frame_type;     /* frame_type = 0 */

    uint8_t pk_len;         /* product key length */
#ifdef __GNUC__
    uint8_t pk[0];          /* product key */
#endif
    uint8_t rand_len;       /* random length */
#ifdef __GNUC__
    uint8_t random[0];      /* random salt */
#endif
    uint8_t security;       /* securation type, per product(3) or device(4) or manufacture(5) */
    uint8_t sign_method;    /* 0: hmacsha1, 1:hmacsha256 */
    uint8_t sign_len;       /* signature length */
#ifdef __GNUC__
    uint8_t sign[0];        /* sign = hmacsha1(secret, random+dev_name+product_key) */
#endif
};

/* response provision frame(probe response) format, send from registrar */
// len = 17 + sign[n] + ssid[n] + passwd[n]
struct ieee80211_registrar_alibaba_ie {
    uint8_t element_id;     /* 221 */
    uint8_t len;            /* len of this struct, exclude element id & len field */
    uint8_t oui[3];         /* D896E0 */
    uint8_t oui_type;       /* 0xAB, device response */

    uint8_t version:4;     /* bit7 - bit4 */
    uint8_t dev_type:4;    /* bit3 - bit0; alink=0, alink_cloud=1, yoc=8 */
    uint8_t sign_len;       /* signature length */
#ifdef __GNUC__
    uint8_t sign[0];        /* sign = hmacsha1(secret, random+dev_name+product_key)*/
#endif
    uint8_t frame_type;     /* frame_type = 0 */

    uint8_t ssid_len;       /* AP's SSID length */
#ifdef __GNUC__
    uint8_t ssid[0];        /* SSID of AP */
#endif
    uint8_t passwd_len;     /* AP's PASSWORD length */
#ifdef __GNUC__
    uint8_t passwd[0];      /* PASSWORD of AP */
#endif
    uint8_t bssid[6];       /* BSSID of AP */
    uint8_t token_len;      /* token length, bind token generated by App, send from cloud to registrar */
#ifdef __GNUC__
    uint8_t token[0];       /* bind token generated by App, send from cloud to registrar */
#endif
    uint8_t token_type;
    uint8_t region_id;
};

#ifdef AWSS_BATCH_DEVAP_ENABLE
// awss mode switch probe request, sent by Registrar, receive by Device in Dev_ap
struct ieee80211_registrar_modeswitch_alibaba_ie {
    uint8_t element_id;     /* 221 */
    uint8_t len;            /* len of this struct, exclude element id & len field */
    uint8_t oui[3];         /* D896E0 */
    uint8_t oui_type;       /* 0xAB, sent by Registrar */
    uint8_t version:4;      /* bit7 - bit4 */
    uint8_t dev_type:4;     /* bit3 - bit0; alink=0, alink_cloud=1, yoc=8 */
    uint8_t frame_type;     /* frame_type = 1 */
    uint8_t switch_to_mode; /* switch to awss mode, 0-switch to zero config 1-RFU */
    uint8_t switch_timeout; /* duration of switch to awss mode, when timeout should switch back */
    uint8_t ap_channel;     /* AP channel indicate to enrollee */
    uint8_t pk_len;         /* product key length */
#ifdef __GNUC__
    uint8_t pk[0];          /* product key */
#endif
};

#define IE_MODESWITCH_POS_FRAME_TYPE        (7)     // frame type position
#define IE_MODESWITCH_POS_MODE              (8)     // switch to mode position
#define IE_MODESWITCH_POS_MODE_TIMEOUT      (9)     // mode timeout position
#define IE_MODESWITCH_POS_AP_CHAN           (10)    // AP channel position
#define IE_MODESWITCH_POS_PK_LEN            (11)    // PK length position
#endif

// FIX LEN only used in mgmt frame sender, for forward compatbility
#ifdef AWSS_BATCH_DEVAP_ENABLE
#define REGISTRAR_SWITCHMODE_IE_FIX_LEN (sizeof(struct ieee80211_registrar_modeswitch_alibaba_ie))
#endif

#define ENROLLEE_SIGN_SIZE          (SHA1_DIGEST_SIZE)
#define ENROLLEE_IE_FIX_LEN         (sizeof(struct ieee80211_enrollee_alibaba_ie) + RANDOM_MAX_LEN + ENROLLEE_SIGN_SIZE)
#define REGISTRAR_IE_FIX_LEN        (sizeof(struct ieee80211_registrar_alibaba_ie))
#define ENROLLEE_INFO_HDR_SIZE      (ENROLLEE_IE_FIX_LEN - 6 + MAX_DEV_NAME_LEN + 1 + MAX_PK_LEN + 1)

#ifndef AWSS_DISABLE_REGISTRAR
/* enrollees info stored by registrar */
typedef struct registrar_enr_record_s {
    uint8_t dev_type_ver;
    uint8_t dev_name_len;
    uint8_t dev_name[MAX_DEV_NAME_LEN + 1];
    uint8_t frame_type;
    uint8_t pk_len;
    uint8_t pk[MAX_PK_LEN + 1];
    uint8_t rand_len;
    uint8_t random[RANDOM_MAX_LEN];
    uint8_t security;                   // encryption per product(3) or device(4) or manufacture(5)
    uint8_t sign_method;                // 0:hmacsha1, 1:hmacsha256
    uint8_t sign_len;
    uint8_t sign[ENROLLEE_SIGN_SIZE];
    uint8_t token_len;                  // length of bind token get from cloud generated by app
    uint8_t token[RANDOM_MAX_LEN];      // token get from cloud generated by app
    uint8_t token_type;                 // token type
    uint8_t region_id;                  
    signed char rssi;
    uint8_t key[MAX_KEY_LEN + 1];       // aes key
    uint8_t state;                      // free or not, refer to registrar_enr_state
    uint8_t checkin_priority;           // smaller means high pri
    uint32_t checkin_timestamp;         // the timestamp start checkin(recev checkin msg from cloud and start send prob resp)
    uint32_t report_timestamp;          // the timestamp of report enrollee/found
    uint32_t interval;                  // report timeout, ms
    uint32_t checkin_timeout;           // checkin timeout, send prob resp duration time
}registrar_enr_record_t;
#endif

/*
 * ENR_FREE     --producer-->   ENR_IN_QUEUE
 * ENR_IN_QUEUE     --cloud----->   ENR_CHECKIN_ENABLE
 * ENR_CHECKIN_ENABLE   --consumer-->   ENR_CHECKIN_ONGOING --> ENR_FREE
 * *any state*      --consumer-->   ENR_FREE
 */
enum registrar_enr_state {
    ENR_FREE = 0,                       // No enrollee info
    ENR_IN_QUEUE,                       // Receive prob-request from enrollee and stored in "enrollee info array"
    ENR_FOUND,                          // Report enrollee/found to cloud(just report out), when timeout, will back to ENR_FREE
    ENR_CHECKIN_ENABLE,                 // Receive checkin msg from cloud
    ENR_CHECKIN_CIPHER,                 // Receive cipher resp from cloud
    ENR_CHECKIN_ONGOING,                // CIPHER->ONGOING, start send probe response
};

extern const uint8_t probe_req_frame[ZC_PROBE_LEN];

/* enrollee API */
#ifdef AWSS_DISABLE_ENROLLEE
static inline void awss_enrollee_init_info(void) { }
static inline void awss_enrollee_broadcast_info(void) { }
static inline void awss_enrollee_destroy_info(void) { }
#else
void awss_enrollee_init_info(void);
void awss_enrollee_broadcast_info(void);
void awss_enrollee_destroy_info(void);
int awss_enrollee_recv_callback(struct parser_res *res);
int awss_enrollee_ieee80211_process(uint8_t *mgmt_header, int len, int link_type,
                                   struct parser_res *res, signed char rssi);
#endif

/* registrar API */
#ifdef AWSS_DISABLE_REGISTRAR
static inline void awss_registrar_deinit(void) { }
static inline void awss_registrar_init(void) { }
#else
void awss_registrar_init(void);
void awss_registrar_deinit(void);
#ifdef AWSS_BATCH_DEVAP_ENABLE
void registrar_switchmode_start(char *p_productkey, int pk_len, uint8_t awss_mode);
#endif
#endif

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif

#endif
