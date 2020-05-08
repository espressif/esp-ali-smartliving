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

/* enrollee/registrar doc see following
 * http://docs.alibaba-inc.com/pages/viewpage.action?pageId=450855381
 */

/* 802.11 management frame def */
#define MGMT_BEACON                         (0x80)
#define MGMT_PROBE_REQ                      (0x40)
#define MGMT_PROBE_RESP                     (0x50)
#define SA_POS                              (10) //source mac pos
#define FCS_SIZE                            (4)
#define AES_KEY_LEN                         (16)
#define MAX_DEV_NAME_LEN                    (64)
#define MAX_PK_LEN                          (20)
#define MAX_KEY_LEN                         (32)
#define MAX_TOKEN_LEN                       (32)
#define ZC_PROBE_LEN                        (46)
#ifdef AWSS_BATCH_DEVAP_ENABLE
#define MAX_ENROLLEE_NUM                    (20) // Registrar Config: max enrollee num supported
#else
#define MAX_ENROLLEE_NUM                    (5) // Registrar Config: max enrollee num supported
#endif
/* fc(2) + dur(2) + da(6) + sa(6) + bssid(6) + seq(2) */
#define MGMT_HDR_LEN                        (24)

/* ie oui def. */
#define WLAN_OUI_ALIBABA                    (0xD896E0)
#define WLAN_OUI_TYPE_ENROLLEE              (0xAA)          // ProbReqA provision frame from Enrollee
#define WLAN_OUI_TYPE_REGISTRAR             (0xAB)          // ProbRespA provision frame from Registrar
#define WLAN_OUI_TYPE_MODESWITCH            (0xAC)          // ProbReqB awssmode switch frame

/* ie vendor version */
#define WLAN_VENDOR_VER_0                   (0)     // zconfig prob vendor element version 0
#define WLAN_VENDOR_VER_1                   (1)     // zconfig prob vendor element version 1, support trans AppToken
#ifdef AWSS_ZCONFIG_APPTOKEN
#define WLAN_VENDOR_VERSION                 WLAN_VENDOR_VER_1
#else
#define WLAN_VENDOR_VERSION                 WLAN_VENDOR_VER_0
#endif

/* ie vendor device type: alink=0, alink_cloud=1, yoc=8 */
#define WLAN_VENDOR_DEVTYPE_ALINK           (0)
#define WLAN_VENDOR_DEVTYPE_ALINK_CLOUD     (1)
#define WLAN_VENDOR_DEVTYPE_YOC             (8)

/* ie vendor version & device type */
#define DEVICE_TYPE_VERSION_0               ((WLAN_VENDOR_VER_0 << 4) | WLAN_VENDOR_DEVTYPE_ALINK_CLOUD)
#define DEVICE_TYPE_VERSION_1               ((WLAN_VENDOR_VER_1 << 4) | WLAN_VENDOR_DEVTYPE_ALINK_CLOUD)

#define DEVICE_TYPE_VERSION                 ((WLAN_VENDOR_VERSION << 4) | WLAN_VENDOR_DEVTYPE_ALINK_CLOUD)

/* ie vendor frame type */
#define ENROLLEE_FRAME_TYPE                 (0)
#define REGISTRAR_FRAME_TYPE                (1)
#define AWSSMODE_SWITCH_FRAME_TYPE          (2)

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
#ifdef AWSS_ZCONFIG_APPTOKEN
    uint8_t token_len;      /* token length, bind token generated by App, send from cloud to registrar */
#ifdef __GNUC__
    uint8_t token[0];       /* bind token generated by App, send from cloud to registrar */
#endif
#endif
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
    uint8_t switch_to_mode; /* switch to awss mode, 0-switch to zero config 1-todo */
    uint8_t ap_channel;     /* AP channel indicate to enrollee */
    uint8_t pk_len;         /* product key length */
#ifdef __GNUC__
    uint8_t pk[0];          /* product key */
#endif
};

#define REGISTRAR_SWITCHMODE_IE_FIX_LEN (sizeof(struct ieee80211_registrar_modeswitch_alibaba_ie))
#endif

#define ENROLLEE_SIGN_SIZE          (SHA1_DIGEST_SIZE)
#define ENROLLEE_IE_FIX_LEN         (sizeof(struct ieee80211_enrollee_alibaba_ie) + RANDOM_MAX_LEN + ENROLLEE_SIGN_SIZE)
#define REGISTRAR_IE_FIX_LEN        (sizeof(struct ieee80211_registrar_alibaba_ie))
#define ENROLLEE_INFO_HDR_SIZE      (ENROLLEE_IE_FIX_LEN - 6 + MAX_DEV_NAME_LEN + 1 + MAX_PK_LEN + 1)

#ifndef AWSS_DISABLE_REGISTRAR
/* enrollees info stored by registrar */
struct enrollee_info {
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
#ifdef AWSS_ZCONFIG_APPTOKEN
    uint8_t token_len;                  // length of bind token get from cloud generated by app
    uint8_t token[RANDOM_MAX_LEN];      // token get from cloud generated by app
#endif
    signed char rssi;
    uint8_t key[MAX_KEY_LEN + 1];       // aes key
    uint8_t state;                      // free or not, refer to enrollee_state
    uint8_t checkin_priority;           // smaller means high pri
    uint32_t checkin_timestamp;         // the timestamp start checkin(recev checkin msg from cloud and start send prob resp)
    uint32_t report_timestamp;          // the timestamp of report enrollee/found
    uint32_t interval;                  // report timeout, ms
    uint32_t checkin_timeout;           // checkin timeout, send prob resp duration time
};
#endif

/*
 * ENR_FREE     --producer-->   ENR_IN_QUEUE
 * ENR_IN_QUEUE     --cloud----->   ENR_CHECKIN_ENABLE
 * ENR_CHECKIN_ENABLE   --consumer-->   ENR_CHECKIN_ONGOING --> ENR_CHECKIN_END/ENR_FREE
 * *any state*      --consumer-->   ENR_FREE
 */
enum enrollee_state {
    ENR_FREE = 0,                       // No enrollee info
    ENR_IN_QUEUE,                       // Receive prob-request from enrollee and stored in "enrollee info array"
    ENR_FOUND,                          // Report enrollee/found to cloud(just report out), when timeout, will back to ENR_FREE
    ENR_CHECKIN_ENABLE,                 // Receive checkin msg from cloud, when timeout,
    ENR_CHECKIN_CIPHER,                 // Receive cipher resp from cloud
    ENR_CHECKIN_ONGOING,                // CIPHER->ONGOING, start send probe response
    ENR_CHECKIN_END,                    // ONGOING timeout
    //ENR_OUTOFDATE = 0
};

extern const uint8_t probe_req_frame[ZC_PROBE_LEN];

/* enrollee API */
#ifdef AWSS_DISABLE_ENROLLEE
static inline void awss_init_enrollee_info(void) { }
static inline void awss_broadcast_enrollee_info(void) { }
static inline void awss_destroy_enrollee_info(void) { }
#else
void awss_init_enrollee_info(void);
void awss_broadcast_enrollee_info(void);
void awss_destroy_enrollee_info(void);
int awss_recv_callback_zconfig(struct parser_res *res);
int awss_ieee80211_zconfig_process(uint8_t *mgmt_header, int len, int link_type,
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
