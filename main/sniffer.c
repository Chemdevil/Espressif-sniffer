#include <stdio.h>
// #include <event.h>
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#define WIFI_CHANNEL_SWITCH_INTERVAL  (500)
#define WIFI_CHANNEL_MAX               (13)

static wifi_country_t wifi_country = {.cc="CN", .schan = 1, .nchan = 13,.policy=WIFI_COUNTRY_POLICY_AUTO};

uint8_t level=0;
uint8_t channel=1;

typedef struct {
  unsigned frame_ctrl:16;
  unsigned duration_id:16;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned sequence_ctrl:16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct{
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0];
} wifi_ieee80211_packet_t;

static void eventHandler(void *ctx, esp_event_base_t event, int32_t event_id,void* event_data);
static void snifferInit(void);
static void wifiSnifferSetChannel(uint8_t channel);
static const char *wifiSnifferPacketType2Str(wifi_promiscuous_pkt_type_t type);
static void wifiSnifferPacketHandler(void *buff, wifi_promiscuous_pkt_type_t type);
static const char* TAG="Sniffer";


esp_err_t eventH(){
    return ESP_OK;
}


void eventHandler(void* ctx, esp_event_base_t event, int32_t event_id, void* event_data){
    if (event == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
    } else if (event == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        // return ESP_OK;
    }
    // eventH();
    
}

static void wifiConnectInit(){
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_LOGI(TAG, "TCP IP Stack initialized");
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_LOGI(TAG,"event loop created");
    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&config));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
}

static void wifiDeinit(){
    // ESP_ERROR_CHECK(esp_wifi_disconnect());
    ESP_ERROR_CHECK(esp_wifi_stop());
    ESP_ERROR_CHECK(esp_wifi_deinit());
}

static void wifi_sniffer_deinit()
{
	ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false)); //set as 'false' the promiscuous mode
	ESP_ERROR_CHECK(esp_wifi_stop()); //it stop soft-AP and free soft-AP control block
	ESP_ERROR_CHECK(esp_wifi_deinit()); //free all resource allocated in esp_wifi_init() and stop WiFi task
}

void snifferInit(void)
{
    ESP_LOGI(TAG,"WIFI configured");
    ESP_ERROR_CHECK(esp_netif_init());
    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&config));
    ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK( esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifiSnifferPacketHandler));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

}

void wifiSnifferSetChannel(uint8_t channel){
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char *wifiSnifferPacketType2Str(wifi_promiscuous_pkt_type_t type)
{
    switch (type)
    {
    case WIFI_PKT_MGMT: return "MGMT";
    case WIFI_PKT_DATA: return "DATA";
    case WIFI_PKT_CTRL: return "Control";
    default:
    case WIFI_PKT_MISC: return "MISC";
    }
}

void wifiSnifferPacketHandler(void* buff, wifi_promiscuous_pkt_type_t type)
{
    const wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t *)buff;
    const wifi_ieee80211_packet_t *packetInfo = (wifi_ieee80211_packet_t *)packet->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &packetInfo->hdr;
    printf("Packet Details Start \n");
  printf("Frame control:%d\n",hdr->frame_ctrl);
  printf("Duration field:%d\n",hdr->duration_id);
  printf("PACKET TYPE=%s\nCHAN=%02d\nRSSI=%02d\nreceiver address=%02x:%02x:%02x:%02x:%02x:%02x\nsender address=%02x:%02x:%02x:%02x:%02x:%02x\nFilter address=%02x:%02x:%02x:%02x:%02x:%02x\n",
    wifiSnifferPacketType2Str(type),
    packet->rx_ctrl.channel,
    packet->rx_ctrl.rssi,
    /* ADDR1 */
    hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],
    hdr->addr1[3],hdr->addr1[4],hdr->addr1[5],
    /* ADDR2 */
    hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
    hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
    /* ADDR3 */
    hdr->addr3[0],hdr->addr3[1],hdr->addr3[2],
    hdr->addr3[3],hdr->addr3[4],hdr->addr3[5]
  );
  printf("Optional Address:%02x:%02x:%02x:%02x:%02x:%02x\n",hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],
    hdr->addr4[3],hdr->addr4[4],hdr->addr4[5]);
  printf("Packet Details finish\n");
  // }

}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    ESP_ERROR_CHECK(ret);
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_LOGI(TAG,"NVS Flash value:%d",ret);
    ESP_LOGI(TAG,"Hello world");
    ESP_ERROR_CHECK( ret );
            // wifiConnectInit();
            //  snifferInit();
        // vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL/portTICK_PERIOD_MS);
        // channel = (channel % WIFI_CHANNEL_MAX) + 1;
        // wifi_sniffer_deinit();
        // wifiDeinit();
    while(1){
        snifferInit();
        vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL/portTICK_PERIOD_MS);
        channel = (channel % WIFI_CHANNEL_MAX) + 1;
        wifi_sniffer_deinit();
    //     wifiDeinit();
    }

}
