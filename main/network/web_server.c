#include "web_server.h"
#include "ota.h"
#include "wifi.h"
#include "settings.h"
#include "log_stream.h"
#include "rtsp_server.h"
#include "esp_http_server.h"
#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "web_server";
static httpd_handle_t s_server = NULL;
#define FILE_CHUNK 1024
#define SPEEDTEST_CHUNK 2048
#define SPEEDTEST_MAX_BYTES ((size_t)16 * 1024 * 1024)

static esp_err_t serve_file(httpd_req_t *req, const char *path, const char *type) {
  FILE *f = fopen(path, "r");
  if (!f) { httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File not found"); return ESP_FAIL; }
  httpd_resp_set_type(req, type);
  char buf[FILE_CHUNK]; size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
    if (httpd_resp_send_chunk(req, buf, n) != ESP_OK) { fclose(f); return ESP_FAIL; }
  }
  fclose(f); return httpd_resp_send_chunk(req, NULL, 0);
}
static esp_err_t root_handler(httpd_req_t *req){ return serve_file(req,"/spiffs/www/index.html","text/html"); }
static esp_err_t logs_handler(httpd_req_t *req){ return serve_file(req,"/spiffs/www/logs.html","text/html"); }
static esp_err_t speedtest_handler(httpd_req_t *req){ return serve_file(req,"/spiffs/www/speedtest.html","text/html"); }
static esp_err_t favicon_handler(httpd_req_t *req){ httpd_resp_set_status(req,"204 No Content"); return httpd_resp_send(req,NULL,0); }
static esp_err_t captive_redirect(httpd_req_t *req){ httpd_resp_set_status(req,"302 Found"); httpd_resp_set_hdr(req,"Location","http://192.168.4.1/"); return httpd_resp_send(req,NULL,0); }

static esp_err_t wifi_scan_handler(httpd_req_t *req) {
  wifi_ap_record_t *ap_list = NULL;
  uint16_t ap_count = 0;

  cJSON *json = cJSON_CreateObject();
  esp_err_t err = wifi_scan(&ap_list, &ap_count);

  if (err == ESP_OK) {
    cJSON *networks = cJSON_CreateArray();
    for (uint16_t i = 0; i < ap_count; i++) {
      cJSON *net = cJSON_CreateObject();
      cJSON_AddStringToObject(net, "ssid", (char *)ap_list[i].ssid);
      cJSON_AddNumberToObject(net, "rssi", ap_list[i].rssi);
      cJSON_AddNumberToObject(net, "channel", ap_list[i].primary);
      cJSON_AddItemToArray(networks, net);
    }
    cJSON_AddItemToObject(json, "networks", networks);
    cJSON_AddBoolToObject(json, "success", true);
    free(ap_list);
  } else {
    cJSON_AddBoolToObject(json, "success", false);
    cJSON_AddStringToObject(json, "error", esp_err_to_name(err));
  }

  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  return ESP_OK;
}

static esp_err_t recv_json(httpd_req_t *req, char *buf, size_t cap){
  if (req->content_len <= 0 || req->content_len >= cap) {
    return ESP_ERR_INVALID_SIZE;
  }
  size_t got = 0;
  while(got<(size_t)req->content_len){ int n=httpd_req_recv(req,buf+got,req->content_len-got); if(n==HTTPD_SOCK_ERR_TIMEOUT) continue; if(n<=0)return ESP_FAIL; got+=n; }
  buf[got]=0; return ESP_OK;
}
static esp_err_t wifi_config_handler(httpd_req_t *req){
  char b[512]; if(recv_json(req,b,sizeof(b))!=ESP_OK){httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"Invalid body");return ESP_FAIL;} cJSON *j=cJSON_Parse(b); cJSON *s=j?cJSON_GetObjectItem(j,"ssid"):NULL; cJSON *p=j?cJSON_GetObjectItem(j,"password"):NULL; cJSON *r=cJSON_CreateObject();
  if(s&&cJSON_IsString(s)){ esp_err_t e=settings_set_wifi_credentials(s->valuestring,(p&&cJSON_IsString(p))?p->valuestring:""); cJSON_AddBoolToObject(r,"success",e==ESP_OK); if(e!=ESP_OK)cJSON_AddStringToObject(r,"error",esp_err_to_name(e)); }
  else { cJSON_AddBoolToObject(r,"success",false); cJSON_AddStringToObject(r,"error","Invalid SSID"); }
  char *out=cJSON_PrintUnformatted(r); httpd_resp_set_type(req,"application/json"); httpd_resp_sendstr(req,out); free(out); cJSON_Delete(r); if(j)cJSON_Delete(j); vTaskDelay(pdMS_TO_TICKS(500)); esp_restart(); return ESP_OK;
}
static esp_err_t device_name_handler(httpd_req_t *req){
  char b[256]; if(recv_json(req,b,sizeof(b))!=ESP_OK){httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"Invalid body");return ESP_FAIL;} cJSON *j=cJSON_Parse(b); cJSON *n=j?cJSON_GetObjectItem(j,"name"):NULL; cJSON *r=cJSON_CreateObject();
  if(n&&cJSON_IsString(n)){ esp_err_t e=settings_set_device_name(n->valuestring); if(e==ESP_OK)wifi_set_hostname(n->valuestring); cJSON_AddBoolToObject(r,"success",e==ESP_OK); if(e!=ESP_OK)cJSON_AddStringToObject(r,"error",esp_err_to_name(e)); } else {cJSON_AddBoolToObject(r,"success",false);cJSON_AddStringToObject(r,"error","Invalid name");}
  char *out=cJSON_PrintUnformatted(r); httpd_resp_set_type(req,"application/json"); httpd_resp_sendstr(req,out); free(out); cJSON_Delete(r); if(j)cJSON_Delete(j); return ESP_OK;
}
static esp_err_t ota_handler(httpd_req_t *req){ if(req->content_len==0){httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"No firmware uploaded");return ESP_FAIL;} ESP_LOGI(TAG,"Stopping RTSP for OTA"); rtsp_server_stop(); esp_err_t e=ota_start_from_http(req); if(e!=ESP_OK){httpd_resp_send_err(req,HTTPD_500_INTERNAL_SERVER_ERROR,esp_err_to_name(e));return e;} httpd_resp_sendstr(req,"Firmware update complete, rebooting now!\n"); vTaskDelay(pdMS_TO_TICKS(500)); esp_restart(); return ESP_OK; }
static const char *reset_reason_str(esp_reset_reason_t r){switch(r){case ESP_RST_POWERON:return"poweron";case ESP_RST_EXT:return"external";case ESP_RST_SW:return"software";case ESP_RST_PANIC:return"panic";case ESP_RST_INT_WDT:return"int_wdt";case ESP_RST_TASK_WDT:return"task_wdt";case ESP_RST_WDT:return"other_wdt";case ESP_RST_DEEPSLEEP:return"deepsleep";case ESP_RST_BROWNOUT:return"brownout";case ESP_RST_SDIO:return"sdio";default:return"unknown";}}
static esp_err_t system_info_handler(httpd_req_t *req){
  cJSON *root=cJSON_CreateObject(),*i=cJSON_CreateObject(); char ip[16]={0},mac[18]={0},name[65]={0}; bool connected=wifi_is_connected(); wifi_get_ip_str(ip,sizeof(ip)); wifi_get_mac_str(mac,sizeof(mac)); settings_get_device_name(name,sizeof(name)); cJSON_AddStringToObject(i,"ip",ip);cJSON_AddStringToObject(i,"mac",mac);cJSON_AddStringToObject(i,"device_name",name);cJSON_AddBoolToObject(i,"wifi_connected",connected);cJSON_AddNumberToObject(i,"free_heap",esp_get_free_heap_size());
  if(connected){wifi_ap_record_t ap;if(esp_wifi_sta_get_ap_info(&ap)==ESP_OK){char ssid[33]={0},bssid[18];memcpy(ssid,ap.ssid,32);snprintf(bssid,sizeof(bssid),"%02x:%02x:%02x:%02x:%02x:%02x",ap.bssid[0],ap.bssid[1],ap.bssid[2],ap.bssid[3],ap.bssid[4],ap.bssid[5]);const char *phy=ap.phy_11n?"11n":ap.phy_11g?"11g":ap.phy_11b?"11b":ap.phy_lr?"LR":"?";cJSON_AddStringToObject(i,"wifi_ssid",ssid);cJSON_AddStringToObject(i,"wifi_bssid",bssid);cJSON_AddNumberToObject(i,"wifi_rssi",ap.rssi);cJSON_AddNumberToObject(i,"wifi_channel",ap.primary);cJSON_AddStringToObject(i,"wifi_phy",phy);}}
  const esp_app_desc_t *d=esp_app_get_description();cJSON_AddStringToObject(i,"firmware_version",d->version);cJSON_AddStringToObject(i,"reset_reason",reset_reason_str(esp_reset_reason()));cJSON_AddNumberToObject(i,"uptime_s",(double)(esp_timer_get_time()/1000000));cJSON_AddItemToObject(root,"info",i);cJSON_AddBoolToObject(root,"success",true);char *out=cJSON_PrintUnformatted(root);httpd_resp_set_type(req,"application/json");httpd_resp_sendstr(req,out);free(out);cJSON_Delete(root);return ESP_OK;
}
static esp_err_t restart_handler(httpd_req_t *req){httpd_resp_sendstr(req,"Restarting\n");vTaskDelay(pdMS_TO_TICKS(200));esp_restart();return ESP_OK;}
static esp_err_t speed_ping(httpd_req_t *req){httpd_resp_set_type(req,"text/plain");httpd_resp_set_hdr(req,"Cache-Control","no-store");return httpd_resp_send(req,"ok",2);}
static esp_err_t speed_download(httpd_req_t *req){size_t bytes=1024*1024;char q[64],v[16];if(httpd_req_get_url_query_str(req,q,sizeof(q))==ESP_OK&&httpd_query_key_value(q,"bytes",v,sizeof(v))==ESP_OK){long x=strtol(v,NULL,10);if(x>0)bytes=x;}if(bytes>SPEEDTEST_MAX_BYTES)bytes=SPEEDTEST_MAX_BYTES;static uint8_t filler[SPEEDTEST_CHUNK];static bool init=false;if(!init){for(size_t i=0;i<sizeof(filler);i++)filler[i]=(uint8_t)(i*37);init=true;}httpd_resp_set_type(req,"application/octet-stream");httpd_resp_set_hdr(req,"Cache-Control","no-store");while(bytes){size_t n=bytes<sizeof(filler)?bytes:sizeof(filler);if(httpd_resp_send_chunk(req,(char*)filler,n)!=ESP_OK)return ESP_FAIL;bytes-=n;}return httpd_resp_send_chunk(req,NULL,0);}
static esp_err_t speed_upload(httpd_req_t *req){size_t got=0,total=req->content_len;uint8_t b[SPEEDTEST_CHUNK];while(got<total){size_t want=total-got;if(want>sizeof(b))want=sizeof(b);int n=httpd_req_recv(req,(char*)b,want);if(n==HTTPD_SOCK_ERR_TIMEOUT)continue;if(n<=0)return ESP_FAIL;got+=n;}char out[64];snprintf(out,sizeof(out),"received=%u",(unsigned)got);httpd_resp_set_type(req,"text/plain");return httpd_resp_sendstr(req,out);}

esp_err_t web_server_start(uint16_t port){ if(s_server)return ESP_OK; httpd_config_t c=HTTPD_DEFAULT_CONFIG();c.server_port=port;c.max_uri_handlers=20;c.stack_size=8192;c.lru_purge_enable=true;esp_err_t e=httpd_start(&s_server,&c);if(e!=ESP_OK)return e;
#define REG(U,M,H) do{httpd_uri_t x={.uri=U,.method=M,.handler=H};ESP_ERROR_CHECK(httpd_register_uri_handler(s_server,&x));}while(0)
  REG("/",HTTP_GET,root_handler);REG("/favicon.ico",HTTP_GET,favicon_handler);REG("/logs",HTTP_GET,logs_handler);REG("/speedtest",HTTP_GET,speedtest_handler);REG("/api/wifi/scan",HTTP_GET,wifi_scan_handler);REG("/api/wifi/config",HTTP_POST,wifi_config_handler);REG("/api/device/name",HTTP_POST,device_name_handler);REG("/api/ota/update",HTTP_POST,ota_handler);REG("/api/system/info",HTTP_GET,system_info_handler);REG("/api/system/restart",HTTP_POST,restart_handler);REG("/api/speedtest/ping",HTTP_GET,speed_ping);REG("/api/speedtest/download",HTTP_GET,speed_download);REG("/api/speedtest/upload",HTTP_POST,speed_upload);REG("/hotspot-detect.html",HTTP_GET,captive_redirect);REG("/library/test/success.html",HTTP_GET,captive_redirect);REG("/generate_204",HTTP_GET,captive_redirect);REG("/connecttest.txt",HTTP_GET,captive_redirect);
#undef REG
  e=log_stream_register(s_server);if(e!=ESP_OK)ESP_LOGW(TAG,"log stream register failed: %s",esp_err_to_name(e));ESP_LOGI(TAG,"Web UI started on port %u",port);return ESP_OK; }
void web_server_stop(void){if(s_server){httpd_stop(s_server);s_server=NULL;}}
