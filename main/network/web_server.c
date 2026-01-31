#include "web_server.h"

#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_system.h"
#include "cJSON.h"
#include <string.h>
#include <stdlib.h>

#include "settings.h"
#include "wifi.h"
#include "ota.h"
#include "rtsp_server.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "web_server";
static httpd_handle_t s_server = NULL;

// HTML control panel
static const char *HTML_CONTROL_PANEL =
    "<!DOCTYPE html><html><head>\n"
    "<meta charset='UTF-8'>\n"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>\n"
    "<title>AirPlay Receiver</title>\n"
    "<style>\n"
    "*{box-sizing:border-box;margin:0;padding:0}\n"
    "body{font-family:-apple-system,system-ui,sans-serif;background:linear-"
    "gradient(135deg,#1a1a2e 0%,#16213e "
    "100%);min-height:100vh;padding:20px;color:#fff}\n"
    ".wrap{max-width:480px;margin:0 auto}\n"
    ".header{text-align:center;padding:30px 0}\n"
    ".header h1{font-size:28px;font-weight:600;margin-bottom:8px}\n"
    ".header p{color:#888;font-size:14px}\n"
    ".status-bar{background:#0f3460;border-radius:12px;padding:16px;margin-"
    "bottom:20px;text-align:center}\n"
    ".status-bar.ok{background:#1b4332}\n"
    ".status-bar.err{background:#5c1a1a}\n"
    ".card{background:rgba(255,255,255,0.05);backdrop-filter:blur(10px);border-"
    "radius:16px;padding:20px;margin-bottom:16px;border:1px solid "
    "rgba(255,255,255,0.1)}\n"
    ".card "
    "h2{font-size:16px;font-weight:600;margin-bottom:16px;color:#e94560}\n"
    ".form-group{margin-bottom:14px}\n"
    ".form-group "
    "label{display:block;font-size:12px;color:#888;margin-bottom:6px;text-"
    "transform:uppercase;letter-spacing:0.5px}\n"
    "input[type=text],input[type=password]{width:100%;padding:12px "
    "14px;background:rgba(0,0,0,0.3);border:1px solid "
    "rgba(255,255,255,0.1);border-radius:8px;color:#fff;font-size:14px}\n"
    "input:focus{outline:none;border-color:#e94560}\n"
    ".btn{display:inline-block;padding:12px "
    "20px;border:none;border-radius:8px;font-size:14px;font-weight:500;cursor:"
    "pointer;transition:all 0.2s}\n"
    ".btn-primary{background:#e94560;color:#fff}\n"
    ".btn-primary:hover{background:#d63850}\n"
    ".btn-secondary{background:rgba(255,255,255,0.1);color:#fff}\n"
    ".btn-secondary:hover{background:rgba(255,255,255,0.2)}\n"
    ".btn-danger{background:#dc3545;color:#fff}\n"
    ".btn-danger:hover{background:#c82333}\n"
    ".btn-block{width:100%;margin-top:10px}\n"
    ".btn:disabled{opacity:0.5;cursor:not-allowed}\n"
    ".wifi-list{max-height:180px;overflow-y:auto;margin:12px "
    "0;border-radius:8px}\n"
    ".wifi-item{padding:12px;background:rgba(0,0,0,0.2);margin-bottom:4px;"
    "border-radius:6px;cursor:pointer;display:flex;justify-content:space-"
    "between;align-items:center}\n"
    ".wifi-item:hover{background:rgba(233,69,96,0.2)}\n"
    ".wifi-item.sel{background:rgba(233,69,96,0.3);border:1px solid #e94560}\n"
    ".wifi-item .ssid{font-weight:500}\n"
    ".wifi-item .rssi{font-size:12px;color:#888}\n"
    ".info-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}\n"
    ".info-item{background:rgba(0,0,0,0.2);padding:12px;border-radius:8px}\n"
    ".info-item "
    "label{font-size:11px;color:#888;display:block;margin-bottom:4px}\n"
    ".info-item span{font-size:14px;font-weight:500}\n"
    ".msg{padding:10px;border-radius:6px;margin-top:10px;font-size:13px}\n"
    ".msg.ok{background:rgba(27,67,50,0.5)}\n"
    ".msg.err{background:rgba(92,26,26,0.5)}\n"
    ".msg.info{background:rgba(15,52,96,0.5)}\n"
    ".file-row{display:flex;gap:10px;align-items:center}\n"
    ".file-name{flex:1;font-size:13px;color:#888}\n"
    ".actions{display:flex;gap:10px;margin-top:10px}\n"
    "</style></head><body>\n"
    "<div class='wrap'>\n"
    "<div class='header'><h1>AirPlay Receiver</h1><p>ESP32 Configuration "
    "Panel</p></div>\n"
    "<div id='status-bar' class='status-bar'>Loading...</div>\n"
    "<div class='card'><h2>WiFi Network</h2>\n"
    "<button class='btn btn-secondary' onclick='scanWiFi()'>Scan "
    "Networks</button>\n"
    "<div id='wifi-list' class='wifi-list'></div>\n"
    "<div class='form-group'><label>Network Name (SSID)</label><input "
    "type='text' id='wifi-ssid' placeholder='Enter or select network'></div>\n"
    "<div class='form-group'><label>Password</label><input type='password' "
    "id='wifi-pass' placeholder='Enter password'></div>\n"
    "<button class='btn btn-primary btn-block' onclick='saveWiFi()'>Connect to "
    "WiFi</button>\n"
    "<div id='wifi-msg'></div></div>\n"
    "<div class='card'><h2>Device Settings</h2>\n"
    "<div class='form-group'><label>AirPlay Device Name</label><input "
    "type='text' id='dev-name' placeholder='My Speaker'></div>\n"
    "<button class='btn btn-primary' onclick='saveName()'>Save Name</button>\n"
    "<div id='name-msg'></div></div>\n"
    "<div class='card'><h2>Firmware Update</h2>\n"
    "<div class='file-row'><input type='file' id='fw-file' accept='.bin' "
    "style='display:none'>\n"
    "<button class='btn btn-secondary' "
    "onclick='document.getElementById(\"fw-file\").click()'>Choose "
    "File</button>\n"
    "<span class='file-name' id='fw-name'>No file selected</span></div>\n"
    "<button class='btn btn-primary btn-block' id='ota-btn' "
    "onclick='startOTA()' disabled>Upload Firmware</button>\n"
    "<div id='ota-msg'></div></div>\n"
    "<div class='card'><h2>System</h2>\n"
    "<div class='info-grid'>\n"
    "<div class='info-item'><label>IP Address</label><span "
    "id='info-ip'>-</span></div>\n"
    "<div class='info-item'><label>MAC Address</label><span "
    "id='info-mac'>-</span></div>\n"
    "<div class='info-item'><label>Device Name</label><span "
    "id='info-name'>-</span></div>\n"
    "<div class='info-item'><label>Free Memory</label><span "
    "id='info-heap'>-</span></div>\n"
    "</div>\n"
    "<div class='actions'><button class='btn btn-danger' "
    "onclick='restart()'>Restart Device</button></div>\n"
    "</div></div>\n"
    "<script>\n"
    "function msg(id,txt,type){var "
    "e=document.getElementById(id);if(e){e.innerHTML='<div class=\"msg "
    "'+type+'\">'+txt+'</"
    "div>';setTimeout(function(){e.innerHTML='';},4000);}}\n"
    "async function scanWiFi(){\n"
    "  var l=document.getElementById('wifi-list');l.innerHTML='<div "
    "class=\"msg info\">Scanning...</div>';\n"
    "  try{var r=await fetch('/api/wifi/scan');var d=await r.json();\n"
    "    "
    "if(d.success&&d.networks.length>0){l.innerHTML='';d.networks.forEach("
    "function(n){\n"
    "      var i=document.createElement('div');i.className='wifi-item';\n"
    "      i.innerHTML='<span class=\"ssid\">'+n.ssid+'</span><span "
    "class=\"rssi\">'+n.rssi+' dBm</span>';\n"
    "      "
    "i.onclick=function(){document.querySelectorAll('.wifi-item').forEach("
    "function(x){x.classList.remove('sel');});i.classList.add('sel');document."
    "getElementById('wifi-ssid').value=n.ssid;};\n"
    "      l.appendChild(i);});}\n"
    "    else{l.innerHTML='<div class=\"msg info\">No networks "
    "found</div>';}}\n"
    "  catch(e){l.innerHTML='<div class=\"msg err\">Scan failed</div>';}}\n"
    "async function saveWiFi(){\n"
    "  var s=document.getElementById('wifi-ssid').value.trim();var "
    "p=document.getElementById('wifi-pass').value;\n"
    "  if(!s){msg('wifi-msg','Enter network name','err');return;}\n"
    "  try{var r=await "
    "fetch('/api/wifi/"
    "config',{method:'POST',headers:{'Content-Type':'application/"
    "json'},body:JSON.stringify({ssid:s,password:p})});\n"
    "    var d=await r.json();if(d.success){msg('wifi-msg','Saved! "
    "Restarting...','ok');}else{msg('wifi-msg',d.error,'err');}}\n"
    "  catch(e){msg('wifi-msg','Error','err');}}\n"
    "async function saveName(){\n"
    "  var "
    "n=document.getElementById('dev-name').value.trim();if(!n){msg('name-msg','"
    "Enter a name','err');return;}\n"
    "  try{var r=await "
    "fetch('/api/device/"
    "name',{method:'POST',headers:{'Content-Type':'application/"
    "json'},body:JSON.stringify({name:n})});\n"
    "    var d=await r.json();if(d.success){msg('name-msg','Saved! Restart to "
    "apply.','ok');loadInfo();}else{msg('name-msg',d.error,'err');}}\n"
    "  catch(e){msg('name-msg','Error','err');}}\n"
    "async function startOTA(){\n"
    "  var "
    "f=document.getElementById('fw-file').files[0];if(!f){msg('ota-msg','"
    "Select a file','err');return;}\n"
    "  "
    "document.getElementById('ota-btn').disabled=true;msg('ota-msg','Uploading."
    "..','info');\n"
    "  try{await "
    "fetch('/api/ota/"
    "update',{method:'POST',headers:{'Content-Type':'application/"
    "octet-stream'},body:f});msg('ota-msg','Done! Rebooting...','ok');}\n"
    "  catch(e){msg('ota-msg','Rebooting...','ok');}}\n"
    "async function restart(){\n"
    "  if(!confirm('Restart the device?'))return;\n"
    "  try{await "
    "fetch('/api/system/"
    "restart',{method:'POST'});msg('','Restarting...','info');}catch(e){}}\n"
    "async function loadInfo(){\n"
    "  try{var r=await fetch('/api/system/info');var d=await r.json();\n"
    "    if(d.success){var i=d.info;var "
    "b=document.getElementById('status-bar');\n"
    "      if(i.wifi_connected){b.className='status-bar "
    "ok';b.innerHTML='Connected to WiFi: '+i.ip;}\n"
    "      else{b.className='status-bar err';b.innerHTML='Not connected - "
    "Configure WiFi below';}\n"
    "      document.getElementById('info-ip').textContent=i.ip||'-';\n"
    "      document.getElementById('info-mac').textContent=i.mac||'-';\n"
    "      "
    "document.getElementById('info-name').textContent=i.device_name||'-';\n"
    "      "
    "document.getElementById('info-heap').textContent=Math.round(i.free_heap/"
    "1024)+' KB';\n"
    "      "
    "document.getElementById('dev-name').placeholder=i.device_name||'';}}catch("
    "e){}}\n"
    "window.onload=function(){\n"
    "  document.getElementById('fw-file').onchange=function(e){var "
    "f=e.target.files[0];\n"
    "    document.getElementById('fw-name').textContent=f?f.name:'No file "
    "selected';\n"
    "    document.getElementById('ota-btn').disabled=!f;};\n"
    "  loadInfo();setInterval(loadInfo,30000);};\n"
    "</script></body></html>";

// API handlers
static esp_err_t root_handler(httpd_req_t *req) {
  httpd_resp_set_type(req, "text/html");
  httpd_resp_send(req, HTML_CONTROL_PANEL, strlen(HTML_CONTROL_PANEL));
  return ESP_OK;
}

// Captive portal detection handlers
// These endpoints are requested by various OS to detect captive portals
static esp_err_t captive_portal_redirect(httpd_req_t *req) {
  // Redirect to the configuration page
  httpd_resp_set_status(req, "302 Found");
  httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
  httpd_resp_send(req, NULL, 0);
  return ESP_OK;
}

// Apple devices (iOS/macOS) check these
static esp_err_t captive_apple_handler(httpd_req_t *req) {
  // Apple expects specific response, redirect instead
  return captive_portal_redirect(req);
}

// Android checks this
static esp_err_t captive_android_handler(httpd_req_t *req) {
  // Android expects 204 for no captive portal, anything else triggers portal
  return captive_portal_redirect(req);
}

// Windows checks this
static esp_err_t captive_windows_handler(httpd_req_t *req) {
  return captive_portal_redirect(req);
}

static esp_err_t wifi_scan_handler(httpd_req_t *req) {
  wifi_ap_record_t *ap_list = NULL;
  uint16_t ap_count = 0;

  cJSON *json = cJSON_CreateObject();
  esp_err_t err = wifi_scan(&ap_list, &ap_count);

  if (err == ESP_OK && ap_list) {
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

static esp_err_t wifi_config_handler(httpd_req_t *req) {
  char content[512];
  int ret = httpd_req_recv(req, content, sizeof(content) - 1);
  if (ret <= 0) {
    httpd_resp_send_500(req);
    return ESP_FAIL;
  }
  content[ret] = '\0';

  cJSON *json = cJSON_Parse(content);
  if (!json) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  cJSON *ssid_json = cJSON_GetObjectItem(json, "ssid");
  cJSON *password_json = cJSON_GetObjectItem(json, "password");

  cJSON *response = cJSON_CreateObject();
  if (ssid_json && cJSON_IsString(ssid_json)) {
    const char *ssid = cJSON_GetStringValue(ssid_json);
    const char *password = password_json && cJSON_IsString(password_json)
                               ? cJSON_GetStringValue(password_json)
                               : "";

    esp_err_t err = settings_set_wifi_credentials(ssid, password);
    if (err == ESP_OK) {
      cJSON_AddBoolToObject(response, "success", true);
      ESP_LOGI(TAG, "WiFi credentials saved. We are restarting...");
      // Schedule restart
      vTaskDelay(pdMS_TO_TICKS(1000));
      esp_restart();
    } else {
      cJSON_AddBoolToObject(response, "success", false);
      cJSON_AddStringToObject(response, "error", esp_err_to_name(err));
    }
  } else {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error", "Invalid SSID");
  }

  char *json_str = cJSON_Print(response);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  cJSON_Delete(response);

  return ESP_OK;
}

static esp_err_t device_name_handler(httpd_req_t *req) {
  char content[256];
  int ret = httpd_req_recv(req, content, sizeof(content) - 1);
  if (ret <= 0) {
    httpd_resp_send_500(req);
    return ESP_FAIL;
  }
  content[ret] = '\0';

  cJSON *json = cJSON_Parse(content);
  if (!json) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  cJSON *name_json = cJSON_GetObjectItem(json, "name");
  cJSON *response = cJSON_CreateObject();

  if (name_json && cJSON_IsString(name_json)) {
    const char *name = cJSON_GetStringValue(name_json);
    esp_err_t err = settings_set_device_name(name);
    if (err == ESP_OK) {
      cJSON_AddBoolToObject(response, "success", true);
    } else {
      cJSON_AddBoolToObject(response, "success", false);
      cJSON_AddStringToObject(response, "error", esp_err_to_name(err));
    }
  } else {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error", "Invalid name");
  }

  char *json_str = cJSON_Print(response);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  cJSON_Delete(response);

  return ESP_OK;
}

static esp_err_t ota_update_handler(httpd_req_t *req) {
  if (req->content_len == 0) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No firmware uploaded");
    return ESP_FAIL;
  }

  // Stop AirPlay to free resources during OTA
  ESP_LOGI(TAG, "Stopping AirPlay for OTA update");
  rtsp_server_stop();

  esp_err_t err = ota_start_from_http(req);

  if (err != ESP_OK) {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                        esp_err_to_name(err));
    return ESP_FAIL;
  }

  // Send response before restarting
  httpd_resp_sendstr(req, "Firmware update complete, rebooting now!\n");
  vTaskDelay(pdMS_TO_TICKS(500));
  esp_restart();

  return ESP_OK;
}

static esp_err_t system_info_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  cJSON *info = cJSON_CreateObject();

  char ip_str[16] = {0};
  char mac_str[18] = {0};
  char device_name[65] = {0};
  bool wifi_connected = wifi_is_connected();

  wifi_get_ip_str(ip_str, sizeof(ip_str));
  wifi_get_mac_str(mac_str, sizeof(mac_str));
  settings_get_device_name(device_name, sizeof(device_name));

  cJSON_AddStringToObject(info, "ip", ip_str);
  cJSON_AddStringToObject(info, "mac", mac_str);
  cJSON_AddStringToObject(info, "device_name", device_name);
  cJSON_AddBoolToObject(info, "wifi_connected", wifi_connected);
  cJSON_AddNumberToObject(info, "free_heap", esp_get_free_heap_size());

  cJSON_AddItemToObject(json, "info", info);
  cJSON_AddBoolToObject(json, "success", true);

  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);

  return ESP_OK;
}

static esp_err_t system_restart_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  cJSON_AddBoolToObject(json, "success", true);

  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);

  ESP_LOGI(TAG, "Restart requested via web interface");
  vTaskDelay(pdMS_TO_TICKS(500));
  esp_restart();

  return ESP_OK;
}

esp_err_t web_server_start(uint16_t port) {
  if (s_server) {
    ESP_LOGW(TAG, "Web server already running");
    return ESP_OK;
  }

  httpd_config_t config = HTTPD_DEFAULT_CONFIG();
  config.server_port = port;
  config.max_uri_handlers = 16; // Increased for captive portal handlers
  config.max_resp_headers = 8;
  config.stack_size = 8192;

  esp_err_t err = httpd_start(&s_server, &config);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start web server: %s", esp_err_to_name(err));
    return err;
  }

  // Register handlers
  httpd_uri_t root_uri = {
      .uri = "/", .method = HTTP_GET, .handler = root_handler};
  httpd_register_uri_handler(s_server, &root_uri);

  httpd_uri_t wifi_scan_uri = {.uri = "/api/wifi/scan",
                               .method = HTTP_GET,
                               .handler = wifi_scan_handler};
  httpd_register_uri_handler(s_server, &wifi_scan_uri);

  httpd_uri_t wifi_config_uri = {.uri = "/api/wifi/config",
                                 .method = HTTP_POST,
                                 .handler = wifi_config_handler};
  httpd_register_uri_handler(s_server, &wifi_config_uri);

  httpd_uri_t device_name_uri = {.uri = "/api/device/name",
                                 .method = HTTP_POST,
                                 .handler = device_name_handler};
  httpd_register_uri_handler(s_server, &device_name_uri);

  httpd_uri_t ota_uri = {.uri = "/api/ota/update",
                         .method = HTTP_POST,
                         .handler = ota_update_handler};
  httpd_register_uri_handler(s_server, &ota_uri);

  httpd_uri_t system_info_uri = {.uri = "/api/system/info",
                                 .method = HTTP_GET,
                                 .handler = system_info_handler};
  httpd_register_uri_handler(s_server, &system_info_uri);

  httpd_uri_t system_restart_uri = {.uri = "/api/system/restart",
                                    .method = HTTP_POST,
                                    .handler = system_restart_handler};
  httpd_register_uri_handler(s_server, &system_restart_uri);

  // Captive portal detection endpoints
  // Apple iOS/macOS
  httpd_uri_t apple_captive1 = {.uri = "/hotspot-detect.html",
                                .method = HTTP_GET,
                                .handler = captive_apple_handler};
  httpd_register_uri_handler(s_server, &apple_captive1);

  httpd_uri_t apple_captive2 = {.uri = "/library/test/success.html",
                                .method = HTTP_GET,
                                .handler = captive_apple_handler};
  httpd_register_uri_handler(s_server, &apple_captive2);

  // Android
  httpd_uri_t android_captive = {.uri = "/generate_204",
                                 .method = HTTP_GET,
                                 .handler = captive_android_handler};
  httpd_register_uri_handler(s_server, &android_captive);

  // Windows
  httpd_uri_t windows_captive = {.uri = "/connecttest.txt",
                                 .method = HTTP_GET,
                                 .handler = captive_windows_handler};
  httpd_register_uri_handler(s_server, &windows_captive);

  ESP_LOGI(TAG, "Web server started on port %d with captive portal support",
           port);
  return ESP_OK;
}

void web_server_stop(void) {
  if (s_server) {
    httpd_stop(s_server);
    s_server = NULL;
    ESP_LOGI(TAG, "Web server stopped");
  }
}
