================================================================
                         SmartAmp 配置说明
================================================================

板子: ESP32 WROVER, 4MB Flash, TAS5805M DAC
蓝牙: Classic A2DP, PIN=0000 (手机自动填入, 免手动输入)

GPIO:
  I2S BCK=13, WS=33, DO=27
  I2C SDA=14, SCL=26
  SPKFAULT 禁用, LED RGB 禁用

----------------------------------------------------------------
变更文件 (4个)
----------------------------------------------------------------
1. sdkconfig.defaults.smartamp  (新建)
   板级配置, 复用 ESPARAGUS_LOUDER, 含GPIO和BT_PIN_CODE=0000
   必须放在 SDKCONFIG_DEFAULTS 列表最后才覆盖 bt 默认值

2. platformio.ini  (修改)
   新增 [env:smartamp], SDKCONFIG_DEFAULTS 顺序: defaults -> bt -> smartamp

3. main/network/web_server.c  (修改)
   Windows配网跳转修复: 新增 /redirect -> captive_windows_handler 路由
   解决连接后跳 msftconnecttest.com/redirect 显示 URI 不匹配问题

4. smartamp.md  (新建, 本文档, 不参与编译)

================================================================
                    初次使用: 环境准备
================================================================
[装ESP-IDF v5.5.x]
  方式1(推荐): 官方安装器
    https://docs.espressif.com/projects/esp-idf/zh-cn/latest/esp32/get-started/
  方式2: 手动
    git clone --recursive https://github.com/espressif/esp-idf.git -b v5.5.1
    cd esp-idf && install.bat esp32

[激活环境]
  开始菜单打开 "ESP-IDF 5.5 CMD" 即可

[验证]
  idf.py --version   -> 应输出 v5.5.x

[取源码]
  git clone --recursive https://github.com/rbouteiller/airplay-esp32.git
  (子模块更新: cd airplay-esp32 && git submodule update --init --recursive)

常见问题:
  idf.py找不到 -> 未激活环境    缺Python依赖 -> esp-idf目录跑 install.bat esp32

================================================================
                        编译 / 烧录
================================================================
先激活 ESP-IDF, 进入项目根目录. 传参用环境变量, 不要用 idf.py -D (无效).

[1] 清理 (初次/改配置/换板后必跑)
    if exist sdkconfig del sdkconfig
    if exist build rmdir /s /q build

[2] 编译
    set IDF_TARGET=esp32&&set SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.bt;sdkconfig.defaults.smartamp&&idf.py build

[3] 烧录 (自动搜串口)
    idf.py flash monitor

注意:
  set X=Y&& 之间不能有空格, 否则值末尾带空格配置回退
  环境变量只对当前CMD窗口有效

================================================================
                   生成合并固件 (Web烧录用)
================================================================
cd build
python %IDF_PATH%\components\esptool_py\esptool\esptool.py --chip esp32 merge_bin -o airplay2-receiver-smartamp.bin @flash_args

产物: build\airplay2-receiver-smartamp.bin (~4MB)

Web烧录: https://web.esphome.io
或
命令行: python -m esptool --chip esp32 --port COM3 --baud 921600 write_flash 0x0 airplay2-receiver-smartamp.bin

================================================================
                       配置验证
================================================================
执行:
  findstr "FLASHSIZE_4MB partitions-4m BOARD_ESPARAGUS_LOUDER DAC_TAS58XX BT_PIN_CODE" sdkconfig

应看到5行:
  CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y
  CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="components/boards/partitions-4m.csv"
  CONFIG_BOARD_ESPARAGUS_LOUDER=y
  CONFIG_DAC_TAS58XX=y
  CONFIG_BT_PIN_CODE="0000"   (不是0000说明加载顺序错)

================================================================
                         注意事项
================================================================
* TAS5805M自动检测, 无需配置 (扫I2C 0x2C-0x2F)
* PIN=0000 是蓝牙音频设备通用码, 安卓自动填入, iPhone需手动输0000
  (免手动输需改 a2dp_sink.c:703 IO_CAP 为 NO_INPUT_NO_OUTPUT 重编译)
* BOARD_NAME 硬编码显示 "Esparagus Audio Brick", 改名要新建板目录
* 分区表: components/boards/partitions-4m.csv (双OTA + SPIFFS)
* SDKCONFIG_DEFAULTS 规则: 通用在前, smartamp在后; 后者覆盖前者
* Win配网: 连WiFi后如跳 msftconnecttest.com 正常, 会自动转到 192.168.4.1
