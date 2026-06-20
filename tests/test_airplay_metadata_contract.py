import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class AirPlayMetadataContractTests(unittest.TestCase):
    def test_protocol_mapping_is_text_artwork_progress(self) -> None:
        source = read("main/network/mdns_airplay.c")
        self.assertIn('#define AIRPLAY_METADATA_TYPES "0,1,2"', source)
        self.assertIn("0 = text", source)
        self.assertIn("1 = artwork", source)
        self.assertIn("2 = progress", source)

    def test_runtime_setting_defaults_enabled_and_is_persisted(self) -> None:
        header = read("main/settings.h")
        source = read("main/settings.c")
        self.assertIn("bool settings_airplay_metadata_enabled(void);", header)
        self.assertIn(
            "esp_err_t settings_set_airplay_metadata_enabled(bool enabled);",
            header,
        )
        self.assertIn('#define NVS_KEY_METADATA_ENABLED "metadata_en"', source)
        self.assertRegex(source, r"g_airplay_metadata_enabled\s*=\s*true")
        self.assertIn(
            "nvs_get_u8(nvs, NVS_KEY_METADATA_ENABLED, &metadata_enabled)",
            source,
        )
        self.assertIn(
            "nvs_set_u8(nvs, NVS_KEY_METADATA_ENABLED, enabled ? 1 : 0)",
            source,
        )

    def test_rtsp_metadata_uses_runtime_gate_not_compile_time_gate(self) -> None:
        source = read("main/rtsp/rtsp_handlers.c")
        self.assertIn("settings_airplay_metadata_enabled()", source)
        self.assertNotIn("CONFIG_ENABLE_AIRPLAY_ARTWORK", source)

    def test_web_api_and_main_page_expose_live_metadata_switch(self) -> None:
        server = read("main/network/web_server.c")
        page = read("data/www/index.html")
        handler = server.split(
            "static esp_err_t airplay_metadata_post_handler", 1
        )[1].split("static esp_err_t gpio_config_get_handler", 1)[0]

        self.assertIn('id="airplay-metadata-enabled"', page)
        self.assertIn("async function loadAirPlayMetadataConfig()", page)
        self.assertIn("async function applyAirPlayMetadataChange(input)", page)
        self.assertIn('cJSON_AddBoolToObject(response, "restarting", false);', handler)
        self.assertNotIn("esp_restart()", handler)
        self.assertRegex(
            server,
            r"(?s)airplay_metadata_get_uri\s*=\s*\{.*?"
            r'\.uri\s*=\s*"/api/airplay/metadata".*?'
            r"\.method\s*=\s*HTTP_GET.*?"
            r"\.handler\s*=\s*airplay_metadata_get_handler\s*\}",
        )
        self.assertRegex(
            server,
            r"(?s)airplay_metadata_post_uri\s*=\s*\{.*?"
            r'\.uri\s*=\s*"/api/airplay/metadata".*?'
            r"\.method\s*=\s*HTTP_POST.*?"
            r"\.handler\s*=\s*airplay_metadata_post_handler\s*\}",
        )


if __name__ == "__main__":
    unittest.main()
