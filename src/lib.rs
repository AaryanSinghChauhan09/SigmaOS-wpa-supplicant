// SPDX-License-Identifier: MIT
// SigmaOS-wpa-supplicant - WPA/WPA2/WPA3 Wi-Fi Supplicant component
// wpa_supplicant-style wireless authentication daemon for SigmaOS,
// inspired by Arch's wpa_supplicant package.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// SECURITY PROTOCOLS
// ============================================================================

/// Wi-Fi security protocols (wpa_supplicant-compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProtocol {
    WpaEap,
    WpaPsk,
    WpaNone,
    RsnEap,
    RsnPsk,
    WpaEapSha256,
    WpaEapSuiteB,
    WpaEapSuiteB192,
    Ieee8021x,
    None,
}

impl SecurityProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WpaEap => "WPA-EAP",
            Self::WpaPsk => "WPA-PSK",
            Self::WpaNone => "WPA-NONE",
            Self::RsnEap => "RSN-EAP",
            Self::RsnPsk => "RSN-PSK",
            Self::WpaEapSha256 => "WPA-EAP-SHA256",
            Self::WpaEapSuiteB => "WPA-EAP-SUITE-B",
            Self::WpaEapSuiteB192 => "WPA-EAP-SUITE-B-192",
            Self::Ieee8021x => "IEEE8021X",
            Self::None => "NONE",
        }
    }

    /// Whether this is an enterprise (802.1X) network
    pub fn is_enterprise(&self) -> bool {
        matches!(self, Self::WpaEap | Self::RsnEap | Self::Ieee8021x
            | Self::WpaEapSha256 | Self::WpaEapSuiteB | Self::WpaEapSuiteB192)
    }

    /// Whether this is a personal (PSK) network
    pub fn is_psk(&self) -> bool {
        matches!(self, Self::WpaPsk | Self::RsnPsk)
    }
}

/// EAP authentication methods for enterprise networks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapMethod {
    Tls,
    Peap,
    Ttls,
    Fast,
    Sim,
    Aka,
    Leap,
    Tnc,
    Pwd,
    Sim2,
    AkaPrime,
    Eapol,
}

impl EapMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tls => "TLS",
            Self::Peap => "PEAP",
            Self::Ttls => "TTLS",
            Self::Fast => "FAST",
            Self::Sim => "SIM",
            Self::Aka => "AKA",
            Self::Leap => "LEAP",
            Self::Tnc => "TNC",
            Self::Pwd => "PWD",
            Self::Sim2 => "SIM2",
            Self::AkaPrime => "AKA'",
            Self::Eapol => "EAPOL",
        }
    }
}

/// Inner authentication for tunneled EAP (PEAP/TTLS)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase2Method {
    MsChapV2,
    Gtc,
    Tls,
    Pwd,
    AkaPrime,
    Sim,
    None,
}

impl Phase2Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MsChapV2 => "MSCHAPV2",
            Self::Gtc => "GTC",
            Self::Tls => "TLS",
            Self::Pwd => "PWD",
            Self::AkaPrime => "AKA'",
            Self::Sim => "SIM",
            Self::None => "NONE",
        }
    }
}

// ============================================================================
// NETWORK CONFIGURATION
// ============================================================================

/// A configured Wi-Fi network (network block in wpa_supplicant.conf)
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// SSID (may be raw bytes for non-UTF8)
    pub ssid: String,
    /// Whether this is a hidden network
    pub scan_ssid: bool,
    /// Priority (higher wins when multiple networks in range)
    pub priority: i32,
    /// Whether this is the currently connected network
    pub current: bool,
    /// Disabled networks are skipped
    pub disabled: bool,

    // Security
    pub key_mgmt: Option<SecurityProtocol>,
    pub psk: Option<String>,          // plaintext or 64-hex
    pub psk_raw: Option<Vec<u8>>,     // raw 32-byte PSK
    pub auth_alg: Option<String>,
    pub pairwise: Option<String>,     // e.g. "CCMP"
    pub group: Option<String>,        // e.g. "CCMP"
    pub proto: Option<String>,        // "WPA" or "RSN"

    // Enterprise (802.1X)
    pub eap_method: Option<EapMethod>,
    pub phase2_method: Option<Phase2Method>,
    pub identity: Option<String>,
    pub anonymous_identity: Option<String>,
    pub password: Option<String>,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub private_key: Option<String>,
    pub private_key_passwd: Option<String>,
    pub subject_match: Option<String>,

    // Misc
    pub wep_key0: Option<String>,
    pub wep_tx_keyidx: Option<u8>,
    pub mac_addr: Option<String>,     // MAC randomization policy
    pub freq_list: Option<Vec<u32>>,  // allowed channels
}

impl NetworkConfig {
    pub fn new(ssid: impl Into<String>) -> Self {
        Self {
            ssid: ssid.into(),
            scan_ssid: false,
            priority: 0,
            current: false,
            disabled: false,
            key_mgmt: None,
            psk: None,
            psk_raw: None,
            auth_alg: None,
            pairwise: None,
            group: None,
            proto: None,
            eap_method: None,
            phase2_method: None,
            identity: None,
            anonymous_identity: None,
            password: None,
            ca_cert: None,
            client_cert: None,
            private_key: None,
            private_key_passwd: None,
            subject_match: None,
            wep_key0: None,
            wep_tx_keyidx: None,
            mac_addr: None,
            freq_list: None,
        }
    }

    /// Create a WPA2-PSK config from SSID + passphrase
    pub fn wpa2_psk(ssid: impl Into<String>, passphrase: impl Into<String>) -> Self {
        let mut n = Self::new(ssid);
        n.key_mgmt = Some(SecurityProtocol::RsnPsk);
        n.proto = Some("RSN".into());
        n.pairwise = Some("CCMP".into());
        n.group = Some("CCMP".into());
        n.psk = Some(passphrase.into());
        n
    }

    /// Create an open network config
    pub fn open(ssid: impl Into<String>) -> Self {
        let mut n = Self::new(ssid);
        n.key_mgmt = Some(SecurityProtocol::None);
        n
    }

    /// Create an enterprise (PEAP/MSCHAPv2) config
    pub fn enterprise_peap(
        ssid: impl Into<String>,
        identity: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        let mut n = Self::new(ssid);
        n.key_mgmt = Some(SecurityProtocol::RsnEap);
        n.eap_method = Some(EapMethod::Peap);
        n.phase2_method = Some(Phase2Method::MsChapV2);
        n.identity = Some(identity.into());
        n.password = Some(password.into());
        n.proto = Some("RSN".into());
        n.pairwise = Some("CCMP".into());
        n.group = Some("CCMP".into());
        n
    }

    /// Validate config completeness for connection
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.ssid.is_empty() {
            return Err(ConfigError::MissingField("ssid".into()));
        }
        match self.key_mgmt {
            Some(p) if p.is_psk() => {
                if self.psk.is_none() && self.psk_raw.is_none() {
                    return Err(ConfigError::MissingField("psk".into()));
                }
            }
            Some(p) if p.is_enterprise() => {
                if self.eap_method.is_none() {
                    return Err(ConfigError::MissingField("eap_method".into()));
                }
                if self.identity.is_none() {
                    return Err(ConfigError::MissingField("identity".into()));
                }
                // TLS client certs needed for EAP-TLS
                if self.eap_method == Some(EapMethod::Tls)
                    && (self.client_cert.is_none() || self.private_key.is_none())
                {
                    return Err(ConfigError::MissingField("client_cert/private_key".into()));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

// ============================================================================
// NETWORK STATE
// ============================================================================

/// Wi-Fi connection state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiState {
    Disconnected,
    Scanning,
    Authenticating,
    Associating,
    ObtainingIp,       // DHCP in progress
    Connected,
    Disconnecting,
    Failed,
}

impl WifiState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disconnected => "DISCONNECTED",
            Self::Scanning => "SCANNING",
            Self::Authenticating => "AUTHENTICATING",
            Self::Associating => "ASSOCIATING",
            Self::ObtainingIp => "OBTAINING_IP",
            Self::Connected => "COMPLETED",
            Self::Disconnecting => "DISCONNECTING",
            Self::Failed => "FAILED",
        }
    }

    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }
}

/// Details of an available (scanned) network
#[derive(Debug, Clone)]
pub struct WifiNetwork {
    pub ssid: String,
    pub bssid: String,          // AP MAC address
    pub signal_dbm: i32,        // negative dBm, e.g. -50 strong, -90 weak
    pub frequency_mhz: u32,
    pub channel: u8,
    pub security: SecurityProtocol,
    pub hidden: bool,
    pub wpa_flags: u8,
    pub rsn_flags: u8,
}

impl WifiNetwork {
    pub fn signal_quality(&self) -> u8 {
        // Map dBm to 0-100 quality (typical: -30=100%, -90=0%)
        let clamped = self.signal_dbm.clamp(-100, -30);
        (((clamped + 100) * 100) / 70) as u8
    }
}

/// Active connection info
#[derive(Debug, Clone)]
pub struct WifiStatus {
    pub state: WifiState,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub frequency_mhz: Option<u32>,
    pub signal_dbm: Option<i32>,
    pub ip_address: Option<String>,
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
    pub connected_since_ms: Option<u64>,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
}

// ============================================================================
// WPA SUPPLICANT DAEMON
// ============================================================================

/// The wpa_supplicant daemon
pub struct WpaSupplicant {
    networks: Mutex<Vec<NetworkConfig>>,
    status: Mutex<WifiStatus>,
    scanned_networks: Mutex<Vec<WifiNetwork>>,
    /// Interface name (e.g. wlan0)
    interface: String,
}

impl WpaSupplicant {
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            networks: Mutex::new(Vec::new()),
            status: Mutex::new(WifiStatus {
                state: WifiState::Disconnected,
                ssid: None,
                bssid: None,
                frequency_mhz: None,
                signal_dbm: None,
                ip_address: None,
                gateway: None,
                dns_servers: Vec::new(),
                connected_since_ms: None,
                bytes_tx: 0,
                bytes_rx: 0,
            }),
            scanned_networks: Mutex::new(Vec::new()),
            interface: interface.into(),
        }
    }

    pub fn interface(&self) -> &str { &self.interface }

    // ---- Network config management ----

    pub fn add_network(&self, config: NetworkConfig) -> Result<usize, ConfigError> {
        config.validate()?;
        let mut networks = self.networks.lock().unwrap();
        networks.push(config);
        Ok(networks.len() - 1)
    }

    pub fn remove_network(&self, index: usize) -> bool {
        let mut networks = self.networks.lock().unwrap();
        if index < networks.len() {
            networks.remove(index);
            true
        } else {
            false
        }
    }

    pub fn list_networks(&self) -> Vec<NetworkConfig> {
        self.networks.lock().unwrap().clone()
    }

    /// Select best network to connect to given scanned results
    pub fn select_best_network(&self) -> Option<usize> {
        let scanned = self.scanned_networks.lock().unwrap();
        let networks = self.networks.lock().unwrap();

        // Score each configured network that matches a scanned AP
        let mut best: Option<(usize, i32)> = None;
        for (i, net) in networks.iter().enumerate() {
            if net.disabled { continue; }
            for ap in scanned.iter() {
                if ap.ssid == net.ssid && !ap.hidden {
                    let score = net.priority * 10 + ap.signal_dbm;
                    if best.map_or(true, |(_, s)| score > s) {
                        best = Some((i, score));
                    }
                }
            }
        }
        best.map(|(i, _)| i)
    }

    // ---- Connection lifecycle ----

    /// Begin connection sequence to a configured network index
    pub fn connect(&self, index: usize) -> Result<(), ConfigError> {
        let networks = self.networks.lock().unwrap();
        if index >= networks.len() {
            return Err(ConfigError::InvalidNetwork(index));
        }
        networks[index].validate()?;
        drop(networks);

        // Simulate state transitions
        {
            let mut status = self.status.lock().unwrap();
            status.state = WifiState::Authenticating;
            status.ssid = Some(networks_snapshot_ssid(self, index));
        }
        // In real impl: talk to wpa_supplicant control socket
        Ok(())
    }

    /// Mark connection as established (called after DHCP completes)
    pub fn mark_connected(&self, ssid: &str, bssid: &str, ip: &str, signal_dbm: i32) {
        let mut status = self.status.lock().unwrap();
        status.state = WifiState::Connected;
        status.ssid = Some(ssid.to_string());
        status.bssid = Some(bssid.to_string());
        status.ip_address = Some(ip.to_string());
        status.signal_dbm = Some(signal_dbm);
        status.connected_since_ms = Some(now_ms());
    }

    pub fn disconnect(&self) {
        let mut status = self.status.lock().unwrap();
        status.state = WifiState::Disconnected;
        status.ssid = None;
        status.bssid = None;
        status.ip_address = None;
        status.signal_dbm = None;
        status.connected_since_ms = None;
    }

    /// Simulate a connection failure
    pub fn mark_failed(&self, reason: &str) {
        let mut status = self.status.lock().unwrap();
        status.state = WifiState::Failed;
        let _ = reason; // logged in real impl
    }

    // ---- Scanning ----

    pub fn update_scan_results(&self, networks: Vec<WifiNetwork>) {
        *self.scanned_networks.lock().unwrap() = networks;
    }

    pub fn scanned_networks(&self) -> Vec<WifiNetwork> {
        self.scanned_networks.lock().unwrap().clone()
    }

    /// Networks sorted by signal strength (best first)
    pub fn best_scanned(&self) -> Vec<WifiNetwork> {
        let mut nets = self.scanned_networks();
        nets.sort_by(|a, b| b.signal_dbm.cmp(&a.signal_dbm));
        nets
    }

    // ---- Status ----

    pub fn status(&self) -> WifiStatus {
        self.status.lock().unwrap().clone()
    }

    /// Generate wpa_supplicant.conf content
    pub fn generate_config(&self) -> String {
        let mut out = String::new();
        out.push_str("# SigmaOS wpa_supplicant configuration\n\n");
        out.push_str(&format!("ctrl_interface=/run/wpa_supplicant\n"));
        out.push_str(&format!("update_config=1\n"));
        out.push_str(&format!("country=US\n\n"));

        for (i, net) in self.networks.lock().unwrap().iter().enumerate() {
            out.push_str(&format!("network={{\n"));
            out.push_str(&format!("    ssid=\"{}\"\n", net.ssid));
            if net.scan_ssid {
                out.push_str("    scan_ssid=1\n");
            }
            if net.priority != 0 {
                out.push_str(&format!("    priority={}\n", net.priority));
            }
            if net.disabled {
                out.push_str("    disabled=1\n");
            }
            if let Some(km) = net.key_mgmt {
                out.push_str(&format!("    key_mgmt={}\n", km.as_str()));
            }
            if let Some(psk) = &net.psk {
                out.push_str(&format!("    psk=\"{}\"\n", psk));
            }
            if let Some(proto) = &net.proto {
                out.push_str(&format!("    proto={}\n", proto));
            }
            if let Some(pairwise) = &net.pairwise {
                out.push_str(&format!("    pairwise={}\n", pairwise));
            }
            if let Some(group) = &net.group {
                out.push_str(&format!("    group={}\n", group));
            }
            if let Some(eap) = net.eap_method {
                out.push_str(&format!("    eap={}\n", eap.as_str()));
            }
            if let Some(p2) = net.phase2_method {
                out.push_str(&format!("    phase2=\"auth={}\"\n", p2.as_str()));
            }
            if let Some(id) = &net.identity {
                out.push_str(&format!("    identity=\"{}\"\n", id));
            }
            if let Some(pw) = &net.password {
                out.push_str(&format!("    password=\"{}\"\n", pw));
            }
            if let Some(ca) = &net.ca_cert {
                out.push_str(&format!("    ca_cert=\"{}\"\n", ca));
            }
            let _ = i;
            out.push_str("}\n\n");
        }
        out
    }
}

fn networks_snapshot_ssid(_w: &WpaSupplicant, index: usize) -> String {
    // Helper to avoid holding lock across status update
    _w.networks.lock().unwrap()
        .get(index)
        .map(|n| n.ssid.clone())
        .unwrap_or_default()
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

// ============================================================================
// ERRORS
// ============================================================================

#[derive(Debug)]
pub enum ConfigError {
    MissingField(String),
    InvalidNetwork(usize),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "missing required field: {}", field),
            Self::InvalidNetwork(i) => write!(f, "invalid network index: {}", i),
        }
    }
}
impl std::error::Error for ConfigError {}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wpa2_psk_config() {
        let net = NetworkConfig::wpa2_psk("MyWiFi", "password123");
        assert!(net.validate().is_ok());
        assert_eq!(net.key_mgmt, Some(SecurityProtocol::RsnPsk));
    }

    #[test]
    fn test_open_network() {
        let net = NetworkConfig::open("FreeWiFi");
        assert!(net.validate().is_ok());
    }

    #[test]
    fn test_enterprise_config() {
        let net = NetworkConfig::enterprise_peap("CorpWiFi", "user@corp.com", "secret");
        assert!(net.validate().is_ok());
        assert_eq!(net.eap_method, Some(EapMethod::Peap));
        assert_eq!(net.phase2_method, Some(Phase2Method::MsChapV2));
    }

    #[test]
    fn test_validation_missing_psk() {
        let mut net = NetworkConfig::new("TestNet");
        net.key_mgmt = Some(SecurityProtocol::RsnPsk);
        assert!(net.validate().is_err());
    }

    #[test]
    fn test_signal_quality() {
        let mut net = WifiNetwork {
            ssid: "test".into(), bssid: "aa:bb".into(),
            signal_dbm: -50, frequency_mhz: 2412, channel: 1,
            security: SecurityProtocol::RsnPsk, hidden: false,
            wpa_flags: 0, rsn_flags: 0,
        };
        assert!(net.signal_quality() > 50);
        net.signal_dbm = -90;
        assert!(net.signal_quality() < 30);
    }

    #[test]
    fn test_select_best_network() {
        let wpa = WpaSupplicant::new("wlan0");
        wpa.add_network(NetworkConfig::wpa2_psk("NetA", "pass")).unwrap();
        wpa.add_network(NetworkConfig::wpa2_psk("NetB", "pass")).unwrap();

        wpa.update_scan_results(vec![
            WifiNetwork {
                ssid: "NetA".into(), bssid: "aa".into(), signal_dbm: -80,
                frequency_mhz: 2412, channel: 1, security: SecurityProtocol::RsnPsk,
                hidden: false, wpa_flags: 0, rsn_flags: 0,
            },
            WifiNetwork {
                ssid: "NetB".into(), bssid: "bb".into(), signal_dbm: -50,
                frequency_mhz: 5180, channel: 36, security: SecurityProtocol::RsnPsk,
                hidden: false, wpa_flags: 0, rsn_flags: 0,
            },
        ]);

        let best = wpa.select_best_network().unwrap();
        assert_eq!(best, 1); // NetB has stronger signal
    }

    #[test]
    fn test_connect_and_status() {
        let wpa = WpaSupplicant::new("wlan0");
        wpa.add_network(NetworkConfig::wpa2_psk("HomeNet", "pass")).unwrap();
        wpa.connect(0).unwrap();
        assert_eq!(wpa.status().state, WifiState::Authenticating);
        wpa.mark_connected("HomeNet", "aa:bb:cc", "192.168.1.10", -55);
        assert!(wpa.status().state.is_connected());
        wpa.disconnect();
        assert_eq!(wpa.status().state, WifiState::Disconnected);
    }

    #[test]
    fn test_generate_config() {
        let wpa = WpaSupplicant::new("wlan0");
        wpa.add_network(NetworkConfig::wpa2_psk("HomeNet", "secret123")).unwrap();
        let conf = wpa.generate_config();
        assert!(conf.contains("ssid=\"HomeNet\""));
        assert!(conf.contains("psk=\"secret123\""));
        assert!(conf.contains("key_mgmt=RSN-PSK"));
    }
}

// ============================================================================
// COMPONENT ENTRY POINT
// ============================================================================

/// Top-level component handle for the SigmaOS component framework.
pub struct Component {
    inner: WpaSupplicant,
}

impl std::fmt::Debug for Component {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Component").finish_non_exhaustive()
    }
}

impl Default for Component {
    fn default() -> Self { Self::new() }
}

impl Component {
    pub fn new() -> Self {
        Self { inner: WpaSupplicant::new("wlan0") }
    }

    pub fn supplicant(&self) -> &WpaSupplicant {
        &self.inner
    }
}
