use eframe::egui;
use std::path::Path;
use std::time::Instant;
use serde::{Deserialize, Serialize};
use std::fs;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use ring::pbkdf2;
use std::num::NonZeroU32;
use num_bigint::BigUint;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use rand::seq::SliceRandom;
use rfd;

type HmacSha256 = Hmac<Sha256>;
type AesCbcDec = Decryptor<Aes256>;
type AesCbcEnc = Encryptor<Aes256>;
type AesGcmCipher = Aes256Gcm;

const MAGIC_FILE_SEGRETO: &[u8; 4] = b"GC57";
const MAGIC_FILE_MESSAGGIO: &[u8; 4] = b"GCM7";
const VERSION_FILE_MESSAGGIO: u8 = 0x02;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 700.0]),
        ..Default::default()
    };

    eframe::run_native(
        "GC57-3P * Programma Sicurezza",
        options,
        Box::new(|_cc| Box::new(AppPrincipale::new())),
    )
}

// ============================================================================
// CONFIG STRUCTURE
// ============================================================================

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Config {
    cartelle: Cartelle,
    dispositivi: Dispositivi,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Cartelle {
    invio: String,
    ricezione: String,
    allegati: String,
    database: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Dispositivi {
    nome_pendrive: String,
}

impl Config {
    const CONFIG_FILE: &'static str = "GC57-3P.cfg";

    fn load_from_file() -> Result<Self, String> {
        let content = fs::read_to_string(Self::CONFIG_FILE)
            .map_err(|e| format!("Impossibile leggere file: {}", e))?;
        
        serde_json::from_str(&content)
            .map_err(|e| format!("JSON non valido: {}", e))
    }

    fn save_to_file(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Errore serializzazione: {}", e))?;
        
        fs::write(Self::CONFIG_FILE, json)
            .map_err(|e| format!("Errore salvataggio: {}", e))?;
        
        Ok(())
    }

    fn default() -> Self {
        Config {
            cartelle: Cartelle {
                invio: String::new(),
                ricezione: String::new(),
                allegati: String::new(),
                database: String::new(),
            },
            dispositivi: Dispositivi {
                nome_pendrive: String::new(),
            },
        }
    }
}

// ============================================================================
// DECIFRATURA FILE SEGRETO
// ============================================================================

#[derive(Clone, Debug)]
struct ComplessitaConfig {
    iterazioni: u32,
}

fn get_complessita_config(complessita: u8) -> Result<ComplessitaConfig, String> {
    match complessita {
        0 => Ok(ComplessitaConfig { iterazioni: 250_000 }),
        1 => Ok(ComplessitaConfig { iterazioni: 500_000 }),
        2 => Ok(ComplessitaConfig { iterazioni: 1_000_000 }),
        3 => Ok(ComplessitaConfig { iterazioni: 5_000_000 }),
        _ => Err(format!("Complessita non valida: {}", complessita)),
    }
}

fn deriva_chiave_aes_256(password: &str, config: ComplessitaConfig) -> [u8; 32] {
    let salt = b"Mio_Salt_Personale_2024";
    let mut derivata = [0u8; 32];
    
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(config.iterazioni).unwrap(),
        salt,
        password.as_bytes(),
        &mut derivata,
    );
    
    derivata
}

fn bytes_to_biguint(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

#[derive(Clone, Debug)]
struct DatiDecifratiGC57 {
    c: BigUint,
    b: BigUint,
    e: u64,
}

fn decifera_file_segreto(
    dati_binari: &[u8],
    password: &str,
) -> Result<DatiDecifratiGC57, String> {
    // 1. Verifica magic number
    if dati_binari.len() < 6 {
        return Err("File troppo piccolo".to_string());
    }

    if &dati_binari[0..4] != MAGIC_FILE_SEGRETO {
        return Err("Magic number non valido".to_string());
    }

    // 2. Leggi version e complessita
    let version = dati_binari[4];
    let complessita = dati_binari[5];

    if version != 0x01 {
        return Err(format!("Version non supportata: {}", version));
    }

    // 3. Estrai configurazione
    let config = get_complessita_config(complessita)?;

    // 4. Estrai IV (16 bytes)
    if dati_binari.len() < 22 {
        return Err("File troppo piccolo per IV".to_string());
    }
    let iv = &dati_binari[6..22];

    // 5. Separa ciphertext e HMAC
    if dati_binari.len() < 54 {
        return Err("File troppo piccolo per HMAC".to_string());
    }
    let ciphertext = &dati_binari[22..dati_binari.len() - 32];
    let hmac_ricevuto = &dati_binari[dati_binari.len() - 32..];

    // 6. Deriva chiave AES dalla password
    let chiave_aes = deriva_chiave_aes_256(password, config);

    // 7. Verifica HMAC (integrità)
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(&chiave_aes)
        .map_err(|e| format!("Errore HMAC: {}", e))?;
    hmac.update(iv);
    hmac.update(ciphertext);
    
    if hmac.verify_slice(hmac_ricevuto).is_err() {
        return Err("Password errata - HMAC non valido".to_string());
    }

    // 8. Decifra con AES-256-CBC
    let iv_array: [u8; 16] = iv.try_into()
        .map_err(|_| "Errore conversione IV".to_string())?;
    
    let key_array: [u8; 32] = chiave_aes;
    let mut payload_padded = ciphertext.to_vec();
    let payload = AesCbcDec::new((&key_array).into(), (&iv_array).into())
        .decrypt_padded_mut::<Pkcs7>(&mut payload_padded)
        .map_err(|e| format!("Errore decifratura: {}", e))?;

    // 9. ESTRAI I DATI DAL PAYLOAD DECIFRATO
    let mut offset;

    // Leggi lunghezza di C (4 bytes)
    if payload.len() < 4 {
        return Err("Errore: payload troppo piccolo per C_len".to_string());
    }
    let c_len = u32::from_be_bytes([
        payload[0],
        payload[1],
        payload[2],
        payload[3],
    ]) as usize;
    offset = 4;

    // Leggi C
    if payload.len() < offset + c_len {
        return Err("Errore: payload troppo piccolo per C".to_string());
    }
    let c_bytes = &payload[offset..offset + c_len];
    let c = bytes_to_biguint(c_bytes);
    offset = offset + c_len;

    // Leggi lunghezza di B (4 bytes)
    if payload.len() < offset + 4 {
        return Err("Errore: payload troppo piccolo per B_len".to_string());
    }
    let b_len = u32::from_be_bytes([
        payload[offset],
        payload[offset + 1],
        payload[offset + 2],
        payload[offset + 3],
    ]) as usize;
    offset = offset + 4;

    // Leggi B
    if payload.len() < offset + b_len {
        return Err("Errore: payload troppo piccolo per B".to_string());
    }
    let b_bytes = &payload[offset..offset + b_len];
    let b = bytes_to_biguint(b_bytes);
    offset = offset + b_len;

    // Leggi E (8 bytes, u64)
    if payload.len() < offset + 8 {
        return Err("Errore: payload troppo piccolo per E".to_string());
    }
    let e = u64::from_be_bytes([
        payload[offset],
        payload[offset + 1],
        payload[offset + 2],
        payload[offset + 3],
        payload[offset + 4],
        payload[offset + 5],
        payload[offset + 6],
        payload[offset + 7],
    ]);

    Ok(DatiDecifratiGC57 { c, b, e })
}

// ============================================================================
// MAIN APP STATE
// ============================================================================

#[derive(PartialEq)]
enum StatoApp {
    Configurazione,
    AttesaChiavetta,
    VerificaPassword,
    Cripta,
}

struct AppPrincipale {
    stato: StatoApp,
    config: Option<Config>,

    // Configurazione
    invio: String,
    ricezione: String,
    allegati: String,
    database: String,
    nome_pendrive: String,
    messaggi_config: Vec<(String, bool)>,

    // Attesa chiavetta
    chiavetta_rilevata: bool,
    ultimo_check_chiavetta: Instant,
    drive_chiavetta: Option<String>,

    // Password
    password: String,
    messaggi_password: Vec<(String, bool)>,
    password_verificata: bool,

    // Dati estratti dal file segreto
    dati_segreto: Option<DatiSegreto>,
    dati_criptazione: Option<DatiCriptazione>,
    semiprimi_cache: Option<Vec<BigUint>>,

    // CRIPTA APP
    codice_utente: String,
    seed_manuale: String,
    messaggio: String,
    allegati_selezionati: Vec<std::path::PathBuf>,
    cartella_allegati: String,
    messaggio_errore: String,
}

#[derive(Clone, Debug)]
struct DatiSegreto {
    c: BigUint,
    b: BigUint,
    e: u64,
}

#[derive(Clone, Debug)]
struct DatiCriptazione {
    k: BigUint,
    chiave_k: [u8; 32],
    chiave_q: [u8; 32],
}

#[derive(Clone, Debug)]
struct FileMessaggioCriptato {
    s1: BigUint,
    nonce_q: [u8; 12],
    blob_q: Vec<u8>,
    nonce_k: [u8; 12],
    blob_k: Vec<u8>,
}

impl Default for AppPrincipale {
    fn default() -> Self {
        Self::new()
    }
}

impl AppPrincipale {
    fn new() -> Self {
        let (stato, config) = if Path::new(Config::CONFIG_FILE).exists() {
            match Config::load_from_file() {
                Ok(cfg) => (StatoApp::AttesaChiavetta, Some(cfg)),
                Err(_) => (StatoApp::Configurazione, None),
            }
        } else {
            (StatoApp::Configurazione, None)
        };

        AppPrincipale {
            stato,
            config,
            invio: String::new(),
            ricezione: String::new(),
            allegati: String::new(),
            database: String::new(),
            nome_pendrive: String::new(),
            messaggi_config: Vec::new(),
            chiavetta_rilevata: false,
            ultimo_check_chiavetta: Instant::now(),
            drive_chiavetta: None,
            password: String::new(),
            messaggi_password: Vec::new(),
            password_verificata: false,
            dati_segreto: None,
            dati_criptazione: None,
            semiprimi_cache: None,
            codice_utente: String::new(),
            seed_manuale: String::new(),
            messaggio: String::new(),
            allegati_selezionati: Vec::new(),
            cartella_allegati: String::new(),
            messaggio_errore: String::new(),
        }
    }
}

impl eframe::App for AppPrincipale {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        match self.stato {
            StatoApp::Configurazione => {
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize([800.0, 700.0].into()));
            }
            StatoApp::AttesaChiavetta => {
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize([500.0, 350.0].into()));
            }
            StatoApp::VerificaPassword => {
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize([500.0, 300.0].into()));
            }
            StatoApp::Cripta => {
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize([900.0, 750.0].into()));
            }
        }

        match self.stato {
            StatoApp::Configurazione => self.mostra_configurazione(ctx),
            StatoApp::AttesaChiavetta => self.mostra_attesa_chiavetta(ctx),
            StatoApp::VerificaPassword => self.mostra_verifica_password(ctx),
            StatoApp::Cripta => self.mostra_cripta(ctx),
        }
    }
}

// ============================================================================
// STEP 1: CONFIGURAZIONE
// ============================================================================

impl AppPrincipale {
    fn mostra_configurazione(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🔐 GC57-3P - Configurazione Iniziale");
            ui.separator();

            ui.label("ℹ️ Inserisci i percorsi delle cartelle e il nome della chiavetta USB:");
            ui.separator();

            ui.label("📁 Cartella INVIO (file criptati creati):");
            ui.text_edit_singleline(&mut self.invio);

            ui.label("📁 Cartella RICEZIONE (file criptati ricevuti):");
            ui.text_edit_singleline(&mut self.ricezione);

            ui.label("📁 Cartella ALLEGATI (allegati ricevuti):");
            ui.text_edit_singleline(&mut self.allegati);

            ui.label("📁 Cartella DATABASE (database_sicurezza.txt):");
            ui.text_edit_singleline(&mut self.database);

            ui.label("💾 Nome Chiavetta USB:");
            ui.text_edit_singleline(&mut self.nome_pendrive);

            ui.separator();

            if ui.button("💾 Salva Configurazione").clicked() {
                self.salva_configurazione();
            }

            for (msg, è_errore) in &self.messaggi_config {
                let colore = if *è_errore {
                    egui::Color32::RED
                } else {
                    egui::Color32::BLACK
                };
                ui.colored_label(colore, msg);
            }
        });
    }

    fn salva_configurazione(&mut self) {
        self.messaggi_config.clear();

        if self.invio.trim().is_empty() || !Path::new(self.invio.trim()).exists() {
            self.messaggi_config
                .push(("❌ Cartella INVIO non valida".to_string(), true));
            return;
        }

        if self.ricezione.trim().is_empty() || !Path::new(self.ricezione.trim()).exists() {
            self.messaggi_config
                .push(("❌ Cartella RICEZIONE non valida".to_string(), true));
            return;
        }

        if self.allegati.trim().is_empty() || !Path::new(self.allegati.trim()).exists() {
            self.messaggi_config
                .push(("❌ Cartella ALLEGATI non valida".to_string(), true));
            return;
        }

        if self.database.trim().is_empty() || !Path::new(self.database.trim()).is_dir() {
            self.messaggi_config
                .push(("❌ Cartella DATABASE non valida".to_string(), true));
            return;
        }

        if self.nome_pendrive.trim().is_empty() {
            self.messaggi_config
                .push(("❌ Nome Chiavetta non può essere vuoto".to_string(), true));
            return;
        }

        let config = Config {
            cartelle: Cartelle {
                invio: self.invio.trim().to_string(),
                ricezione: self.ricezione.trim().to_string(),
                allegati: self.allegati.trim().to_string(),
                database: Path::new(self.database.trim())
                    .join("database_sicurezza.txt")
                    .to_string_lossy()
                    .into_owned(),
            },
            dispositivi: Dispositivi {
                nome_pendrive: self.nome_pendrive.trim().to_uppercase(),
            },
        };

        match config.save_to_file() {
            Ok(_) => {
                self.messaggi_config
                    .push(("✓ Configurazione salvata!".to_string(), false));
                self.config = Some(config);
                // Il database potrebbe essere cambiato: invalida cache semiprimi.
                self.semiprimi_cache = None;
                self.stato = StatoApp::AttesaChiavetta;
            }
            Err(e) => {
                self.messaggi_config
                    .push((format!("❌ Errore: {}", e), true));
            }
        }
    }
}

// ============================================================================
// STEP 2: ATTESA CHIAVETTA
// ============================================================================

#[cfg(target_os = "windows")]
fn trova_usb_con_nome(nome_volume: &str) -> Option<String> {
    use winapi::um::fileapi::GetVolumeInformationW;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    if nome_volume.is_empty() {
        return None;
    }

    for drive_letter in b'D'..=b'Z' {
        let drive = format!("{}:\\", drive_letter as char);

        let mut label_buffer = [0u16; 32];
        let mut serial = 0u32;
        let mut max_component = 0u32;
        let mut flags = 0u32;

        let drive_wide: Vec<u16> = OsStr::new(&drive)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            if GetVolumeInformationW(
                drive_wide.as_ptr(),
                &mut label_buffer[0],
                32,
                &mut serial,
                &mut max_component,
                &mut flags,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                let label = String::from_utf16_lossy(&label_buffer)
                    .trim_end_matches('\0')
                    .to_string();

                if label.to_uppercase() == nome_volume.to_uppercase() {
                    return Some(drive);
                }
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn trova_usb_con_nome(nome_volume: &str) -> Option<String> {
    if nome_volume.is_empty() {
        return None;
    }

    let mount_paths = ["/media", "/mnt"];

    for mount_path in &mount_paths {
        if let Ok(entries) = fs::read_dir(mount_path) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if let Some(folder_name) = path.file_name() {
                        if let Some(name_str) = folder_name.to_str() {
                            if name_str.to_uppercase() == nome_volume.to_uppercase() {
                                return Some(path.to_string_lossy().to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn trova_usb_con_nome(nome_volume: &str) -> Option<String> {
    if nome_volume.is_empty() {
        return None;
    }

    if let Ok(entries) = fs::read_dir("/Volumes") {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if let Some(folder_name) = path.file_name() {
                    if let Some(name_str) = folder_name.to_str() {
                        if name_str.to_uppercase() == nome_volume.to_uppercase() {
                            return Some(path.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }
    }

    None
}

impl AppPrincipale {
    fn mostra_attesa_chiavetta(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(30.0);

            ui.label(
                egui::RichText::new("🔌 Chiavetta USB Richiesta")
                    .size(28.0)
                    .strong()
                    .color(egui::Color32::BLUE),
            );

            ui.add_space(20.0);

            if let Some(cfg) = &self.config {
                ui.label(
                    egui::RichText::new(format!(
                        "Inserisci la chiavetta USB denominata:\n\n\"{}\"",
                        cfg.dispositivi.nome_pendrive
                    ))
                    .size(16.0)
                    .color(egui::Color32::BLACK),
                );
            }

            ui.add_space(30.0);

            if self.ultimo_check_chiavetta.elapsed().as_secs() >= 1 {
                if let Some(cfg) = &self.config {
                    if let Some(drive) = trova_usb_con_nome(&cfg.dispositivi.nome_pendrive) {
                        self.chiavetta_rilevata = true;
                        self.drive_chiavetta = Some(drive);
                    } else {
                        self.chiavetta_rilevata = false;
                        self.drive_chiavetta = None;
                    }
                }
                self.ultimo_check_chiavetta = Instant::now();
            }

            ui.horizontal(|ui| {
                if self.chiavetta_rilevata {
                    ui.colored_label(egui::Color32::BLACK, "✓ Chiavetta rilevata!");
                } else {
                    ui.colored_label(egui::Color32::YELLOW, "⏳ In attesa della chiavetta...");
                }
            });

            ui.add_space(30.0);

            ui.horizontal(|ui| {
                if ui.button("✓ Prosegui").clicked() {
                    self.verifica_file_segreto();
                }

                if ui.button("✗ Esci").clicked() {
                    std::process::exit(1);
                }
            });
        });
    }

    fn verifica_file_segreto(&mut self) {
        if !self.chiavetta_rilevata {
            return;
        }

        if let Some(drive) = &self.drive_chiavetta {
            let file_segreto = format!("{}File_Segreto_GC57.dat", drive);

            if Path::new(&file_segreto).exists() {
                self.stato = StatoApp::VerificaPassword;
                self.password.clear();
                self.messaggi_password.clear();
                self.password_verificata = false;
            } else {
                self.messaggi_password
                    .push(("❌ ERRORE: File_Segreto_GC57.dat non trovato!".to_string(), true));
            }
        }
    }
}

// ============================================================================
// STEP 3: VERIFICA PASSWORD
// ============================================================================

impl AppPrincipale {
    fn mostra_verifica_password(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(30.0);

            ui.label(
                egui::RichText::new("🔐 Verifica Password")
                    .size(28.0)
                    .strong()
                    .color(egui::Color32::BLUE),
            );

            ui.add_space(20.0);

            ui.label("Inserisci la password per accedere al file segreto:");

            ui.text_edit_singleline(&mut self.password);

            ui.add_space(20.0);

            if ui.button("Verifica Password").clicked() {
                self.verifica_password();
            }

            if ui.button("✗ Esci").clicked() {
                std::process::exit(1);
            }

            ui.add_space(20.0);

            for (msg, è_errore) in &self.messaggi_password {
                let colore = if *è_errore {
                    egui::Color32::RED
                } else {
                    egui::Color32::BLACK
                };
                ui.colored_label(colore, msg);
            }
        });
    }

    fn verifica_password(&mut self) {
        self.messaggi_password.clear();

        if self.password.trim().is_empty() {
            self.messaggi_password
                .push(("❌ Password non può essere vuota".to_string(), true));
            return;
        }

        if let Some(drive) = &self.drive_chiavetta {
            let file_segreto = format!("{}File_Segreto_GC57.dat", drive);

            if !Path::new(&file_segreto).exists() {
                self.messaggi_password
                    .push(("❌ File segreto non trovato!".to_string(), true));
                return;
            }

            // Leggi il file binario
            match fs::read(&file_segreto) {
                Ok(dati_binari) => {
                    // Decifra con la password inserita
                    match decifera_file_segreto(&dati_binari, self.password.trim()) {
                        Ok(dati_decifrati) => {
                            self.password_verificata = true;
                            self.messaggi_password
                                .push(("✓ Password corretta!".to_string(), false));

                            // Popola DatiSegreto
                            self.dati_segreto = Some(DatiSegreto {
                                c: dati_decifrati.c,
                                b: dati_decifrati.b,
                                e: dati_decifrati.e,
                            });

                            // Passa all'interfaccia di criptazione
                            self.stato = StatoApp::Cripta;
                        }
                        Err(e) => {
                            self.messaggi_password
                                .push((format!("❌ {}", e), true));
                        }
                    }
                }
                Err(e) => {
                    self.messaggi_password
                        .push((format!("❌ Errore lettura file: {}", e), true));
                }
            }
        }
    }
}

// ============================================================================
// STEP 4: INTERFACCIA CRIPTA
// ============================================================================

impl AppPrincipale {
    fn mostra_cripta(&mut self, ctx: &egui::Context) {
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.label(
            egui::RichText::new("🔐 GC57-3P * Programma Sicurezza")
                .color(egui::Color32::BROWN)
                .family(egui::FontFamily::Monospace)
                .size(28.0)
                .strong(),
        );

        ui.separator();

        ui.colored_label(egui::Color32::BLACK, "👤 Codice Utente:");
        ui.add(
            egui::TextEdit::singleline(&mut self.codice_utente)
                .hint_text("Inserisci codice utente")
                .interactive(self.password_verificata),
        );

        ui.colored_label(egui::Color32::BLACK, "🌱 Seed Manuale:");
        ui.add(
            egui::TextEdit::singleline(&mut self.seed_manuale)
                .hint_text("Inserisci seed manuale")
                .interactive(self.password_verificata),
        );

        ui.separator();

        ui.colored_label(egui::Color32::BLACK, "📝 Scrivi il messaggio:");
        egui::TextEdit::multiline(&mut self.messaggio)
            .desired_rows(15)
            .desired_width(f32::INFINITY)
            .interactive(self.password_verificata)
            .show(ui);

        ui.separator();

        ui.horizontal(|ui| {
            // COLONNA SINISTRA: ALLEGATI
            ui.vertical(|ui| {
                ui.set_width(300.0);
                ui.label("📎 Allegati:");

                if ui.button("📁 Carica Allegati").clicked() {
                    if self.password_verificata {
                        self.apri_cartella_allegati();
                    } else {
                        self.messaggio_errore = "❌ Inserisci prima la password".to_string();
                    }
                }

                ui.separator();

                // Visualizza l'ultimo allegato caricato (solo lettura)
                if let Some(allegato) = self.allegati_selezionati.last() {
                    let nome = allegato
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    ui.colored_label(egui::Color32::BLACK, format!("✓ {}", nome));
                } else {
                    ui.colored_label(egui::Color32::GRAY, "(nessun file)");
                }
            });

            ui.separator();

            // COLONNA DESTRA: AZIONI
            ui.vertical(|ui| {
                ui.colored_label(egui::Color32::BLUE, "⚙️ Azioni:");

                if ui.button("🔒 Criptazione").clicked() {
                    if self.password_verificata {
                        self.cripta_messaggio();
                    } else {
                        self.messaggio_errore = "❌ Inserisci prima la password".to_string();
                    }
                }

                if ui.button("🔓 Decriptazione").clicked() {
                    if self.password_verificata {
                        self.decripta_messaggio();
                    } else {
                        self.messaggio_errore = "❌ Inserisci prima la password".to_string();
                    }
                }

                ui.separator();

                if ui.button("❌ Cancella Tutto").clicked() {
                    self.codice_utente.clear();
                    self.seed_manuale.clear();
                    self.messaggio.clear();
                    self.allegati_selezionati.clear();
                    self.messaggio_errore.clear();
                }

                if ui.button("🚪 Logout").clicked() {
                    self.password.clear();
                    self.password_verificata = false;
                    self.codice_utente.clear();
                    self.seed_manuale.clear();
                    self.messaggio.clear();
                    self.allegati_selezionati.clear();
                    self.messaggio_errore.clear();
                    self.stato = StatoApp::AttesaChiavetta;
                }
            });
        });

        ui.separator();

        if let Some(dati) = &self.dati_segreto {
            ui.colored_label(egui::Color32::BLACK, "🔑 Dati Caricati:");
            ui.label(format!("c (B-1): {} bits", dati.c.bits()));
            ui.label(format!("b (base): {} bits", dati.b.bits()));
            ui.label(format!("e (esponente): {}", dati.e));
            ui.separator();
        }

        if !self.messaggio_errore.is_empty() {
            let colore = if self.messaggio_errore.contains("✓") {
                egui::Color32::BLACK
            } else {
                egui::Color32::RED
            };
            ui.colored_label(colore, &self.messaggio_errore);
        }
    });
}

fn apri_cartella_allegati(&mut self) {
    let file = rfd::FileDialog::new()
        .set_directory(self.get_documenti_path())
        .pick_file();

    if let Some(percorso) = file {
        match std::fs::read(&percorso) {
            Ok(_contenuto) => {
                // Aggiungi il file ai selezionati
                self.allegati_selezionati.push(percorso.clone());
                
                let nome_file = percorso
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                
                self.messaggio_errore = format!("✓ File caricato: {}", nome_file);
            }
            Err(e) => {
                self.messaggio_errore = format!("❌ Errore lettura file: {}", e);
            }
        }
    }
}

fn get_documenti_path(&self) -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(home) = std::env::var("USERPROFILE") {
            return std::path::PathBuf::from(format!("{}\\Documents", home));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return std::path::PathBuf::from(format!("{}/Documents", home));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return std::path::PathBuf::from(format!("{}/Documents", home));
        }
    }

    std::path::PathBuf::from(".")
 }
     
 
fn leggi_semiprimo_da_database(&self) -> Result<BigUint, String> {
    let semiprimi = self
        .semiprimi_cache
        .as_ref()
        .ok_or("❌ Cache database non inizializzata".to_string())?;

    if semiprimi.is_empty() {
        return Err("❌ Database vuoto o senza semiprimi validi".to_string());
    }

    let mut rng = rand::thread_rng();
    semiprimi
        .choose(&mut rng)
        .cloned()
        .ok_or("❌ Impossibile selezionare un semiprimo".to_string())
}

fn carica_semiprimi_cache(&mut self) -> Result<(), String> {
    if self.semiprimi_cache.is_some() {
        return Ok(());
    }

    let cfg = self
        .config
        .as_ref()
        .ok_or("❌ Configurazione non caricata".to_string())?;

    let contenuto = std::fs::read_to_string(&cfg.cartelle.database)
        .map_err(|e| format!("❌ Errore lettura database: {}", e))?;

    let semiprimi: Vec<BigUint> = contenuto
        .lines()
        .map(str::trim)
        .filter(|riga| !riga.is_empty())
        .filter_map(|riga| BigUint::parse_bytes(riga.as_bytes(), 10))
        .collect();

    if semiprimi.is_empty() {
        return Err("❌ Database vuoto o senza semiprimi validi".to_string());
    }

    self.semiprimi_cache = Some(semiprimi);
    Ok(())
}

fn gcd(a: BigUint, b: BigUint) -> BigUint {
    let mut a = a;
    let mut b = b;

    while b != BigUint::from(0u8) {
        let temp = b.clone();
        b = a % b;
        a = temp;
    }

    a
}

fn genera_k_da_seed(&self, b: &BigUint, e: u64) -> Result<BigUint, String> {
    if self.seed_manuale.trim().is_empty() {
        return Err("❌ Inserisci il seed manuale".to_string());
    }

    Self::genera_k_da_seed_testo(self.seed_manuale.trim(), b, e)
}

fn genera_k_da_seed_testo(seed_text: &str, b: &BigUint, e: u64) -> Result<BigUint, String> {
    if e < 1 {
        return Err("❌ Esponente non valido: deve essere >= 1".to_string());
    }

    let seed: u64 = seed_text
        .trim()
        .parse()
        .map_err(|_| "❌ Seed manuale non valido (usa un numero intero)".to_string())?;

    let basso_exp: u32 = (e - 1)
        .try_into()
        .map_err(|_| "❌ Esponente troppo grande".to_string())?;
    let alto_exp: u32 = e
        .try_into()
        .map_err(|_| "❌ Esponente troppo grande".to_string())?;

    let low = b.pow(basso_exp);
    let high = b.pow(alto_exp);

    if high <= low {
        return Err("❌ Range di generazione k non valido".to_string());
    }

    let mut rng = StdRng::seed_from_u64(seed);

    // Stessa logica del main veloce: offset piccolo e deterministico da seme.
    let span = &high - &low;
    let random_offset = BigUint::from(rng.next_u64()) % span;

    Ok(low + random_offset)
}

fn decifra_aes256_cbc(chiave: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let mut payload_padded = ciphertext.to_vec();
    let payload = AesCbcDec::new(chiave.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut payload_padded)
        .map_err(|e| format!("❌ Errore decifratura AES: {}", e))?;
    Ok(payload.to_vec())
}

fn cifra_aes256_gcm(chiave: &[u8; 32], plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>), String> {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = AesGcmCipher::new_from_slice(chiave)
        .map_err(|e| format!("❌ Errore inizializzazione AES-GCM: {}", e))?;

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| "❌ Errore cifratura AES-GCM".to_string())?;

    Ok((nonce, ciphertext))
}

fn decifra_aes256_gcm(chiave: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = AesGcmCipher::new_from_slice(chiave)
        .map_err(|e| format!("❌ Errore inizializzazione AES-GCM: {}", e))?;

    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| "❌ Errore decifratura AES-GCM (tag non valido o dati manomessi)".to_string())
}

fn calcola_hash_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn sanitizza_nome_allegato(nome: &str) -> Result<String, String> {
    let nome = nome.trim();
    if nome.is_empty() {
        return Err("❌ Nome allegato vuoto".to_string());
    }

    let path = Path::new(nome);
    if path.components().count() != 1 {
        return Err("❌ Nome allegato non valido (path traversal bloccato)".to_string());
    }

    let base = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("❌ Nome allegato non valido".to_string())?;

    if base == "." || base == ".." {
        return Err("❌ Nome allegato non valido".to_string());
    }

    Ok(base.to_string())
}

fn leggi_len_prefixed(payload: &[u8], offset: &mut usize) -> Result<Vec<u8>, String> {
    if payload.len() < *offset + 4 {
        return Err("❌ Payload corrotto: lunghezza campo mancante".to_string());
    }

    let len = u32::from_be_bytes([
        payload[*offset],
        payload[*offset + 1],
        payload[*offset + 2],
        payload[*offset + 3],
    ]) as usize;
    *offset += 4;

    if payload.len() < *offset + len {
        return Err("❌ Payload corrotto: campo incompleto".to_string());
    }

    let campo = payload[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(campo)
}

fn estrai_tutti_i_campi(payload: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut offset = 0usize;
    let mut campi = Vec::new();

    while offset < payload.len() {
        campi.push(Self::leggi_len_prefixed(payload, &mut offset)?);
    }

    Ok(campi)
}

fn parse_file_messaggio_criptato(dati: &[u8]) -> Result<FileMessaggioCriptato, String> {
    if dati.len() < 5 {
        return Err("❌ File messaggio troppo piccolo".to_string());
    }

    if &dati[0..4] != MAGIC_FILE_MESSAGGIO {
        return Err("❌ Magic number messaggio non valido".to_string());
    }

    let version = dati[4];
    if version != VERSION_FILE_MESSAGGIO {
        return Err(format!("❌ Version file messaggio non supportata: {}", version));
    }

    let mut offset = 5usize;

    let s1_bytes = Self::leggi_len_prefixed(dati, &mut offset)?;
    let s1 = BigUint::from_bytes_be(&s1_bytes);

    if dati.len() < offset + 12 {
        return Err("❌ File corrotto: nonce prima porta mancante".to_string());
    }
    let nonce_q: [u8; 12] = dati[offset..offset + 12]
        .try_into()
        .map_err(|_| "❌ File corrotto: nonce prima porta non valido".to_string())?;
    offset += 12;
    let blob_q = Self::leggi_len_prefixed(dati, &mut offset)?;

    if dati.len() < offset + 12 {
        return Err("❌ File corrotto: nonce seconda porta mancante".to_string());
    }
    let nonce_k: [u8; 12] = dati[offset..offset + 12]
        .try_into()
        .map_err(|_| "❌ File corrotto: nonce seconda porta non valido".to_string())?;
    offset += 12;
    let blob_k = Self::leggi_len_prefixed(dati, &mut offset)?;

    if offset != dati.len() {
        return Err("❌ File corrotto: dati extra inattesi".to_string());
    }

    Ok(FileMessaggioCriptato {
        s1,
        nonce_q,
        blob_q,
        nonce_k,
        blob_k,
    })
}

fn deriva_chiave_aes_da_biguint(valore: &BigUint) -> [u8; 32] {
    let bytes = valore.to_bytes_be();
    let mut derivata = [0u8; 32];
    let salt = b"Chiavi_AES_2024";

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(100_000).unwrap(),
        salt,
        &bytes,
        &mut derivata,
    );

    derivata
}

fn append_len_prefixed(buffer: &mut Vec<u8>, data: &[u8]) -> Result<(), String> {
    let len = u32::try_from(data.len())
        .map_err(|_| "❌ Campo troppo grande da serializzare".to_string())?;
    buffer.extend_from_slice(&len.to_be_bytes());
    buffer.extend_from_slice(data);
    Ok(())
}

fn serializza_campi(campi: &[&[u8]]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for campo in campi {
        Self::append_len_prefixed(&mut out, campo)?;
    }
    Ok(out)
}

fn cifra_aes256_cbc(chiave: &[u8; 32], plaintext: &[u8]) -> Result<([u8; 16], Vec<u8>), String> {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let mut buffer = vec![0u8; plaintext.len() + 16];
    buffer[..plaintext.len()].copy_from_slice(plaintext);

    let ciphertext = AesCbcEnc::new(chiave.into(), (&iv).into())
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
        .map_err(|e| format!("❌ Errore cifratura AES: {}", e))?
        .to_vec();

    Ok((iv, ciphertext))
}

fn costruisci_file_criptato(
    &self,
    s1: &BigUint,
    dati_criptazione: &DatiCriptazione,
) -> Result<Vec<u8>, String> {
    let k_bytes = dati_criptazione.k.to_bytes_be();
    let seed_bytes = self.seed_manuale.trim().as_bytes();
    let codice_utente_bytes = self.codice_utente.trim().as_bytes();
    let messaggio_bytes = self.messaggio.as_bytes();

    let (nome_allegato, bytes_allegato) = if let Some(percorso) = self.allegati_selezionati.last() {
        let nome = percorso
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let contenuto = fs::read(percorso)
            .map_err(|e| format!("❌ Errore lettura allegato: {}", e))?;
        (nome.into_bytes(), contenuto)
    } else {
        (Vec::new(), Vec::new())
    };

    let payload_q = Self::serializza_campi(&[seed_bytes, codice_utente_bytes])?;
    let hash_allegato = if bytes_allegato.is_empty() {
        Vec::new()
    } else {
        Self::calcola_hash_sha256(&bytes_allegato)
    };

    let payload_k = Self::serializza_campi(&[
        k_bytes.as_slice(),
        messaggio_bytes,
        nome_allegato.as_slice(),
        hash_allegato.as_slice(),
        bytes_allegato.as_slice(),
    ])?;

    let (nonce_q, blob_q) = Self::cifra_aes256_gcm(&dati_criptazione.chiave_q, &payload_q)?;
    let (nonce_k, blob_k) = Self::cifra_aes256_gcm(&dati_criptazione.chiave_k, &payload_k)?;

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC_FILE_MESSAGGIO);
    out.push(VERSION_FILE_MESSAGGIO);

    let s1_bytes = s1.to_bytes_be();
    Self::append_len_prefixed(&mut out, &s1_bytes)?;

    out.extend_from_slice(&nonce_q);
    Self::append_len_prefixed(&mut out, &blob_q)?;

    out.extend_from_slice(&nonce_k);
    Self::append_len_prefixed(&mut out, &blob_k)?;

    Ok(out)
}

fn salva_file_criptato(&mut self, bytes_file: &[u8]) -> Result<std::path::PathBuf, String> {
    let cfg = self
        .config
        .as_ref()
        .ok_or("❌ Configurazione non caricata".to_string())?;

    let directory_iniziale = std::path::PathBuf::from(&cfg.cartelle.invio);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let nome_default = format!("GC57_Messaggio_{}.dat", timestamp);

    let path = rfd::FileDialog::new()
        .set_directory(&directory_iniziale)
        .set_file_name(&nome_default)
        .save_file()
        .ok_or("❌ Salvataggio annullato".to_string())?;

    fs::write(&path, bytes_file).map_err(|e| format!("❌ Errore scrittura file: {}", e))?;
    Ok(path)
}

fn genera_chiavi_aes(&mut self, s1: BigUint) -> Result<(), String> {
    let dati = self
        .dati_segreto
        .as_ref()
        .ok_or("❌ Dati segreto non caricati".to_string())?;

    let c = dati.c.clone();
    let b = dati.b.clone();
    let e = dati.e;

    // S = S1 - c
    let s = if s1 > c {
        s1.clone() - c.clone()
    } else {
        return Err("❌ S1 deve essere maggiore di c".to_string());
    };

    // p = gcd(S, S mod c)
    let s_mod_c = s.clone() % c.clone();
    let p = Self::gcd(s.clone(), s_mod_c);
    if p == BigUint::from(1u8) {
        return Err("❌ Fattorizzazione fallita: p = 1".to_string());
    }

    // q = S // p
    let q = s.clone() / p.clone();

    // k random da seed nel range richiesto
    let k = self.genera_k_da_seed(&b, e)?;

    // p1 = S // (c - k)
    if k >= c {
        return Err("❌ Verifica fallita: k deve essere minore di c".to_string());
    }
    let p1 = s.clone() / (c.clone() - k.clone());
    if p1 != p {
        return Err("❌ Verifica fallita: p1 != p".to_string());
    }

    let chiave_q = Self::deriva_chiave_aes_da_biguint(&q);
    let chiave_k = Self::deriva_chiave_aes_da_biguint(&k);

    self.dati_criptazione = Some(DatiCriptazione {
        k,
        chiave_k,
        chiave_q,
    });

    Ok(())
}

 fn cripta_messaggio(&mut self) {
    // Validazione: messaggio non vuoto
    if self.messaggio.trim().is_empty() {
        self.messaggio_errore = "❌ Il messaggio è vuoto!".to_string();
        return;
    }

    // Validazione: messaggio con almeno 20 caratteri
    if self.messaggio.trim().len() < 20 {
        self.messaggio_errore = "❌ Il messaggio deve contenere almeno 20 caratteri".to_string();
        return;
    }
    let codice_vuoto = self.codice_utente.trim().is_empty();
    let seed_vuoto = self.seed_manuale.trim().is_empty();
    if codice_vuoto && seed_vuoto {
        self.messaggio_errore = "❌ Inserisci codice utente e seed manuale".to_string();
        return;
    }
    if codice_vuoto {
        self.messaggio_errore = "❌ Inserisci il codice utente".to_string();
        return;
    }
    if seed_vuoto {
        self.messaggio_errore = "❌ Inserisci il seed manuale".to_string();
        return;
    }

    self.messaggio_errore = "⏳ Operazione in corso: calcolo chiavi...".to_string();
    
    if let Err(e) = self.carica_semiprimi_cache() {
        self.messaggio_errore = e;
        return;
    }

    match self.leggi_semiprimo_da_database() {
        Ok(s1) => match self.genera_chiavi_aes(s1.clone()) {
            Ok(()) => {
                let dati_criptazione = match &self.dati_criptazione {
                    Some(d) => d.clone(),
                    None => {
                        self.messaggio_errore = "❌ Chiavi AES non disponibili".to_string();
                        return;
                    }
                };

                match self.costruisci_file_criptato(&s1, &dati_criptazione) {
                    Ok(file_bytes) => match self.salva_file_criptato(&file_bytes) {
                        Ok(path_salvato) => {
                            self.messaggio_errore = format!(
                                "✓ File criptato salvato: {}",
                                path_salvato.to_string_lossy()
                            );
                        }
                        Err(e) => {
                            self.messaggio_errore = e;
                            return;
                        }
                    },
                    Err(e) => {
                        self.messaggio_errore = e;
                        return;
                    }
                }

            }
            Err(e) => {
                self.messaggio_errore = e;
            }
        },
        Err(e) => {
            self.messaggio_errore = e;
        }
    }
}

fn decripta_messaggio(&mut self) {
    let cfg = match &self.config {
        Some(c) => c.clone(),
        None => {
            self.messaggio_errore = "❌ Configurazione non caricata".to_string();
            return;
        }
    };

    let dati = match &self.dati_segreto {
        Some(d) => d.clone(),
        None => {
            self.messaggio_errore = "❌ Dati file segreto non caricati".to_string();
            return;
        }
    };

    let file_input = rfd::FileDialog::new()
        .set_directory(&cfg.cartelle.ricezione)
        .pick_file();

    let percorso_file = match file_input {
        Some(p) => p,
        None => {
            self.messaggio_errore = "⚠️ Decriptazione annullata: nessun file selezionato".to_string();
            return;
        }
    };

    let dati_file = match fs::read(&percorso_file) {
        Ok(b) => b,
        Err(e) => {
            self.messaggio_errore = format!("❌ Errore lettura file: {}", e);
            return;
        }
    };

    let file_criptato = match Self::parse_file_messaggio_criptato(&dati_file) {
        Ok(f) => f,
        Err(e) => {
            self.messaggio_errore = e;
            return;
        }
    };

    let c = dati.c;
    let b = dati.b;
    let e = dati.e;

    if file_criptato.s1 <= c {
        self.messaggio_errore = "❌ File non valido: S1 deve essere maggiore di c".to_string();
        return;
    }

    // Prima porta: S = S1 - c, p = gcd(S, S mod c), q = S // p
    let s = file_criptato.s1.clone() - c.clone();
    let s_mod_c = s.clone() % c.clone();
    let p = Self::gcd(s.clone(), s_mod_c);
    if p <= BigUint::from(1u8) {
        self.messaggio_errore = "❌ Fattorizzazione fallita: p non valido".to_string();
        return;
    }
    let q = s.clone() / p.clone();

    let chiave_q = Self::deriva_chiave_aes_da_biguint(&q);
    let payload_q = match Self::decifra_aes256_gcm(&chiave_q, &file_criptato.nonce_q, &file_criptato.blob_q) {
        Ok(pq) => pq,
        Err(e) => {
            self.messaggio_errore = format!("{} (prima porta)", e);
            return;
        }
    };

    let campi_q = match Self::estrai_tutti_i_campi(&payload_q) {
        Ok(campi) => campi,
        Err(e) => {
            self.messaggio_errore = format!("{} (prima porta)", e);
            return;
        }
    };

    if campi_q.len() != 2 {
        self.messaggio_errore = "❌ Prima porta non valida: attesi seed e codice utente".to_string();
        return;
    }

    let seed_ricevuto = match String::from_utf8(campi_q[0].clone()) {
        Ok(sv) => sv,
        Err(_) => {
            self.messaggio_errore = "❌ Seed ricevuto non valido".to_string();
            return;
        }
    };
    let codice_ricevuto = match String::from_utf8(campi_q[1].clone()) {
        Ok(cv) => cv,
        Err(_) => {
            self.messaggio_errore = "❌ Codice utente ricevuto non valido".to_string();
            return;
        }
    };

    self.seed_manuale = seed_ricevuto.clone();
    self.codice_utente = codice_ricevuto.clone();

    let risposta = rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Info)
        .set_title("Conferma prima porta")
        .set_description(&format!(
            "Prima porta aperta.\nCodice utente: {}\nSeed: {}\n\nProseguire con la seconda porta?",
            self.codice_utente,
            self.seed_manuale
        ))
        .set_buttons(rfd::MessageButtons::YesNo)
        .show();

    if !matches!(risposta, rfd::MessageDialogResult::Yes) {
        self.messaggio_errore = "⚠️ Operazione interrotta dall'utente dopo la prima verifica".to_string();
        return;
    }

    // Seconda porta: k da seed e verifica p1 = S // (c-k)
    let k = match Self::genera_k_da_seed_testo(&seed_ricevuto, &b, e) {
        Ok(kv) => kv,
        Err(err) => {
            self.messaggio_errore = err;
            return;
        }
    };

    if k >= c {
        self.messaggio_errore = "❌ Verifica fallita: k deve essere minore di c".to_string();
        return;
    }

    let denominatore = c.clone() - k.clone();
    if denominatore == BigUint::from(0u8) {
        self.messaggio_errore = "❌ Verifica fallita: denominatore nullo".to_string();
        return;
    }

    let p1 = s.clone() / denominatore;
    if p1 != p {
        self.messaggio_errore = "❌ Verifica fallita: p1 diverso da p".to_string();
        return;
    }

    let chiave_k = Self::deriva_chiave_aes_da_biguint(&k);
    let payload_k = match Self::decifra_aes256_gcm(&chiave_k, &file_criptato.nonce_k, &file_criptato.blob_k) {
        Ok(pk) => pk,
        Err(e) => {
            self.messaggio_errore = format!("{} (seconda porta)", e);
            return;
        }
    };

    let campi_k = match Self::estrai_tutti_i_campi(&payload_k) {
        Ok(campi) => campi,
        Err(e) => {
            self.messaggio_errore = format!("{} (seconda porta)", e);
            return;
        }
    };

    if campi_k.len() != 5 {
        self.messaggio_errore = "❌ Seconda porta non valida: attesi k, messaggio, nome allegato, hash allegato e contenuto".to_string();
        return;
    }

    // Terza porta: conferma che k nel file corrisponde a k rigenerato dal seed ricevuto.
    let k_file = BigUint::from_bytes_be(&campi_k[0]);
    if k_file != k {
        self.messaggio_errore = "❌ Terza porta fallita: k nel file non coincide con k rigenerato dal seed".to_string();
        return;
    }

    let messaggio_decifrato = match String::from_utf8(campi_k[1].clone()) {
        Ok(m) => m,
        Err(_) => {
            self.messaggio_errore = "❌ Messaggio decifrato non valido (UTF-8)".to_string();
            return;
        }
    };
    let nome_allegato = String::from_utf8(campi_k[2].clone()).unwrap_or_default();
    let hash_allegato_atteso = campi_k[3].clone();
    let contenuto_allegato = campi_k[4].clone();

    self.messaggio = messaggio_decifrato;
    self.allegati_selezionati.clear();

    if !nome_allegato.trim().is_empty() && !contenuto_allegato.is_empty() {
        if hash_allegato_atteso.is_empty() {
            self.messaggio_errore = "❌ Hash allegato mancante: possibile manomissione".to_string();
            return;
        }

        let hash_calcolato = Self::calcola_hash_sha256(&contenuto_allegato);
        if hash_calcolato != hash_allegato_atteso {
            self.messaggio_errore = "❌ Allarme integrita: hash allegato non corrispondente".to_string();
            return;
        }

        let nome_sicuro = match Self::sanitizza_nome_allegato(&nome_allegato) {
            Ok(n) => n,
            Err(e) => {
                self.messaggio_errore = e;
                return;
            }
        };

        let percorso_allegato = std::path::PathBuf::from(&cfg.cartelle.allegati).join(&nome_sicuro);
        match fs::write(&percorso_allegato, &contenuto_allegato) {
            Ok(_) => {
                self.messaggio_errore = format!(
                    "✓ Messaggio decriptato. Allegato salvato in: {}",
                    percorso_allegato.to_string_lossy()
                );
            }
            Err(e) => {
                self.messaggio_errore = format!(
                    "✓ Messaggio decriptato, ma errore salvataggio allegato: {}",
                    e
                );
            }
        }
    } else {
        if !hash_allegato_atteso.is_empty() {
            self.messaggio_errore = "❌ Metadati allegato incoerenti: hash presente senza allegato".to_string();
            return;
        }
        self.messaggio_errore = "✓ Messaggio decriptato con successo!".to_string();
    }
}

}