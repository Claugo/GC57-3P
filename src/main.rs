/*!
 * GC57-3P GUI – Implementazione Rust con caricamento allegati
 *
 * Struttura a tre porte (3P):
 *   PORTA 0 – Semiprimo pubblico (memorizzato in chiaro nel file .gc57)
 *   PORTA 1 – Autenticazione operatore (seme + firma, cifrata AES-256-CBC con chiave q)
 *   PORTA 2 – Contenuto protetto (k + testo + allegato, cifrata AES-256-GCM con chiave k)
 */

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use aes::Aes256;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use eframe::egui::{self, Color32, RichText, ScrollArea, TextEdit};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use num_integer::Integer;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

// ============================================================
// Struct: AllegatoCaricato
// ============================================================

/// Rappresenta un allegato caricato dall'utente.
#[derive(Clone)]
pub struct AllegatoCaricato {
    /// Nome del file con estensione (es. "documento.pdf")
    pub nome: String,
    /// Percorso completo del file sul disco
    pub percorso: String,
    /// Contenuto binario del file
    pub contenuto: Vec<u8>,
}

impl AllegatoCaricato {
    /// Dimensione del file in bytes
    pub fn dimensione(&self) -> usize {
        self.contenuto.len()
    }
}

// ============================================================
// Modalità applicazione
// ============================================================

#[derive(PartialEq, Clone)]
enum Modalita {
    /// Schermata principale
    Principale,
    /// Schermata di cifratura (INVIA)
    Invia,
    /// Schermata di decifratura (RICEVI)
    Ricevi,
    /// Schermata di configurazione parametri segreti
    ConfiguraParametri,
}

// ============================================================
// Parametri segreti GC57
// ============================================================

#[derive(Clone)]
struct ParametriSegreti {
    /// C = B - 1 (parametro di fase)
    c: BigUint,
    /// Base per la generazione di k
    base: BigUint,
    /// Esponente per la generazione di k
    esponente: u32,
}

// ============================================================
// Payload cifrato per serializzazione JSON
// ============================================================

#[derive(Serialize, Deserialize)]
struct Porta1Payload {
    seme: String,
    firma: String,
}

#[derive(Serialize, Deserialize)]
struct Porta2Payload {
    /// Allegato codificato in base64, None se assente
    allegato: Option<String>,
    /// Chiave k serializzata come stringa (big integer)
    k: String,
    /// Nome del file allegato con estensione, None se assente
    nome_allegato: Option<String>,
    /// Testo del messaggio in chiaro
    testo: String,
}

// ============================================================
// AppPrincipale – stato principale dell'applicazione
// ============================================================

pub struct AppPrincipale {
    // --- navigazione ---
    modalita: Modalita,

    // --- INVIA: campi per la cifratura ---
    messaggio_invia: String,
    /// Allegato singolo caricato (sostituisce il precedente se caricato di nuovo)
    allegato: Option<AllegatoCaricato>,
    file_semiprimi: Option<String>,
    seme: String,
    firma: String,
    stato_cifratura: String,
    errore_cifratura: bool,

    // --- RICEVI: campi per la decifratura ---
    file_gc57: Option<String>,
    messaggio_decifrato: String,
    /// Allegato recuperato dalla decifratura: (nome, contenuto)
    allegato_decifrato: Option<(String, Vec<u8>)>,
    stato_decifratura: String,
    errore_decifratura: bool,

    // --- Parametri segreti GC57 ---
    parametri: Option<ParametriSegreti>,
    /// Campi di input per la configurazione manuale dei parametri
    input_c: String,
    input_base: String,
    input_esponente: String,
    /// Percorso del file segreto GC57
    file_segreto: Option<String>,
    /// Password per decodificare il file segreto
    input_password: String,
    stato_config: String,
    errore_config: bool,
}

impl Default for AppPrincipale {
    fn default() -> Self {
        Self {
            modalita: Modalita::Principale,
            messaggio_invia: String::new(),
            allegato: None,
            file_semiprimi: None,
            seme: String::new(),
            firma: String::new(),
            stato_cifratura: String::new(),
            errore_cifratura: false,
            file_gc57: None,
            messaggio_decifrato: String::new(),
            allegato_decifrato: None,
            stato_decifratura: String::new(),
            errore_decifratura: false,
            parametri: None,
            input_c: String::new(),
            input_base: String::new(),
            input_esponente: String::new(),
            file_segreto: None,
            input_password: String::new(),
            stato_config: String::new(),
            errore_config: false,
        }
    }
}

// ============================================================
// Funzioni di supporto cross-platform
// ============================================================

/// Restituisce il percorso della cartella Documenti dell'utente
/// compatibile con Windows, Linux e macOS.
pub fn get_documenti_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        // Windows: usa USERPROFILE o HOMEDRIVE+HOMEPATH
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            return PathBuf::from(userprofile).join("Documents");
        }
        if let (Ok(drive), Ok(path)) =
            (std::env::var("HOMEDRIVE"), std::env::var("HOMEPATH"))
        {
            return PathBuf::from(format!("{}{}", drive, path)).join("Documents");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join("Documents");
        }
    }
    #[cfg(target_os = "linux")]
    {
        // Prova XDG_DOCUMENTS_DIR, poi ~/Documents
        if let Ok(docs) = std::env::var("XDG_DOCUMENTS_DIR") {
            let p = PathBuf::from(docs);
            if p.exists() {
                return p;
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join("Documents");
        }
    }
    // Fallback: directory corrente
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

// ============================================================
// Funzione: apri_cartella_allegati
// ============================================================

/// Apre una dialog di selezione file e restituisce l'allegato caricato.
/// Utilizza la cartella Documenti come directory di partenza.
/// Accetta qualsiasi formato di file (PDF, DOC, EXE, AVI, JPG, ecc.).
/// Se l'utente seleziona un nuovo file, questo sostituisce il precedente.
pub fn apri_cartella_allegati() -> Option<AllegatoCaricato> {
    let cartella_inizio = get_documenti_path();

    let percorso = rfd::FileDialog::new()
        .set_title("Carica Allegato")
        .set_directory(&cartella_inizio)
        .add_filter("Tutti i file", &["*"])
        .pick_file()?;

    let nome = percorso
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());

    let contenuto = std::fs::read(&percorso).ok()?;

    Some(AllegatoCaricato {
        nome,
        percorso: percorso.to_string_lossy().into_owned(),
        contenuto,
    })
}

// ============================================================
// Crittografia – derivazione chiave
// ============================================================

/// Deriva una chiave AES-256 (32 byte) da un intero grande tramite SHA-256.
fn deriva_chiave_aes(valore: &BigUint) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(valore.to_str_radix(10).as_bytes());
    hasher.finalize().into()
}

// ============================================================
// Crittografia – Porta 1 (AES-256-CBC)
// ============================================================

/// Cifra i dati di Porta 1 (seme + firma) con AES-256-CBC usando q come chiave.
/// Restituisce [IV (16 byte)] + [ciphertext].
fn cifra_porta1(seme: &str, firma: &str, chiave_q: &BigUint) -> Result<Vec<u8>, String> {
    let payload = Porta1Payload {
        seme: seme.to_owned(),
        firma: firma.to_owned(),
    };
    let json_bytes = serde_json::to_vec(&payload)
        .map_err(|e| format!("Serializzazione Porta 1 fallita: {}", e))?;

    // padding PKCS#7
    let block_size = 16usize;
    let pad_len = block_size - (json_bytes.len() % block_size);
    let mut padded = json_bytes.clone();
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));

    let aes_key = deriva_chiave_aes(chiave_q);
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    let cipher = Aes256CbcEnc::new(&aes_key.into(), &iv.into());
    let ciphertext = cipher
        .encrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(&padded);

    let mut result = Vec::with_capacity(16 + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decifra i dati di Porta 1.
fn decifra_porta1(dati: &[u8], chiave_q: &BigUint) -> Result<Porta1Payload, String> {
    if dati.len() < 32 {
        return Err("Dati Porta 1 troppo corti".to_string());
    }
    let iv: [u8; 16] = dati[..16].try_into().unwrap();
    let ciphertext = &dati[16..];

    let aes_key = deriva_chiave_aes(chiave_q);
    let cipher = Aes256CbcDec::new(&aes_key.into(), &iv.into());
    let decrypted = cipher
        .decrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(ciphertext)
        .map_err(|e| format!("Decifratura Porta 1 fallita: {}", e))?;

    // rimuovi padding PKCS#7
    if decrypted.is_empty() {
        return Err("Dati decifrati vuoti".to_string());
    }
    let pad_len = *decrypted.last().unwrap() as usize;
    if pad_len == 0 || pad_len > 16 || pad_len > decrypted.len() {
        return Err("Padding non valido in Porta 1".to_string());
    }
    let json_bytes = &decrypted[..decrypted.len() - pad_len];

    serde_json::from_slice(json_bytes)
        .map_err(|e| format!("Deserializzazione Porta 1 fallita: {}", e))
}

// ============================================================
// Crittografia – Porta 2 (AES-256-GCM)
// ============================================================

/// Cifra i dati di Porta 2 (k + testo + allegato opzionale) con AES-256-GCM.
/// Restituisce [nonce (12 byte)] + [ciphertext] + [tag (16 byte)].
fn cifra_porta2(
    chiave_k: &BigUint,
    testo: &str,
    allegato: Option<&AllegatoCaricato>,
) -> Result<Vec<u8>, String> {
    let (allegato_b64, nome_allegato) = match allegato {
        Some(a) => (
            Some(BASE64.encode(&a.contenuto)),
            Some(a.nome.clone()),
        ),
        None => (None, None),
    };

    let payload = Porta2Payload {
        allegato: allegato_b64,
        k: chiave_k.to_str_radix(10),
        nome_allegato,
        testo: testo.to_owned(),
    };
    let json_bytes = serde_json::to_vec(&payload)
        .map_err(|e| format!("Serializzazione Porta 2 fallita: {}", e))?;

    let aes_key = deriva_chiave_aes(chiave_k);
    let cipher = Aes256Gcm::new(&aes_key.into());

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_with_tag = cipher
        .encrypt(nonce, json_bytes.as_ref())
        .map_err(|e| format!("Cifratura Porta 2 fallita: {}", e))?;

    // aes-gcm restituisce ciphertext + tag (16 byte) concatenati
    let mut result = Vec::with_capacity(12 + ciphertext_with_tag.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext_with_tag);
    Ok(result)
}

/// Decifra i dati di Porta 2.
fn decifra_porta2(dati: &[u8], chiave_k: &BigUint) -> Result<Porta2Payload, String> {
    if dati.len() < 12 + 16 {
        return Err("Dati Porta 2 troppo corti".to_string());
    }
    let nonce_bytes: [u8; 12] = dati[..12].try_into().unwrap();
    let ciphertext_with_tag = &dati[12..];

    let aes_key = deriva_chiave_aes(chiave_k);
    let cipher = Aes256Gcm::new(&aes_key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map_err(|_| "Decifratura Porta 2 fallita: chiave o dati non validi".to_string())?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Deserializzazione Porta 2 fallita: {}", e))
}

// ============================================================
// Funzione: carica_semiprimo_random
// ============================================================

/// Carica un semiprimo casuale dal database (file di testo con un semiprimo per riga).
fn carica_semiprimo_random(percorso: &str) -> Result<BigUint, String> {
    let contenuto = std::fs::read_to_string(percorso)
        .map_err(|e| format!("Errore lettura file semiprimi: {}", e))?;

    let righe: Vec<&str> = contenuto
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();

    if righe.is_empty() {
        return Err("File semiprimi vuoto".to_string());
    }

    let indice = (OsRng.next_u64() as usize) % righe.len();
    BigUint::parse_bytes(righe[indice].trim().as_bytes(), 10)
        .ok_or_else(|| "Semiprimo non valido nel database".to_string())
}

// ============================================================
// Funzione: deriva_k_da_seme
// ============================================================

/// Deriva la chiave k in modo deterministico dal seme, usando HMAC-SHA256.
/// Il valore k è nell'intervallo [base^(esponente-3), base^esponente].
fn deriva_k_da_seme(seme: &str, base: &BigUint, esponente: u32) -> BigUint {
    // Usa HMAC-SHA256 per derivare un valore deterministico dal seme
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(seme.as_bytes())
        .expect("HMAC accetta chiavi di qualsiasi lunghezza");
    mac.update(b"gc57-k");
    let result = mac.finalize().into_bytes();

    // Interpreta i primi 16 byte come un intero big-endian
    let random_val = BigUint::from_bytes_be(&result[..16]);

    // Calcola i limiti dell'intervallo
    let basso = if esponente >= 3 {
        base.pow(esponente - 3)
    } else {
        BigUint::from(1u32)
    };
    let alto = base.pow(esponente);

    if alto <= basso {
        return basso;
    }

    let intervallo = &alto - &basso;
    &basso + (&random_val % &intervallo)
}

// ============================================================
// Funzione: avvia_cifratura
// ============================================================

/// Esegue la cifratura completa GC57-3P e salva il file .gc57.
fn avvia_cifratura(
    app: &AppPrincipale,
    percorso_output: &str,
) -> Result<(), String> {
    let parametri = app
        .parametri
        .as_ref()
        .ok_or("Parametri segreti non caricati")?;

    let file_semiprimi = app
        .file_semiprimi
        .as_ref()
        .ok_or("File semiprimi non selezionato")?;

    if app.messaggio_invia.trim().len() < 20 {
        return Err("Il testo deve contenere almeno 20 caratteri".to_string());
    }
    if app.seme.trim().is_empty() || app.firma.trim().is_empty() {
        return Err("Seme e firma sono obbligatori".to_string());
    }

    // --- carica semiprimo casuale dal database ---
    let semiprimo = carica_semiprimo_random(file_semiprimi)?;

    // --- fattorizzazione GC57 ---
    let sp = &semiprimo - &parametri.c;
    let sp_mod_c = &sp % &parametri.c;
    let p = sp.gcd(&sp_mod_c);
    if p == BigUint::from(1u32) {
        return Err("Fattorizzazione fallita: p=1. Verificare i parametri.".to_string());
    }
    let q = &sp / &p;

    // --- derivazione k ---
    let k = deriva_k_da_seme(&app.seme, &parametri.base, parametri.esponente);

    // --- PORTA 1: cifratura seme + firma con chiave q ---
    let porta1_bytes = cifra_porta1(&app.seme, &app.firma, &q)?;

    // --- PORTA 2: cifratura k + testo + allegato con chiave k ---
    let porta2_bytes = cifra_porta2(&k, &app.messaggio_invia, app.allegato.as_ref())?;

    // --- scrittura file binario ---
    let semiprimo_bytes = semiprimo.to_bytes_be();

    let mut file_data = Vec::new();

    // Header identificativo (7 byte)
    file_data.extend_from_slice(b"GC57-3P");

    // Semiprimo (4 byte lunghezza big-endian + dati)
    file_data.extend_from_slice(&(semiprimo_bytes.len() as u32).to_be_bytes());
    file_data.extend_from_slice(&semiprimo_bytes);

    // Porta 1 (4 byte lunghezza + dati)
    file_data.extend_from_slice(&(porta1_bytes.len() as u32).to_be_bytes());
    file_data.extend_from_slice(&porta1_bytes);

    // Porta 2 (4 byte lunghezza + dati)
    file_data.extend_from_slice(&(porta2_bytes.len() as u32).to_be_bytes());
    file_data.extend_from_slice(&porta2_bytes);

    std::fs::write(percorso_output, &file_data)
        .map_err(|e| format!("Errore scrittura file: {}", e))?;

    Ok(())
}

// ============================================================
// Funzione: avvia_decifratura
// ============================================================

/// Legge e decifra un file .gc57.
/// Restituisce (messaggio_testo, Option<(nome_allegato, contenuto_allegato)>).
fn avvia_decifratura(
    percorso_file: &str,
    parametri: &ParametriSegreti,
    _seme_operatore: &str,
) -> Result<(String, Option<(String, Vec<u8>)>), String> {
    let file_data = std::fs::read(percorso_file)
        .map_err(|e| format!("Errore lettura file: {}", e))?;

    let mut offset = 0usize;

    // --- header ---
    if file_data.len() < 7 || &file_data[..7] != b"GC57-3P" {
        return Err("File non valido o formato GC57 errato".to_string());
    }
    offset += 7;

    // --- semiprimo ---
    if file_data.len() < offset + 4 {
        return Err("File corrotto (semiprimo)".to_string());
    }
    let len_semiprimo = u32::from_be_bytes(file_data[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if file_data.len() < offset + len_semiprimo {
        return Err("File corrotto (semiprimo dati)".to_string());
    }
    let semiprimo = BigUint::from_bytes_be(&file_data[offset..offset + len_semiprimo]);
    offset += len_semiprimo;

    // --- porta 1 ---
    if file_data.len() < offset + 4 {
        return Err("File corrotto (porta 1)".to_string());
    }
    let len_porta1 = u32::from_be_bytes(file_data[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if file_data.len() < offset + len_porta1 {
        return Err("File corrotto (porta 1 dati)".to_string());
    }
    let porta1_bytes = &file_data[offset..offset + len_porta1];
    offset += len_porta1;

    // --- porta 2 ---
    if file_data.len() < offset + 4 {
        return Err("File corrotto (porta 2)".to_string());
    }
    let len_porta2 = u32::from_be_bytes(file_data[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if file_data.len() < offset + len_porta2 {
        return Err("File corrotto (porta 2 dati)".to_string());
    }
    let porta2_bytes = &file_data[offset..offset + len_porta2];

    // --- fattorizzazione GC57 ---
    let sp = &semiprimo - &parametri.c;
    let sp_mod_c = &sp % &parametri.c;
    let p = sp.gcd(&sp_mod_c);
    if p == BigUint::from(1u32) {
        return Err("Fattorizzazione fallita: p=1. Verificare i parametri.".to_string());
    }
    let q = &sp / &p;

    // --- decifra porta 1 ---
    let dati_p1 = decifra_porta1(porta1_bytes, &q)?;

    // --- ri-deriva k dal seme estratto ---
    let k = deriva_k_da_seme(&dati_p1.seme, &parametri.base, parametri.esponente);

    // Verifica opzionale: l'operatore può confrontare il seme atteso
    // (nel sistema GC57 completo, il seme è verificato tramite firma digitale)

    // --- decifra porta 2 ---
    let dati_p2 = decifra_porta2(porta2_bytes, &k)?;

    // --- recupero allegato ---
    let allegato = match (dati_p2.allegato, dati_p2.nome_allegato) {
        (Some(b64), Some(nome)) => {
            let contenuto = BASE64
                .decode(&b64)
                .map_err(|e| format!("Decodifica allegato fallita: {}", e))?;
            Some((nome, contenuto))
        }
        _ => None,
    };

    Ok((dati_p2.testo, allegato))
}

// ============================================================
// Funzione: carica_parametri_da_file_segreto
// ============================================================

/// Legge e decodifica il file segreto GC57 (formato testo offuscato con XOR).
/// Il file contiene:
///   riga 0: "GC57-SECRET-V1"
///   riga 1: C
///   riga 2: base
///   riga 3: esponente
fn carica_parametri_da_file_segreto(
    percorso: &str,
    password: &str,
) -> Result<ParametriSegreti, String> {
    let contenuto = std::fs::read_to_string(percorso)
        .map_err(|e| format!("Errore lettura file segreto: {}", e))?;

    // Decodifica XOR compatibile con il tool Python (chiave = SHA-256 della password)
    let chiave: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(password.as_bytes());
        h.finalize().into()
    };
    let dati_codificati = contenuto.trim();
    let dati_bytes = BASE64
        .decode(dati_codificati)
        .map_err(|_| "File segreto: formato base64 non valido".to_string())?;

    let decifrato: Vec<u8> = dati_bytes
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ chiave[i % chiave.len()])
        .collect();

    let testo = String::from_utf8_lossy(&decifrato);
    let righe: Vec<&str> = testo.lines().map(str::trim).filter(|l| !l.is_empty()).collect();

    if righe.len() < 4 || righe[0] != "GC57-SECRET-V1" {
        return Err("Password errata o file segreto non valido".to_string());
    }

    let c = BigUint::parse_bytes(righe[1].as_bytes(), 10)
        .ok_or_else(|| "Parametro C non valido".to_string())?;
    let base = BigUint::parse_bytes(righe[2].as_bytes(), 10)
        .ok_or_else(|| "Parametro base non valido".to_string())?;
    let esponente: u32 = righe[3]
        .parse()
        .map_err(|_| "Parametro esponente non valido".to_string())?;

    Ok(ParametriSegreti { c, base, esponente })
}

// ============================================================
// eframe::App – implementazione GUI
// ============================================================

impl eframe::App for AppPrincipale {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Stile globale
        let visuals = egui::Visuals::light();
        ctx.set_visuals(visuals);

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.modalita.clone() {
                Modalita::Principale => self.mostra_schermata_principale(ui),
                Modalita::Invia => self.mostra_schermata_invia(ui, ctx),
                Modalita::Ricevi => self.mostra_schermata_ricevi(ui, ctx),
                Modalita::ConfiguraParametri => self.mostra_schermata_config(ui, ctx),
            }
        });
    }
}

// ============================================================
// Schermate GUI
// ============================================================

impl AppPrincipale {
    /// Schermata principale con i due pulsanti INVIA / RICEVI
    fn mostra_schermata_principale(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(30.0);
            ui.heading(
                RichText::new("GC57-3P")
                    .size(36.0)
                    .color(Color32::from_rgb(33, 97, 140)),
            );
            ui.label(
                RichText::new("Sistema di Sicurezza a Tre Porte")
                    .size(16.0)
                    .color(Color32::GRAY),
            );
            ui.add_space(10.0);

            // Indicatore stato parametri
            if self.parametri.is_some() {
                ui.label(
                    RichText::new("✅ Parametri segreti caricati")
                        .color(Color32::from_rgb(39, 174, 96)),
                );
            } else {
                ui.label(
                    RichText::new("⚠ Parametri segreti non caricati")
                        .color(Color32::from_rgb(231, 76, 60)),
                );
            }

            ui.add_space(40.0);

            // Pulsanti principali
            ui.horizontal(|ui| {
                ui.add_space(80.0);

                let btn_invia = egui::Button::new(
                    RichText::new("📤  INVIA\nCifra e invia un messaggio").size(14.0),
                )
                .min_size(egui::vec2(200.0, 80.0))
                .fill(Color32::from_rgb(41, 128, 185));

                if ui.add(btn_invia).clicked() {
                    self.modalita = Modalita::Invia;
                }

                ui.add_space(30.0);

                let btn_ricevi = egui::Button::new(
                    RichText::new("📥  RICEVI\nDecifra un messaggio ricevuto").size(14.0),
                )
                .min_size(egui::vec2(200.0, 80.0))
                .fill(Color32::from_rgb(39, 174, 96));

                if ui.add(btn_ricevi).clicked() {
                    self.modalita = Modalita::Ricevi;
                }
            });

            ui.add_space(30.0);

            let btn_config = egui::Button::new(
                RichText::new("⚙  Configura Parametri Segreti").size(13.0),
            )
            .min_size(egui::vec2(260.0, 40.0));

            if ui.add(btn_config).clicked() {
                self.modalita = Modalita::ConfiguraParametri;
            }
        });
    }

    /// Schermata INVIA – cifratura messaggio con allegato
    fn mostra_schermata_invia(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) {
        ScrollArea::vertical().show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui.button("← Indietro").clicked() {
                    self.modalita = Modalita::Principale;
                    self.stato_cifratura.clear();
                    self.errore_cifratura = false;
                }
                ui.heading(
                    RichText::new("INVIA DATI CRIPTATI – GC57-3P")
                        .color(Color32::from_rgb(33, 97, 140)),
                );
            });

            ui.add_space(10.0);
            ui.separator();

            // ── Card: Seleziona database semiprimi ──────────────────────
            egui::Frame::new()
                .fill(Color32::WHITE)
                .stroke(egui::Stroke::new(1.0, Color32::LIGHT_GRAY))
                .corner_radius(6.0)
                .inner_margin(12.0)
                .outer_margin(4.0)
                .show(ui, |ui| {
                    ui.label(RichText::new("💾  Database Semiprimi").strong());
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        let nome = self
                            .file_semiprimi
                            .as_deref()
                            .map(|p| {
                                std::path::Path::new(p)
                                    .file_name()
                                    .map(|n| n.to_string_lossy().into_owned())
                                    .unwrap_or_else(|| p.to_owned())
                            })
                            .unwrap_or_else(|| "Nessun file selezionato".to_string());

                        ui.label(RichText::new(&nome).color(Color32::DARK_GRAY));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Seleziona file…").clicked() {
                                if let Some(p) = rfd::FileDialog::new()
                                    .set_title("Seleziona database semiprimi")
                                    .add_filter("Tutti i file", &["*"])
                                    .pick_file()
                                {
                                    self.file_semiprimi = Some(p.to_string_lossy().into_owned());
                                }
                            }
                        });
                    });
                });

            // ── Card: Messaggio ─────────────────────────────────────────
            egui::Frame::new()
                .fill(Color32::WHITE)
                .stroke(egui::Stroke::new(1.0, Color32::LIGHT_GRAY))
                .corner_radius(6.0)
                .inner_margin(12.0)
                .outer_margin(4.0)
                .show(ui, |ui| {
                    ui.label(RichText::new("✍  Scrivi il Messaggio").strong());
                    ui.add_space(6.0);
                    ui.add(
                        TextEdit::multiline(&mut self.messaggio_invia)
                            .desired_rows(8)
                            .desired_width(f32::INFINITY)
                            .hint_text("Inserisci il messaggio (minimo 20 caratteri)…"),
                    );
                    let n = self.messaggio_invia.len();
                    let colore = if n < 20 {
                        Color32::from_rgb(231, 76, 60)
                    } else {
                        Color32::GRAY
                    };
                    ui.label(RichText::new(format!("{} caratteri", n)).color(colore));
                });

            // ── Card: Allegato ──────────────────────────────────────────
            egui::Frame::new()
                .fill(Color32::WHITE)
                .stroke(egui::Stroke::new(1.0, Color32::LIGHT_GRAY))
                .corner_radius(6.0)
                .inner_margin(12.0)
                .outer_margin(4.0)
                .show(ui, |ui| {
                    ui.label(RichText::new("📎  Allegato").strong());
                    ui.add_space(6.0);

                    ui.horizontal(|ui| {
                        // Pulsante principale: apre il file dialog
                        if ui
                            .button(RichText::new("📁 Carica Allegati").size(13.0))
                            .clicked()
                        {
                            // Apre la dialog e sostituisce l'allegato precedente
                            if let Some(allegato) = apri_cartella_allegati() {
                                self.allegato = Some(allegato);
                            }
                        }

                        if self.allegato.is_none() {
                            ui.label(
                                RichText::new("Nessun allegato caricato (opzionale)")
                                    .color(Color32::GRAY),
                            );
                        }
                    });

                    // Visualizzazione allegato caricato
                    let allegato_info = self.allegato.as_ref().map(|a| (a.nome.clone(), a.dimensione()));
                    if let Some((nome_allegato, dimensione_allegato)) = allegato_info {
                        let mut rimuovi = false;
                        ui.add_space(6.0);
                        egui::Frame::new()
                            .fill(Color32::from_rgb(232, 244, 248))
                            .corner_radius(4.0)
                            .inner_margin(8.0)
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label("📄");
                                    ui.vertical(|ui| {
                                        // Nome completo con estensione
                                        ui.label(
                                            RichText::new(&nome_allegato)
                                                .strong()
                                                .color(Color32::DARK_BLUE),
                                        );
                                        // Dimensione in bytes
                                        ui.label(
                                            RichText::new(format!(
                                                "{} bytes",
                                                dimensione_allegato
                                            ))
                                            .size(11.0)
                                            .color(Color32::GRAY),
                                        );
                                    });
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            // Pulsante di rimozione allegato
                                            if ui
                                                .button(
                                                    RichText::new("✕ Rimuovi")
                                                        .color(Color32::from_rgb(231, 76, 60)),
                                                )
                                                .clicked()
                                            {
                                                rimuovi = true;
                                            }
                                        },
                                    );
                                });
                            });
                        if rimuovi {
                            self.allegato = None;
                        }
                    }
                });

            // ── Card: Seme e Firma ──────────────────────────────────────
            egui::Frame::new()
                .fill(Color32::WHITE)
                .stroke(egui::Stroke::new(1.0, Color32::LIGHT_GRAY))
                .corner_radius(6.0)
                .inner_margin(12.0)
                .outer_margin(4.0)
                .show(ui, |ui| {
                    ui.label(RichText::new("🔑  Autenticazione Operatore").strong());
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label("Seme:");
                        ui.add(TextEdit::singleline(&mut self.seme).desired_width(200.0));
                        ui.add_space(20.0);
                        ui.label("Firma Digitale:");
                        ui.add(TextEdit::singleline(&mut self.firma).desired_width(200.0));
                    });
                });

            // ── Pulsante Avvia Cifratura ────────────────────────────────
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                let abilita = self.parametri.is_some()
                    && self.file_semiprimi.is_some()
                    && self.messaggio_invia.trim().len() >= 20
                    && !self.seme.trim().is_empty()
                    && !self.firma.trim().is_empty();

                ui.add_enabled_ui(abilita, |ui| {
                    if ui
                        .button(
                            RichText::new("🔒  Avvia Cifratura")
                                .size(15.0)
                                .color(Color32::WHITE),
                        )
                        .clicked()
                    {
                        self.esegui_cifratura();
                    }
                });

                if !abilita {
                    ui.label(
                        RichText::new(
                            "Completa tutti i campi e carica i parametri segreti per cifrare",
                        )
                        .color(Color32::GRAY)
                        .size(11.0),
                    );
                }
            });

            // ── Stato operazione ────────────────────────────────────────
            if !self.stato_cifratura.is_empty() {
                ui.add_space(6.0);
                let colore = if self.errore_cifratura {
                    Color32::from_rgb(231, 76, 60)
                } else {
                    Color32::from_rgb(39, 174, 96)
                };
                ui.label(RichText::new(&self.stato_cifratura).color(colore));
            }
        });
    }

    /// Schermata RICEVI – decifratura messaggio con allegato
    fn mostra_schermata_ricevi(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) {
        ScrollArea::vertical().show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui.button("← Indietro").clicked() {
                    self.modalita = Modalita::Principale;
                    self.stato_decifratura.clear();
                    self.errore_decifratura = false;
                    self.messaggio_decifrato.clear();
                    self.allegato_decifrato = None;
                }
                ui.heading(
                    RichText::new("RICEVI DATI CRIPTATI – GC57-3P")
                        .color(Color32::from_rgb(39, 174, 96)),
                );
            });

            ui.add_space(10.0);
            ui.separator();

            // ── Seleziona file .gc57 ─────────────────────────────────────
            egui::Frame::new()
                .fill(Color32::WHITE)
                .stroke(egui::Stroke::new(1.0, Color32::LIGHT_GRAY))
                .corner_radius(6.0)
                .inner_margin(12.0)
                .outer_margin(4.0)
                .show(ui, |ui| {
                    ui.label(RichText::new("📂  File GC57 da decriptare").strong());
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        let nome = self
                            .file_gc57
                            .as_deref()
                            .map(|p| {
                                std::path::Path::new(p)
                                    .file_name()
                                    .map(|n| n.to_string_lossy().into_owned())
                                    .unwrap_or_else(|| p.to_owned())
                            })
                            .unwrap_or_else(|| "Nessun file selezionato".to_string());

                        ui.label(RichText::new(&nome).color(Color32::DARK_GRAY));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Seleziona file GC57…").clicked() {
                                if let Some(p) = rfd::FileDialog::new()
                                    .set_title("Apri file GC57")
                                    .add_filter("File GC57", &["gc57"])
                                    .add_filter("Tutti i file", &["*"])
                                    .pick_file()
                                {
                                    self.file_gc57 = Some(p.to_string_lossy().into_owned());
                                }
                            }
                        });
                    });
                });

            // ── Pulsante Decifra ─────────────────────────────────────────
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let abilita = self.parametri.is_some() && self.file_gc57.is_some();

                ui.add_enabled_ui(abilita, |ui| {
                    if ui
                        .button(RichText::new("🔓  Decifra Messaggio").size(15.0))
                        .clicked()
                    {
                        self.esegui_decifratura();
                    }
                });

                if !abilita {
                    ui.label(
                        RichText::new("Seleziona il file e carica i parametri segreti")
                            .color(Color32::GRAY)
                            .size(11.0),
                    );
                }
            });

            // ── Stato operazione ─────────────────────────────────────────
            if !self.stato_decifratura.is_empty() {
                ui.add_space(6.0);
                let colore = if self.errore_decifratura {
                    Color32::from_rgb(231, 76, 60)
                } else {
                    Color32::from_rgb(39, 174, 96)
                };
                ui.label(RichText::new(&self.stato_decifratura).color(colore));
            }

            // ── Messaggio decifrato ──────────────────────────────────────
            if !self.messaggio_decifrato.is_empty() {
                egui::Frame::new()
                    .fill(Color32::WHITE)
                    .stroke(egui::Stroke::new(1.0, Color32::LIGHT_GRAY))
                    .corner_radius(6.0)
                    .inner_margin(12.0)
                    .outer_margin(4.0)
                    .show(ui, |ui| {
                        ui.label(RichText::new("✉  Messaggio Decifrato").strong());
                        ui.add_space(6.0);
                        ui.add(
                            TextEdit::multiline(&mut self.messaggio_decifrato.clone())
                                .desired_rows(8)
                                .desired_width(f32::INFINITY),
                        );
                    });
            }

            // ── Allegato decifrato ───────────────────────────────────────
            if let Some(ref allegato) = self.allegato_decifrato {
                egui::Frame::new()
                    .fill(Color32::WHITE)
                    .stroke(egui::Stroke::new(1.0, Color32::LIGHT_GRAY))
                    .corner_radius(6.0)
                    .inner_margin(12.0)
                    .outer_margin(4.0)
                    .show(ui, |ui| {
                        ui.label(RichText::new("📎  Allegato Decifrato").strong());
                        ui.add_space(6.0);
                        egui::Frame::new()
                            .fill(Color32::from_rgb(232, 248, 232))
                            .corner_radius(4.0)
                            .inner_margin(8.0)
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label("📄");
                                    ui.vertical(|ui| {
                                        // Nome completo con estensione
                                        ui.label(
                                            RichText::new(&allegato.0)
                                                .strong()
                                                .color(Color32::DARK_GREEN),
                                        );
                                        // Dimensione in bytes
                                        ui.label(
                                            RichText::new(format!(
                                                "{} bytes",
                                                allegato.1.len()
                                            ))
                                            .size(11.0)
                                            .color(Color32::GRAY),
                                        );
                                    });
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            // Pulsante salvataggio allegato
                                            if ui
                                                .button(RichText::new("💾 Salva"))
                                                .clicked()
                                            {
                                                self.salva_allegato_decifrato();
                                            }
                                        },
                                    );
                                });
                            });
                    });
            }
        });
    }

    /// Schermata di configurazione parametri segreti GC57
    fn mostra_schermata_config(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) {
        ui.horizontal(|ui| {
            if ui.button("← Indietro").clicked() {
                self.modalita = Modalita::Principale;
                self.stato_config.clear();
                self.errore_config = false;
            }
            ui.heading(RichText::new("⚙  Configurazione Parametri Segreti"));
        });

        ui.add_space(10.0);
        ui.separator();

        // ── Metodo 1: carica dal file segreto ────────────────────────
        egui::Frame::new()
            .fill(Color32::WHITE)
            .stroke(egui::Stroke::new(1.0, Color32::LIGHT_GRAY))
            .corner_radius(6.0)
            .inner_margin(12.0)
            .outer_margin(4.0)
            .show(ui, |ui| {
                ui.label(RichText::new("📁  Carica da File Segreto GC57").strong());
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    let nome = self
                        .file_segreto
                        .as_deref()
                        .map(|p| {
                            std::path::Path::new(p)
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_else(|| p.to_owned())
                        })
                        .unwrap_or_else(|| "Nessun file selezionato".to_string());

                    ui.label(RichText::new(&nome).color(Color32::DARK_GRAY));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Seleziona file…").clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .set_title("Seleziona File_Segreto_GC57.dat")
                                .add_filter("File DAT", &["dat"])
                                .add_filter("Tutti i file", &["*"])
                                .pick_file()
                            {
                                self.file_segreto = Some(p.to_string_lossy().into_owned());
                            }
                        }
                    });
                });

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.add(
                        TextEdit::singleline(&mut self.input_password)
                            .desired_width(250.0)
                            .password(true),
                    );
                    if ui.button("Carica Parametri").clicked() {
                        self.carica_parametri_da_file();
                    }
                });
            });

        ui.add_space(10.0);
        ui.label(RichText::new("— oppure —").color(Color32::GRAY));
        ui.add_space(10.0);

        // ── Metodo 2: inserimento manuale ────────────────────────────
        egui::Frame::new()
            .fill(Color32::WHITE)
            .stroke(egui::Stroke::new(1.0, Color32::LIGHT_GRAY))
            .corner_radius(6.0)
            .inner_margin(12.0)
            .outer_margin(4.0)
            .show(ui, |ui| {
                ui.label(RichText::new("✏  Inserimento Manuale Parametri").strong());
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("C:");
                    ui.add(TextEdit::singleline(&mut self.input_c).desired_width(300.0));
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label("Base:");
                    ui.add(TextEdit::singleline(&mut self.input_base).desired_width(300.0));
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label("Esponente:");
                    ui.add(TextEdit::singleline(&mut self.input_esponente).desired_width(100.0));
                });
                ui.add_space(8.0);
                if ui.button("Applica Parametri Manuali").clicked() {
                    self.applica_parametri_manuali();
                }
            });

        // ── Stato ────────────────────────────────────────────────────
        if !self.stato_config.is_empty() {
            ui.add_space(8.0);
            let colore = if self.errore_config {
                Color32::from_rgb(231, 76, 60)
            } else {
                Color32::from_rgb(39, 174, 96)
            };
            ui.label(RichText::new(&self.stato_config).color(colore));
        }

        // ── Parametri correnti ────────────────────────────────────────
        if let Some(ref p) = self.parametri {
            ui.add_space(10.0);
            egui::Frame::new()
                .fill(Color32::from_rgb(240, 255, 240))
                .corner_radius(4.0)
                .inner_margin(8.0)
                .show(ui, |ui| {
                    ui.label(RichText::new("✅ Parametri caricati:").strong());
                    let c_str = p.c.to_str_radix(10);
                    ui.label(format!("C = {} (…)", &c_str[..10.min(c_str.len())]));
                    ui.label(format!("Base = {}", p.base));
                    ui.label(format!("Esponente = {}", p.esponente));
                });
        }
    }

    // ── Azioni ──────────────────────────────────────────────────────────

    fn esegui_cifratura(&mut self) {
        self.stato_cifratura.clear();
        self.errore_cifratura = false;

        // Seleziona dove salvare il file .gc57
        let percorso_output = match rfd::FileDialog::new()
            .set_title("Salva file GC57")
            .add_filter("File GC57", &["gc57"])
            .save_file()
        {
            Some(p) => p.to_string_lossy().into_owned(),
            None => {
                self.stato_cifratura = "Salvataggio annullato".to_string();
                return;
            }
        };

        match avvia_cifratura(self, &percorso_output) {
            Ok(()) => {
                self.stato_cifratura = format!(
                    "✅ File salvato con successo: {}",
                    std::path::Path::new(&percorso_output)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| percorso_output.clone())
                );
            }
            Err(e) => {
                self.stato_cifratura = format!("❌ Errore: {}", e);
                self.errore_cifratura = true;
            }
        }
    }

    fn esegui_decifratura(&mut self) {
        self.stato_decifratura.clear();
        self.errore_decifratura = false;
        self.messaggio_decifrato.clear();
        self.allegato_decifrato = None;

        let file_gc57 = match &self.file_gc57 {
            Some(p) => p.clone(),
            None => return,
        };

        let parametri = match &self.parametri {
            Some(p) => p.clone(),
            None => return,
        };

        match avvia_decifratura(&file_gc57, &parametri, "") {
            Ok((testo, allegato)) => {
                self.messaggio_decifrato = testo;
                self.allegato_decifrato = allegato;
                if self.allegato_decifrato.is_some() {
                    self.stato_decifratura =
                        "✅ Messaggio e allegato decifrati con successo".to_string();
                } else {
                    self.stato_decifratura = "✅ Messaggio decifrato con successo".to_string();
                }
            }
            Err(e) => {
                self.stato_decifratura = format!("❌ Errore: {}", e);
                self.errore_decifratura = true;
            }
        }
    }

    fn salva_allegato_decifrato(&self) {
        if let Some(ref allegato) = self.allegato_decifrato {
            let cartella = get_documenti_path();
            if let Some(percorso) = rfd::FileDialog::new()
                .set_title("Salva allegato")
                .set_directory(&cartella)
                .set_file_name(&allegato.0)
                .save_file()
            {
                if let Err(e) = std::fs::write(&percorso, &allegato.1) {
                    eprintln!("Errore salvataggio allegato: {}", e);
                }
            }
        }
    }

    fn carica_parametri_da_file(&mut self) {
        self.stato_config.clear();
        self.errore_config = false;

        let file = match &self.file_segreto {
            Some(f) => f.clone(),
            None => {
                self.stato_config = "Selezionare prima il file segreto".to_string();
                self.errore_config = true;
                return;
            }
        };

        match carica_parametri_da_file_segreto(&file, &self.input_password) {
            Ok(p) => {
                self.parametri = Some(p);
                self.stato_config = "✅ Parametri caricati correttamente".to_string();
            }
            Err(e) => {
                self.stato_config = format!("❌ {}", e);
                self.errore_config = true;
            }
        }
    }

    fn applica_parametri_manuali(&mut self) {
        self.stato_config.clear();
        self.errore_config = false;

        let c = match BigUint::parse_bytes(self.input_c.trim().as_bytes(), 10) {
            Some(v) => v,
            None => {
                self.stato_config = "❌ Parametro C non valido".to_string();
                self.errore_config = true;
                return;
            }
        };

        let base = match BigUint::parse_bytes(self.input_base.trim().as_bytes(), 10) {
            Some(v) => v,
            None => {
                self.stato_config = "❌ Parametro Base non valido".to_string();
                self.errore_config = true;
                return;
            }
        };

        let esponente: u32 = match self.input_esponente.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                self.stato_config = "❌ Parametro Esponente non valido".to_string();
                self.errore_config = true;
                return;
            }
        };

        self.parametri = Some(ParametriSegreti { c, base, esponente });
        self.stato_config = "✅ Parametri applicati correttamente".to_string();
    }
}

// ============================================================
// Entry point
// ============================================================

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("GC57-3P – Sistema di Sicurezza")
            .with_inner_size([800.0, 650.0])
            .with_min_inner_size([600.0, 500.0]),
        ..Default::default()
    };

    eframe::run_native(
        "GC57-3P",
        options,
        Box::new(|_cc| Ok(Box::new(AppPrincipale::default()))),
    )
}
