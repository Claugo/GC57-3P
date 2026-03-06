#  Scheda Programma - GC57-3P (Rust GUI)

  

## 1. Perché implementarlo in Rust (dopo Python)

Il progetto nasce da una base Python e viene portato in Rust per motivi tecnici e strategici legati alla qualità del software.

  **Motivazioni principali:**

- **Sicurezza della memoria**: Rust riduce in modo strutturale intere classi di bug (use-after-free, condizioni di gara non controllate), utili in un'app che tratta materiale cifrato.

- **Affidabilità in produzione**: il controllo del compilatore rende più rigorosa la gestione degli errori e degli stati applicativi.

- **Performance prevedibili**: esecuzione nativa senza Runtime pesante, con latenza e consumo risorse più stabili.

- **Distribuzione professionale**: binari standalone, toolchain solida, maggiore aderenza a pratiche industriali di hardening e auditing.

- **Evoluzione dell'architettura**: passaggio da prototipo rapido (Python) a piattaforma robusta e manutenibile nel lungo periodo.

  
In sintesi, Python è stato ideale per sperimentare rapidamente il modello; Rust e la scelta per consolidarlo e prepararlo a una distribuzione più professionale. Il carattere sperimentale del progetto non cambia: cambia invece l'avvicinamento a tecnologie più adatte alla protezione dei dati.

  
Pertanto, il progetto `GC57-3P` rimane un'app desktop sperimentale orientata a:

- cifrare messaggi testuali;

- includere un eventuale allegato nel file cifrato;

- verificare integrità e autenticità dei dati in fase di decriptazione;

- usare un meccanismo a "porte" logiche basato su parametri numerici (`c`, `b`, `e`, `S1`, `k`, `p`, `q`).

  
**L'interfaccia grafica e sviluppata con `egui/eframe`.**


## 1.1 Visione e intenzione progettuale

Oltre allo scopo tecnico immediato, il progetto nasce con una direzione precisa:

- essere distribuito come **open source**;

- favorire revisione pubblica, audit di sicurezza, test indipendenti e contributi esterni;

- evolvere da prototipo sperimentale a **banco di prova strutturato**;

- preparare una possibile adozione in contesti professionali tramite hardening progressivo.

  
In questa ottica, il codice non è visto solo come prodotto finale, ma come piattaforma collaborativa per:

- validare scelte crittografiche e architetturali;

- misurare robustezza operativa in scenari reali;

- costruire una base tecnica credibile per una futura distribuzione a livello professionale.

  
## 2. Flusso operativo (alto livello)

Il programma segue questi stati principali:

1. **Configurazione**

2. **Attesa chiavetta USB**

3. **Verifica password**

4. **Cripta/Decripta**

  
### 2.1 Configurazione

Vengono impostati e salvati in `GC57-3P.cfg`:

- cartella invio (output file cifrati);

- cartella ricezione (input file da decriptare);

- cartella allegati (salvataggio allegati estratti);

- percorso database (`database_sicurezza.txt`);

- nome volume USB richiesto.

  
### 2.2 Attesa chiavetta

L'app cerca periodicamente una USB con il nome volume configurato.

Quando la trova, controlla la presenza di `File_Segreto_GC57.dat`.

  

### 2.3 Verifica password e apertura file segreto

Il file segreto viene:

- validato con magic number `GC57`;

- verificato con `HMAC-SHA256`;

- decifrato con `AES-256-CBC`;

- parsato per estrarre i parametri numerici principali: `c`, `b`, `e`.

  
### 2.4 Criptazione messaggio

In sintesi:

- seleziona un `S1` dal database;

- ricava `S`, `p`, `q`;

- genera `k` da seed manuale;

- deriva due chiavi simmetriche (da `q` e da `k`);

- crea due payload (prima e seconda porta);

- cifra entrambi con `AES-256-GCM`;

- salva file `.dat` con formato binario versionato (`0x02`).

  

### 2.5 Decriptazione messaggio

In sintesi:

- parse del file messaggio (`GCM7`, versione `0x02`);

- apertura prima porta con chiave derivata da `q`;

- estrazione seed e codice utente;

- ricostruzione `k` dal seed e verifica porta logica;

- apertura seconda porta con chiave derivata da `k`;

- estrazione messaggio + allegato;

- controllo hash allegato;

- salvataggio allegato (con sanitizzazione nome file).

  

## 3. Crittografia usata

  

### 3.1 File segreto USB (`File_Segreto_GC57.dat`)

- **KDF**: `PBKDF2-HMAC-SHA256`

- **Cifratura**: `AES-256-CBC`

- **Integrita**: `HMAC-SHA256`

  

### 3.2 File messaggio (`GC57_Messaggio_*.dat`)

- **Versione formato**: `0x02`

- **Cifratura autenticata**: `AES-256-GCM`

- **Integrita allegato**: hash `SHA-256` salvato nel payload e verificato in decriptazione

  

## 4. Formato file messaggio (v0x02)

**Struttura logica:**

1. `MAGIC` (`GCM7`)

2. `VERSION` (`0x02`)

3. `S1` (length-prefixed)

4. `nonce_q` (12 byte) + `blob_q` (length-prefixed, AES-GCM)

5. `nonce_k` (12 byte) + `blob_k` (length-prefixed, AES-GCM)

  

**Payload seconda porta contiene:**

- `k`

- testo messaggio

- nome allegato

- hash allegato (`SHA-256`)

- bytes allegato

  

## 5. Librerie e componenti principali

Dipendenze principali (`Cargo.toml`):

- UI: `eframe`, `egui`

- Crypto: `aes-gcm`, `aes`, `cbc`, `cipher`, `hmac`, `sha2`, `ring`

- Numeri grandi: `num-bigint`, `num-traits`

- Random: `rand`

- Dialog file: `rfd`

- Config JSON: `serde`, `serde_json`

- Supporto Windows USB: `winapi`

  

## 6. Controlli di sicurezza implementati

- verifica nome volume USB atteso;

- verifica integrità file segreto via HMAC;

- cifratura autenticata AES-GCM sui payload messaggio;

- controllo hash allegato in decriptazione;

- blocco su hash mismatch;

- blocco su inconsistenze metadati allegato;

- sanitizzazione nome allegato (anti path traversal);

- validazioni su input utente (seed, messaggio minimo, campi obbligatori).

  

## 7. Limitazioni attuali

- formato messaggio focalizzato su `v0x02`;

- alcune funzioni CBC sono presenti ma non sono centrali nel flusso messaggio corrente (v0x02 con AES-GCM) e potranno essere razionalizzate nelle prossime versioni.

  

## 8. File principali del progetto

- `src/main.rs`: logica applicativa completa (UI + crypto + flussi)

- `Cargo.toml`: dipendenze Rust

- `GC57-3P.cfg`: configurazione runtime

- `database_sicurezza.txt`: sorgente semiprimi

- `File_Segreto_GC57.dat`: file chiave/parametri su USB

  

## 9. Uso rapido (operativo)

1. Avvia app.

2. Configura cartelle + nome USB.

3. Inserisci la chiavetta con il nome volume impostato in `GC57-3P.cfg` e copia `File_Segreto_GC57.dat` nella root della chiavetta.

4. Copia `database_sicurezza.txt` nel percorso configurato.

5. Verifica password.

6. Cripta o decripta da interfaccia.

  

Esempio di `GC57-3P.cfg`:

```json

{

  "cartelle": {

    "invio": "G:\\inviati",

    "ricezione": "G:\\ricevuti",

    "allegati": "G:\\allegati",

    "database": "G:\\database_sicurezza.txt"

  },

  "dispositivi": {

    "nome_pendrive": "GC573P"

  }

}

```

  

Il file `GC57-3P.cfg` deve trovarsi nella stessa cartella dell'eseguibile; in caso di errori di configurazione, può essere modificato manualmente.

  

Per decriptazione con allegato:

- se hash ok, procede;

- se hash non coincide, blocca con allarme integrita.

  

## 10. Distribuzione del software

Il software viene distribuito in formato aperto, includendo:

- codice sorgente per analisi e revisione;

- versione compilata in `.exe` distribuita in un file .zip;

- database di Semiprimi offuscati;

- `File_Segreto_GC57.dat` e relativa password per test controllati.

  

Per provare correttamente il programma, attenersi alle istruzioni indicate al punto **9. Uso rapido (operativo)**.

  

Il presente software è rilasciato con licenza Apache 2.0. Per i dettagli completi, consultare il file `LICENSE`.

## Nota:
tutto il materiale fornito per provare il programma e strettamente legato alla sperimentazione. Il sistema è totalmente configurabile e può essere reimpostato in modo del tutto personale (password, database, file segreto).