"""
GC57-3P – Progetto di sicurezza basato su semiprimi e controllo di fase

Autore: Claudio Govi
Versione: V0.0.2 (Gennaio 2026)
Metodo: GC57-3P

------------------------------------------------------------
DESCRIZIONE GENERALE
------------------------------------------------------------

GC57-3P è un sistema di sicurezza che utilizza un semiprimo come
struttura portante per la protezione e l’accesso ai dati, basandosi
su un principio di offuscamento lineare controllato.

Il semiprimo non viene cifrato né mascherato: viene reso
informativamente inaccessibile attraverso una traslazione
congruenziale che dipende da un parametro segreto (C).
Il segreto non è nascosto, ma trattato come dato irreversibile:
senza conoscerne il valore esatto non è possibile riallineare
correttamente il sistema.

Il metodo GC57-3P non ricerca i fattori del semiprimo in modo diretto,
ma sfrutta un allineamento di fase che consente la loro ricostruzione
solo all’interno della traiettoria congruenziale corretta.

------------------------------------------------------------
STRUTTURA A TRE PORTE (3P)
------------------------------------------------------------

Il sistema è strutturato in tre livelli logici (porte):

PORTA 0 – Semiprimo pubblico
    Il semiprimo è memorizzato in chiaro nel file.
    Da solo non consente alcuna apertura senza il corretto riallineamento.

PORTA 1 – Autenticazione operatore
    Contiene i dati di seme e firma digitale.
    Questa porta è cifrata utilizzando come chiave
    il fattore primo più grande del semiprimo (q),
    scelto intenzionalmente per la sua rarità informativa
    e per la maggiore difficoltà di intercettazione.

PORTA 2 – Contenuto protetto
    Contiene il messaggio, eventuali allegati e la chiave k.
    L’accesso a questa porta è subordinato alla corretta apertura
    della Porta 1 e alla ricostruzione deterministica di k.

------------------------------------------------------------
NOTA SULLA SCELTA DI p E q
------------------------------------------------------------

Nelle prime versioni sperimentali la Porta 1 era associata al fattore
p (fattore più piccolo del semiprimo). In seguito a un’analisi
concettuale del modello GC57, questa scelta è stata rivista.

La Porta 1 utilizza ora il fattore q (fattore primo più grande),
poiché:
- è informativamente più raro,
- è meno intercettabile in processi lineari,
- è più coerente con la filosofia di controllo della fase GC57.

Questa modifica non altera il metodo matematico,
ma ne rafforza la robustezza logica e la sicurezza operativa.

------------------------------------------------------------
PRINCIPIO CHIAVE
------------------------------------------------------------

GC57-3P non basa la propria sicurezza sulla non linearità,
ma sul controllo della fase iniziale di un processo lineare.

Un dato può essere pubblico e allo stesso tempo irrecuperabile
se la sua funzione non è nascondere il valore,
ma fissare l’unica traiettoria congruenziale corretta.

------------------------------------------------------------
CRONOLOGIA MODIFICHE
------------------------------------------------------------

- Dicembre 2025:
  Prima implementazione GC57-3P.
  Introduzione struttura a tre porte.

- Revisione concettuale:
  Sostituzione di p con q come chiave della Porta 1
  per aumentare la robustezza informativa del sistema.

------------------------------------------------------------
"""

from tkinter import ttk
import tkinter as tk
from tkinter import font
from tkinter import filedialog, messagebox, simpledialog
import struct

import os
import sys
import random
import json
import base64
from hashlib import sha256
import hashlib
from math import gcd
import win32api

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- VARIABILI GLOBALI DI STATO ---
DatiCondivisi = {
    "carica_semiprimi": None,
    "carica_allegato": None,
    "C": None,
    "base": None,
    "esponente": None,
}

# === CONFIGURAZIONE AVVIO ===
CFG_FILE = "GC57-3P.cfg"
VERSION = "GC57-3P V0.0.1 Dicembre 2025" 

# ******************************************************************
# === CONFIGURAZIONE INIZIALE RICERCA FILE CFG

if not os.path.exists(CFG_FILE):
    def chiudi_programma():
        risposta = messagebox.askquestion("Attenzione:", "uscire dal programma?")
        if risposta == "yes":
            rootcfg.destroy()
            quit()

    def normalizza_percorso(percorso):
        percorso = percorso.replace("\\", "/")
        if not percorso.endswith("/"):
            percorso += "/"
        return percorso

    def salva_esci():
        controlli = [e2_cfg, e3_cfg, e4_cfg, e5_cfg, e6_cfg]
        etichette = [
            "Cartella INVIO",
            "Cartella RICEVE",
            "Cartella ALLEGATI",
            "Cartella SEMIPRIMI",
            "Nome PenDrive",
        ]

        for idx, entry in enumerate(controlli[:-1]):
            percorso = entry.get().strip()
            if percorso == "" or not os.path.exists(percorso):
                messagebox.showerror(
                    "Attenzione:", f"{etichette[idx]} non valida o inesistente"
                )
                return

        if controlli[-1].get() == "":
            messagebox.showerror("Attenzione:", "Manca il nome PenDrive")
            return

        with open(CFG_FILE, "w") as f:
            for entry in controlli[:-1]:
                percorso_norm = normalizza_percorso(entry.get().strip())
                f.write(percorso_norm + "\n")
            f.write(controlli[-1].get().strip().upper() + "\n")

        messagebox.showinfo("Salvataggi CFG:", "Configurazione Salvata")
        rootcfg.destroy()

    rootcfg = tk.Tk()
    rootcfg.title("Configurazione Cartelle GC57")
    rootcfg.configure(bg="#458B74")
    rootcfg.geometry("415x480")

    testo = """Se appare questa finestra è perché il programma viene eseguito per la prima volta in questa posizione, 
oppure il file 'GC57-3P.cfg' è stato cancellato.

Copiare e incollare con CTRL+V la posizione delle cartelle:"""

    tk.Label(
        rootcfg,
        text=testo,
        justify=tk.LEFT,
        font="arial 12 bold",
        wraplength=400,
        bg="#458B74",
    ).place(x=10, y=20)

    labels = [
        "Incollare Indirizzo Cartella INVIO",
        "Incollare Indirizzo Cartella RICEVE",
        "Incollare Indirizzo Cartella ALLEGATI",
        "Incollare Indirizzo Cartella SEMIPRIMI",
        "Inserire il nome della PenDrive (Chiavi)",
    ]

    entries = []
    py = 180
    for label_text in labels:
        tk.Label(rootcfg, text=label_text, bg="#458B74", font="arial 12 bold").place(
            x=10, y=py
        )
        py += 20
        entry = tk.Entry(rootcfg, width=40, fg="#104E8B", font="arial 12")
        entry.place(x=10, y=py)
        entries.append(entry)
        py += 30

    e2_cfg, e3_cfg, e4_cfg, e5_cfg, e6_cfg = entries

    tk.Button(
        rootcfg,
        text="Salva ed Esci",
        font="arial 12 bold",
        cursor="hand1",
        bg="green",
        command=salva_esci,
    ).place(x=150, y=py)
    rootcfg.protocol("WM_DELETE_WINDOW", chiudi_programma)
    rootcfg.mainloop()

# Carica configurazione
with open(CFG_FILE, "r") as cfg:
    DIR_INVIATI = cfg.readline().strip().replace("\\", "/")
    DIR_RICEVUTI = cfg.readline().strip().replace("\\", "/")
    DIR_ALLEGATI = cfg.readline().strip().replace("\\", "/")
    DIR_SEMIPRIMI = cfg.readline().strip().replace("\\", "/")
    USB_LABEL = cfg.readline().strip().upper()


# ******************************************************************


def apri_file_allegato(entry_target):
    path = filedialog.askopenfilename(
        initialdir=DIR_ALLEGATI,
        title="Seleziona Allegato",
        filetypes=[("Tutti i file", "*.*")],
    )

    if path:  # Verifichiamo che l'utente non abbia annullato la selezione
        DatiCondivisi["carica_allegato"] = path
        nome_file = os.path.basename(path)
        entry_target.delete(0, tk.END)
        entry_target.insert(0, nome_file)


def apri_file_semiprimi(entry_target):
    path = filedialog.askopenfilename(
        initialdir=DIR_SEMIPRIMI,
        title="Seleziona file semiprimi",
        filetypes=[("Tutti i file", "*.*")],
    )

    if path:  # Verifichiamo che non sia stata annullata la selezione
        DatiCondivisi["carica_semiprimi"] = path
        nome_file = os.path.basename(path)
        entry_target.delete(0, tk.END)
        entry_target.insert(0, nome_file)


# ***********************************************************************************
# ************************* ricerca USB e controllo del drive
# ***********************************************************************************

def trova_usb_con_nome(nome_volume=USB_LABEL):
    drives = win32api.GetLogicalDriveStrings().split("\000")[:-1]

    for drive in drives:
        try:
            label = win32api.GetVolumeInformation(drive)[0]
            if label == nome_volume:
                return drive
        except:
            continue

    return None


def deriva_chiave_da_password(password: str) -> bytes:
    return hashlib.sha256(password.encode("utf-8")).digest()


def decodifica_con_password(dati_codificati: str, password: str) -> str:
    chiave = deriva_chiave_da_password(password)
    dati_bytes = base64.b64decode(dati_codificati)

    decifrato = bytes(
        dati_bytes[i] ^ chiave[i % len(chiave)] for i in range(len(dati_bytes))
    )

    return decifrato.decode("utf-8", errors="ignore")


def bootstrap_gc57():
    messagebox.showinfo("USB", "Inserisci la pen drive con il nome: " + USB_LABEL)

    usb = trova_usb_con_nome(USB_LABEL)
    if usb is None:
        messagebox.showerror("Errore", "Chiavetta GC573P non trovata.")
        sys.exit()

    percorso_file = os.path.join(usb, "File_Segreto_GC57.dat")
    if not os.path.exists(percorso_file):
        messagebox.showerror(
            "Errore", "File_Segreto_GC57.dat non trovato sulla chiavetta GC573P."
        )
        sys.exit()

    with open(percorso_file, "r", encoding="utf-8") as f:
        dati_codificati = f.read().strip()

    MAX_TENTATIVI = 3
    tentativi = 0

    while tentativi < MAX_TENTATIVI:
        password = simpledialog.askstring(
            "Password", "Inserisci la password per caricare i parametri GC57:", show="*"
        )

        if password is None:
            sys.exit()

        dati_decodificati = decodifica_con_password(dati_codificati, password)
        righe = [r.strip() for r in dati_decodificati.splitlines() if r.strip()]

        if len(righe) == 4 and righe[0] == "GC57-SECRET-V1":
            # ✔ successo
            break

        tentativi += 1

        if tentativi < MAX_TENTATIVI:
            messagebox.showwarning(
                "Password errata",
                f"Password non valida.\nTentativi rimasti: {MAX_TENTATIVI - tentativi}",
            )
        else:
            messagebox.showerror(
                "Accesso negato",
                "Numero massimo di tentativi superato.\nIl programma verrà chiuso.",
            )
            sys.exit()

    C = int(righe[1])
    base = int(righe[2])
    esponente = int(righe[3])
    messagebox.showinfo(
        "GC57", "Parametri caricati.\nÈ ora possibile rimuovere la chiavetta USB."
    )
    DatiCondivisi["C"] = C
    DatiCondivisi["base"] = base
    DatiCondivisi["esponente"] = esponente
    return C, base, esponente

# ***********************************************************************************
# ************************* carica semiprimo in modo casuale dal database
# ***********************************************************************************

def carica_semiprimo_random(path):
    """Carica semiprimo con verifica di integrità"""
    if not os.path.exists(path):
        raise FileNotFoundError(f"File semiprimi non trovato: {path}")

    with open(path, "r") as file:
        righe = file.readlines()
        if not righe:
            raise ValueError("File semiprimi vuoto")

        # Selezione random sicura
        semiprimo = int(random.SystemRandom().choice(righe).strip())
        return semiprimo

# ***********************************************************************************
# ************************* porta1 cifra i dati seme e firma
# ***********************************************************************************

def cifra_porta1(dati: dict, chiave: int) -> dict:
    """
    Cifra i dati della porta 1 (seme, firma) con AES-256-CBC usando la chiave p.
    Ritorna un dizionario con iv e ciphertext.
    """

    # --- serializzazione dati ---
    import json

    dati_bytes = json.dumps(dati, sort_keys=True).encode("utf-8")

    # --- derivazione chiave AES da p ---
    from hashlib import sha256

    key = sha256(str(chiave).encode()).digest()  # 32 byte → AES-256

    # --- padding PKCS#7 ---
    def pad_pkcs7(data, block_size=16):
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len]) * pad_len

    dati_padded = pad_pkcs7(dati_bytes)

    # --- cifratura AES-CBC ---
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(dati_padded)

    # --- ritorno struttura cifrata ---
    return {"iv": iv, "ciphertext": ciphertext}

# ***********************************************************************************
# ************************* porta2 cifra i dati k, testo a mano, allegato se presente
# ***********************************************************************************

def cifra_porta2(dati: dict, chiave: int) -> dict:
    """
    Cifra i dati della porta 2 (k, testo, allegato opzionale) con AES-256-GCM
    usando la chiave k.
    Ritorna un dizionario con nonce, ciphertext e tag.
    """


    # --- preparazione dati ---
    # se l'allegato è presente (bytes), lo codifichiamo in base64

    dati_serializzabili = {
        "k": dati["k"],
        "testo": dati["testo"],
        "nome_allegato": dati.get("nome_allegato"),  
        "allegato": (
            base64.b64encode(dati["allegato"]).decode("utf-8")
            if dati.get("allegato") is not None
            else None
        ),
    }

    dati_bytes = json.dumps(dati_serializzabili, sort_keys=True).encode("utf-8")

    # --- derivazione chiave AES da k ---
    key = sha256(str(chiave).encode()).digest()  # 32 byte → AES-256

    # --- cifratura AES-GCM ---
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(dati_bytes)

    # --- ritorno struttura cifrata ---
    return {"nonce": nonce, "ciphertext": ciphertext, "tag": tag}


# ***********************************************************************************
# ************************* avvia cifratura
# ***********************************************************************************

def avvia_cifratura(C, base, esponente, txt_area, entry_codifica):

    def input_seme_firma():
        # imput dei dati di seme e firma da inserire nel dovumento
        dialogo = tk.Toplevel()
        dialogo.title("Dati Richiesti")
        dialogo.configure(bg="#2d4d4a")

        # --- Centratura della finestra ---
        larghezza_finestra = 200
        altezza_finestra = 200

        # Recuperiamo le dimensioni del tuo monitor
        larghezza_schermo = dialogo.winfo_screenwidth()
        altezza_schermo = dialogo.winfo_screenheight()

        # Calcoliamo la posizione X e Y per metterla al centro
        posizione_x = int((larghezza_schermo / 2) - (larghezza_finestra / 2))
        posizione_y = int((altezza_schermo / 2) - (altezza_finestra / 2))

        # Impostiamo la geometria: "Larghezza x Altezza + PosizioneX + PosizioneY"
        dialogo.geometry(f"{larghezza_finestra}x{altezza_finestra}+{posizione_x}+{posizione_y}")

        dialogo.grab_set()
        dati = {"seme": "", "firma": ""}

        # --- Campo Seme ---
        tk.Label(dialogo, text="Inserire (Seme):", bg="#2d4d4a").pack(padx=30, pady=5)
        entry_seme = tk.Entry(dialogo, width=40,justify="center") # Caratteri nascosti
        entry_seme.pack(padx=20, pady=5)
        entry_seme.focus_set() # Mette il cursore qui all'inizio

        # --- Campo Firma ---
        tk.Label(dialogo, text="Inserire Firma Digitale:", bg="#2d4d4a").pack(
            padx=20, pady=5
        )
        entry_firma = tk.Entry(dialogo,width=30,justify="center")
        entry_firma.pack(padx=20, pady=5)

        def invia(event=None):
            dati["seme"] = entry_seme.get()
            dati["firma"] = entry_firma.get()
            dialogo.destroy()

        # Bottone OK
        btn_ok = tk.Button(dialogo, text="OK", command=invia, width=10)
        btn_ok.pack(pady=10)

        # Permette di premere "Invio" sulla tastiera per confermare
        dialogo.bind('<Return>', invia)

        # Attende la chiusura della finestra
        dialogo.wait_window()
        return dati["seme"], dati["firma"]

    # Ora hai Seme e Firma pronti per il tuo algoritmo GC57

    if not entry_codifica.get():
        messagebox.showwarning("Attenzione", "Caricare la codifica prima di avviare.")
        return

    testo = txt_area.get("1.0", "end-1c").strip()
    if len(testo) < 20:
        messagebox.showwarning("Attenzione", "Il testo deve contenere almeno 20 caratteri.")
        return

    Seme, Firma = input_seme_firma()
    if not Seme or not Firma:
        messagebox.showinfo("Attenzione","Senza questi dati l'operazione non può essere eseguita.\nIl processo verrà annullato")
        return

    # Raccolta dati:
    # carica il semiprimo in modo casuale dal database
    semiprimo=carica_semiprimo_random(DatiCondivisi["carica_semiprimi"])
    Sp=semiprimo-C
    p=gcd(Sp,Sp%C)
    q=Sp//p
    if p!=1:
        pass
    else:
        messagebox.showerror("Attenzione","la fattorizzazione non è andata a buon fine\nIl processo verrà annullato")        
        return
    random.seed(Seme)
    basso=esponente-3
    alto=esponente
    k=random.randint(base**basso,base**alto)
    k_verifica=Sp//(C-k)
    if k_verifica==p:
        pass
    else:
        messagebox.showerror(
            "Attenzione",
            "la verifica di K non è andata a buon fine\nIl processo verrà annullato",
        )
    chiave_criptazione_prima_porta=q
    chiave_criptazione_seconda_porta=k
    # ==============================
    # PORTA 1 – cifratura seme + firma con chiave p
    # ==============================

    dati_porta1 = {"seme": Seme, "firma": Firma}

    porta1_cifrata = cifra_porta1(dati=dati_porta1, chiave=chiave_criptazione_prima_porta)

    # ==============================
    # PORTA 2 – cifratura k + testo + (eventuale allegato)
    # ==============================
    allegato_bytes = None
    nome_allegato = None
    if DatiCondivisi.get("carica_allegato"):
        with open(DatiCondivisi["carica_allegato"], "rb") as f:
            allegato_bytes = f.read()
        nome_allegato = os.path.basename(DatiCondivisi["carica_allegato"])
    dati_porta2 = {
        "k": chiave_criptazione_seconda_porta,
        "testo": testo,
        "allegato": allegato_bytes,
        "nome_allegato": nome_allegato,
    }
    porta2_cifrata = cifra_porta2(dati=dati_porta2, chiave=chiave_criptazione_seconda_porta)

    percorso_file = filedialog.asksaveasfilename(
        title="Salva file GC57",
        defaultextension=".gc57",
        filetypes=[
            ("File GC57", "*.gc57"),
            ("Tutti i file", "*.*"),
           ],
        )

    if not percorso_file:
        messagebox.showinfo("Operazione annullata", "Salvataggio annullato dall'utente.")
        return

    with open(percorso_file, "wb") as f:
        # header identificativo
        f.write(b"GC57-3P")

        # semiprimo (intero grande)
        semiprimo_bytes = semiprimo.to_bytes((semiprimo.bit_length() + 7) // 8, "big")
        f.write(struct.pack(">I", len(semiprimo_bytes)))
        f.write(semiprimo_bytes)

        # porta 1
        p1 = porta1_cifrata["iv"] + porta1_cifrata["ciphertext"]
        f.write(struct.pack(">I", len(p1)))
        f.write(p1)

        # porta 2
        p2 = porta2_cifrata["nonce"] + porta2_cifrata["ciphertext"] + porta2_cifrata["tag"]
        f.write(struct.pack(">I", len(p2)))
        f.write(p2)
    messagebox.showinfo("File Criptato","memorizzazione avvenuta con successo")        


# ***********************************************************************************
# ************************* Finestra invia V0.0.2
# ***********************************************************************************
def apri_finestra_invia(C, base, esponente):
    finestra_invia = tk.Toplevel(root)
    finestra_invia.title("GC57 INVIA v2 - Cifratura 3P")
    finestra_invia.geometry("750x700")

    # Colori moderni
    colore_sfondo = "#f5f5f5"
    colore_card = "#ffffff"
    colore_blu = "#2196F3"
    colore_verde = "#90EE90"
    colore_grigio = "#757575"
    colore_testo_scuro = "#212121"
    colore_testo_chiaro = "#0E0C0C"
    colore_bordo = "#e0e0e0"

    finestra_invia.configure(bg=colore_sfondo)

    # Header
    header = tk.Frame(finestra_invia, bg="white", height=80)
    header.pack(fill="x")
    header.pack_propagate(False)

    tk.Label(
        header,
        text="INVIA DATI CRIPTATI - SICUREZZA GC57-3P",
        font=("Segoe UI", 18, "bold"),
        bg="white",
        fg=colore_testo_scuro,
    ).pack(pady=25)

    # Main area
    main = tk.Frame(finestra_invia, bg=colore_sfondo)
    main.pack(fill="both", expand=True, padx=30, pady=20)

    # 1. CARD SELEZIONA CODIFICA
    codifica_card = tk.Frame(
        main, bg="white", highlightbackground=colore_bordo, highlightthickness=1
    )
    codifica_card.pack(fill="x", pady=(0, 15))

    cod_header = tk.Frame(codifica_card, bg="white")
    cod_header.pack(fill="x", padx=20, pady=(15, 5))

    tk.Label(cod_header, text="💾", font=("Segoe UI", 14), bg="white").pack(
        side="left", padx=(0, 8)
    )

    tk.Label(
        cod_header,
        text="Seleziona Codifica",
        font=("Segoe UI", 12, "bold"),
        bg="white",
        fg=colore_testo_scuro,
    ).pack(side="left")

    cod_row = tk.Frame(codifica_card, bg="white")
    cod_row.pack(fill="x", padx=20, pady=(5, 15))

    entry_codifica = tk.Entry(
        cod_row,
        font=("Segoe UI", 10),
        bg="#f8f9fa",
        fg=colore_testo_scuro,
        relief="flat",
    )
    entry_codifica.insert(0, "Seleziona file semiprimi dal database...")
    entry_codifica.pack(side="left", fill="x", expand=True, padx=(0, 10))

    tk.Button(
        cod_row,
        text="Seleziona Codifica",
        font=("Segoe UI", 10, "bold"),
        bg=colore_blu,
        fg="white",
        cursor="hand2",
        relief="flat",
        padx=20,
        pady=10,
        command=lambda: apri_file_semiprimi(entry_codifica),
    ).pack(side="right")

    # 2. CARD MESSAGGIO
    msg_card = tk.Frame(
        main,
        bg="white",
        highlightbackground=colore_bordo,
        highlightthickness=1,
        height=250,
    )
    msg_card.pack(fill="x", pady=(0, 15))
    msg_card.pack_propagate(False)

    msg_header = tk.Frame(msg_card, bg="white")
    msg_header.pack(fill="x", padx=20, pady=(15, 5))

    tk.Label(msg_header, text="✍️", font=("Segoe UI", 14), bg="white").pack(
        side="left", padx=(0, 8)
    )

    tk.Label(
        msg_header,
        text="Scrivi il Messaggio",
        font=("Segoe UI", 12, "bold"),
        bg="white",
        fg=colore_testo_scuro,
    ).pack(side="left")

    text_frame = tk.Frame(msg_card, bg="white")
    text_frame.pack(fill="both", expand=True, padx=20, pady=(5, 15))

    txt_area = tk.Text(
        text_frame,
        font=("Segoe UI", 11),
        bg="#f8f9fa",
        fg=colore_testo_scuro,
        relief="flat",
        padx=15,
        pady=15,
        wrap="word",
    )
    txt_area.pack(side="left", fill="both", expand=True)

    scrollbar = ttk.Scrollbar(text_frame, command=txt_area.yview)
    scrollbar.pack(side="right", fill="y")
    txt_area.config(yscrollcommand=scrollbar.set)

    # 3. CARD CARICA ALLEGATO
    allegato_card = tk.Frame(
        main, bg="white", highlightbackground=colore_bordo, highlightthickness=1
    )
    allegato_card.pack(fill="x", pady=(0, 20))

    all_header = tk.Frame(allegato_card, bg="white")
    all_header.pack(fill="x", padx=20, pady=(15, 5))

    tk.Label(all_header, text="📎", font=("Segoe UI", 14), bg="white").pack(
        side="left", padx=(0, 8)
    )

    tk.Label(
        all_header,
        text="Carica Allegato",
        font=("Segoe UI", 12, "bold"),
        bg="white",
        fg=colore_testo_scuro,
    ).pack(side="left")

    all_row = tk.Frame(allegato_card, bg="white")
    all_row.pack(fill="x", padx=20, pady=(5, 15))

    entry_allegato = tk.Entry(
        all_row,
        font=("Segoe UI", 10),
        bg="#f8f9fa",
        fg=colore_testo_scuro,
        relief="flat",
    )
    entry_allegato.insert(0, "Nessun allegato selezionato")
    entry_allegato.pack(side="left", fill="x", expand=True, padx=(0, 10))

    tk.Button(
        all_row,
        text="Carica Allegato",
        font=("Segoe UI", 10, "bold"),
        bg="#757575",
        fg="white",
        cursor="hand2",
        relief="flat",
        padx=20,
        pady=10,
        command=lambda: apri_file_allegato(entry_allegato),
    ).pack(side="right")

    # 4. PULSANTE AVVIA CIFRATURA
    btn_frame = tk.Frame(main, bg=colore_sfondo)
    btn_frame.pack(fill="x")

    tk.Button(
        btn_frame,
        text="Avvia Cifratura",
        font=("Segoe UI", 12, "bold"),
        bg=colore_verde,
        fg=colore_testo_scuro,
        cursor="hand2",
        relief="flat",
        padx=40,
        pady=15,
        command=lambda: avvia_cifratura(C, base, esponente, txt_area, entry_codifica),
    ).pack(side="right")

    # Gestione chiusura finestra
    def chiudi_invio():
        finestra_invia.destroy()
        root.deiconify()

    finestra_invia.protocol("WM_DELETE_WINDOW", chiudi_invio)


# /**************************/ Separazione invia / ricevi /**************************/


def verifica_operatore(seme, firma):
    risposta = {"ok": False}

    finestra = tk.Toplevel()
    finestra.title("Verifica Dati – Porta 1")
    finestra.configure(bg="#2d4d4a")

    # --- centratura finestra ---
    finestra.update_idletasks()
    larghezza = 500
    altezza = 300

    schermo_larghezza = finestra.winfo_screenwidth()
    schermo_altezza = finestra.winfo_screenheight()

    x = (schermo_larghezza // 2) - (larghezza // 2)
    y = (schermo_altezza // 2) - (altezza // 2)

    finestra.geometry(f"{larghezza}x{altezza}+{x}+{y}")

    finestra.grab_set()
    
    # Testo principale
    testo = (
        "Si prega di controllare se il seme e la firma riportati\n"
        "corrispondono a quelli dichiarati.\n\n"
    )

    tk.Label(
        finestra,
        text=testo,
        bg="#2d4d4a",
        fg="white",
        font=("Helvetica", 11),
        justify="center",
    ).pack(pady=15)

    # Seme
    tk.Label(
        finestra,
        text=f"SEME:\n{seme}",
        bg="#2d4d4a",
        fg="#90ee90",
        font=("Helvetica", 11, "bold"),
        wraplength=450,
        justify="center",
    ).pack(pady=5)

    # Firma
    tk.Label(
        finestra,
        text=f"FIRMA:\n{firma}",
        bg="#2d4d4a",
        fg="#add8e6",
        font=("Helvetica", 11, "bold"),
        wraplength=450,
        justify="center",
    ).pack(pady=5)

    # Frame pulsanti
    frame_btn = tk.Frame(finestra, bg="#2d4d4a")
    frame_btn.pack(pady=20)

    def continua():
        risposta["ok"] = True
        finestra.destroy()

    def blocca():
        risposta["ok"] = False
        finestra.destroy()

    tk.Button(
        frame_btn,
        text="CONTINUA",
        width=12,
        bg="#90ee90",
        command=continua,
    ).pack(side=tk.LEFT, padx=20)

    tk.Button(
        frame_btn,
        text="BLOCCA",
        width=12,
        bg="#ff7f7f",
        command=blocca,
    ).pack(side=tk.RIGHT, padx=20)

    finestra.wait_window()
    return risposta["ok"]


# ***********************************************************************************
# ************************* Decifra file criptato porta 1 estrae seme e firma
# ***********************************************************************************


def decifra_porta1(porta1_cifrata: dict, chiave: int) -> dict:
    """
    Decifra la porta 1 usando la chiave p.
    Ritorna un dizionario con seme e firma.
    """

    iv = porta1_cifrata["iv"]
    ciphertext = porta1_cifrata["ciphertext"]

    # derivazione chiave AES da p
    key = sha256(str(chiave).encode()).digest()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    dati_padded = cipher.decrypt(ciphertext)

    # rimozione padding PKCS#7
    pad_len = dati_padded[-1]
    dati_bytes = dati_padded[:-pad_len]

    dati = json.loads(dati_bytes.decode("utf-8"))
    return dati


# ***********************************************************************************
# ******************** Decifra file criptato porta 2 estrae k, testo liber, allegato
# ***********************************************************************************


def decifra_porta2(porta2_cifrata: dict, chiave: int) -> dict:
    key = sha256(str(chiave).encode()).digest()

    cipher = AES.new(key, AES.MODE_GCM, nonce=porta2_cifrata["nonce"])
    dati_bytes = cipher.decrypt_and_verify(
        porta2_cifrata["ciphertext"], porta2_cifrata["tag"]
    )

    dati = json.loads(dati_bytes.decode("utf-8"))

    # decodifica allegato se presente
    if dati.get("allegato") is not None:
        dati["allegato"] = base64.b64decode(dati["allegato"])
    else:
        dati["allegato"] = None

    return dati


# ***********************************************************************************
# *************************  lettura messaggio criptato
# ***********************************************************************************


def lettura_file_criptato(txt_area, entry_allegato):
    percorso = filedialog.askopenfilename(
        title="Apri file GC57",
        filetypes=[("File GC57", "*.gc57"), ("Tutti i file", "*.*")],
    )
    if not percorso:
        return

    with open(percorso, "rb") as f:
        # --- header ---
        header = f.read(7)
        if header != b"GC57-3P":
            messagebox.showerror("Errore", "File non valido o formato GC57 errato")
            return

        # --- semiprimo ---
        len_semiprimo = struct.unpack(">I", f.read(4))[0]
        semiprimo_bytes = f.read(len_semiprimo)
        semiprimo = int.from_bytes(semiprimo_bytes, "big")

        # --- porta 1 ---
        len_porta1 = struct.unpack(">I", f.read(4))[0]
        porta1_bytes = f.read(len_porta1)

    # ricostruzione porta1_cifrata
    porta1_cifrata = {"iv": porta1_bytes[:16], "ciphertext": porta1_bytes[16:]}

    # --- recupero dati segreti ---
    C = DatiCondivisi["C"]
    base = DatiCondivisi["base"]
    esponente = DatiCondivisi["esponente"]

    # --- fattorizzazione ---
    Sp = semiprimo - C
    p = gcd(Sp, Sp % C)
    q=Sp//p
    if p == 1:
        messagebox.showerror(
            "Attenzione",
            "La fattorizzazione non è andata a buon fine\nIl processo verrà annullato",
        )
        return

    # --- apertura prima porta ---
    dati_porta1 = decifra_porta1(porta1_cifrata=porta1_cifrata, chiave=q)

    seme = dati_porta1["seme"]
    firma = dati_porta1["firma"]

    if not verifica_operatore(seme, firma):
        messagebox.showinfo(
        "Operazione interrotta", "La decifratura è stata bloccata dall'operatore."
        )
        return
    random.seed(seme)
    basso = esponente - 3
    alto = esponente
    k = random.randint(base**basso, base**alto)
    k_verifica = Sp // (C - k)
    if k_verifica == p:
        pass
    else:
        messagebox.showerror(
            "Attenzione",
            "la verifica di K non è andata a buon fine\nIl processo verrà annullato",
        )
    chiave_decriptazione_seconda_porta = k
    with open(percorso, "rb") as f:
        # header
        f.read(7)

        # semiprimo
        len_semiprimo = struct.unpack(">I", f.read(4))[0]
        f.read(len_semiprimo)

        # porta 1
        len_porta1 = struct.unpack(">I", f.read(4))[0]
        f.read(len_porta1)

        # porta 2
        len_porta2 = struct.unpack(">I", f.read(4))[0]
        porta2_bytes = f.read(len_porta2)

        porta2_cifrata = {
        "nonce": porta2_bytes[:12],
        "ciphertext": porta2_bytes[12:-16],
        "tag": porta2_bytes[-16:],
    }

    dati_porta2 = decifra_porta2(
        porta2_cifrata=porta2_cifrata, chiave=chiave_decriptazione_seconda_porta
    )

    if dati_porta2["k"] != chiave_decriptazione_seconda_porta:
        messagebox.showerror("Errore", "Chiave K non coerente.\nAccesso negato.")
        return

    testo = dati_porta2["testo"]
    allegato = dati_porta2["allegato"]
    nome_allegato = dati_porta2.get("nome_allegato")

    txt_area.delete("1.0", tk.END)
    txt_area.insert(tk.END, testo)

    if nome_allegato:
        entry_allegato.delete(0, tk.END)
        entry_allegato.insert(0, nome_allegato)

        percorso = os.path.join(DIR_ALLEGATI, nome_allegato)

        # scrittura file
        with open(percorso, "wb") as f:
            f.write(allegato)

        messagebox.showinfo(
            "Allegato salvato", f"Allegato salvato correttamente:\n{percorso}"
        )


# ***********************************************************************************
# ************************* Finestra ricevi V0.0.2
# ***********************************************************************************
def apri_finestra_ricevi():
    finestra_ricevi = tk.Toplevel(root)
    finestra_ricevi.title("GC57 RICEVI v2 - Decifratura 3P")
    finestra_ricevi.geometry("750x600")

    # Colori moderni
    colore_sfondo = "#f5f5f5"
    colore_card = "#ffffff"
    colore_verde = "#90EE90"
    colore_testo_scuro = "#212121"
    colore_testo_chiaro = "#0E0505"
    colore_bordo = "#e0e0e0"

    finestra_ricevi.configure(bg=colore_sfondo)

    # Header
    header = tk.Frame(finestra_ricevi, bg="white", height=80)
    header.pack(fill="x")
    header.pack_propagate(False)

    tk.Label(
        header,
        text="RICEVI DATI CRIPTATI - VERIFICA INTEGRITÀ",
        font=("Segoe UI", 18, "bold"),
        bg="white",
        fg=colore_testo_scuro,
    ).pack(pady=25)

    # Main area
    main = tk.Frame(finestra_ricevi, bg=colore_sfondo)
    main.pack(fill="both", expand=True, padx=30, pady=20)

    # CARD MESSAGGIO DECIFRATO (con altezza fissa)
    msg_card = tk.Frame(
        main,
        bg="white",
        highlightbackground=colore_bordo,
        highlightthickness=1,
        height=350,
    )
    msg_card.pack(fill="x", pady=(0, 15))
    msg_card.pack_propagate(False)  # Blocca l'altezza

    msg_header = tk.Frame(msg_card, bg="white")
    msg_header.pack(fill="x", padx=20, pady=(15, 5))

    tk.Label(msg_header, text="📄", font=("Segoe UI", 14), bg="white").pack(
        side="left", padx=(0, 8)
    )

    tk.Label(
        msg_header,
        text="Messaggio Decifrato",
        font=("Segoe UI", 12, "bold"),
        bg="white",
        fg=colore_testo_scuro,
    ).pack(side="left")

    # Text area
    text_frame = tk.Frame(msg_card, bg="white")
    text_frame.pack(fill="both", expand=True, padx=20, pady=(5, 15))

    txt_area = tk.Text(
        text_frame,
        font=("Segoe UI", 11),
        bg="#f8f9fa",
        fg=colore_testo_chiaro,
        relief="flat",
        padx=15,
        pady=15,
        wrap="word",
    )
    txt_area.pack(side="left", fill="both", expand=True)

    scrollbar = ttk.Scrollbar(text_frame, command=txt_area.yview)
    scrollbar.pack(side="right", fill="y")
    txt_area.config(yscrollcommand=scrollbar.set)

    # Bottom panel (DEVE ESSERE VISIBILE)
    bottom = tk.Frame(main, bg=colore_sfondo)
    bottom.pack(fill="x")

    # Card allegato
    allegato_card = tk.Frame(
        bottom, bg="white", highlightbackground=colore_bordo, highlightthickness=1
    )
    allegato_card.pack(side="left", fill="x", expand=True, padx=(0, 15))

    allegato_inner = tk.Frame(allegato_card, bg="white")
    allegato_inner.pack(fill="x", padx=20, pady=15)

    tk.Label(
        allegato_inner,
        text="Allegato",
        font=("Segoe UI", 10, "bold"),
        bg="white",
        fg=colore_testo_scuro,
        width=10,
        anchor="w",
    ).pack(side="left")

    entry_allegato = tk.Entry(
        allegato_inner,
        font=("Segoe UI", 10),
        bg="#f8f9fa",
        fg=colore_testo_chiaro,
        relief="flat",
    )
    entry_allegato.pack(side="left", fill="x", expand=True, padx=(10, 0))

    # Button Carica e Decifra
    tk.Button(
        bottom,
        text="Carica e Decifra",
        font=("Segoe UI", 12, "bold"),
        bg=colore_verde,
        fg=colore_testo_scuro,
        cursor="hand2",
        relief="flat",
        padx=40,
        pady=15,
        command=lambda: lettura_file_criptato(txt_area, entry_allegato),
    ).pack(side="right")

    # Gestione chiusura finestra
    def chiudi_ricevi():
        finestra_ricevi.destroy()
        root.deiconify()

    finestra_ricevi.protocol("WM_DELETE_WINDOW", chiudi_ricevi)


if __name__ == "__main__":

    # ***********************************************************************************
    # ************************* Finestra principale V0.0.2
    # ***********************************************************************************

    root = tk.Tk()
    root.withdraw()

    parametri = bootstrap_gc57()
    C, base, esponente = parametri

    root.deiconify()

    # Colori moderni
    colore_fondo_finestra = "#f5f5f5"
    colore_card = "#ffffff"
    colore_verde = "#90EE90"
    colore_blu = "#2196F3"
    colore_testo_scuro = "#212121"
    colore_testo_chiaro = "#757575"
    colore_bordo = "#e0e0e0"

    root.title("GC57-3P Security System")
    root.geometry("600x400")
    root.configure(bg=colore_fondo_finestra)

    # Definizione dei font moderni
    font_titolo = font.Font(family="Segoe UI", size=28, weight="bold")
    font_sottotitolo = font.Font(family="Segoe UI", size=10)
    font_bottoni = font.Font(family="Segoe UI", size=11, weight="bold")
    font_footer = font.Font(family="Segoe UI", size=9)

    # Header con titolo
    frame_header = tk.Frame(root, bg=colore_fondo_finestra)
    frame_header.pack(fill='x', pady=(30, 10))

    label_titolo = tk.Label(
        frame_header,
        text="GC57-3P",
        font=font_titolo,
        bg=colore_fondo_finestra,
        fg=colore_testo_scuro
    )
    label_titolo.pack()

    label_sottotitolo = tk.Label(
        frame_header,
        text="Sistema di Sicurezza Basato su Semiprimi",
        font=font_sottotitolo,
        bg=colore_fondo_finestra,
        fg=colore_testo_chiaro
    )
    label_sottotitolo.pack()

    # Container per le card (invece di frame_pulsanti)
    container_card = tk.Frame(root, bg=colore_fondo_finestra)
    container_card.pack(expand=True, fill='both', padx=40, pady=20)
    
    container_card.grid_columnconfigure(0, weight=1)
    container_card.grid_columnconfigure(1, weight=1)
    container_card.grid_rowconfigure(0, weight=1)

    # Funzioni helper per nascondere/mostrare finestra principale
    def apri_ricezione_e_nascondi():
        root.withdraw()
        apri_finestra_ricevi()

    def apri_invio_e_nascondi():
        root.withdraw()
        apri_finestra_invia(C, base, esponente)

    # CARD RICEZIONE (sinistra)
    # Outer frame per padding
    outer_ricezione = tk.Frame(container_card, bg=colore_fondo_finestra)
    outer_ricezione.grid(row=0, column=0, padx=15, pady=10, sticky='nsew')

    # Card con bordo
    card_ricezione = tk.Frame(
        outer_ricezione,
        bg=colore_card,
        highlightbackground=colore_bordo,
        highlightthickness=1
    )
    card_ricezione.pack(expand=True, fill='both', padx=3, pady=3)

    # Contenuto card
    content_ricezione = tk.Frame(card_ricezione, bg=colore_card)
    content_ricezione.pack(expand=True, padx=25, pady=25)

    tk.Label(
        content_ricezione,
        text="📥 Ricezione",
        font=('Segoe UI', 16, 'bold'),
        bg=colore_card,
        fg=colore_testo_scuro
    ).pack(pady=(10, 5))

    tk.Label(
        content_ricezione,
        text="Decifra messaggi\ne allegati ricevuti",
        font=('Segoe UI', 10),
        bg=colore_card,
        fg=colore_testo_scuro,
        justify='center'
    ).pack(pady=(0, 20))

    btn_ricezione = tk.Button(
        content_ricezione,
        text="Apri",
        command=apri_ricezione_e_nascondi,
        font=font_bottoni,
        bg=colore_verde,
        fg=colore_testo_scuro,
        cursor='hand2',
        relief='flat',
        bd=0,
        padx=30,
        pady=12
    )
    btn_ricezione.pack()

    # CARD INVIO (destra)
    # Outer frame per padding
    outer_invio = tk.Frame(container_card, bg=colore_fondo_finestra)
    outer_invio.grid(row=0, column=1, padx=15, pady=10, sticky='nsew')

    # Card con bordo
    card_invio = tk.Frame(
        outer_invio,
        bg=colore_card,
        highlightbackground=colore_bordo,
        highlightthickness=1
    )
    card_invio.pack(expand=True, fill='both', padx=3, pady=3)

    # Contenuto card
    content_invio = tk.Frame(card_invio, bg=colore_card)
    content_invio.pack(expand=True, padx=25, pady=25)

    tk.Label(
        content_invio,
        text="📤 Invio",
        font=('Segoe UI', 16, 'bold'),
        bg=colore_card,
        fg=colore_testo_scuro
    ).pack(pady=(10, 5))

    tk.Label(
        content_invio,
        text="Cifra e proteggi\ni tuoi messaggi",
        font=('Segoe UI', 10),
        bg=colore_card,
        fg=colore_testo_chiaro,
        justify='center'
    ).pack(pady=(0, 20))

    btn_invio = tk.Button(
        content_invio,
        text="Apri",
        command=apri_invio_e_nascondi,
        font=font_bottoni,
        bg=colore_blu,
        fg="white",
        cursor='hand2',
        relief='flat',
        bd=0,
        padx=30,
        pady=12
    )
    btn_invio.pack()

    # Footer
    frame_footer = tk.Frame(root, bg=colore_fondo_finestra)
    frame_footer.pack(side='bottom', fill='x', pady=10)

    tk.Label(
        frame_footer,
        text="GC57-3P V0.0.1 • Dicembre 2025 • Claudio Govi",
        font=font_footer,
        bg=colore_fondo_finestra,
        fg=colore_testo_chiaro
    ).pack()

    # Avvio del ciclo principale
    root.mainloop()
