import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import secrets
import random
from random import randint
import os
from math import gcd
from gmpy2 import next_prime as nprime
import time
from tkinter import filedialog
import base64
import hashlib
from tkinter import simpledialog


T = time.time_ns()
counter = 0
seed = hash((T, counter))
random.seed(seed)

# --- VARIABILI GLOBALI DI STATO ---
DatiCondivisi = {
    "a": None,
    "b": None,
    "campo": None,
    "nascosto_x": None,
    "nascosto_y": None,
    "p_primo": None,
    "q_primo": None,
    "semiprimo": None,
    "esp1": None,
    "Be": None,
}

# ****************************************************************
# ********** Crea password file segreto
# ****************************************************************


def deriva_chiave_da_password(password: str) -> bytes:
    """Deriva una chiave binaria dalla password (demo)."""
    return hashlib.sha256(password.encode()).digest()


def codifica_con_password(dati: str, password: str) -> str:
    chiave = deriva_chiave_da_password(password)
    dati_bytes = dati.encode("utf-8")

    cifrato = bytes(
        dati_bytes[i] ^ chiave[i % len(chiave)] for i in range(len(dati_bytes))
    )

    return base64.b64encode(cifrato).decode("ascii")


# ****************************************************************
# ********** Individuazione numeri primi con gmpy2 nprime
# ****************************************************************

def get_next_prime(start_num):
    """Trova il prossimo numero primo > start_num usando la libreria gmpy2."""
    return nprime(start_num)


# --- 2. LOGICA DI BACKGROUND ---
MIN_BIT_A = 990
DIFFERENZA_BIT_MINIMA = 150
MAX_BIT_LIMIT = 5000


def verifica_metriche(a, b):
    bit_a = a.bit_length()
    bit_b = b.bit_length()
    if bit_a < MIN_BIT_A:
        return False, f"ERRORE: A troppo piccolo ({bit_a} < {MIN_BIT_A} bit)."
    if bit_b <= (bit_a + DIFFERENZA_BIT_MINIMA):
        return (
            False,
            f"ERRORE: B troppo vicino ad A (Diff. < {DIFFERENZA_BIT_MINIMA} bit).",
        )
    return True, "Metriche OK."

# ****************************************************************
# ********** Creazione dati
# ****************************************************************

def creazione_dati():
    """
    Apre una finestra per configurare e avviare la creazione dei file di dati.
    """

    win_creazione = tk.Toplevel(root)
    win_creazione.title("Creazione Dati")
    win_creazione.geometry("400x250")
    win_creazione.resizable(False, False)

    # Centra la finestra
    root_x = root.winfo_x()
    root_y = root.winfo_y()
    root_w = root.winfo_width()
    root_h = root.winfo_height()
    win_w = 400
    win_h = 250
    x = root_x + (root_w // 2) - (win_w // 2)
    y = root_y + (root_h // 2) - (win_h // 2)
    win_creazione.geometry(f'{win_w}x{win_h}+{x}+{y}')

    frame = tk.Frame(win_creazione, padx=10, pady=10)
    frame.pack(fill="both", expand=True)

    # --- Input Fields ---
    tk.Label(frame, text="Inserire nome file dati:").grid(row=0, column=0, sticky="w", pady=5)
    entry_nome_file = tk.Entry(frame, width=30)
    entry_nome_file.grid(row=0, column=1, sticky="ew", pady=5)
    entry_nome_file.insert(0, "database_sicurezza")

    tk.Label(frame, text="Inserire quantità:").grid(row=1, column=0, sticky="w", pady=5)
    entry_quantita = tk.Entry(frame, width=10)
    entry_quantita.grid(row=1, column=1, sticky="w", pady=5)
    entry_quantita.insert(0, "1")

    # --- Status Labels ---
    status_frame = tk.LabelFrame(frame, text="Stato Creazione", padx=10, pady=10)
    status_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=10)

    status_labels_text = [
        "Database creato",
        "File condivisione segreto creato",
        "File estensione pagliaio creato"
    ]
    status_indicators = []

    for i, text in enumerate(status_labels_text):
        indicator = tk.Frame(status_frame, width=15, height=15, bg="lightgrey", bd=1, relief="sunken")
        indicator.grid(row=i, column=0, padx=5, pady=2)
        status_indicators.append(indicator)
        tk.Label(status_frame, text=text).grid(row=i, column=1, sticky="w")

    # --- Start Button ---
    btn_avvia = tk.Button(
        frame,
        text="Avvia",
        command=lambda: avvia_processo_creazione(status_indicators, entry_nome_file, entry_quantita)
    )
    btn_avvia.grid(row=2, column=0, columnspan=2, pady=10)


def avvia_processo_creazione(indicators, entry_nome_file, entry_quantita):
    base_a = DatiCondivisi["a"]
    base_b = DatiCondivisi["b"]
    I = DatiCondivisi["campo"]
    base = DatiCondivisi["Be"]
    esponente = DatiCondivisi["esp1"]
    C = base_b - 1

    nome_database = entry_nome_file.get()
    quantita = int(entry_quantita.get())

    # --- richiesta password (NON viene salvata) ---
    password = simpledialog.askstring(
        "Password", "Inserire password per proteggere il file segreto:", show="*"
    )
    if not password:
        scrivi_log("Creazione annullata: password mancante.", "errore")
        return

    scrivi_log("Avvio creazione file...", "normale")

    # --- 1. Database semiprimi offuscati ---
    with open(nome_database, "w", encoding="utf-8") as scrivi:
        for i in range(quantita):
            primo1 = nprime(base_a + randint(1, I))
            primo2 = nprime(base_b + randint(1, I))
            S = primo1 * primo2

            if gcd(S, S % C) != 1:
                scrivi.write(str(S + C) + "\n")
            else:
                scrivi_log(f"Numero {i} non valido, scartato.", "errore")

    indicators[0].config(bg="green")

    # --- 2. File segreto cifrato (password NON memorizzata) ---
    # Header fisso per riconoscere decodifica valida
    dati_segreti = "GC57-SECRET-V1\n" f"{C}\n" f"{base}\n" f"{esponente}\n"

    dati_codificati = codifica_con_password(dati_segreti, password)

    with open("File_Segreto_GC57.dat", "w", encoding="utf-8") as scrivi:
        scrivi.write(dati_codificati)

    indicators[1].config(bg="green")
    indicators[2].config(bg="green")

    scrivi_log("Fine creazione file segreto cifrato.", "successo")


# ****************************************************************
# ********** Generazione numeri con secret
# ****************************************************************

def genera_secrets_con_target(target_bits):
    variazione = secrets.randbelow(5) - 2
    bits_per_a = target_bits + variazione
    if bits_per_a < MIN_BIT_A:
        bits_per_a = MIN_BIT_A
    a = secrets.randbits(bits_per_a) | 1
    bits_per_b = bits_per_a +250 + secrets.randbelow(50)
    b = secrets.randbits(bits_per_b) | 1
    return a, b


def calcola_campo_gc57(a, b):
    chiave = b - 1
    try:
        modulo_val = ((a + 1) * (b + 1)) % chiave
        if modulo_val == 0:
            return None, None, "Errore Matematico: Modulo 0."
        campo = (chiave // modulo_val) * 2
        return (
            campo,
            f"Lunghezza: {campo.bit_length()} bit | Cifre: {len(str(campo))}",
            None,
        )
    except Exception as e:
        return None, None, f"Errore imprevisto: {e}"


def genera_sfida_semiprimo(val_a, val_b, val_campo):
    if val_campo <= 2:
        return None, None, None, None, None, "Errore: Campo troppo piccolo."
    offset_x = secrets.randbelow(val_campo - 1) + 1
    offset_y = secrets.randbelow(val_campo - 1) + 1
    p_primo = get_next_prime(val_a + offset_x)
    q_primo = get_next_prime(val_b + offset_y)
    final_x = p_primo - val_a
    final_y = q_primo - val_b
    semiprimo = p_primo * q_primo
    return final_x, final_y, p_primo, q_primo, semiprimo, None

# --- FUNZIONI UTILI ---
def mostra_help_a():
    messagebox.showinfo("Info A", "A deve essere >= 1000 bit.\nIl valore di default è stato impostato al minimo di 150 bit e un massimo di 5000 bit\n")


def mostra_help_b():
    messagebox.showinfo("Info B", "Il valore di B viene impostato in automatico a seconda del valore impostato su A")


def mostra_help_campo():
    messagebox.showinfo("Info Campo:","Questo valore viene trovato in base alla distaza tra A e B\nIl valore impostato di default si può modificare\n diminuendo o aumentando la differenza tra A e B")


def mostra_help_pagliaio():
    help_win = tk.Toplevel(root)
    help_win.title("Spiegazione del Test Pagliaio")
    help_win.geometry("550x450")
    help_win.resizable(False, False)

    # Centra la finestra di aiuto rispetto alla finestra principale
    root_x = root.winfo_x()
    root_y = root.winfo_y()
    root_w = root.winfo_width()
    root_h = root.winfo_height()
    win_w = 550
    win_h = 450
    x = root_x + (root_w // 2) - (win_w // 2)
    y = root_y + (root_h // 2) - (win_h // 2)
    help_win.geometry(f'{win_w}x{win_h}+{x}+{y}')

    testo_spiegazione = """Test Pagliaio
Il Test Pagliaio è una procedura di verifica progettata per controllare la correttezza strutturale del sistema GC57 e, in particolare, della selezione del valore k.

Ruolo del valore k:
Il valore k serve a estrarre, in modo deterministico ma non prevedibile, un numero all’interno di un intervallo molto ampio chiamato pagliaio.

Concetto di pagliaio
Dato un semiprimo S, composto da due fattori primi p e q, nella matematica classica l’unica divisione significativa di S è quella per p o per q.

Il sistema GC57 non utilizza direttamente questa divisione classica.
Esso lavora invece su una struttura derivata, nella quale esiste un insieme molto ampio di valori che, se utilizzati correttamente, permettono di ricondurre in modo stabile al fattore p.

Questo insieme costituisce il pagliaio.

Il valore k (l’“ago”) è un singolo elemento estratto da questo insieme tramite il seme.
In assenza della chiave B-1, individuare il valore corretto equivale a cercare un ago in un pagliaio
Il test è molto veloce e viene ripetuto per il valore inserito nella casella a fianco del pulsante "Test Pagliaio".

Scopo del test:

Il Test Pagliaio verifica che:

il pagliaio sia stato stimato correttamente;

qualunque valore valido estratto all’interno di esso restituisca sempre p secondo l’operazione prevista dal sistema.

Se il test fallisce, significa che:

la stima del pagliaio è errata,

oppure che i parametri scelti (A, B, distanza, campo) non sono adeguati.

Esecuzione

Il test è rapido e viene ripetuto per il numero di iterazioni indicato nella casella accanto al pulsante “Test Pagliaio”.
"""

    text_area = scrolledtext.ScrolledText(help_win, wrap=tk.WORD, font=("Arial", 10), padx=10, pady=10)
    text_area.insert(tk.INSERT, testo_spiegazione)
    text_area.configure(state="disabled")
    text_area.pack(expand=True, fill="both", padx=10, pady=5)

    tk.Button(help_win, text="Chiudi", command=help_win.destroy, width=10).pack(pady=10)

def scrivi_log(messaggio, tipo="normale"):
    log_area.configure(state="normal")
    tag = None
    if tipo == "errore":
        tag = "tag_errore"
    elif tipo == "successo":
        tag = "tag_successo"
    elif tipo == "dati_input":
        tag = "tag_input"
    elif tipo == "calcolo_xy":
        tag = "tag_xy"
    log_area.insert(tk.END, ">> " + messaggio + "\n", tag)
    log_area.see(tk.END)
    log_area.configure(state="disabled")


# --- AZIONI GUI ---


def comando_genera():
    try:
        bit_target = int(entry_bits.get())
    except ValueError:
        scrivi_log("Target Bit non valido.", "errore")
        return
    if bit_target > MAX_BIT_LIMIT or bit_target < MIN_BIT_A:
        scrivi_log("Bit fuori range.", "errore")
        return

    a, b = genera_secrets_con_target(bit_target)
    text_a.delete("1.0", tk.END)
    text_a.insert("1.0", str(a))
    text_b.delete("1.0", tk.END)
    text_b.insert("1.0", str(b))
    text_campo.configure(state="normal")
    text_campo.delete("1.0", tk.END)
    text_campo.configure(state="disabled")
    text_semiprimo.configure(state="normal")
    text_semiprimo.delete("1.0", tk.END)
    text_campo.configure(state="disabled")
    lbl_stats_campo.config(text="")

    # Reset Globale
    for key in DatiCondivisi:
        DatiCondivisi[key] = None
    scrivi_log(f"Generati nuovi valori (Target ~{bit_target} bit).", "normale")

# ****************************************************************
# ********** Analizza i dati del campo
# ****************************************************************

def comando_analizza_campo_e_calcola_tutto():
    """
    QUESTA E' LA FUNZIONE CHIAVE:
    1. Valida Input A e B
    2. Calcola il Campo GC57
    3. GENERA SUBITO IL SEMIPRIMO IN BACKGROUND
    """
    val_a_str = text_a.get("1.0", "end-1c").strip()
    val_b_str = text_b.get("1.0", "end-1c").strip()
    if not val_a_str or not val_b_str:
        scrivi_log("Campi vuoti.", "errore")
        return
    try:
        val_a = int(val_a_str)
        val_b = int(val_b_str)
    except ValueError:
        scrivi_log("Numeri non validi.", "errore")
        return

    scrivi_log(
        f"INPUT -> A: {val_a.bit_length()} bit | B: {val_b.bit_length()} bit",
        "dati_input",
    )
    esito, msg = verifica_metriche(val_a, val_b)
    if not esito:
        scrivi_log(msg, "errore")
        return

    # ****************************************************************
    # ********** Calcolo del campo
    # ****************************************************************

    campo, stats, errore = calcola_campo_gc57(val_a, val_b)
    if errore:
        scrivi_log(errore, "errore")
        return

    text_campo.configure(state="normal")
    text_campo.delete("1.0", tk.END)
    text_campo.insert("1.0", str(campo))
    text_campo.configure(state="disabled")
    lbl_stats_campo.config(text=stats)
    scrivi_log(f"CAMPO CALCOLATO -> {stats}", "successo")

    # 2. Generazione Automatica Semiprimo (Background)
    scrivi_log("Generazione automatica del Semiprimo N in corso...", "normale")
    root.update()  # Aggiorna la grafica
    x, y, p, q, semiprimo, err_gen = genera_sfida_semiprimo(val_a, val_b, campo)

    if err_gen:
        scrivi_log(err_gen, "errore")
        return

    # 3. Mostra Semiprimo
    text_semiprimo.configure(state="normal")
    text_semiprimo.delete("1.0", tk.END)
    text_semiprimo.insert("1.0", str(semiprimo))
    text_semiprimo.configure(state="disabled")
    lbl_stats_semiprimo.config(text=f"Lunghezza: {semiprimo.bit_length()} bit")
    scrivi_log(f"SEMIPRIMO GENERATO ({semiprimo.bit_length()} bit).", "successo")

    # 4. Salvataggio Dati
    DatiCondivisi["a"] = val_a
    DatiCondivisi["b"] = val_b
    DatiCondivisi["campo"] = campo
    DatiCondivisi["nascosto_x"] = x
    DatiCondivisi["nascosto_y"] = y
    DatiCondivisi["p_primo"] = p
    DatiCondivisi["q_primo"] = q
    DatiCondivisi["semiprimo"] = semiprimo

# ****************************************************************
# ********** Test del pagliaio
# ****************************************************************

def test_pagliaio():
    """Esegue il test 'pagliaio' recuperando i dati necessari."""
    # 1. Controlla se i dati necessari sono disponibili
    if any(
        DatiCondivisi[key] is None for key in ["b", "semiprimo", "p_primo"]
    ):
        messagebox.showwarning(
            "Dati Mancanti",
            "Prima genera e analizza i valori con 'Analizza e Calcola...'",
        )
        return

    # 2. Recupera il numero di test dall'entry
    try:
        num_test = int(entry_test_pagliaio.get())
    except ValueError:
        scrivi_log("Numero di test non valido.", "errore")
        return

    # 3. Recupera i valori per il test
    chiave = DatiCondivisi["b"] - 1
    semiprimo_n = DatiCondivisi["semiprimo"]
    primo_p = DatiCondivisi["p_primo"]
    cicli=entry_test_pagliaio.get()
    if cicli==0:
        messagebox.showwarning("Attenzione"," manca il numero dei cicli di test")
        return
    cicli=int(cicli)
    Be=10
    DatiCondivisi["Be"]=Be
    for i in range(1, 3000):
        r1 = semiprimo_n // (chiave - Be**i)
        if r1 != primo_p:
            esp1 = i - 1
            break
    DatiCondivisi["esp1"]=esp1
    scrivi_log(f"Avvio Test Pagliaio con {num_test} iterazioni.", "normale")
    # --- Inizio test
    
    for i in range(cicli):
        p1=randint(1,Be**esp1)
        p2=chiave-p1
        if semiprimo_n//p2!=primo_p:
            messagebox.showwarning("Attenzione",f"Test fallito al numero {i} ")
            return
    #messagebox.showinfo("Successo:","il test è andato a buon fine")
    risposta=messagebox.askquestion("Il test è stato superato","Procedere con la creazione dati?:\n(SI) per procedere\n(NO) per annullare")
    if risposta=="yes":
        creazione_dati()
    else:
        return  


def salva_log_su_file():
    """Salva il contenuto del log su un file di testo"""
    contenuto = log_area.get("1.0", tk.END)  # Legge tutto il testo del log
    if not contenuto.strip():
        messagebox.showinfo("Log Vuoto", "Non c'è nulla da salvare.")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("File di Testo", "*.txt"), ("Tutti i file", "*.*")],
        title="Salva Log Operazioni",
    )

    if file_path:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(contenuto)
            messagebox.showinfo("Successo", f"Log salvato in:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Errore", f"Impossibile salvare il file:\n{e}")


# --- GUI ---
root = tk.Tk()
root.title("Progetto Sicurezza GC57. Creazione dati per il suo funzionamento")
root.geometry("900x780")
# -- LOG --
frame_log = tk.LabelFrame(
    root, text=" Log Operazioni ", font=("Arial", 10, "bold"), height=130
)
frame_log.pack(side=tk.BOTTOM, fill="x", padx=10, pady=10)
frame_log.pack_propagate(False)

# 1. PRIMA inseriamo il bottone (così sta in alto)
btn_save_log = tk.Button(
    frame_log,
    text="Salva Log su File",
    command=salva_log_su_file,
    font=("Arial", 8),
    bg="#e0e0e0",
)
btn_save_log.pack(anchor="ne", padx=5, pady=0)  # 'ne' = Nord-Est (Alto a Destra)

# 2. POI inseriamo l'area di testo (che riempie il resto dello spazio)
log_area = scrolledtext.ScrolledText(frame_log, font=("Consolas", 9))
log_area.pack(fill="both", expand=True, padx=5, pady=5)
log_area.configure(state="disabled")

# 3. Infine configuriamo i colori
log_area.tag_config("tag_errore", foreground="red")
log_area.tag_config("tag_successo", foreground="green")
log_area.tag_config("tag_input", foreground="blue")
log_area.tag_config("tag_xy", foreground="purple")

# TAB 1
tab1 = tk.Frame(root)
tab1.pack(fill="both", expand=True, padx=10, pady=5)
frame_input = tk.Frame(tab1)
frame_input.pack(pady=5, padx=20)
tk.Label(
    frame_input, text="Target Bit (A):", font=("Arial", 11, "bold"), fg="blue"
).grid(row=0, column=0, sticky="e", pady=5)
entry_bits = tk.Entry(frame_input, width=10, font=("Consolas", 11), justify="center")
entry_bits.insert(0, "1000")
entry_bits.grid(row=0, column=1, sticky="w", pady=5)
tk.Label(frame_input, text="Valore A:", font=("Arial", 11, "bold")).grid(
    row=1, column=0, sticky="ne", pady=5
)
text_a = tk.Text(frame_input, width=70, height=3, font=("Consolas", 10))
text_a.grid(row=1, column=1, pady=5)
tk.Button(frame_input, text="?", width=3, bg="#DDDDDD", command=mostra_help_a).grid(
    row=1, column=2, padx=5, sticky="n", pady=5
)
tk.Label(frame_input, text="Valore B:", font=("Arial", 11, "bold")).grid(
    row=2, column=0, sticky="ne", pady=5
)
text_b = tk.Text(frame_input, width=70, height=3, font=("Consolas", 10))
text_b.grid(row=2, column=1, pady=5)
tk.Button(frame_input, text="?", width=3, bg="#DDDDDD", command=mostra_help_b).grid(
    row=2, column=2, padx=5, sticky="n", pady=5
)
frame_btn1 = tk.Frame(tab1)
frame_btn1.pack(pady=10)

tk.Button(
    frame_btn1,
    text="Genera Valori",
    command=comando_genera,
    bg="lightblue",
    font=("Arial", 10),
    padx=10,
).pack(side=tk.LEFT, padx=10)

tk.Button(
    frame_btn1,
    text="Analizza e Calcola Campo - Crea il Semiprimo",
    command=comando_analizza_campo_e_calcola_tutto,
    bg="lightgreen",
    font=("Arial", 10, "bold"),
    padx=10,
).pack(side=tk.LEFT, padx=10)


# * visualizzazione campo
frame_res1 = tk.LabelFrame(
    tab1, text=" Risultato: CAMPO ", font=("Arial", 10, "bold"), fg="darkblue"
)

frame_res1.pack(pady=10, padx=20)

frame_res1.columnconfigure(1, weight=1)
lbl_stats_campo = tk.Label(
    frame_res1, text="", font=("Arial", 9, "italic"), fg="#555555"
)
lbl_stats_campo.grid(row=0, column=0, columnspan=2, sticky="w", padx=10)
text_campo = tk.Text(
    frame_res1,
    width=80,
    height=3,
    font=("Consolas", 10),
    bg="#FFA200",
    state="disabled",
)
text_campo.grid(row=1, column=0, padx=10, pady=5)
tk.Button(frame_res1, text="?", width=1, bg="#DDDDDD", command=mostra_help_campo).grid(
    row=1, column=1, sticky="n", pady=5, padx=5
)

# * visualizzazione semiprimo

frame_res2 = tk.LabelFrame(
    tab1, text=" Risultato: Semiprimo ", font=("Arial", 10, "bold"), fg="darkblue"
)

frame_res2.pack(pady=10, padx=20)

frame_res2.columnconfigure(0, weight=1)  # Colonna 0 (Text) si espande
lbl_stats_semiprimo = tk.Label(
    frame_res2, text="", font=("Arial", 9, "italic"), fg="#555555"
)
lbl_stats_semiprimo.grid(row=0, column=0, columnspan=2, sticky="w", padx=10)
text_semiprimo = tk.Text(
    frame_res2,
    height=10,  # Aumentata l'altezza
    font=("Consolas", 10),
    bg="#4E8FCC",
    fg="black",
    state="disabled",
)
text_semiprimo.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
tk.Button(frame_res2, text="?", width=1, bg="#DDDDDD", command=mostra_help_campo).grid(
    row=1, column=1, sticky="n", pady=5, padx=5
)

# * visualizzazione test pagliaio
tk.Button(
    tab1,
    text="Test Pagliaio",
    command=test_pagliaio,
    bg="#3152AA",
    fg="#F0E840",
    font=("Arial", 10),
).place(relx=0.4, rely=0.95, anchor="c")

tk.Button(tab1, text="?", width=3, command=mostra_help_pagliaio).place(
    relx=0.47, rely=0.95, anchor="c"
)
entry_test_pagliaio = tk.Entry(
    tab1, width=4, font=("Consolas", 10), justify="center"
)
entry_test_pagliaio.insert(0, "10")
entry_test_pagliaio.place(relx=0.55, rely=0.95, anchor="c")

root.mainloop()
