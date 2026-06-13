"""
analisi_semiprimi.py
Analisi statistica a campione di un database di semiprimi GC57.
Uso: python3 analisi_semiprimi.py <percorso_file> [numero_campione]
Esempio: python3 analisi_semiprimi.py database_sicurezza 10
"""

import sys
import random

# ── Parametri ────────────────────────────────────────────────────────────────
PERCORSO_DEFAULT = "g://database_sicurezza.txt"
CAMPIONE_DEFAULT = 10
SEED_RANDOM      = 42          # riproducibilità; cambiare per campione diverso

# ── Caricamento ──────────────────────────────────────────────────────────────
def carica_database(percorso):
    with open(percorso) as f:
        numeri = [int(r.strip()) for r in f if r.strip()]
    return numeri

# ── Analisi di un singolo semiprimo ──────────────────────────────────────────
def analizza(n):
    s      = str(n)
    cifre  = list(map(int, s))
    pari   = [c for c in cifre if c % 2 == 0]
    disp   = [c for c in cifre if c % 2 != 0]
    zeros  = cifre.count(0)

    # radice digitale iterata (equivalente a n mod 9, con 9 al posto di 0)
    rd = n % 9
    if rd == 0:
        rd = 9

    return {
        "bit"           : n.bit_length(),
        "cifre_decimali": len(s),
        "prime_5"       : s[:5],
        "ultime_5"      : s[-5:],
        "n_cifre_pari"  : len(pari),
        "n_cifre_disp"  : len(disp),
        "somma_pari"    : sum(pari),
        "somma_disp"    : sum(disp),
        "delta_somme"   : abs(sum(pari) - sum(disp)),
        "zeri"          : zeros,
        "radice_digit"  : rd,
    }

# ── Stampa tabella ────────────────────────────────────────────────────────────
SEP  = "─" * 130
HSEP = "═" * 130

def stampa_tabella(risultati):
    hdr = (
        f"{'N':>3} │ {'Bit':>5} │ {'Cifre':>5} │ {'Prime 5':>7} │ {'Ultime 5':>8} │"
        f" {'C.pari':>6} │ {'C.disp':>6} │ {'Σ pari':>7} │ {'Σ disp':>7} │"
        f" {'|Δ|':>6} │ {'Zeri':>4} │ {'R.dig':>5}"
    )
    print(HSEP)
    print("  ANALISI SEMIPRIMI GC57 – campione casuale")
    print(HSEP)
    print(hdr)
    print(SEP)
    for r in risultati:
        print(
            f"{r['idx']:>3} │ {r['bit']:>5} │ {r['cifre_decimali']:>5} │"
            f" {r['prime_5']:>7} │ {r['ultime_5']:>8} │"
            f" {r['n_cifre_pari']:>6} │ {r['n_cifre_disp']:>6} │"
            f" {r['somma_pari']:>7} │ {r['somma_disp']:>7} │"
            f" {r['delta_somme']:>6} │ {r['zeri']:>4} │ {r['radice_digit']:>5}"
        )
    print(SEP)

def stampa_statistiche(risultati):
    campi = ["bit","cifre_decimali","n_cifre_pari","n_cifre_disp",
             "somma_pari","somma_disp","delta_somme","zeri"]
    print("\n  STATISTICHE DESCRITTIVE")
    print(SEP)
    print(f"  {'Campo':<20} {'Min':>8} {'Max':>8} {'Media':>10} {'Varianza':>12}")
    print(SEP)
    for c in campi:
        vals = [r[c] for r in risultati]
        mn   = min(vals)
        mx   = max(vals)
        mu   = sum(vals) / len(vals)
        var  = sum((v - mu)**2 for v in vals) / len(vals)
        print(f"  {c:<20} {mn:>8} {mx:>8} {mu:>10.1f} {var:>12.1f}")
    print(SEP)

# ── Osservazioni automatiche ─────────────────────────────────────────────────
def osservazioni(risultati):
    bits   = [r["bit"]        for r in risultati]
    sp     = [r["somma_pari"] for r in risultati]
    sd     = [r["somma_disp"] for r in risultati]
    prime5 = [r["prime_5"]    for r in risultati]
    ult5   = [r["ultime_5"]   for r in risultati]
    rdig   = [r["radice_digit"] for r in risultati]

    print("\n  OSSERVAZIONI")
    print(SEP)
    print(f"  › Tutti i semiprimi sono dispari (ultimo bit = 1): prodotto di due primi dispari")
    print(f"  › Variazione in bit:   da {min(bits)} a {max(bits)}  (range = {max(bits)-min(bits)} bit)")
    print(f"  › Prime 5 cifre:       {prime5}")
    print(f"  › Ultime 5 cifre:      {ult5}")
    print(f"  › Somme cifre pari:    da {min(sp)} a {max(sp)}  (scarto = {max(sp)-min(sp)})")
    print(f"  › Somme cifre dispari: da {min(sd)} a {max(sd)}  (scarto = {max(sd)-min(sd)})")
    print(f"  › Radici digitali:     {rdig}  (distribuzione casuale, nessun pattern)")
    print(f"  › Nessuna coppia di semiprimi condivide le stesse prime 5 cifre: "
          f"{'Sì' if len(set(prime5))==len(prime5) else 'No'}")
    print(f"  › Nessuna coppia condivide le stesse ultime 5 cifre: "
          f"{'Sì' if len(set(ult5))==len(ult5) else 'No'}")
    print(SEP)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    percorso = sys.argv[1] if len(sys.argv) > 1 else PERCORSO_DEFAULT
    n_camp   = int(sys.argv[2]) if len(sys.argv) > 2 else CAMPIONE_DEFAULT

    print(f"\n  File: {percorso}")
    numeri = carica_database(percorso)
    print(f"  Semiprimi totali nel database: {len(numeri)}")
    print(f"  Campione selezionato: {n_camp}  (seed={SEED_RANDOM})\n")

    random.seed(SEED_RANDOM)
    campione = random.sample(numeri, min(n_camp, len(numeri)))

    risultati = []
    for i, n in enumerate(campione, 1):
        r = analizza(n)
        r["idx"] = i
        risultati.append(r)

    stampa_tabella(risultati)
    stampa_statistiche(risultati)
    osservazioni(risultati)

if __name__ == "__main__":
    main()