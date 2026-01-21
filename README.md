# GC57-3P – Dimostrazione operativa del metodo GC57

Questo repository contiene **GC57-3P**, un programma dimostrativo sviluppato per illustrare l’applicazione pratica del metodo **GC57** all’utilizzo dei semiprimi in un contesto di sicurezza crittografica sperimentale.

Il progetto **non ha finalità commerciali** né pretende di costituire un sistema di sicurezza certificato.  
Il suo scopo è esclusivamente **didattico e concettuale**: mostrare, in modo operativo, come un semiprimo pubblico possa essere utilizzato come struttura portante di un sistema di protezione dei dati basato sul controllo della fase e sull’assenza di orientamento informativo per un potenziale attaccante.

---

## Obiettivo del programma

GC57-3P è stato progettato per:

- dimostrare l’utilizzo operativo del metodo GC57 su grandi semiprimi;
- integrare tale metodo in un flusso completo di cifratura e decifratura;
- mostrare come la sicurezza possa emergere da una combinazione controllata di elementi, piuttosto che dalla sola complessità di una funzione crittografica;
- fornire un ambiente sperimentale ripetibile e verificabile.

Il sistema non si limita a cifrare un messaggio, ma implementa una **logica a più livelli**, nella quale l’accesso ai dati è possibile solo quando tutte le condizioni di coerenza del modello sono soddisfatte.

---

## Principio di funzionamento

Nel modello GC57-3P il semiprimo è **pubblico** e non viene cifrato né mascherato.  
La sicurezza non deriva dall’occultamento del valore, ma dal fatto che, in assenza dei parametri corretti, **non esiste una strategia orientabile** per ricostruirne i fattori in modo operativo.

A differenza della fattorizzazione classica di un semiprimo, in cui l’attaccante dispone di un oggetto matematico ben definito e può applicare strategie adattive o sub-esponenziali basate su esclusione progressiva, nel modello GC57:

- non esiste una mappa del problema;
- ogni tentativo errato è informativamente neutro;
- il fallimento non riduce lo spazio di ricerca.

L’informazione utile emerge solo nella **chiusura globale del sistema**: esclusivamente la combinazione corretta dei parametri consente la ricostruzione coerente dei fattori e l’accesso ai dati protetti.

**GC57-3P non impedisce il calcolo: impedisce l’orientamento.**

---

## Struttura a tre porte (GC57-3P)

Il sistema è organizzato in tre livelli logici distinti:

- **Porta 0 – Semiprimo pubblico**  
  Il semiprimo è memorizzato in chiaro e costituisce la struttura portante del sistema.  
  Da solo non consente alcuna apertura senza il corretto riallineamento dei parametri.

- **Porta 1 – Autenticazione operatore**  
  Contiene i dati di seme e firma digitale.  
  Questa porta è cifrata utilizzando come chiave il fattore primo maggiore del semiprimo (**q**), scelto per la sua rarità informativa e per la maggiore difficoltà di intercettazione in processi lineari.

- **Porta 2 – Contenuto protetto**  
  Contiene il messaggio, eventuali allegati e la chiave operativa finale.  
  L’accesso è subordinato alla corretta apertura della Porta 1 e alla ricostruzione coerente del sistema.

Questa separazione consente di distinguere chiaramente tra struttura matematica, controllo di accesso e contenuto informativo.

---

## Novità della versione 1.0.2 del programma GC573P_V102

La versione **1.0.2** introduce due aggiornamenti principali:

- **Miglioramento dell’interfaccia grafica**  
  L’interfaccia è stata riorganizzata per rendere più chiara la separazione tra le funzioni di invio e ricezione, migliorando la leggibilità e la comprensione del flusso operativo.

- **Revisione concettuale della chiave della Porta 1**  
  La chiave di accesso della Porta 1 è stata spostata dal fattore primo minore (*p*) al fattore primo maggiore (*q*).  
  Questa scelta non modifica il metodo matematico di base, ma rafforza la coerenza logica del modello GC57, privilegiando l’elemento informativamente più raro.

---

## Struttura del repository

- `programmi/`  
  Contiene i programmi Python che implementano e dimostrano il funzionamento del sistema GC57-3P.

- `screenshot/`  
  Raccolta di immagini che documentano l’interfaccia grafica e i principali passaggi operativi del programma.

- `doc/`  
  Documentazione descrittiva del funzionamento logico e operativo del sistema, con supporto visivo.

---

## Nota importante

Il metodo GC57 si basa su un **modello logico originale**, sviluppato e verificato empiricamente.  
Il codice presente in questo repository deve essere considerato **strumento dimostrativo** e non un prodotto di sicurezza pronto per l’uso in ambienti reali.

---

## Autore

**Claudio Govi**  
ORCID: https://orcid.org/0009-0005-9020-0691
