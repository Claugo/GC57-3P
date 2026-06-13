# GC57-3P – Appendice B

## Proprietà di sicurezza, dimostrazione numerica e natura del prototipo

_© Govi Claudio – Giugno 2026_

---

## 1. Proprietà di sicurezza del metodo GC57-3P

Il metodo GC57-3P garantisce le seguenti proprietà, ciascuna derivante da un livello distinto del sistema. È importante distinguere tra proprietà del metodo e proprietà dell'implementazione prototipale: le prime sono strutturali e indipendenti dal codice; le seconde dipendono dalle scelte implementative adottate nella dimostrazione software.

### 1.1 Confidenzialità

Il contenuto del messaggio e dell'eventuale allegato è cifrato con AES-256-CBC, con chiave derivata dal valore `k` tramite PBKDF2-HMAC-SHA256. La chiave `k` non viene mai trasmessa: viene rigenerata localmente dal destinatario a partire dal seed e dai parametri condivisi (`B`, `E`), che non compaiono mai nel canale di comunicazione.

Un attaccante che intercetti il file messaggio dispone di:

- il semiprimo `S` in chiaro;
- il ciphertext della prima porta (`blob_q`), cifrato con chiave derivata da `q`;
- il ciphertext della seconda porta (`blob_k`), cifrato con chiave derivata da `k`.

Senza `C = B−1`, l'attaccante non può fattorizzare `S` e quindi non ottiene né `q` né `k`. Senza `B` ed `E`, anche conoscendo il seed non può ricostruire `k`. Le due chiavi di cifratura rimangono inaccessibili.

### 1.2 Integrità

L'integrità del sistema è garantita su due livelli distinti.

**File segreto (chiavetta USB)**

Il file che contiene `C`, `B` ed `E` è protetto da AES-256-CBC con HMAC-SHA256. L'HMAC viene verificato prima di qualsiasi tentativo di decifratura: una modifica anche di un solo bit al file segreto produce un errore di verifica immediato, senza esporre nessuna informazione sui dati contenuti.

**File messaggio**

L'integrità del file messaggio è garantita in modo stratificato:

- **Magic number** `GCM7` e numero di versione: qualsiasi alterazione della struttura binaria viene rilevata immediatamente al parsing.
- **AES-CBC con padding PKCS7**: una modifica al ciphertext produce un errore di padding in decifratura, bloccando il processo.
- **Verifica di coerenza di `k`**: dopo la decifratura della seconda porta, il valore `k` contenuto nel file viene confrontato con il `k` rigenerato localmente. La corrispondenza è condizione necessaria per proseguire.

Queste tre condizioni operano in sequenza: il fallimento di una qualsiasi di esse blocca il processo e non produce output parziale.

### 1.3 Autenticità procedurale

GC57-3P introduce una forma di autenticità che non dipende da firme digitali né da infrastrutture esterne. Un messaggio è considerato autentico se e solo se supera tutte e tre le porte. Il superamento della terza porta dimostra che il mittente conosceva `B` ed `E` al momento della generazione del messaggio, poiché solo chi possiede questi parametri può inserire nel file il valore `k` corretto.

Questa proprietà implica anche l'impossibilità di generare messaggi falsi: un attaccante che superi la prima porta (fattorizzando `S` con metodi alternativi) ottiene il seed e il codice utente, ma non può costruire un file con il valore `k` corretto senza conoscere `B` ed `E`. Il messaggio falsificato fallirebbe sistematicamente alla terza porta.

### 1.4 Variabilità per messaggio

Ogni messaggio utilizza un semiprimo `S` distinto, selezionato casualmente dal database. Ogni messaggio utilizza una chiave `k` distinta, determinata dal seed inserito dall'utente. Di conseguenza:

- `S` cambia completamente ad ogni messaggio: non esiste relazione algebrica visibile tra semiprimi successivi.
- `k` cambia ad ogni messaggio: le chiavi di cifratura non si ripetono.
- L'analisi statistica del traffico intercettato non produce informazioni sfruttabili.

Questo comportamento si distingue da RSA, dove la chiave pubblica è fissa e nota, e da AES in modalità simmetrica semplice, dove la stessa chiave viene riutilizzata su più messaggi.

---

## 2. Dimostrazione numerica della prima porta

La proprietà fondamentale del metodo GC57 è la fattorizzazione in tempo costante O(1) di un semiprimo strutturato. La seguente dimostrazione è stata eseguita sperimentalmente e mostra il funzionamento reale del meccanismo.

### 2.1 Costruzione del semiprimo

Il semiprimo è generato secondo lo schema:

```
p = nextprime(A + rand(1, I))
q = nextprime(B + rand(1, I))
S = p × q
```

dove `A` e `B` sono interi positivi con `B ≫ A`, e `I` è l'intervallo deterministico definito dalla differenza in bit tra `B` e `A`. Il fattore `q` è della stessa grandezza di `B` ma cambia nelle ultime cifre per effetto del componente casuale.

### 2.2 Esempio verificato

**Dati:**

```
S = 448622512203337194221276139585016644902288811200702966361000544390146215407531
C = 1468240587099340662894700798468435766837740434882
```

**Applicando la formula GC57:**

```
S mod C = 1286801395652655315225440976608050757944763410969
p = gcd(S, S mod C) = 305551090294838407408218795241
q = S ÷ p = 1468240587099340662894700798472647178403678456691
```

**Verifica:**

|Controllo|Risultato|
|---|---|
|p × q = S|✓|
|p è primo|✓ (98 bit)|
|q è primo|✓ (161 bit)|
|Operazioni eseguite|una divisione modulare + un GCD|

Nessuna ricerca, nessuna iterazione.

Si noti che `q` differisce da `C = B−1` solo nelle ultime cifre, confermando la struttura `q = nextprime(B + y)` con `y` piccolo rispetto a `B`. Questo non costituisce una debolezza: `S` maschera completamente `q`, e un attaccante che osservi solo `S` non ha nessun modo di stimare `B`.

A titolo illustrativo, la differenza tra `B` e `q` occupa circa la metà delle cifre di `q`: le prime metà sono identiche, le seconde divergono completamente per effetto del componente casuale e di `nextprime`.

### 2.3 Scalabilità

La proprietà O(1) non dipende dalla dimensione del semiprimo. Il costo computazionale è determinato esclusivamente dall'algoritmo di Euclide, la cui complessità è `O(log² n)` rispetto alla dimensione degli operandi, non rispetto alla dimensione del semiprimo da fattorizzare.

Il sistema è stato verificato su semiprimi fino a **76.000 bit**, con fattori di 36.000 e 40.000 bit, con tempi di esecuzione dello stesso ordine di grandezza dei casi piccoli.

A titolo di confronto: un semiprimo RSA a 2048 bit richiede, per un attaccante privo della chiave privata, un costo computazionale stimato in anni su hardware classico. Un semiprimo GC57 di dimensione equivalente viene fattorizzato dal destinatario legittimo in microsecondi, senza alcun aumento di costo al crescere della dimensione.

---

## 3. Analisi statistica del database semiprimi

Per dimostrare l'indipendenza statistica dei semiprimi generati dal sistema GC57-3P, è stato scritto un programma Python (`analisi_semiprimi.py`) che estrae un campione casuale dal database e calcola le seguenti metriche per ogni semiprimo:

- **Bit**: dimensione in bit
- **Cifre**: numero di cifre decimali
- **Prime 5 / Ultime 5**: prime e ultime 5 cifre decimali
- **C.pari / C.disp**: conteggio delle cifre pari e dispari
- **Σ pari / Σ disp**: somma delle cifre pari e delle cifre dispari
- **|Δ|**: valore assoluto della differenza tra le due somme
- **Zeri**: numero di cifre zero presenti
- **R.dig**: radice digitale iterata (equivalente a `n mod 9`)

### 3.1 Risultati su campione di 10 semiprimi (97 totali nel database)

|N|Bit|Cifre|Prime 5|Ultime 5|C.pari|C.disp|Σ pari|Σ disp|\|Δ\||Zeri|R.dig|
|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
|1|2284|688|21148|12787|331|357|1332|1783|451|67|1|
|2|2287|689|18340|16887|362|327|1506|1621|115|55|4|
|3|2285|688|36632|16629|324|364|1222|1836|614|70|7|
|4|2287|689|16468|80607|340|349|1344|1717|373|70|1|
|5|2282|687|50297|47725|335|352|1178|1872|694|81|8|
|6|2287|689|20713|05995|357|332|1412|1608|196|74|5|
|7|2287|689|15646|43033|344|345|1324|1773|449|75|1|
|8|2285|688|42923|80603|350|338|1380|1616|236|75|8|
|9|2287|689|19393|65605|353|336|1464|1652|188|56|2|
|10|2287|689|18238|22999|339|350|1398|1736|338|64|2|

### 3.2 Statistiche descrittive

|Campo|Min|Max|Media|Varianza|
|:--|--:|--:|--:|--:|
|bit|2282|2287|2285.8|2.8|
|cifre decimali|687|689|688.5|0.5|
|cifre pari|324|362|343.5|129.8|
|cifre dispari|327|364|345.0|121.8|
|Σ pari|1178|1506|1356.0|9102.4|
|Σ dispari|1608|1872|1721.4|8136.8|
|\|Δ somme\||115|694|365.4|32451.6|
|zeri|55|81|68.7|63.6|

### 3.3 Osservazioni

- **Tutti i semiprimi sono dispari**: è una conseguenza diretta del fatto che sono prodotto di due primi dispari. Nessuna eccezione nel database.
- **Le prime 5 cifre sono tutte diverse tra loro**: nessuna coppia nel campione condivide le stesse cifre iniziali, nonostante i semiprimi abbiano tutti circa 688-689 cifre.
- **Le ultime 5 cifre sono tutte diverse tra loro**: stessa proprietà, confermata sull'estremità opposta del numero.
- **Le somme delle cifre pari variano da 1178 a 1506** (scarto 328) e quelle delle cifre dispari da 1608 a 1872 (scarto 264): variazione ampia e non sistematica.
- **Il delta |Σ pari − Σ disp| varia da 115 a 694**: non esiste un pattern costante nel rapporto tra le due popolazioni di cifre.
- **Le radici digitali** `[1, 4, 7, 1, 8, 5, 1, 8, 2, 2]` non mostrano nessun pattern: distribuzione casuale conforme a un numero pseudocasuale di grandi dimensioni.
- **Variazione in bit**: da 2282 a 2287, range di soli 5 bit, coerente con la costruzione `S = p × q` dove p e q hanno dimensioni controllate dall'intervallo I.

> Il programma `analisi_semiprimi.py` è incluso nel repository ed è eseguibile su qualsiasi database GC57:
> 
> ```
> python3 analisi_semiprimi.py database_sicurezza 10
> ```

---

## 4. Proprietà matematica della floor division e costruzione del pagliaio

### 4.1 Due metodi equivalenti per la prima porta

La prima porta del sistema GC57-3P può essere superata in due modi distinti, entrambi O(1) e verificati sperimentalmente sullo stesso semiprimo:

```
Metodo GC57 classico:  p = gcd(S, S mod C)
Metodo floor division: p = S // C
```

I due metodi producono risultato identico. La ragione matematica è la seguente:

```
S = p × q,  C = q − 1

S // C = (p × q) // (q − 1)
       = p + p // (q−1)
```

Poiché `p ≪ q` per costruzione (`B ≫ A`), il termine `p // (q−1)` vale esattamente 0. Quindi `S // C = p` esattamente, senza resto. Il metodo GCD è più robusto in generale; la floor division è più diretta ma richiede rigorosamente `p ≪ q`.

### 4.2 La floor division come fondamento del pagliaio

La floor division non serve solo come metodo alternativo per la prima porta — è il meccanismo con cui viene costruito e delimitato il pagliaio della chiave `k`.

La proprietà chiave è che `S // k = p` non vale solo per `k = C`, ma per un intero intervallo di valori:

```
S // k = p   per ogni k ∈ [S/(p+1) + 1,  S/p]
```

L'ampiezza di questo intervallo è circa `S/p² ≈ q`. Tutti i valori interi di k in questo intervallo producono lo stesso quoziente p — non perché dividano S esattamente, ma perché la divisione intera tronca esattamente al confine tra p e p+1.

### 4.3 Determinazione dell'esponente massimo E

Il programma incrementa l'esponente a partire da `k = base^1` finché `S // base^e` restituisce ancora p. Il massimo e per cui la condizione è soddisfatta diventa l'esponente E salvato nel file segreto.

La base non è fissa ma scelta dall'operatore. Con base 3 e base 10 lo spazio risultante è equivalente poiché `3^120 ≈ 10^60`. Con i parametri del database di esempio (A ≈ 1498 bit, B ≈ 2571 bit, I ≈ 1074 bit), l'esponente E raggiunge valori dell'ordine di 10² per base 3, producendo uno spazio del pagliaio computazionalmente irraggiungibile senza conoscere p.

### 4.4 Il pagliaio come segreto condizionato

Il pagliaio non è un segreto assoluto, chiunque conosca p può calcolarne i limiti. Ma p è nascosto dietro la prima porta. La catena di dipendenza è:

```
Senza C  →  impossibile ottenere p  →  impossibile conoscere i limiti del pagliaio
Con p    →  si calcolano i limiti   →  ma serve il seed per sapere dove pescare k
Con seed →  si determina k          →  ma serve B ed E per rigenerarlo correttamente
```

Le tre porte sono concatenate: il superamento di ciascuna è condizione necessaria ma non sufficiente per la successiva.

---

## 5. Flusso operativo del sistema

### 5.1 Fase di cifratura

```
1. Inserimento chiavetta USB
   → lettura File_Segreto_GC57.dat
2. Inserimento password
   → verifica HMAC → decifratura AES-256-CBC → estrazione C, B, E
3. Caricamento semiprimo casuale S dal database
4. Fattorizzazione: p = S // C  (o gcd)
   → se fallisce: errore, selezionare nuovo semiprimo
5. Cifratura prima porta (blob_q) con chiave derivata da p
   → contiene: seed + codice utente
6. Generazione k: seed + B + E → k deterministico nel pagliaio
7. Cifratura seconda porta (blob_k) con chiave derivata da k
   → contiene: testo + allegato + k_embedded
8. Output: file con S in chiaro + blob_q + blob_k
```

Il controllo al passo 4 garantisce che ogni file prodotto sia sempre decifrabile dal destinatario legittimo con lo stesso seed. Non esiste un file cifrato con GC57-3P che non possa essere decifrato se la fattorizzazione è andata a buon fine in fase di cifratura.

### 5.2 Fase di decifratura

```
1. Inserimento chiavetta USB
   → lettura File_Segreto_GC57.dat
2. Inserimento password
   → verifica HMAC → decifratura AES-256-CBC → estrazione C, B, E
3. Lettura S dal file → fattorizzazione: p = S // C
4. Decifratura blob_q con chiave derivata da p
   → estrazione seed + codice utente
5. Rigenerazione k: seed + B + E → stesso k deterministico
6. Decifratura blob_k con chiave derivata da k
   → estrazione testo + allegato + k_embedded
7. Verifica coerenza: k_rigenerato == k_embedded
   → se non coincidono: blocco immediato, nessun output
8. Output: testo nell'editor + allegato + codice utente + seed
```

### 5.3 Garanzia di integrità end-to-end

Il sistema non produce mai output parziale. Ogni fase fallisce in modo esplicito. Le condizioni di blocco sono:

|Punto di blocco|Causa|Conseguenza|
|:--|:--|:--|
|Verifica HMAC file segreto|file alterato o password errata|nessun accesso ai parametri|
|Fattorizzazione S|C errato o S corrotto|nessun accesso al seed|
|Padding PKCS7|blob_q o blob_k alterati|errore di decifratura esplicito|
|Verifica k_embedded|messaggio non generato con B ed E corretti|blocco accesso al contenuto|

Solo il superamento di tutte le condizioni produce l'output finale.

---

## 6. Natura e ruolo del prototipo

Il software GC57-3P è un prototipo dimostrativo, non un sistema di sicurezza commerciale. Questa distinzione è esplicita e intenzionale.

### 6.1 Cosa dimostra il prototipo

Il prototipo ha un unico obiettivo: mostrare che il metodo GC57-3P non è solo un modello teorico, ma è riproducibile e verificabile da chiunque disponga delle competenze tecniche necessarie. In particolare dimostra:

- che la fattorizzazione in O(1) funziona su hardware ordinario con numeri di dimensione operativa reale;
- che le tre porte logiche possono essere implementate in sequenza con comportamento corretto;
- che il sistema produce e consuma file strutturati in modo coerente tra mittente e destinatario;
- che la verifica di coerenza di `k` blocca correttamente i messaggi non validi.

### 6.2 Cosa il prototipo non pretende di essere

Il prototipo non costituisce un sistema pronto per uso operativo. Le scelte implementative adottate sono state fatte nell'ottica della chiarezza dimostrativa, non dell'ottimizzazione della sicurezza. Un sistema operativo richiederebbe:

- audit del codice da parte di esperti di sicurezza;
- sale casuale per ogni istanza di derivazione della chiave;
- HMAC esplicito sull'intero file messaggio;
- gestione sicura della memoria per i valori sensibili (`k`, `q`, `C`);
- protocolli di distribuzione della chiave `B` fuori banda verificati.

### 6.3 Base per sviluppi futuri

Il metodo GC57-3P è presentato come base concettuale aperta. Una struttura specializzata nel settore della sicurezza potrebbe partire da questo prototipo per:

- condurre un'analisi formale delle proprietà di sicurezza, inclusa la riduzione a problemi computazionali noti;
- valutare la resistenza del sistema a scenari di attacco specifici, inclusi attacchi quantistici;
- sviluppare un'implementazione di produzione con le garanzie crittografiche complete;
- esplorare varianti del modello a porte per contesti operativi diversi.

Il prototipo funzionante è la risposta alla domanda più semplice che si possa fare a qualsiasi proposta crittografica: **funziona davvero?** La risposta, verificabile da chiunque, è sì.

---
