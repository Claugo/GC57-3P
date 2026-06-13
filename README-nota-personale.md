# GC57-3P – Nota di visione personale

_Govi Claudio – Giugno 2026_

---

Questa nota non fa parte della documentazione tecnica del metodo GC57-3P. È una riflessione personale su ciò che il sistema cerca di esprimere dal punto di vista concettuale, scritta con l'intenzione di trasmettere la prospettiva di chi lo ha sviluppato.

---

## Un uso diverso dello stesso oggetto matematico

I sistemi crittografici esistenti usano il semiprimo in un modo preciso: è la chiave pubblica, statica, nota a tutti, riutilizzata per ogni messaggio. In RSA il semiprimo è il punto di partenza della comunicazione, è pubblico per definizione.

In GC57-3P il semiprimo ha un ruolo completamente diverso. È usa-e-getta, cambia ad ogni messaggio, e non è una chiave pubblica ma un contenitore temporaneo che trasporta un fattore nascosto. Non viene pubblicato perché deve essere noto, viene trasmesso perché è inutile senza C. È lo stesso oggetto matematico usato in modo opposto.

Questa inversione non è un dettaglio tecnico. È il punto da cui nasce tutto il resto del sistema.

---

## Una terza categoria

I sistemi di sicurezza tradizionali dividono il mondo in due categorie:

- **Simmetrico**: stessa chiave per tutti i messaggi, deve essere distribuita in modo sicuro.
- **Asimmetrico**: chiave pubblica e chiave privata fisse, la chiave privata non cambia mai.

GC57-3P non appartiene a nessuna delle due. Mittente e destinatario condividono lo stesso file segreto, in questo senso è simmetrico. Ma la chiave operativa k che cifra ogni messaggio non esiste prima della comunicazione, non viene trasmessa, e non è uguale da un messaggio all'altro. Viene generata nel momento in cui si cifra e rigenerata dall'altra parte senza negoziazione.

Non è key exchange. Non è key distribution. È qualcosa che potrebbe chiamarsi **convergenza deterministica della chiave**: due parti che, partendo dagli stessi parametri e dallo stesso seed, arrivano autonomamente alla stessa chiave senza mai comunicarla.

La sicurezza non risiede nella segretezza della chiave di cifratura, risiede nel fatto che produrre un messaggio valido richiede una sequenza di operazioni che solo chi conosce B ed E può eseguire correttamente. La chiave è un risultato del processo, non il segreto.

Questa distinzione è sottile ma reale, e suggerisce una terza categoria: **simmetrico procedurale con asimmetria di conoscenza**.

---

## L'integrità come proprietà procedurale

Nei sistemi classici l'integrità è garantita da strumenti crittografici: HMAC, firme digitali, cifratura autenticata. Questi strumenti verificano che i dati non siano stati alterati.

GC57-3P aggiunge un secondo livello che non dipende da algoritmi crittografici: la verifica di coerenza di k. Un messaggio può essere crittograficamente integro, nessun bit alterato, padding corretto, HMAC valido, e tuttavia essere rifiutato perché k_embedded non corrisponde a k_rigenerato.

Questo secondo livello verifica non che i dati siano intatti, ma che il messaggio sia stato prodotto seguendo l'intera sequenza del processo. È una proprietà procedurale: dimostra l'origine, non solo l'integrità. Un attaccante che costruisse un messaggio formalmente corretto senza conoscere B ed E fallirebbe qui, indipendentemente dalla qualità crittografica del suo lavoro.

---

## Cosa rimane aperto

Questa nota non pretende di dimostrare che il sistema sia sicuro in senso formale. La domanda che rimane aperta, e che richiede competenze e strumenti che vanno oltre questo lavoro, è se la sicurezza della prima porta sia riducibile a un problema computazionale noto con garanzie dimostrabili.

Un semiprimo GC57 non è un semiprimo generico: ha la struttura `p ≪ q` con `q ≈ B`. Quanto questa struttura riduca lo spazio di ricerca per un attaccante che conosce il generatore non è ancora formalizzato. Non è un difetto dichiarato, è una domanda aperta, onestamente riconosciuta come tale.

Il valore di questo lavoro non sta nel rispondere a quella domanda, ma nell'averla posta in modo preciso e nell'aver costruito un prototipo funzionante che permette a chiunque di verificare il comportamento del sistema e di partire da una base concreta per approfondire.

---

## Una nota finale

Questo sistema è nato da un'esplorazione personale, non da una formazione nel settore della sicurezza. Il suo valore, se esiste, è nell'idea, nel modo in cui combina elementi noti in un'architettura che non ha un precedente diretto evidente. La realizzazione tecnica è un prototipo dimostrativo, non un prodotto.

Se qualcuno con le competenze giuste trovasse questa idea degna di analisi formale, questo documento avrebbe raggiunto il suo scopo.

---

_© Govi Claudio – Giugno 2026_