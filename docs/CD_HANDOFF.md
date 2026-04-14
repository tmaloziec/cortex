# Cortex v1.0.8 — Handoff note for CD

Krótka notka dla CD (Claude Dispatcher / Claude Developer) przejmującego
temat po zamknięciu v1.0.8. Żadnego wywarzania — tylko stan, interfejs,
decyzje i roadmap.

---

## Stan faktyczny

**Tag w GitHub:** `v1.0.8` (commit `ef80219`) — pierwszy stable.
Poprzednie tagi `v1.0.7` → `v1.0.8-rc5` są historyczne, zostawione.

**Testy:** 57 zielonych (5 invariants STRICT + 52 policy regression).
Uruchamiaj:

```bash
python3 tests/test_invariants.py
python3 tests/test_policy.py
```

**CI:** `.github/workflows/invariants.yml` odpala to plus `pip-audit
--strict` plus `git diff --exit-code UNSAFE.md` na każdy push / PR.
Commercial licensees muszą ustawić ten workflow jako branch-protection
required check w swoim forku.

**Dokumentacja:** `docs/USER_GUIDE.md`, `docs/ARCHITECTURE.md`,
`docs/PLUGIN_GUIDE.md`. Threat model w `/SECURITY.md`, tabela
protect/unprotect w sekcji "What the security invariants DO and
DO NOT protect against".

**Niezłomne invariants:**

1. AST walker pilnuje że żaden moduł poza `security/` nie
   konstruuje `{"role": ...}` bezpośrednio.
2. Każdy FastAPI route ma `Depends(_require_auth_dep)` albo
   `Depends(_public_endpoint)` (ten drugi wymaga whitelisty).
3. `request.client.host` nie jest czytany nigdzie poza
   `security.ClientIdentity.from_request`.
4. `RecoveryEngine` odrzuca każde `fallback_fn` które nie pochodzi
   z `FallbackPolicy.from_env().as_recovery_callable()` —
   capability sentinel zamknięty w closure.
5. Każdy `# invariant: allow-<rule>` ma lifecycle (`until=YYYY-MM-DD`
   po okresie grace kończącym 2026-06-01) albo jest
   grandfathered w `UNSAFE.md`.

Złamanie któregokolwiek = CI fail. Zmiana któregokolwiek wymaga
review w `CODEOWNERS` (obecnie @tmaloziec; dopisz siebie albo
kogoś dodatkowego kiedy to przejmujesz).

---

## Interfejs dla CD

CD zazwyczaj dispatcher-uje taski do innych agentów. Cortex jest po
drugiej stronie tej relacji: jest **agentem wykonawczym**.

**Żeby CD mógł wysłać Cortexowi task:**

1. CS_URL ustawiony tak samo po obu stronach.
2. Cortex uruchomiony w mode `worker`:
   ```bash
   CS_URL=http://192.168.5.130:3032 AGENT_NAME=cortex-adax ./run.sh worker
   ```
3. CD robi `POST $CS_URL/api/tasks` z payloadem:
   ```json
   {
     "target": "cortex-adax",
     "title": "Przeczytaj /tmp/raport.md i streść",
     "description": "Pełny kontekst...",
     "priority": "normal"
   }
   ```
4. Cortex zobaczy task w ciągu `POLL_INTERVAL` sekund (default 10,
   można obniżyć do 1–3 na LAN). Wykona w swojej pętli agenta,
   zapisze wynik w `PATCH /api/tasks/<id>/status`, zostawi notatkę w
   `POST /api/notes`.

**Żeby CD mógł przeczytać co Cortex zrobił:**

- `GET $CS_URL/api/notes?agent=cortex-adax` — notatki / obserwacje.
- `GET $CS_URL/api/tasks/<id>` — pełna historia taska.
- `GET $CS_URL/api/memory/conversations` — lustrzane kopie sesji
  (jeśli Cortex miał CS_URL ustawiony przy rozmowach interaktywnych).

**Czego CD NIE dostaje dziś:**

- Push / WebSocket do Cortexa — Cortex-worker tylko polluje.
  Żeby mu coś "wrzucić na priorytet" trzeba czekać na jego kolejny
  poll albo odpalić z krótszym `POLL_INTERVAL`.
- Broadcast "attention all agents" — CS musi dystrybuować
  indywidualnymi taskami na nazwę; lista agentów jest w
  `GET /api/agents`.
- Szyfrowanego kanału — zobacz niżej.

---

## Szyfrowanie komunikacji Cortex ↔ CS

**Stan obecny (v1.0.8):** plaintext HTTP. `validate_cs_url` odrzuca
URL-e z `user:pass@` w ścieżce (wyciek do access logów) i URL-e spoza
`http://` / `https://`.

**Co to oznacza praktycznie:**

- **Na LAN którą kontrolujesz** (192.168.5.0/24 w homelabie) — OK, to
  twoja sieć, threat model zakłada że LAN jest zaufany. Commercial
  licensees muszą to udokumentować jako wymaganie deployment.
- **Między sieciami / przez internet** — NIE wolno.
  - Natychmiastowe rozwiązanie: owinąć w VPN
    (WireGuard / Tailscale / OpenVPN / FortiClient). Tunel robi
    szyfrowanie za was; Cortex widzi CS po wewnętrznym adresie i
    reszta nie wie co tam lata.
  - Docelowe rozwiązanie: v1.1 doda natywne HTTPS z pinowanym
    łańcuchem certów i tokenami per-agent. Obecnie nie ma.

**Jak to zadziała w v1.1:**

- `CS_URL=https://cs.example.com` — HTTPS wymagany dla non-loopback.
- `CORTEX_CS_CERT_BUNDLE=/path/to/ca.pem` — custom CA dla self-signed.
- `CORTEX_AGENT_TOKEN=...` — token JWT per-agent, rotowalny przez CS.
- `security.TokenVerifier` Protocol — pluggable weryfikator po
  stronie Cortexa; `Principal` zamiast gołego `AGENT_NAME`.

Jeśli CD musi dziś uruchomić coś cross-network a v1.1 jeszcze nie ma,
ustaw Tailscale między maszynami i leć na `CS_URL=http://100.x.y.z:3032`
(wewnętrzny Tailscale IP) — szyfrowanie + auth za was od Tailscale,
Cortex po staremu.

---

## CS jako multi-agent hub

**Tak, CS jest projektowany jako węzeł międzyagentowy**, ale są granice.

### Co CS daje dziś

- **Rejestr agentów.** `POST /api/agents/register` + heartbeat.
  `GET /api/agents` zwraca listę żyjących. Każdy Cortex / CD / inny
  agent melduje się tam.
- **Kolejka tasków.** Task ma `target: <agent_name>`; agent pollujący
  dostaje tylko swoje. CD może dispatch'ować do konkretnego agenta
  albo — jeśli CS tak został rozbudowany — do klasy agentów.
- **Pamięć kolektywna.** `POST /api/notes`, `POST /api/memory/
  conversations`. Wszyscy agenci piszą do jednej bazy. ChromaDB na
  porcie 3037 pozwala na semantic search.
- **Briefing.** `GET /api/agents/<name>/briefing` — CS może
  aggregated context przygotować dla konkretnego agenta przed sesją.

### Co CS NIE daje dziś

- **Auth tokenów.** Każdy kto trafi do `192.168.5.130:3032` może
  udawać dowolnego agenta. Trust jest network-level.
- **Kanału pilnego (push).** Komunikacja jest pull-based ze strony
  agentów. CS nie może sam wywołać Cortexa. Pilne taski czekają na
  kolejny poll. Jeśli `POLL_INTERVAL=10`, worst case 10s.
- **Cross-network discovery.** Agent musi znać CS_URL. Nie ma
  mechanizmu "zapytaj DNS-SD kto jest CS-em". Commercial licensees
  docelowo potrzebują service mesh (Consul / etcd / Kubernetes
  service registry) albo prostego DNS CNAME per environment.

### Cortex w infrastrukturze rozproszonej — dzisiaj wykonalne

Scenariusz: "Cortex-laptop w domu, Cortex-adax w biurze na VPN,
CD w chmurze pod publicznym endpointem, wszyscy rozmawiają przez
wspólnego CS-a".

Wykonalne z v1.0.8, wymaga tylko:

1. CS na publicznym adresie albo wewnątrz VPN-a. Jeśli publicznym —
   **koniecznie za reverse proxy z TLS** (nginx + Let's Encrypt,
   Caddy z auto-HTTPS). HTTP bezpośrednio na publicznym IP to hazard.
2. Każdy agent ma CS_URL ustawiony na ten sam endpoint. Dla routingu
   przez VPN to `http://<tailscale-ip>:3032` albo
   `https://cs.wewnętrzna.domena`.
3. Każdy agent ma unikalny `AGENT_NAME` (`cortex-laptop`,
   `cortex-adax`, `cd-cloud`). CS rozróżnia po nazwie.
4. Tasks routowane `target=<name>`. CD widzi wszystkich agentów przez
   `GET /api/agents` i decyduje komu przydzielić.
5. Polling-interval dopasowany do tolerancji opóźnień. Na LAN 3s
   wystarcza; cross-WAN z kosztem energii lepiej 15s.

### Cortex w infrastrukturze rozproszonej — planowane v1.1+

- Token per agent wydawany przez CS przy rejestracji. Cortex wysyła
  `Authorization: Bearer <cs-issued-token>`. Token ma expiry, można
  revoke-ować jednym requestem.
- WebSocket push z CS → agent dla pilnych tasków. Polling zostaje
  jako fallback (gdy WS padnie).
- mTLS dla cross-network deployment — każdy agent ma swój cert
  wydany przez wspólny CA; CS weryfikuje.

### Kiedy CS NIE jest dobry jako hub

- **Gdy latencja < 100ms jest wymagana.** Polling + HTTP overhead +
  serializacja JSON nie nadają się. Użyj Redis / RabbitMQ /
  ZeroMQ do czasu rzeczywistego.
- **Gdy wymagana jest spójność stanu między agentami.** CS jest
  "eventually consistent" message bus, nie Raft-based replikacja.
- **Gdy agenci muszą widzieć real-time dane innych agentów.** Dziś
  każdy musi pollować. Nie jest to problem dla zadań rozłożonych w
  minutach; jest problemem dla "Cortex-A zaczął write, Cortex-B chce
  natychmiast wiedzieć".

---

## Co CD powinien zrobić teraz

### Natychmiast (jeśli CD już działa):

1. **Upewnij się że CS_URL jest spójny między CD a Cortex-workerem.**
   `curl -s $CS_URL/api/agents` z maszyny CD powinno zwrócić listę
   w której jest Cortex.
2. **Zweryfikuj że Cortex pobiera taski.** Wyślij testowy task
   (`target=<cortex-name>`), poczekaj `POLL_INTERVAL` sekund,
   sprawdź `GET /api/tasks/<id>/status` czy zmienił się na
   `in_progress` / `done`.
3. **Ustaw monitoring.** `GET /api/agents` co N sekund; jeśli
   heartbeat Cortexa starszy niż 3 × `POLL_INTERVAL`, to jest
   dead. Alertuj.

### Krótkoterminowo (tydzień / dwa):

1. **Jeśli CD jest w innej sieci niż CS** — postaw Tailscale / WG
   między nimi. HTTP plaintext cross-WAN to niedopuszczalne.
2. **Jeśli chcesz szybszą reakcję Cortexa** — skróć mu
   `POLL_INTERVAL=3`. Kosztuje ~20x więcej HTTP requests ale
   opóźnienie spada z 10s do 3s.
3. **Zrób plan co wysyłasz do Cortexa.** Cortex to *agent wykonawczy
   z dostępem do shell/FS*. Task "sprawdź plik X" jest OK; task
   "zrób coś kreatywnego" jest OK; task "wykonaj dowolny shell
   command" jest **granica Policy Engine** i Cortex tego nie zrobi
   bez ASK albo DENY. CD powinien formulować taski w kategoriach
   pracy, nie konkretnych komend — model sam zdecyduje czego użyć.

### Długoterminowo (v1.1 prep):

1. **Przemyśl token management.** Dziś LAN trust; v1.1 każdy agent
   dostaje JWT. CD jako dispatcher będzie musiał albo wydawać tokeny
   sam (alternatywny issuer), albo delegować do CS-as-issuer.
   Decyzja polityczna, nie techniczna.
2. **Plugin ecosystem.** Jeśli CD ma dystrybuować pluginy do
   Cortexów, ustal curation policy. Dziś plugin = trusted Python,
   read before enable. Komercyjnie to wymaga signed plugins albo
   sandboxing (v1.2 subinterpreters).

---

## Pytania na które odpowiedź brzmi "zobacz docs"

| Pytanie | Dokument |
|:--|:--|
| Jak uruchomić Cortex? | `docs/USER_GUIDE.md` |
| Jakie są zmienne środowiskowe? | `docs/USER_GUIDE.md` tabele |
| Jak działa Policy Engine? | `docs/USER_GUIDE.md` + `policy.py` header |
| Co to jest invariant #4? | `docs/ARCHITECTURE.md` + `tests/test_invariants.py` |
| Jak napisać plugin? | `docs/PLUGIN_GUIDE.md` |
| Jaki jest threat model? | `SECURITY.md` sekcja "Threat model" |
| Co się stało w rundzie R-cośtam? | `SECURITY.md` sekcje `v1.0.x additions` |
| Co jest otwarte / co nie? | `UNSAFE.md` (auto-generowany) |

## Pytania na które odpowiedź brzmi "zapytaj operatora"

- Czy commercial deployment ma CI workflow włączony?
- Które CA podpisuje certy w sieci docelowej?
- Jaki model językowy ma być default dla danego agenta?
- Czy ten konkretny plugin jest reviewed, czy ma być zablokowany?

---

## Kontakt / eskalacja

Security invariant do relaxowania → PR z sign-off od `CODEOWNERS`
reviewera `security/`. Nie ma innej ścieżki — CI by-passy nie są
obsługiwane.

Bug w Cortex → GitHub issue, tag `bug`.

Bug w CS → to nie repo Cortexa. CS jest osobnym projektem,
Cortex tylko klient.

Plugin zgłaszany do oficjalnego ecosystemu → TBD. Commercial
licensees muszą to wypracować; upstream (AGPLv3 fork) pluginy
ekosystemu nie ma i nie planuje.

---

*Dokument napisany przez Claude Opus 4.6 (1M context) podczas
domknięcia v1.0.8. Jeśli coś tu jest niejasne po przeczytaniu
pozostałych trzech dokumentów, otwórz issue — to znak że któraś
sekcja wymaga rozbudowy.*
