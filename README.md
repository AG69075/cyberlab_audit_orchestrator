# Audit Orchestrator — Backend

Backend Node/Express du module Audit Orchestrator de [cyberlab](https://github.com/AG69075), une webapp Flutter d'outils de reconnaissance réseau. Ce service réalise un audit de **posture externe passif** d'une cible unique (en-têtes HTTP, TLS, DNS, chemins exposés) et, si une clé Gemini est fournie, en produit une synthèse destinée à un client non technique.

## Architecture

```
Flutter webapp (navigateur)
        │  HTTPS, CORS restreint
        ▼
Cloudflare Worker (cyberlab-audit-proxy)
        │  HTTPS + header x-internal-token
        ▼
Cloudflare Tunnel (cloudflared)
        │  réseau Docker interne
        ▼
Backend Node (ce repo) ──┬── HTTP GET / TLS / DoH vers la cible
                         ├── Google Gemini (synthèse rédigée, optionnelle)
                         └── dns-analyzer (phase active : sous-domaines)
```

Le backend n'expose **aucun port public**. `cloudflared` établit une connexion sortante vers Cloudflare depuis le conteneur Docker ; le Worker Cloudflare est le seul point d'entrée public, et c'est lui qui relaie les requêtes vers le backend en y attachant un token partagé. Rien n'écoute directement sur Internet côté NAS.

## Ce que fait le scan

| Bloc | Détail |
|---|---|
| `headers` | En-têtes HTTP de sécurité (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy), redirection http→https, divulgation de versions, flags des cookies. |
| `tls` | Une poignée de main TLS : version du protocole, expiration et validité du certificat, chaîne, taille de clé. |
| `dns` | SPF, DMARC, DNSSEC (DS), CAA — via DNS-over-HTTPS Cloudflare, aucun binaire. |
| `exposure` | Requêtes GET sur ~25 chemins bien connus (`/.git/config`, `/.env`, `/server-status`, sauvegardes, `security.txt`…). Un résultat n'est retenu que si le contenu correspond à une signature (pas de faux positif sur les SPA qui renvoient `index.html` partout). |

Chaque constat a une sévérité (`crit`, `high`, `medium`, `low`, `info`) et une pénalité ; le rapport donne un score sur 100 et une note de `A+` à `F`.

### Phase active (opt-in)

Avec `{ "target": "...", "active": true }`, deux sondes légères et non destructives s'ajoutent, plus une découverte de sous-domaines :

- **CORS** : un GET avec un `Origin` factice, pour détecter une réflexion d'origine.
- **Réflexion d'entrée** : un marqueur inerte dans quelques paramètres de requête, vérifié en écho. Jamais présenté comme « XSS confirmée », uniquement comme « réflexion non filtrée ».
- **Sous-domaines** : délégués au service `dns-analyzer` (Sublist3r, passif, sans brute force).

**Aucune** injection SQL, fuzzing, brute force, JWT ou contournement d'auth. Ces tests restent une checklist manuelle côté app.

### Synthèse IA (optionnelle)

Gemini reçoit uniquement les constats calculés (jamais la cible) et rédige un résumé exécutif, les risques métier et un plan de remédiation priorisé, en français. La détection reste 100 % déterministe. En cas d'erreur transitoire (429, 5xx), le service retente jusqu'à 5 fois, en basculant sur un modèle de secours.

## Endpoints

| Méthode | Route | Description |
|---|---|---|
| `POST` | `/api/audit` | Lance un audit en tâche de fond (`target`, `active?`), retourne un `job_id` |
| `GET` | `/api/audit/:jobId` | Statut/résultat d'un audit (`pending` / `done` / `error`) |
| `GET` | `/health` | Health check (pas d'auth requise, utilisé par Docker `HEALTHCHECK`) |

Quand le statut est `done`, `data` contient le rapport complet (`score`, `findings[]`, `sections`, `ai`). Les jobs expirent après 1 heure.

Toutes les routes `/api/*` requièrent le header `x-internal-token`, égal à la variable d'environnement `INTERNAL_API_TOKEN`. Sans correspondance : `401`.

## Variables d'environnement

| Variable | Requise | Description |
|---|---|---|
| `INTERNAL_API_TOKEN` | Oui | Secret partagé avec le Worker Cloudflare. Le serveur refuse de démarrer si absente (fail-closed). |
| `TUNNEL_TOKEN` | Déploiement | Token du tunnel `cloudflared`, généré dans Cloudflare Zero Trust. |
| `GEMINI_API_KEY` | Non | Clé API Google Gemini. Absente : le rapport sort avec `ai.available = false` et les constats seuls. |
| `GEMINI_MODEL` | Non | Modèle principal. Par défaut : `gemini-2.0-flash`. |
| `GEMINI_FALLBACK_MODEL` | Non | Modèle de secours après un échec transitoire. Par défaut : `gemini-3.5-flash-lite`. |
| `DNS_ANALYZER_INTERNAL_TOKEN` | Non | Token du service `dns-analyzer` (son propre `INTERNAL_API_TOKEN`). Absent : la phase active saute la découverte de sous-domaines. |
| `DNS_ANALYZER_BASE_URL` | Non | URL de `dns-analyzer`. Par défaut : `http://dns-analyzer:4002`. |
| `ALLOWED_ORIGINS` | Non | Origines CORS autorisées, séparées par des virgules. Par défaut : l'origine du Worker `cyberlab-audit-proxy`. |
| `PORT` | Non | Port d'écoute. Par défaut : `4003`. |

## Lancer en local

```bash
npm install
INTERNAL_API_TOKEN=$(openssl rand -hex 32) npm start
```

Aucun binaire externe requis (Node 22, DNS via DoH). Pour la phase active complète, un `dns-analyzer` joignable est nécessaire.

## Déploiement (Docker Compose + Cloudflare Tunnel)

Le backend tourne dans un conteneur Docker, sans port publié. Un conteneur `cloudflared` sur le même réseau Docker route le trafic public vers le service via son nom (`audit-orchestrator:4003`), configuré comme *Public Hostname* d'un tunnel Cloudflare Zero Trust.

1. **Clé Gemini** (optionnelle) : https://aistudio.google.com/apikey
2. **Tunnel** : Zero Trust → Access → Tunnels → nouveau tunnel « audit-orchestrator », type Docker. Route publique → `http://audit-orchestrator:4003`. Récupérer le `TUNNEL_TOKEN`.
3. Créer le fichier `.env` (non versionné, voir `.gitignore`) :
   ```
   INTERNAL_API_TOKEN=<secret partagé avec le Worker, openssl rand -hex 32>
   TUNNEL_TOKEN=<token du tunnel>
   GEMINI_API_KEY=<clé Gemini, optionnelle>
   DNS_ANALYZER_INTERNAL_TOKEN=<token de dns-analyzer, optionnel>
   ```
4. Depuis le dossier du projet compose :
   ```bash
   docker compose up -d --build audit-orchestrator cloudflared-audit
   ```
5. **Worker proxy** (`cyberlab-audit-proxy`, dans le repo Flutter) : définir les secrets `INTERNAL_API_TOKEN` et `ORIGIN_BASE` (URL publique du tunnel) avec `wrangler secret put`, puis `npx wrangler deploy`.
6. Reporter l'URL du Worker dans `_backendBaseUrl` de `audit_orchestrator_screen.dart`.

Le conteneur tourne en utilisateur non-root (UID 10001) et embarque un `HEALTHCHECK` sur `/health`.

## Sécurité

Ce service émet des requêtes vers des cibles fournies par l'utilisateur. Les protections en place :

- **Garde SSRF** : la cible est résolue avant tout scan, et toute adresse privée, loopback ou link-local (IPv4 et IPv6) est refusée.
- **Validation stricte** en entrée : schéma `http(s)` uniquement, nom d'hôte ou IP valide, longueur bornée, corps JSON limité à 16 Ko.
- **Authentification** : token partagé requis sur `/api/*`, vérifié avant tout traitement.
- **Rate limiting** : 12 créations d'audit/min, 120 lectures de statut/min, et 3 phases actives par 10 min et par IP.
- **Plafond de jobs concurrents** : 3 audits simultanés max.
- **Pas de shell** : aucune commande système, uniquement `fetch`, `tls` et `dns` natifs de Node.
- **IA cloisonnée** : Gemini ne voit que les constats calculés, jamais la cible, et a l'interdiction d'inventer.
- **CORS restreint** à l'origine du Worker (configurable via `ALLOWED_ORIGINS`).
- **Aucune exposition réseau directe** : le port applicatif n'est jamais publié sur l'hôte, tout passe par le tunnel Cloudflare sortant.

N'auditer que des cibles pour lesquelles vous avez une autorisation, en particulier avec la phase active.
