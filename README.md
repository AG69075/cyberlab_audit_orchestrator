# audit_orchestrator

Backend de l'outil Cyberlab **Audit Orchestrator**. Réalise un audit de
**posture externe passif** d'une cible unique puis, si une clé Gemini est
fournie, en produit une synthèse destinée à un client non technique.

## Ce que fait le scan (non intrusif)

| Bloc | Détail |
|---|---|
| `headers` | En-têtes HTTP de sécurité (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy), redirection http→https, divulgation de versions, flags des cookies. Note A–F. |
| `tls` | Une poignée de main TLS : version du protocole, expiration et validité du certificat, chaîne, taille de clé. |
| `dns` | SPF, DMARC, DNSSEC (DS), CAA — via DNS-over-HTTPS Cloudflare, aucun binaire. |
| `exposure` | Requêtes GET sur ~18 chemins bien connus (`/.git/config`, `/.env`, `/server-status`, backups…) + présence de `security.txt`. |

**Aucune** injection, fuzzing, brute force ou contournement d'auth. Les tests
actifs (XSS, SQLi, contrôle d'accès) restent une checklist manuelle côté app.

## API

```
POST /api/audit        { "target": "https://exemple.com" }   -> { job_id }
GET  /api/audit/:jobId                                        -> { status, data? }
GET  /health
```

`status` : `pending` | `done` | `error`. Quand `done`, `data` contient le
rapport complet (`score`, `findings[]`, `sections`, `ai`).

Toutes les routes `/api` exigent l'en-tête `x-internal-token` (le Worker
Cloudflare l'ajoute). Rate limit : 12 req/min.

## Déploiement

1. **Clé Gemini** (optionnelle) : https://aistudio.google.com/apikey
2. **Tunnel** : Cloudflare Zero Trust → Access → Tunnels → nouveau tunnel
   « audit-orchestrator », type Docker. Route publique →
   `http://audit-orchestrator:4003`. Récupère le `TUNNEL_TOKEN`.
3. `cp .env.example .env` et remplir `INTERNAL_API_TOKEN`
   (`openssl rand -hex 32`), `TUNNEL_TOKEN`, `GEMINI_API_KEY`.
4. Depuis `/Volumes/docker/cyberlab` :
   ```
   docker compose up -d --build audit-orchestrator cloudflared-audit
   ```
5. **Worker proxy** : `workers/cyberlab-audit-proxy/` dans le repo Flutter.
   Définir les secrets `wrangler secret put INTERNAL_API_TOKEN` et
   `wrangler secret put ORIGIN_BASE` (l'URL publique du tunnel), puis
   `npx wrangler deploy`.
6. Reporter l'URL du Worker dans `_backendBaseUrl` de
   `lib/features/projects/pentest/audit_orchestrator_screen.dart`.

## Variables d'environnement

Voir `.env.example`. `GEMINI_API_KEY` absente ⇒ le rapport sort avec
`ai.available = false` et les findings déterministes seuls.
