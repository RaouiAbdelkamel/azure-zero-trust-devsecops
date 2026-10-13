# Phase 2 — Secure API

Microservice Python 3.11/FastAPI, avec validation cryptographique des access tokens Microsoft Entra v2 et intégration Key Vault facultative. Les fichiers Terraform de la Phase 1 sont préservés.

## Organisation

```text
app/
├── src/secure_api/
│   ├── __init__.py
│   ├── main.py                  # Factory ASGI, middleware et lancement Uvicorn
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py            # Health, informations publiques et route protégée
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py            # Configuration Pydantic validée, immuable
│   │   ├── security.py          # RS256, JWKS, claims et autorisation
│   │   └── logging.py           # Événements JSON à champs autorisés
│   └── services/
│       ├── __init__.py
│       └── keyvault.py          # SDK officiel, identité sans client secret
├── tests/
│   ├── conftest.py              # Clés éphémères locales, appels externes interdits
│   ├── test_health.py
│   ├── test_config.py
│   ├── test_security.py
│   ├── test_keyvault.py
│   └── test_layers.py           # Sécurité de lecture des archives Docker
├── scripts/
│   ├── resolve_base_image.py    # Résolution et contrôle du digest officiel
│   ├── Install-Gitleaks.ps1     # Version précise et checksum vérifié
│   ├── Test-Container.ps1       # Build, runtime restreint, health, SIGTERM
│   ├── scan_image_layers.py     # Secrets dans chaque couche, même fichier supprimé
│   └── smoke_local.py           # Requêtes HTTP réelles en loopback, sans Azure
├── Dockerfile
├── .dockerignore
├── .gitleaks.toml
├── .env.example
├── base-image.json              # Manifeste du digest de base vérifié
├── pyproject.toml
├── requirements.lock            # Production : versions exactes et hashes
├── requirements-dev.lock        # Outils/tests : versions exactes et hashes
├── Makefile
├── README.md
└── VALIDATION.md
```

Les répertoires `.venv/`, `reports/`, `tools/` et les caches sont locaux et ignorés par Git. `.dockerignore` fonctionne en liste d'autorisation : seuls le Dockerfile, le lock de production et les sources entrent dans le contexte.

## Endpoints

| Route | Authentification | Comportement |
|---|---|---|
| `GET /health/live` | Aucune | `200 {"status":"alive"}` tant que le processus répond |
| `GET /health/ready` | Aucune | `200` après startup ; `503` si l'état local est non prêt |
| `GET /api/v1/info` | Aucune | Nom, version et environnement uniquement |
| `GET /api/v1/secure` | JWT Entra | `200 {"status":"authorized"}`, sans identité ni token dans la réponse |

La readiness ne contacte ni Entra ni Key Vault. L'application démarre sans abonnement Azure. En mode local, tant que l'authentification n'est pas configurée, `/api/v1/secure` retourne **503**, jamais un succès anonyme. Un token absent/invalide donne 401 ; un token valide sans les permissions exigées donne 403 ; une indisponibilité JWKS donne 503.

## Installation locale — PowerShell

```powershell
Set-Location C:\Users\Abdelkamel\Documents\08_CARRIERE\Azure\app
py -3.11 -m venv .venv
.venv\Scripts\python -m pip install --require-hashes --only-binary=:all: -r requirements-dev.lock
$env:PYTHONPATH = (Resolve-Path src).Path
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:APP_ENV = 'development'
.venv\Scripts\python -m secure_api.main
```

Puis, dans un deuxième terminal :

```powershell
Invoke-RestMethod http://localhost:8080/health/live
Invoke-RestMethod http://localhost:8080/health/ready
Invoke-RestMethod http://localhost:8080/api/v1/info
```

Ne pas lancer en mode reload en production. Le lanceur `python -m secure_api.main` fixe le port 8080, désactive access logs et confiance dans les proxy headers, limite la concurrence et active les timeouts configurés. `APP_WORKERS` est compris entre 1 et 8 ; commencer avec un worker par pod et augmenter les replicas AKS selon la charge. SIGTERM est géré par Uvicorn, avec timeout de grâce par défaut de 20 secondes ; prévoir `terminationGracePeriodSeconds: 30` au minimum en Phase 4.

Le fichier `.env.example` contient uniquement des paramètres publics et n'est **jamais chargé implicitement**. Utiliser les variables d'environnement PowerShell, une configuration Kubernetes ou, en développement seulement, un chargement explicite contrôlé. Les variables de production `APP_ENV=production`, `APP_AUTH_ENABLED=true`, tenant/audience et permissions sont obligatoires ; une configuration incohérente refuse le démarrage. `/docs`, `/redoc` et `/openapi.json` sont désactivés en production. Le mode développement peut publier le schéma explicitement ; la CSP stricte reste adaptée à une API JSON, sans autoriser les scripts de Swagger UI.

## JWT entrant — Microsoft Entra ID

Le service accepte un seul tenant Azure public et des **access tokens v2**, avec RS256 uniquement. Configurer une registration Entra **dédiée à l'API**, son client ID comme audience v2 et un scope tel que `api.read`. L'authentification interactive/client est assurée en amont ; l'API ne contient aucun client secret et ne délivre pas de token.

```powershell
$env:APP_ENV = 'production'
$env:APP_AUTH_ENABLED = 'true'
$env:APP_ENTRA_TENANT_ID = '<TENANT_UUID>'
$env:APP_ENTRA_AUDIENCE = '<API_REGISTRATION_CLIENT_UUID>'
$env:APP_REQUIRED_SCOPES = '["api.read"]'
$env:APP_REQUIRED_ROLES = '[]'
```

L'implémentation impose signature, issuer exact `https://login.microsoftonline.com/TENANT/v2.0`, audience exacte, `exp`, `iat`, `nbf`, `sub`, tenant et version. Les clés proviennent uniquement de l'URL Microsoft construite depuis le tenant configuré. `jku`, `x5u`, algorithmes alternatifs et clés RSA inférieures à 2048 bits sont rejetés. L'issuer éventuel attaché à la clé Microsoft est également contrôlé. La récupération JWKS utilise un timeout de 5 secondes, un cache de 300 secondes et un cooldown de rafraîchissement de 30 secondes ; les clés individuelles ne sont pas mises en cache indéfiniment.

Toutes les permissions configurées sont requises. Si scopes et rôles sont tous deux configurés, **les deux catégories doivent être satisfaites**. Pour un client applicatif sans utilisateur, configurer `APP_REQUIRED_SCOPES=[]` et les app roles exigés, par exemple `APP_REQUIRED_ROLES=["API.Reader"]`. Ne pas utiliser la registration API comme registration de connexion interactive. La gestion réelle des registrations, consentements et affectations de rôles sera qualifiée avec Entra ; les tests utilisent exclusivement des clés RSA générées en mémoire et des JWT synthétiques.

La Phase 1 autorise `login.microsoftonline.com` à travers le pare-feu. Les futures NetworkPolicies doivent aussi autoriser les flux HTTPS JWKS et d'échange de jetons Entra nécessaires. Les restrictions par client appelant, quotas et protections anti-abus pourront être complétées à l'ingress selon le modèle d'autorisation métier.

## Identité sortante — Key Vault

`DefaultAzureCredential` est configuré explicitement : Workload Identity, et identité managée uniquement hors production. Les identités client secret/certificat, CLI, PowerShell, broker et caches développeur sont exclues. Les variables introduisant une identité permanente ou modifiant la chaîne (`AZURE_CLIENT_SECRET`, `AZURE_CLIENT_CERTIFICATE_PATH`, `AZURE_TOKEN_CREDENTIALS`) sont refusées. L'autorité est fixée à Azure public. En production, l'absence de configuration Workload Identity refuse l'accès sans fallback IMDS vers l'identité du nœud.

Key Vault est désactivé par défaut ; son client et son credential sont créés au premier accès effectif, puis fermés à l'arrêt. Les erreurs du SDK sont remplacées par une exception applicative générique ; aucune valeur, exception interne ou token n'est journalisé. Aucune route HTTP ne renvoie un secret ou ne laisse un utilisateur sélectionner son nom.

Pour AKS en Phase 4 :

- ServiceAccount `fastapi/fastapi` correspondant au subject fédéré `system:serviceaccount:fastapi:fastapi` de la Phase 1.
- Annotation `azure.workload.identity/client-id` avec `identity_client_ids.app` ; label pod `azure.workload.identity/use: "true"`.
- Injection par le webhook de `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` et `AZURE_FEDERATED_TOKEN_FILE` ; aucun token inscrit dans un manifest ou dans Terraform.
- `APP_KEYVAULT_ENABLED=true` et `APP_KEYVAULT_URL` issu de l'output **`app_vault_uri`**, jamais du coffre de signature.
- La Phase 1 ne donne aucun accès de données à l'identité `app`. Ajouter uniquement le rôle de lecture requis au secret effectivement consommé, après identification du besoin métier.

Cette intégration prépare le SDK. Aucune connexion réelle à Azure n'a été validée et aucun secret n'est nécessaire pour le microservice de référence. La signature Notation relève du job CI et du coffre de signature ; elle ne dépend pas d'un secret applicatif.

## Contrôles applicatifs

| Contrôle | Implémentation |
|---|---|
| Validation | Configuration et réponses Pydantic ; JWT et noms de secrets contrôlés |
| Erreurs | 500 et 422 génériques, sans trace ni valeurs rejetées |
| Logs | JSON : timestamp UTC, niveau, ID serveur, route normalisée, statut, durée |
| Confidentialité | Aucun log des headers, cookies, query strings, corps, tokens ou erreurs SDK |
| Headers | `nosniff`, `no-referrer`, `no-store`, CSP `default-src 'none'` |
| HSTS | Facultatif, émis uniquement si le schéma HTTPS est effectivement établi |
| CORS | Désactivé par défaut ; origines exactes, HTTPS obligatoire en production, sans credentials |
| Documentation | Désactivée par défaut et obligatoire en production |
| Authorization | RS256 + issuer/audience/dates/tenant + scopes/rôles, refus en cas d'échec |
| Dépendances | Deux locks complets, versions exactes et SHA-256, installation binaire uniquement |

Les headers de proxy ne sont jamais considérés comme preuve de TLS. Si TLS termine à l'ingress, appliquer HSTS à cet ingress ; ne pas activer une confiance globale dans `X-Forwarded-Proto`. Les exceptions de scan statique sont limitées aux opérations techniques nécessaires et documentées dans `VALIDATION.md`.

## Image Docker

```powershell
docker build -t secure-fastapi:phase2 .
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges=true `
  --user 10001:10001 -p 127.0.0.1:8080:8080 -e APP_ENV=development secure-fastapi:phase2
```

Ne pas ajouter `seccomp=builtin` : le script contrôle la présence du profil builtin **par défaut** du moteur et ne l'écrase pas. Docker doit utiliser le moteur Linux ; la compilation n'exige aucun changement de configuration Windows ou Azure.

Le Dockerfile emploie deux stages basés sur la même image officielle slim fixée au digest enregistré dans `base-image.json`. Le manifeste a été récupéré directement depuis Docker Hub et son SHA-256 vérifié. Cette vérification d'intégrité ne constitue pas une signature/provenance indépendante de la base. Une mise à jour requiert une nouvelle résolution, une revue des deux `FROM`, un scan et les tests ; le tag seul n'est pas immuable.

Le builder crée une venv **sans pip** puis installe les wheels de production avec hashes. Le runtime reçoit seulement cette venv et les sources ; les outils de développement sont exclus. Les copies appartiennent à root pour empêcher UID 10001 de modifier son code. Un utilisateur/groupe système sans home et sans shell de connexion est créé ; l'image impose `USER 10001:10001`, port 8080, `PYTHONDONTWRITEBYTECODE=1`, logs sans buffering et `STOPSIGNAL SIGTERM`. Pip/setuptools/wheel hérités de la base sont supprimés. L'image slim conserve certains utilitaires système ; elle n'est pas distroless.

L'application n'écrit aucun fichier en fonctionnement normal. Aucun volume `/tmp` n'est requis pour les routes de référence. Si une future fonction l'exige, utiliser un `emptyDir` borné en taille, éventuellement en mémoire ; conserver la racine en lecture seule. `readOnlyRootFilesystem`, capabilities, seccomp et `allowPrivilegeEscalation` seront imposés par les manifests et l'admission : un Dockerfile ne peut pas appliquer ces contrôles à lui seul.

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]
  seccompProfile:
    type: RuntimeDefault
```

Pour le pool Phase 1, prévoir `nodeSelector: {workload: application}` et la toleration du taint `workload=application:NoSchedule`. Les probes GET utilisent `/health/live` et `/health/ready` sur le port 8080 sans token. Les budgets mémoire/CPU, PDB, replicas et NetworkPolicies seront définis en Phase 4.

## Tests et analyses

```powershell
.venv\Scripts\python -m pytest --junitxml=reports/pytest.xml
.venv\Scripts\python scripts/smoke_local.py
.venv\Scripts\python -m ruff check src tests scripts
.venv\Scripts\python -m ruff format --check src tests scripts
.venv\Scripts\python -m bandit -r src scripts/resolve_base_image.py scripts/scan_image_layers.py scripts/smoke_local.py -c pyproject.toml
.venv\Scripts\python -m pip_audit -r requirements.lock --require-hashes --disable-pip
.venv\Scripts\python -m pip_audit -r requirements-dev.lock --require-hashes --disable-pip
.venv\Scripts\python -m pip check
```

Le seuil pytest est de **85 % avec branches**, sur tout `src/secure_api`. Les tests interdisent les connexions externes ; une connexion loopback est autorisée pour la self-pipe asyncio Windows. Les transports FastAPI sont en mémoire ; tous les accès JWKS/Key Vault sont injectés/mocks.

Installation locale de Gitleaks (version 8.30.1, checksum du zip vérifié avant exécution) :

```powershell
& ./scripts/Install-Gitleaks.ps1
./tools/gitleaks.exe dir . --config .gitleaks.toml --redact --no-banner
```

Cette analyse exclut uniquement environnements générés, outils, rapports et caches ; elle ne prouve pas l'absence de secrets dans un historique Git qui n'existe pas encore ici. Elle utilise des signatures de détection et ne garantit pas la détection de tout secret arbitraire.

Lorsque le moteur Linux Docker est disponible :

```powershell
docker desktop start --timeout 45
& ./scripts/Test-Container.ps1
.venv\Scripts\python scripts/scan_image_layers.py --image secure-fastapi:phase2
```

Le premier script vérifie UID/GID, absence de groupe root, dépendances de test/pip/compilateurs, credentials permanents configurés, read-only rootfs, capabilities effectives nulles, no-new-privileges, seccomp actif, health checks et arrêt propre. Le second sauvegarde l'image et scanne **chaque couche séparément**, y compris les fichiers supprimés par une couche ultérieure, ainsi que la configuration de l'image. Il n'extrait ni symlinks, ni devices, ni chemins hors répertoire temporaire. Les fichiers temporaires sont nettoyés automatiquement. Il ne remplace pas le scan CVE de l'OS avec Trivy.

Pour régénérer les locks après une mise à jour revue :

```powershell
.venv\Scripts\pip-compile --generate-hashes --strip-extras -o requirements.lock pyproject.toml
.venv\Scripts\pip-compile --allow-unsafe --generate-hashes --strip-extras --extra dev `
  -c requirements.lock -o requirements-dev.lock pyproject.toml
```

`--allow-unsafe` est le nom de l'option pip-tools permettant de verrouiller aussi **pip et setuptools**, nécessaires aux outils de développement ; ce n'est pas une désactivation de la vérification des hashes. Le lock a été résolu sur Python 3.11 Windows ; les wheels Linux amd64 correspondantes ont aussi été téléchargées avec hashes. Une compilation/exécution Linux reste nécessaire pour qualifier l'image. Les installations utilisent PyPI comme index unique, sans index supplémentaire susceptible de créer une dependency confusion. Pour une reproductibilité plus forte, utiliser en Phase 3 un miroir interne immuable de ces wheels.

## Contrat de la Phase 3

Aucun pipeline de production n'est créé ici. Les sources Python, locks et Dockerfile sont prêts pour CodeQL, Ruff/Bandit, audit SCA et scanners d'image. Installer et verrouiller Trivy/Syft sur le runner selon les versions approuvées au moment de l'intégration ; ne pas utiliser de script d'installation distant exécuté sans vérification ni d'Action à tag mutable.

Conventions : service/image `secure-api`, version OCI `1.0.0`, port 8080, contexte Docker `app/`, lock runtime `app/requirements.lock`, rapports locaux `app/reports/`. Générer le SBOM **à partir de l'image finale**, pas de la venv développeur, pour éviter d'y inclure les outils de test. Exemple après installation de Syft sur le runner :

```text
syft secure-fastapi:phase2 -o cyclonedx-json=reports/sbom.cdx.json
trivy image --scanners vuln,secret --image-config-scanners secret --exit-code 1 secure-fastapi:phase2
```

Ces commandes préparatoires n'ont pas été exécutées. Notation signera le digest poussé dans `acr_login_server` avec l'identité **sign** et la clé non exportable du **signing_vault_uri**. La provenance et le SBOM doivent être associés au même digest. Ratify vérifiera la signature et le signataire au déploiement ; Kubernetes devra référencer `REGISTRY/secure-api@sha256:DIGEST`, jamais un tag seul. Un scan réussi et un SBOM ne constituent pas une vérification de provenance.

Les runners doivent pouvoir joindre ACR/Key Vault via les Private Endpoints ; le sous-réseau réservé en Phase 1 n'est pas encore peuplé de runners. Aucun push ACR, signature, test de Ratify, ni connexion Azure n'a été exécuté. Voir `VALIDATION.md` pour distinguer les contrôles effectués des contrôles restant à réaliser.

## Sources techniques

- [Validation des claims Entra](https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation)
- [Access tokens Microsoft](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
- [Chaîne DefaultAzureCredential Python](https://learn.microsoft.com/azure/developer/python/sdk/authentication/credential-chains)
- [PyJWT : API de vérification et cache JWKS](https://pyjwt.readthedocs.io/en/latest/api.html)
- [Paramètres Uvicorn](https://www.uvicorn.org/settings/)
- [Gitleaks v8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)
