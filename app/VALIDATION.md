# Rapport de réalisation — Phase 2

Date : 13 octobre 2026. Workspace : `C:\Users\Abdelkamel\Documents\08_CARRIERE\Azure`.

**L'application est implémentée et validée localement. La Phase 2 n'est pas entièrement homologuée : le build et le runtime Docker restent bloqués par une panne du moteur Docker Desktop.** Aucun résultat Docker/Azure n'est présenté comme réussi.

## A. Architecture réalisée

L'arborescence complète des fichiers se trouve dans [README.md](README.md#organisation). Les fichiers applicatifs, tests, deux locks, Dockerfile, scripts de vérification et documentation sont créés dans `app/`. Les ressources Terraform existantes n'ont pas été modifiées. Le README racine relie les phases.

Deux identités distinctes sont prises en compte : les JWT Entra entrants authentifient les appelants de l'API ; Workload Identity authentifie l'application auprès de Key Vault. Aucun abonnement Azure n'est requis localement.

## B. Fonctionnalités implémentées

Les quatre endpoints demandés sont implémentés. La liveness reste indépendante de la readiness ; la readiness dépend de l'état local du cycle de vie, sans appel Azure. `info` expose uniquement service/version/environnement ; `secure` ne renvoie aucune identité ni donnée confidentielle.

La vérification JWT impose une signature RS256 valide, une clé RSA >= 2048 bits, un tenant et un issuer Microsoft v2 exacts, l'audience API, les claims temporels et les scopes/rôles configurés. Les erreurs d'authentification/permission sont distinguées sans révéler de détails internes. JWKS distant n'est contacté qu'au premier token nécessitant une clé ; tests entièrement locaux.

Le service Key Vault crée son client tardivement avec le SDK officiel, interdit les credentials permanents et les fallbacks développeur, et refuse IMDS en production. Il accepte des clients injectés pour les tests et remplace les erreurs SDK par des messages génériques. Aucun endpoint n'expose les secrets.

Logs JSON, validation Pydantic, erreurs 500/422 génériques, headers de sécurité, CORS explicite, documentation désactivée et contrôle HTTPS pour HSTS sont implémentés.

## C. Sécurité Docker

Mesures présentes dans le code :

- Deux stages, image Python slim officielle fixée au digest réel `sha256:0a310eeecf4e1f5a0743f9a6520c90c88d089c903ca5fd283f501e3a805f5f89`.
- Manifeste récupéré depuis Docker Hub et hash vérifié ; preuve stockée dans `base-image.json`.
- Venv de production sans pip ; installation avec `--require-hashes --only-binary=:all:`.
- Copie des sources et dépendances seulement ; liste d'autorisation `.dockerignore`.
- Utilisateur/groupe système 10001, aucun home, shell nologin ; `USER 10001:10001`.
- Code et dépendances appartenant à root ; port 8080 ; pas de reload, `.pyc`, buffering de logs ni secrets en arguments.
- SIGTERM et timeout Uvicorn ; paramètres compatibles avec une racine en lecture seule.

Les contrôles Linux effectifs (UID, capabilities, seccomp, read-only, arrêt propre, absence de compilateurs) sont **préparés, mais non exécutés**. Le script Docker échoue immédiatement lorsque le moteur n'est pas accessible ; il ne valide pas les tests suivants par défaut.

## D. Contrôles exécutés

| Contrôle | Résultat | Nombre / portée | Couverture | Statut |
|---|---|---|---|---|
| pytest : configuration | Réussi | 21 tests | Incluse au total | Exécuté |
| pytest : health/lifecycle/lanceur | Réussi | 4 tests | Incluse au total | Exécuté |
| pytest : Key Vault et identité | Réussi | 15 tests, SDK mocké | Incluse au total | Exécuté |
| pytest : lecture sûre des layers | Réussi | 3 tests, archives synthétiques | Hors périmètre de couverture applicative | Exécuté |
| pytest : JWT, headers, erreurs, logs, CORS | Réussi | 46 tests | Incluse au total | Exécuté |
| **pytest total** | **89 passés, 0 échec, 0 ignoré** | Toute l'application + tests scripts | **99,10 % avec branches ; seuil 85 %** | **Exécuté** |
| HTTP réel local | Réussi | 5 routes sur Uvicorn, loopback | Sans objet | Exécuté |
| Ruff lint | Aucune erreur | Sources, tests et scripts Python | Sans objet | Exécuté |
| Ruff format | Conforme | 19 fichiers Python | Sans objet | Exécuté |
| Bandit | 0 finding restant | Sources et scripts Python, 8 contrôles locaux explicitement justifiés | Sans objet | Exécuté avec exceptions revues |
| pip-audit runtime | 0 vulnérabilité connue | 30 distributions verrouillées | Sans objet | Exécuté |
| pip-audit développement | 0 vulnérabilité connue | 71 distributions verrouillées | Sans objet | Exécuté |
| pip check | Aucune incohérence | Venv locale | Sans objet | Exécuté |
| Gitleaks 8.30.1 | Aucun secret détecté | Arborescence applicative hors fichiers générés, sorties expurgées | Sans objet | Exécuté |
| Digest Python officiel | Manifeste SHA-256 concordant | Index Docker Hub | Sans objet | Exécuté |
| Wheels runtime Linux amd64 | Téléchargement avec hashes réussi | 30 distributions | Sans objet | Exécuté, sans exécution Linux |
| Syntaxe PowerShell du script conteneur | Aucune erreur de parsing | Script PowerShell | Sans objet | Exécuté ; ne prouve pas son runtime |
| Build Docker | Moteur inaccessible | Aucune image construite | Sans objet | Bloqué |
| Exécution Linux Restricted | Non exécutée | UID/GID, caps, seccomp, rootfs, SIGTERM, probes | Sans objet | À relancer |
| Secrets des couches Docker | Non exécuté | Script fourni ; aucune image disponible | Sans objet | À relancer |
| Trivy OS/image, Syft SBOM | Non exécutés | Phase 3 / image finale | Sans objet | À réaliser |
| Entra / Key Vault / AKS réels | Non exécutés | Pas de déploiement Azure | Sans objet | À qualifier |

Rapports machines locaux : `reports/pytest.xml`, `coverage.json`, `bandit.json`, `audit-runtime.json`, `audit-dev.json`, `gitleaks.json`, `smoke.json`. Ces fichiers sont ignorés par Git ; le présent rapport synthétique est versionnable.

Le smoke test a obtenu : `/health/live=200`, `/health/ready=200`, `/api/v1/info=200`, `/api/v1/secure=503` en mode local sans authentification configurée, `/docs=404`. L'autorisation 200 avec JWT valide et tous les refus cryptographiques sont testés via le transport ASGI et des clés locales.

## E. Vulnérabilités et corrections

Aucune CVE n'a été signalée par pip-audit pour les deux locks à la date de l'analyse. Cela concerne les dépendances Python interrogées dans la base d'avis, pas l'OS Debian ni l'image finale. Aucun CVE ou numéro de version corrigée n'est inventé. Les audits devront être relancés en CI et après chaque mise à jour.

Les contrôles ont permis de corriger :

- Compatibilité des tests avec le `TestClient` actuel : `httpx2` exact ajouté au lock **dev**, HTTPX de test retiré des dépendances runtime.
- Reproductibilité des outils : pip et setuptools inclus dans le lock dev via `--allow-unsafe`, sans relâcher les hashes.
- Test réseau Windows : autorisation limitée au loopback pour la self-pipe asyncio, tout accès externe interdit.
- Risque d'argument/exécution et extraction d'archives : argv sans shell, binaire Docker résolu par chemin, refus des références commençant par `-`, rejet de traversal, aucun lien/device extrait.
- PowerShell : passage explicite des tableaux d'arguments à Docker et décodage UTF-8 des checksums renvoyés en bytes.

Exceptions statiques revues, sans suppression globale :

| Identifiant | Nombre | Justification |
|---|---:|---|
| B104 / Ruff S104 | 1 | Bind `0.0.0.0:8080` nécessaire dans le conteneur ; exposition contrôlée par réseau et manifests |
| B310 / Ruff S310 | 2 | URLs HTTPS littérales du registre Docker officiel ; aucune URL choisie par un utilisateur |
| B404 | 2 | Import subprocess dans les deux scripts de validation CLI locaux |
| B603 / Ruff S603 | 3 | Exécutables locaux résolus et argv explicites, sans shell, pour Docker/Gitleaks/Uvicorn |
| Ruff S505 | 1 test | Clé RSA 1024 bits générée uniquement pour prouver son rejet ; aucune clé faible applicative |

Ces diagnostics génériques ne correspondent pas à des CVE détectées dans l'application. Aucun avis de vulnérabilité des dépendances n'a été ignoré.

## F. Limites et blocage Docker

Python local : 3.11.9. Docker client : 29.8.1, contexte `desktop-linux`. La version du moteur n'a pas pu être interrogée.

Une tentative de `docker desktop start --timeout 45` a été effectuée. Les logs locaux de Docker Desktop rapportent un échec d'initialisation du **Secrets Engine**, lors de l'accès/renommage de son socket `engine.sock` en `engine.sock.stale`. Le named pipe `dockerDesktopLinuxEngine` reste absent. Les commandes CLI en attente ont été interrompues ; aucun reset, suppression de stockage Docker, changement WSL/Windows ou déploiement Azure n'a été réalisé.

La réparation du moteur est un préalable externe. Après réparation par l'opérateur, exécuter :

```powershell
Set-Location C:\Users\Abdelkamel\Documents\08_CARRIERE\Azure\app
docker version
& ./scripts/Test-Container.ps1
.venv\Scripts\python scripts/scan_image_layers.py --image secure-fastapi:phase2
```

Si l'OS ou l'image comporte des vulnérabilités, mettre à jour la base et ses digests, reconstruire puis relancer tous les contrôles concernés avant d'accepter la Phase 2. La collecte du SBOM et les scans Trivy de l'OS restent requis en Phase 3. La signature/provenance, l'accès privé réel à ACR et les comportements d'admission restent non validés.

## G. Préparation Phase 3

Contexte `app/`, image `secure-api`, port 8080, runtime Python 3.11, version OCI 1.0.0. Les dépendances de production sont séparées des outils de tests. Les rapports sont exploitables en CI et la couverture impose un seuil.

Le pipeline futur utilisera les identités OIDC **build** et **sign** de la Phase 1, des runners privés, `acr_login_server`, le coffre **signing_vault_uri** et une clé de signature non exportable. Le SBOM doit représenter l'image finale ; la signature et la provenance doivent référencer son digest. Aucune donnée de signature n'est couplée au service Key Vault applicatif.

Le deployment devra référencer l'image par digest, avec ServiceAccount `fastapi/fastapi`, UID/GID 10001, capacités supprimées, seccomp RuntimeDefault, racine en lecture seule, PSS Restricted et probes sur 8080. L'identité applicative de Phase 1 n'a aucun rôle de données par défaut ; un besoin précis est nécessaire avant tout accès Key Vault.

L'intégration est préparée dans le code et la documentation. Aucun pipeline de production n'a été créé, conformément au périmètre demandé.
