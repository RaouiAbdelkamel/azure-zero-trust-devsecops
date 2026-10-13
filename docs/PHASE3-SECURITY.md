# C. Contrôles de sécurité

Toutes les actions tierces sont épinglées par SHA de commit ; les sept outils natifs sont téléchargés depuis leurs dépôts officiels et leur archive est vérifiée avant extraction du seul binaire attendu. Buildx et le digest de l'image BuildKit sont verrouillés. `refresh-tool-lock.py` est une opération de maintenance à revoir ; elle ne met pas automatiquement à jour les workflows ni le builder.

Ruff, Bandit, CodeQL security-extended, pip-audit des deux lockfiles, Gitleaks sur les fichiers et tout l'historique accessible, Trivy sur les sources et l'image constituent les contrôles obligatoires. Dependabot propose des mises à jour ; sa configuration seule ne prouve pas qu'une mise à jour est sûre. Les dépendances applicatives doivent correspondre à la liste approuvée et disposer de hashes. Une erreur d'outil, un rapport manquant, un job skipped ou un résultat non conforme bloque la qualification.

Les vulnérabilités HIGH/CRITICAL bloquent, même sans correctif disponible. Les secrets bloquent quelle que soit leur sévérité. Les autres niveaux sont conservés. pip-audit bloque toute vulnérabilité connue. CodeQL bloque les alertes warning/error. Les champs de contenu, snippets, code et secrets sont masqués avant conservation ; un rapport JSON partiel est supprimé. Les alertes ne sont jamais rendues conformes par la sanitisation.

Les dérogations de vulnérabilités sont vides par défaut. Toute demande exige package exact, identifiant, propriétaire, justification, compensation et expiration de 30 jours maximum. La CI vérifie les dates ; le changement de la politique exige une revue humaine indépendante avant mise en production.

## Modifications limitées du socle

- Backend Terraform : `network_rules.default_action=Deny` et `bypass=None` explicites.
- AKS : `network_policy=cilium` explicite, cohérent avec le dataplane Cilium.
- Scanner des couches Phase 2 : sélection explicite du binaire Gitleaks verrouillé sur Linux.
- Base du Dockerfile : remplacement de Bookworm par Python officiel Alpine 3.24, toujours Python 3.11 et digest vérifié. Le scan réel Bookworm bloque 55 occurrences HIGH/CRITICAL ; Trixie reste bloqué. Alpine conserve son inventaire APK et dispose de wheels musllinux verrouillées pour les dépendances existantes. Les composants setuptools/pip/wheel sont retirés du runtime comme en Phase 2. La qualification complète du nouvel environnement reste obligatoire.

Trivy AZU-0010 recommande un bypass AzureServices pour Storage. Ce backend ne nécessite aucun service de ce type. La déviation documentée est limitée à la ressource et au hash exact du fichier `infra/bootstrap-state/main.tf`, expire le 12 novembre 2026, et conserve endpoint privé, accès public désactivé et réseau Deny. Une modification du fichier ou l'expiration bloque à nouveau. Aucun ignore général n'est utilisé.

## D. Qualification Docker

Le build multi-stage conserve l'utilisateur 10001:10001. La CI dérive un tar Docker depuis l'export OCI, vérifie les hashes des couches décompressées contre les diff IDs, le charge et vérifie son digest de configuration contre le manifeste OCI. Elle impose rootfs en lecture seule, capabilities vides, no-new-privileges, seccomp actif, limites mémoire/CPU/PID, puis vérifie UID/GID, absence des outils de build, endpoints de santé et arrêt SIGTERM. Les couches historiques sont inspectées pour les secrets. Aucun accès au moteur Docker Windows n'est nécessaire.

## E. SBOM et traçabilité

Syft produit `out/sbom.cdx.json` et `out/sbom.spdx.json` depuis l'image OCI construite. Les marqueurs de format et la présence de composants sont contrôlés ; ce contrôle ne remplace pas une validation exhaustive des schémas officiels. `build.json` lie commit, dépôt, run, manifestes, configuration et hashes des preuves. `provenance.buildkit.json` doit désigner le manifeste de plateforme. `qualification.json` contient les contrôles terminés. Ces fichiers ne sont conservés comme candidat que lorsque toutes les étapes obligatoires ont réussi.

La signature des preuves ajoute une liaison cryptographique au digest image dans ACR. Un SBOM seul n'atteste ni l'innocuité ni l'origine d'un composant ; l'analyse des vulnérabilités et la revue des mises à jour restent nécessaires.
