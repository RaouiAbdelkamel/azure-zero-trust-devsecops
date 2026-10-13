# C. Contrôles de sécurité

Toutes les actions tierces sont épinglées par SHA de commit ; les sept outils natifs sont téléchargés depuis leurs dépôts officiels et leur archive est vérifiée avant extraction du seul binaire attendu. Buildx et le digest de l'image BuildKit sont verrouillés. `refresh-tool-lock.py` est une opération de maintenance à revoir ; elle ne met pas automatiquement à jour les workflows ni le builder.

Ruff, Bandit, CodeQL security-extended, pip-audit des deux lockfiles, Gitleaks sur les fichiers et tout l'historique accessible, Trivy sur les sources et l'image constituent les contrôles obligatoires. Dependabot propose des mises à jour ; sa configuration seule ne prouve pas qu'une mise à jour est sûre. Les dépendances applicatives doivent correspondre à la liste approuvée et disposer de hashes. Une erreur d'outil, un rapport manquant, un job skipped ou un résultat non conforme bloque la qualification.

Les vulnérabilités HIGH/CRITICAL bloquent, même sans correctif disponible. Les secrets bloquent quelle que soit leur sévérité. Les autres niveaux sont conservés. pip-audit bloque toute vulnérabilité connue. CodeQL bloque les alertes warning/error. Les champs de contenu, snippets, code et secrets sont masqués avant conservation ; un rapport JSON partiel est supprimé. Les alertes ne sont jamais rendues conformes par la sanitisation.

Les dérogations de vulnérabilités sont vides par défaut. Toute demande exige package exact, identifiant, propriétaire, justification, compensation et expiration de 30 jours maximum. La CI vérifie les dates ; le changement de la politique exige une revue humaine indépendante avant mise en production.

## Modifications limitées du socle

- Backend Terraform : `network_rules.default_action=Deny` et `bypass=None` explicites.
- AKS : `network_policy=cilium` explicite, cohérent avec le dataplane Cilium.
- Scanner des couches Phase 2 : sélection explicite du binaire Gitleaks verrouillé sur Linux.

Trivy AZU-0010 recommande un bypass AzureServices pour Storage. Ce backend ne nécessite aucun service de ce type. La déviation documentée est limitée à la ressource et au hash exact du fichier `infra/bootstrap-state/main.tf`, expire le 12 novembre 2026, et conserve endpoint privé, accès public désactivé et réseau Deny. Une modification du fichier ou l'expiration bloque à nouveau. Aucun ignore général n'est utilisé.

## D. Qualification Docker

Le build multi-stage conserve l'utilisateur 10001:10001. La CI charge l'export Docker du même build et vérifie son digest de configuration contre le manifeste OCI. Elle impose rootfs en lecture seule, capabilities vides, no-new-privileges, seccomp actif, limites mémoire/CPU/PID, puis vérifie UID/GID, absence des outils de build, endpoints de santé et arrêt SIGTERM. Les couches historiques sont inspectées pour les secrets. Aucun accès au moteur Docker Windows n'est nécessaire.

## E. SBOM et traçabilité

Syft produit `out/sbom.cdx.json` et `out/sbom.spdx.json` depuis l'image OCI construite. Les schémas et la présence de composants sont contrôlés. `build.json` lie commit, dépôt, run, manifestes et configuration. `provenance.buildkit.json` doit désigner le manifeste de plateforme. `qualification.json` et `bundle.json` lient les contrôles et hashes. Ces fichiers ne sont conservés comme candidat que lorsque toutes les étapes obligatoires ont réussi.

La signature des preuves ajoute une liaison cryptographique au digest image dans ACR. Un SBOM seul n'atteste ni l'innocuité ni l'origine d'un composant ; l'analyse des vulnérabilités et la revue des mises à jour restent nécessaires.
