# H. Rapport de validation

Ce rapport distingue les contrôles locaux, la CI Linux réelle et les intégrations non exécutées. Dernière préparation : 13 octobre 2026.

| Contrôle | Résultat constaté |
|---|---|
| Tests des règles de sécurité | 31 tests locaux réussis |
| actionlint, lint et format scripts Python | réussis localement |
| Syntaxe Bash | vérifiée avec Git Bash |
| Politiques workflows et dépendances | réussies localement |
| Outils natifs | sept archives verrouillées et vérifiées |
| Terraform root/bootstrap | fmt/validate réussis ; aucun apply |
| Trivy sources | contrôle HIGH/CRITICAL réussi après correctifs et déviation AZU-0010 limitée |
| Gitleaks fichiers | scan local réussi ; outils téléchargés exclus explicitement |
| CI GitHub Linux | en attente de publication et d'exécution réelle |
| Docker Linux et SBOM | en attente du workflow Container qualification |
| OIDC, réseau Azure, ACR | non exécutés ; configuration désactivée |
| Notation Azure / signataire approuvé | non exécutés ; trust store vide |
| Ratify/Gatekeeper Deny sur AKS | Phase 4, non exécuté |

Les tests de règles utilisent des rapports synthétiques pour prouver le refus de vulnérabilités critiques, secrets, exceptions expirées, dépendances non approuvées, SBOM vide, digest modifié, workflow mutable et résultat de release incomplet. Ils ne constituent pas des tests cryptographiques ni des preuves de connexion Azure.

Consulter les runs et leurs artefacts dans [GitHub Actions](https://github.com/RaouiAbdelkamel/azure-zero-trust-devsecops/actions). Les rapports sont conservés 30 jours, les candidats 14 jours et les métadonnées de release vérifiées 90 jours. Un run échoué ne fournit aucune image qualifiée. La Phase 3A n'est complète que lorsque tous ses critères Linux ont réellement réussi ; les Phases 3B/3C exigent une exécution Azure réelle.
