# H. Rapport de validation

Ce rapport distingue les contrôles locaux, la CI Linux réelle et les intégrations non exécutées. Dernière préparation : 13 octobre 2026.

| Contrôle | Résultat constaté |
|---|---|
| Tests des règles de sécurité | 39 tests locaux réussis ; les premiers runs Linux exécutent aussi ces tests |
| actionlint, lint et format scripts Python | réussis localement |
| Syntaxe Bash | vérifiée avec Git Bash |
| Politiques workflows et dépendances | réussies localement |
| Outils natifs | sept archives verrouillées et vérifiées |
| Terraform root/bootstrap | fmt/validate réussis, 3 tests Terraform offline réussis ; aucun apply |
| Trivy sources | contrôle HIGH/CRITICAL réussi après correctifs et déviation AZU-0010 limitée |
| Gitleaks fichiers et historique | scans locaux et Linux réussis ; outils téléchargés exclus explicitement |
| Pytest applicatif | 89 tests réussis Windows et Linux, couverture 99,10 % |
| Ruff / Bandit | réussis Linux ; aucune alerte Bandit |
| pip-audit | aucune vulnérabilité connue dans les 30 dépendances runtime / 71 dev analysées |
| CodeQL security-extended | analyse et publication SARIF réussies Linux, 0 résultat |
| CI GitHub Linux | exécutée réellement ; qualification complète encore en cours |
| Docker Linux et SBOM | en attente du workflow Container qualification |
| OIDC, réseau Azure, ACR | non exécutés ; configuration désactivée |
| Notation Azure / signataire approuvé | non exécutés ; trust store vide |
| Ratify/Gatekeeper Deny sur AKS | Phase 4, non exécuté |

Les résultats de scans des sources sont constatés notamment dans le [run 38431202698](https://github.com/RaouiAbdelkamel/azure-zero-trust-devsecops/actions/runs/38431202698). Ce run a échoué à l'export Docker d'un index contenant des attestations : aucune qualification globale n'est revendiquée. Le build OCI du [run 38432045044](https://github.com/RaouiAbdelkamel/azure-zero-trust-devsecops/actions/runs/38432045044) réussit ; sa qualification s'arrête sur une tentative d'écriture d'un blob immutable, corrigée ensuite. La CI préserve la provenance et dérive maintenant le tar runtime des blobs vérifiés, sans rebuild.

Les tests de règles utilisent des rapports synthétiques pour prouver le refus de vulnérabilités critiques, secrets, exceptions expirées, dépendances non approuvées, SBOM vide, digest modifié, workflow mutable et résultat de release incomplet. Les tests OCI contrôlent aussi récursivement la substitution/suppression de blobs, la taille des descripteurs et les hashes de couches décompressées. Ils ne constituent pas des tests cryptographiques ni des preuves de connexion Azure.

Consulter les runs et leurs artefacts dans [GitHub Actions](https://github.com/RaouiAbdelkamel/azure-zero-trust-devsecops/actions). Les rapports sont conservés 30 jours, les candidats 14 jours et les métadonnées de release vérifiées 90 jours. Un run échoué ne fournit aucune image qualifiée. La Phase 3A n'est complète que lorsque tous ses critères Linux ont réellement réussi ; les Phases 3B/3C exigent une exécution Azure réelle.
