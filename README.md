# Azure Zero Trust & DevSecOps — Secure Software Supply Chain

Projet de référence : infrastructure Azure privée et microservice FastAPI durci.

| Phase | Livrable | État |
|---|---|---|
| 1 | [Infrastructure Terraform](infra/README.md) | Validée localement ; non déployée sur Azure |
| 2 | [Application et Dockerfile](app/README.md) | Tests locaux exécutés ; voir [rapport de validation](app/VALIDATION.md) pour Docker |
| 3 | [CI, SBOM et préparation OIDC/Notation](docs/PHASE3-ARCHITECTURE.md) | Implémentée ; [validation réelle](docs/PHASE3-VALIDATION.md), Azure désactivé |
| 4 | Admission, NetworkPolicies et déploiement par digest | À réaliser |

Les identités entrantes JWT et sortantes Workload Identity ont des responsabilités distinctes. Aucun secret permanent n'est requis pour les tests locaux. Ne pas considérer le socle comme homologué production avant la recette Azure, la validation réelle du conteneur et les politiques d'admission de la Phase 4.

Dépôt public : [RaouiAbdelkamel/azure-zero-trust-devsecops](https://github.com/RaouiAbdelkamel/azure-zero-trust-devsecops). Voir [GitHub Actions](https://github.com/RaouiAbdelkamel/azure-zero-trust-devsecops/actions) pour les résultats et artefacts. La CI Azure exige des environnements protégés, des identités distinctes et des runners privés éphémères ; les [prérequis opérateur](docs/AZURE-OIDC-SETUP.md) restent à appliquer après revue.
