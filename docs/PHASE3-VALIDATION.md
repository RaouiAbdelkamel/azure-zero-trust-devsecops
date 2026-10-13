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
| Docker, runtime et SBOM | réussis localement le 13 octobre 2026 ; la qualification GitHub du code courant reste en attente |
| Scan Gitleaks des couches | 9 occurrences expurgées, toutes rattachées à des fixtures statiques précises ; finding synthétique bloqué |
| OIDC, réseau Azure, ACR | non exécutés ; configuration désactivée |
| Notation Azure / signataire approuvé | non exécutés ; trust store vide |
| Ratify/Gatekeeper Deny sur AKS | Phase 4, non exécuté |

## Validation locale complémentaire — 13 octobre 2026

Le moteur Docker Desktop Linux était accessible pendant cette validation. Le build local de l’image Python Alpine épinglée a réussi. Le runtime a satisfait les contrôles UID/GID 10001, capabilities effectives nulles, `no-new-privileges`, seccomp actif, rootfs read-only, absence d’outils de build, endpoints de santé, compatibilité JWT RS256/RSA et certificats CA, puis arrêt SIGTERM propre. Trivy a terminé le scan vulnérabilités/secrets et son gate ; Syft a produit les SBOM CycloneDX et SPDX, acceptés par le gate du dépôt.

Gitleaks 8.30.1 a relevé neuf occurrences dans l’image. Les deux occurrences de la même empreinte publique GPG dans le config Python et les sept occurrences de code ou de métadonnées des paquets Python/cryptography/PyJWT ont été associées à des empreintes et lignes exactes, chemins contraints et expiration au 12 novembre 2026. Aucun chemin Python n’est exclu globalement. Un test négatif a ajouté un jeton GitHub fictif à une image dérivée : le gate des couches a échoué sur cette occurrence, avec un rapport expurgé.

Ces contrôles sont locaux. Buildx local v0.37.1 et BuildKit v0.33 ne correspondent pas aux versions verrouillées pour GitHub (Buildx v0.38.0 et image BuildKit épinglée). Ils ne remplacent donc pas la validation de provenance du workflow. Les changements locaux ne sont pas encore publiés ; le dernier run CI Security de main, 38443139832 (commit b0dc3f5), a échoué au gate des couches : deux occurrences approuvées par la politique publiée, sept non approuvées. La Phase 3B ne sera considérée validée qu'après réussite de la qualification du commit courant sur GitHub Actions.

Les résultats de scans des sources sont constatés notamment dans le [run 38431202698](https://github.com/RaouiAbdelkamel/azure-zero-trust-devsecops/actions/runs/38431202698). Ce run a échoué à l'export Docker d'un index contenant des attestations : aucune qualification globale n'est revendiquée. Le build OCI du [run 38432045044](https://github.com/RaouiAbdelkamel/azure-zero-trust-devsecops/actions/runs/38432045044) réussit ; sa qualification s'arrête sur une tentative d'écriture d'un blob immutable, corrigée ensuite. La CI préserve la provenance et dérive maintenant le tar runtime des blobs vérifiés, sans rebuild.

Les tests de règles utilisent des rapports synthétiques pour prouver le refus de vulnérabilités critiques, secrets, exceptions expirées, dépendances non approuvées, SBOM vide, digest modifié, workflow mutable et résultat de release incomplet. Les tests OCI contrôlent aussi récursivement la substitution/suppression de blobs, la taille des descripteurs et les hashes de couches décompressées. Ils ne constituent pas des tests cryptographiques ni des preuves de connexion Azure.

Consulter les runs et leurs artefacts dans [GitHub Actions](https://github.com/RaouiAbdelkamel/azure-zero-trust-devsecops/actions). Les rapports sont conservés 30 jours, les candidats 14 jours et les métadonnées de release vérifiées 90 jours. Un run échoué ne fournit aucune image qualifiée. La Phase 3A n'est complète que lorsque tous ses critères Linux ont réellement réussi ; la Phase 3B exige la qualification Docker/OCI GitHub du commit final et la Phase 3C exige une intégration Azure réelle.


## Correction Phase 3B2 — 14 octobre 2026

L'audit a démontré deux contournements dans le matcher précédent : la branche GPG ignorait les lignes approuvées et aucun compteur ne refusait un finding supplémentaire. La politique v2 impose des chemins complets, des occurrences uniques et plafonnées, des coordonnées exactes, les SHA-256 du fichier/ligne/fragment ou du scalaire JSON attendu, des contextes JSON précis et une expiration. Les couches exportées sont liées aux diff IDs avant extraction. Les rapports perdent toute valeur de secret et tout champ libre non nécessaire avant validation de la politique.

La correction passe 113 tests applicatifs (couverture applicative 99,10 %, dont 27 tests du scanner) et les 39 tests des gates. Le scan réel accepte les neuf occurrences attendues et rejette une dixième occurrence. Ruff, Bandit, pip-audit, Gitleaks sources/historique, actionlint, runtime Docker, Trivy et SBOM passent localement. Le graphe OCI local et le sujet de sa provenance SLSA sont vérifiés ; l'identité du builder GitHub verrouillé reste à qualifier. Voir [le rapport détaillé et la proposition de commit](PHASE3B2-VALIDATION.md).

Aucun commit, push ou déploiement n'a été réalisé pendant cette correction. `reports/coverage.json` reste suivi et présent localement : son retrait de l'index attend une autorisation explicite.
