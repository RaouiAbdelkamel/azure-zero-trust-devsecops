# Phase 3B2 — Validation Gitleaks et proposition de publication

Contrôles exécutés dans la nuit du 13 au 14 octobre 2026, sur Windows/Python 3.11.9 et Docker Desktop Linux. Aucun commit, push, déploiement Azure, changement Terraform ou réécriture d’historique.

## Causes et corrections

1. La branche `match_sha256` du matcher GPG vérifiait seulement que StartLine == EndLine. Elle ignorait `lines: [1]` et approuvait donc le même fragment sur une autre ligne.
2. Aucun compteur ni identité d’occurrence n’était vérifié. Un finding dupliqué, même dixième, satisfaisait encore l’exception existante.

La politique v2 remplace les suffixes par des chemins complets relatifs à la racine de scan. Chaque fichier de couche est lié à son ordinal OCI (`layer-2`, `layer-5`), son contenu complet SHA-256, sa ligne avec terminaison, ses colonnes inclusives et son fragment SHA-256. Les diff IDs du config sont vérifiés sur les octets décompressés avant extraction : l’ordinal désigne ainsi une couche précise de l’image examinée.

L’ordinal est stable pour le Dockerfile et la base épinglés actuels. Un réagencement des couches ou une mise à jour de paquet nécessite une nouvelle revue ; aucun wildcard ne compense automatiquement ces changements. Le digest complet d’une couche de dépendances peut varier avec des métadonnées de build : il n’est pas utilisé comme exception globale. La combinaison ordinal + chemin complet + octets du fichier + occurrence restreint l’approbation au contenu public examiné.

Pour GPG, le config complet varie avec le build. Les deux exceptions portent sur `config.Env[2]` et `history[5].created_by`, avec SHA-256 du scalaire complet et du fragment exact. Les colonnes sont calculées à partir du token JSON à ce chemin précis ; la ligne autorisée reste 1. Les autres chemins JSON, contextes, lignes et colonnes échouent. Les clés JSON dupliquées et le JSON invalide échouent.

Chaque revue impose propriétaire, justification, contrôle compensatoire, expiration et plafond explicite. Plafonds : GPG 2, distutils 1, cryptography 2, PyJWT API 3, METADATA 1. Chaque emplacement ne peut être consommé qu’une fois, même si le plafond global n’est pas atteint. Les scopes incomplets ou ambigus échouent. Expiration exclusive : 12 novembre 2026, durée maximale 30 jours.

Les rapports sont réduits aux coordonnées, règles et chemins nécessaires ; Secret et Match sont remplacés par REDACTED avant validation de la politique. Les annotations d’approbation préexistantes et champs libres sont supprimés. Gitleaks est également lancé avec `--redact`. Aucun nouvel allowlist global ni exclusion de chemin de bibliothèque.

## Tests négatifs exécutés

| Test demandé | Preuve automatisée | Résultat |
|---|---|---|
| 1. GPG autorisé | test_gpg_authorized_occurrence_accepted ; scan réel des neuf occurrences | Réussi |
| 2. Même empreinte GPG, ligne interdite | test_unapproved_occurrence_rejected[line] | Refus confirmé |
| 3. Occurrence supplémentaire | test_file_exception_exact_scope_rejected[tenth/limit], doublon GPG ; rejeu des neuf findings réels + dixième | Refus confirmé |
| 4. Finding inconnu | mutation unknown ; règle github-pat native | Refus confirmé |
| 5. Empreinte modifiée | mutations fingerprint et file_hash | Refus confirmé |
| 6. Exception expirée | mutation expired | Refus confirmé |
| 7. Secret synthétique dans une couche | tar de couche OCI, extraction par le scanner, vrai Gitleaks verrouillé, code retour 1 et gate en échec | Refus confirmé |
| 8. Rapports sans valeurs de secrets | même test natif, stdout/stderr/JSON vérifiés ; rapport brut hostile avec politique expirée | Réussi |

Les tests complémentaires couvrent changement de couche, suffixe trompeur, colonnes, contexte, approval forgée, scope incomplet, digest substitué et extraction sûre. Le test natif échoue si Gitleaks est absent ; il n’est pas ignoré silencieusement.

## Contrôles exécutés et limites

| Contrôle | Résultat / portée |
|---|---|
| Pytest application | 113 réussis, dont 27 tests scanner ; couverture de secure_api 99,10 % (le matcher n’est pas inclus dans ce pourcentage) |
| Pytest gates | 39 réussis, dont substitutions de blobs/provenance et intégrité OCI |
| Ruff check et format | Réussis sur app/src, app/tests, app/scripts, scripts, security/tests |
| Bandit | 0 finding, 0 erreur sur app/src et app/scripts |
| pip-audit runtime/dev ; pip check | 30 / 71 dépendances, 0 vulnérabilité connue ; environnement cohérent |
| Gitleaks sources / historique | Aucun finding ; historique complet local --all, 12 commits |
| Gitleaks couches | Vrai scan : 9 findings publics approuvés ; rejeu à 10 refusé ; secret synthétique natif refusé |
| Docker Build | Build local précédent réutilisé : base, sources Python et couches vérifiées ; aucune entrée Docker modifiée par la correction. Les scripts/tests sont exclus du contexte de build. Aucun rebuild coûteux redondant |
| Docker Runtime Security | Relancé : UID/GID 10001, capabilities nulles, seccomp, no-new-privileges, rootfs read-only, probes, RSA/JWT, CA et SIGTERM réussis |
| Trivy image et sources | Scans relancés, gates réussis : 0 vulnérabilité HIGH/CRITICAL et 0 secret. Le scan misconfig utilise la déviation AZU-0010 existante et signale les variables Terraform non renseignées ; aucune recette Azure |
| SBOM CycloneDX / SPDX | Régénérés sur l’image : 1 032 composants / 71 packages, gate réussi |
| OCI digest | Graphe complet exporté : hashes et tailles vérifiés récursivement ; 8 couches et diff IDs vérifiés ; base épinglée et sources courantes correspondantes |
| OCI provenance | Attestation SLSA v1 locale et digest de son subject vérifiés. Identité/authenticité du builder GitHub verrouillé et qualification du commit final non validées localement |
| Workflows GitHub Actions | actionlint, politiques workflows/dépendances et syntaxe de tous les scripts Bash réussis |
| CodeQL du correctif | Non exécuté localement ; dernier main publié : jobs CodeQL et SARIF réussis. Nouveau scan requis sur le commit final |
| Azure / ACR / Key Vault / Notation | Non exécutés, Phase 3C ; aucun déploiement |
| Admission AKS | Non exécutée, Phase 4 |

Image locale : `secure-fastapi:phase3b-local`. Digest racine OCI : `sha256:8b1e3139dbd03e7979e13b9ae75ed5116b317e6122991ac0a0cd2e8a895c4a1d`. Digest config exporté : `sha256:02eef1d48121b47ecee757738d7c54283836ede447e02fd9820d17a7fc57bdf2`. Ces objets sont distincts. Aucun digest signé ACR n’est revendiqué.

Les preuves locales générées restent ignorées dans `.reports/current-audit/` et `app/reports/` : layers-hardened.json, nine-verified.json, tenth-blocked.json, image-binding.json, oci-integrity.json, audits, scans, SBOM et phase3b2-pytest.xml. Les preuves ne sont pas des artefacts GitHub qualifiés. Buildx local 0.37.1 / BuildKit 0.33 diffèrent des versions verrouillées pour la CI.

## État Git et contenu proposé

HEAD : `68e68b949df63d1856aa5b53a9bea6b61035a5fe` (commit existant de l’utilisateur). Main distant observé : `b0dc3f5e3ad41a959c5233c11481e6fd0fd1a6e0`. HEAD est un commit en avance, zéro en retard. Aucun déplacement distant observé pendant la correction ; aucun autre agent actif dans ce chat. Cette observation sera à renouveler juste avant un éventuel push.

L’index contenait déjà uniquement app/VALIDATION.md et docs/PHASE3-VALIDATION.md. Il est conservé tel quel ; leurs ajouts de cette correction restent dans le working tree. Aucun fichier n’a été ajouté à l’index par cette correction.

Commit proposé : `Durcir les exceptions Gitleaks des couches OCI`.

Contenu exact proposé, hors retrait conditionnel du coverage :

- .gitignore : ignore /reports/ pour les futurs fichiers générés.
- app/scripts/scan_image_layers.py : scopes stricts, parser de contexte JSON, limites/unicité, rapports expurgés, validation des diff IDs et image unique.
- app/tests/test_layers.py : 24 tests supplémentaires, pour 27 tests scanner au total.
- security/policies/layer-false-positives.json : migration des cinq revues vers le schéma v2, neuf occurrences bornées et justifiées.
- app/VALIDATION.md : conserve les ajouts préexistants de l’utilisateur et actualise l’état local.
- docs/PHASE3-VALIDATION.md : conserve les ajouts préexistants, corrige le dernier run main et distingue 3B de 3C.
- docs/PHASE3B2-VALIDATION.md : ce rapport.

Le diff exact, l’inventaire SHA-256 et les scans des contenus proposés et déjà staged sont préparés dans `.reports/current-audit/proposed-commit.patch`, `proposed-commit-files.json`, `proposed-commit-scan.json` et `staged-scan.json`. Ces artefacts ne sont pas staged.

`git ls-files reports/` ne retourne que reports/coverage.json. Ce rapport reste suivi et présent localement. .gitignore ne retire pas un fichier déjà suivi. Commande préparée, **non exécutée et soumise à l’autorisation explicite de l’utilisateur** :

```powershell
git rm --cached -- reports/coverage.json
```

Après cette autorisation, le retrait du coverage de l’index pourra constituer le huitième changement du commit ; sa copie locale sera conservée. Aucun commit ni push n’est autorisé par la présente proposition.

## GitHub restant et risques résiduels

Le dernier run CI Security main est [38443139832](https://github.com/RaouiAbdelkamel/azure-zero-trust-devsecops/actions/runs/38443139832), sur b0dc3f5 : quality, CodeQL et SARIF réussis ; qualification conteneur échouée sur sept findings non approuvés par la politique alors publiée. Les runs Dependabot ne qualifient pas le candidat courant. Aucun run du commit local 68e68b9 ou du correctif non committé n’est revendiqué.

Après autorisations distinctes de commit et de push : qualifier le SHA final par CI Security, vérifier la réussite du container/release gate, les tests natifs Linux, CodeQL, SBOM/provenance du builder verrouillé et l’archive candidate avec son ID et SHA-256. Ne pas déclencher les workflows Azure désactivés pendant cette validation.

La correction est validée localement. Phase 3B entière reste ouverte jusqu’à qualification GitHub du candidat final. Les exceptions devront être réévaluées avant le 12 novembre ; mises à jour du scanner, des dépendances, de la base ou du Dockerfile peuvent bloquer volontairement le gate. La provenance locale n’est pas une preuve cryptographique d’un builder approuvé. Aucune signature OCI, confiance Notation ou admission AKS n’est encore validée.

## Avancement des phases

| Phase | État vérifié | Suite |
|---|---|---|
| 1 — Terraform privé/RBAC/identités | Code et validations locales existants ; non déployé ; inchangé ici | Recette Azure future |
| 2 — FastAPI et Docker durci | Application et runtime validés localement | Intégration Azure future |
| 3A — CI sécurité sources | Jobs quality/CodeQL/SARIF de main b0dc3f5 réussis | Revalider le SHA final |
| 3B1 — Build/runtime/Trivy/SBOM/OCI | Validés localement ; candidat GitHub non qualifié | Builder verrouillé et artefact final GitHub |
| 3B2 — Exceptions Gitleaks couches | Deux contournements corrigés ; tests et scan local réussis | Publication autorisée puis tests natifs Linux |
| 3B — Qualification complète | En attente GitHub ; aucune homologation production | CI Security entièrement verte |
| 3C — OIDC/ACR/Key Vault/Notation | Préparée, désactivée et non exécutée | Après validation complète 3B et périmètre autorisé |
| 4 — Admission AKS/NetworkPolicies | À réaliser et à tester | Après chaîne de confiance 3C |


## Relecture avant publication — 14 octobre 2026

La branche main distante et HEAD sont inchangés. L'index préexistant reste identique. Les sept fichiers correspondaient au précédent inventaire ; la relecture a ensuite corrigé un encodage erroné des accents dans app/VALIDATION.md et docs/PHASE3-VALIDATION.md, puis actualisé leur état documentaire. Aucun code, test, workflow ou fichier Terraform n'a changé lors de cette relecture.

Les 27 tests du scanner et les 39 tests des gates ont été relancés avec succès ; Ruff et actionlint passent. Une première invocation combinée depuis la racine a échoué à importer secure_api, faute du pythonpath défini dans app/pyproject.toml ; les suites ont ensuite été lancées depuis leurs répertoires corrects. Aucun test n'a été ignoré. Le rejeu des neuf findings réels accepte les neuf et refuse le dixième. Les autres preuves restent applicables aux entrées inchangées : aucun rebuild ou scan lourd redondant.

Le patch, les inventaires et les scans du contenu proposé ont été régénérés après correction de l'encodage. Le retrait conditionnel du coverage, le commit et le push attendent toujours leurs autorisations explicites. La surveillance du nouveau workflow et le plan détaillé de Phase 3C restent conditionnés respectivement à la publication autorisée et à la validation complète de Phase 3B.
