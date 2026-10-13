# I. Modèle de menaces et risques résiduels

| Menace | Contrôle | Risque restant / validation |
|---|---|---|
| Secret permanent exfiltré | OIDC par environnement, aucun secret CI, Gitleaks | runner/token temporaire compromis ; runner éphémère et revue indispensables |
| Action ou outil substitué | commit SHA et SHA-256 d'archive, builder par digest | compromission upstream avant verrouillage ; revue des mises à jour |
| Dependency confusion | pins/hashes, liste de dépendances approuvées, audit | paquet légitime compromis sans CVE ; revue et surveillance |
| Image vulnérable | Trivy HIGH/CRITICAL sans ignore unfixed | base vulnérable sans correctif bloque la livraison |
| PR malveillante | CI sans Azure, aucune exécution PR sur pool privé | protections main et équipes GitHub restent à configurer |
| Artefact GitHub remplacé | run/commit/ID et SHA ZIP ancré dans log | administrateur GitHub compromis ; journalisation indépendante recommandée |
| Rebuild après qualification | copie OCI, hashes des blobs et digest remote | registre ou outils compromis ; signatures et vérification indépendante |
| Signature non approuvée | confiance stricte, sujet exact, CA publique approuvée | vol d'autorité de signature ; PKI, rotation/révocation à valider |
| Preuves ou SBOM substitués | artefact de preuves signé, subject image et hashes | preuves décrivent le build, sans garantie SLSA revendiquée |
| Mouvement latéral AKS | réseau privé et Cilium Phase 1 | NetworkPolicies et admission Deny Phase 4 non réalisées |

Les identités build/sign ont AcrPush sur un registre dédié ; un acteur avec ce droit peut aussi supprimer des artefacts. Ce risque requiert séparation des reviewers, surveillance ACR et rétention adaptée. La vérification de configuration du registre est une vérification ponctuelle, pas une prévention permanente de dérive.

Le dépôt est public avec l'autorisation du propriétaire. Ne jamais y ajouter certificats privés, tokens, états Terraform, rapports bruts contenant du code sensible ni paramètres confidentiels. Les identifiants Entra/ressources et certificats publics éventuels ne sont pas des secrets, mais leur exposition doit être revue selon la politique d'entreprise.

## J. Préparation Phase 4

Les métadonnées de release portent la référence ACR par digest, le commit, le digest des preuves et les statuts des contrôles. Ratify doit utiliser le même trust store approuvé, vérifier les signatures et échouer fermé en cas d'erreur. Gatekeeper doit exiger l'image du registre autorisé, son digest et un résultat de vérification valide. Les politiques d'admission doivent être testées en **Deny**, y compris images non signées, signataire inconnu, digest altéré et indisponibilité du vérificateur.

Azure Policy activée dans Terraform ne prouve pas ces contrôles : une initiative Audit ne bloque aucun déploiement. Les manifests Kubernetes, namespaces, seccomp/non-root et NetworkPolicies default-deny avec exceptions explicites seront livrés en Phase 4. Aucun cluster n'a été testé ici.
