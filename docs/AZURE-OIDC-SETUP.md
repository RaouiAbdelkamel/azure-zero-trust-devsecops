# F. Intégration Azure — préparation opérateur

Cette procédure doit être exécutée après validation de la CI et revue de sécurité. Aucun `terraform apply`, rôle Azure, certificat ou environnement GitHub n'a été créé par la Phase 3.

## Identités et fédérations

Renseigner `github_repository = "RaouiAbdelkamel/azure-zero-trust-devsecops"` dans la configuration Terraform Phase 1. Les fédérations existantes utilisent l'issuer `https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange` et les subjects exacts :

```text
repo:RaouiAbdelkamel/azure-zero-trust-devsecops:environment:build-production
repo:RaouiAbdelkamel/azure-zero-trust-devsecops:environment:sign-production
```

Build et sign sont deux identités managées distinctes. Build a AcrPush sur le registre dédié. Sign a AcrPush et le rôle personnalisé du coffre de signature : keys/read, keys/sign/action, certificates/read, sans secrets/get. Ce mode ACR est `LegacyRegistryPermissions` ; les rôles couvrent le registre dédié, pas une repository ABAC. Ne pas les réutiliser sur un registre mutualisé.

La vérification CI nécessite une **nouvelle** identité distincte et une fédération :

```text
repo:RaouiAbdelkamel/azure-zero-trust-devsecops:environment:release-production
```

Lui attribuer uniquement AcrPull sur ce registre, sans Key Vault. Ne pas réutiliser l'identité AKS Ratify. Une extension Terraform de Phase 1 reste à approuver et appliquer pour cette identité. Les trois identités CI nécessitent également une permission ARM `Microsoft.ContainerRegistry/registries/read`, limitée au registre, pour contrôler sa configuration privée. Préférer un rôle personnalisé à Reader sur le groupe de ressources. Aucun rôle Owner/Contributor/Key Vault Administrator n'est requis à l'exécution.

## GitHub et configuration publique

Créer les environnements `build-production`, `sign-production`, `release-production` avec reviewers obligatoires, auto-approbation interdite, règle de branche personnalisée exactement `main`. Vérifier que le plan GitHub applique ces contrôles. Configurer la protection main et les revues CODEOWNERS avec une équipe indépendante ; CODEOWNERS seul n'impose pas la revue. Ces réglages n'ont pas été modifiés par ce projet.

Renseigner les valeurs publiques dans `security/azure-config.json` : UUID subscription/tenant et client IDs distincts, nom ACR privé, nom coffre de signature, certificat, URL **versionnée** de la clé, sujet approuvé et chemins/hashes des certificats publics. Vérifier la configuration avec `python scripts/policy.py azure`. Ajouter ensuite la variable GitHub `AZURE_RELEASE_ENABLED=true` et `enabled=true` dans le fichier par PR revue, lorsque les prérequis sont réellement disponibles.

Aucun client secret, mot de passe ACR, clé privée ou token permanent n'est accepté. azure/login obtient un token OIDC ponctuel ; az expose un token ACR temporaire transmis à ORAS par stdin. Les configurations de connexion sont dans RUNNER_TEMP avec permissions 700, supprimées en fin de job, sur un runner détruit après chaque exécution.

## G. Certificat et signature

Faire émettre par la PKI approuvée un certificat de signature avec la clé RSA-HSM non exportable du coffre de signature Premium. Utiliser un certificat adapté à la signature de code, sa chaîne publique et une clé versionnée. La procédure de délivrance/rotation dépend de la PKI de l'entreprise ; le pipeline ne crée pas cette racine de confiance.

Le plugin Azure Key Vault utilise `credential_type=azurecli` et `ca_certs=<chaîne publique locale>` pour éviter la récupération de la chaîne dans un secret Key Vault. Le script vérifie que le certificat référence la version de clé configurée, que cette clé est RSA-HSM, non exportable et activée. Notation signe l'image et l'artefact de preuves, puis vérifie immédiatement les deux signatures avec une politique stricte. Le job de vérification indépendant contrôle à nouveau ces références et preuves.

Après une CI main push réussie au commit courant, déclencher `azure-publish-sign.yml` avec son run ID ; puis `verify-release.yml` avec le run ID de signature réussi au même commit. Un changement de main impose un nouveau build et une nouvelle qualification. Aucun déploiement AKS n'est effectué.

Sources : [signature avec CA et Key Vault](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tutorial-sign-trusted-ca), [configuration du plugin Azure KV](https://github.com/Azure/notation-azure-kv/blob/main/docs/plugin-config.md).
