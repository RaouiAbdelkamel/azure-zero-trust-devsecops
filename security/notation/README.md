# Confiance Notation

La politique initiale est vide et refuse toute image. Ne pas ajouter `*` comme identité de confiance ni `skip` comme vérification.

Après délivrance par la PKI réelle, déposer uniquement les certificats **publics** : `certificates/root.pem` et `certificates/ca-bundle.pem`. La chaîne doit correspondre au certificat de signature RSA-HSM. Enregistrer le SHA-256 du fichier racine et le sujet X.509 exact dans `security/azure-config.json`. Ne jamais exporter la clé privée ni utiliser un certificat de test comme racine de production.

Créer une seule règle de confiance pour `<registre>.azurecr.io/secure-api`, niveau `strict`, trust store `ca:production`, et `trustedIdentities` contenant exactement `x509.subject: <DN approuvé>`. Le validateur refuse une autre scope, plusieurs règles, un sujet générique ou un hash de racine différent.

Le plugin utilise la chaîne publique locale via `ca_certs` et le token Azure CLI OIDC. La signature est COSE. La clé Key Vault reste non exportable ; aucune permission secrets/get n'est ajoutée pour obtenir sa chaîne.

Vérifier avec la version verrouillée de Notation les extensions du certificat, la validité, la chaîne, la révocation et l'accès aux endpoints PKI nécessaires. Prévoir rotation du certificat et revue de la politique avant expiration. Aucun test cryptographique Notation ni signature Azure n'est revendiqué sans exécution réelle des jobs concernés.

[Spécification officielle trust policy](https://github.com/notaryproject/specifications/blob/main/specs/trust-store-trust-policy.md), [configuration officielle du plugin](https://github.com/Azure/notation-azure-kv/blob/main/docs/plugin-config.md).
