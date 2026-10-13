# Runners et réseau privé

La Phase 3A s'exécute sur Ubuntu GitHub standard et ne possède aucune identité Azure. Les PR, notamment de forks, ne doivent jamais être exécutées sur les runners privés de publication/signature.

Les Phases 3B/3C utilisent trois pools distincts de runners self-hosted Linux éphémères, labels `azure-private`, `ephemeral` et respectivement `publish`, `sign`, `verify`. Ils doivent être provisionnés dans un réseau accédant aux Private Endpoints ACR et Key Vault, disposer d'Azure CLI, Python 3.11 et gh, et être détruits après chaque job. Les identités attachées à une VM ne doivent pas permettre d'éviter les limites OIDC du job. Aucun fichier d'authentification ni cache Docker partagé entre pools.

Sur ce dépôt public, ne connecter ces pools qu'après avoir restreint leur accès aux workflows de release approuvés et vérifié les protections GitHub du plan utilisé. Les environnements protégés et les scripts de preflight complètent l'isolation ; ils ne sécurisent pas un runner permanent compromis ni une modification non revue de main.

Configurer les zones Private DNS et liens VNet existants pour ACR et les deux coffres. Les scripts exigent des adresses privées et un TLS valide pour ACR et le coffre de signature ; ils contrôlent par ARM l'accès public désactivé et l'absence d'admin ACR. Aucun contournement de vérification TLS ou ouverture publique n'est utilisé.

Les sorties nécessaires restent explicites : GitHub Actions/API/artefacts, Entra et ARM, endpoints privés ACR/Key Vault, téléchargements des outils vérifiés et endpoints PKI de révocation si requis. Filtrer par pare-feu/proxy validé, prévoir DNS fiable et synchronisation d'heure. Les FQDN de téléchargement et de stockage GitHub peuvent évoluer : appliquer la liste officielle à jour et vérifier les flux dans le réseau réel. Ne pas intercepter le TLS des échanges OIDC.

Une alternative est le [réseau privé Azure pour les runners GitHub hébergés](https://docs.github.com/en/organizations/managing-organization-settings/configuring-private-networking-for-github-hosted-runners-in-your-organization), sous réserve d'organisation/plan compatible et de validation de l'isolation. Elle n'est pas provisionnée ici.
