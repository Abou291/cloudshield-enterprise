# AegisShield 0.8.1 — connexion AWS par navigateur

La version 0.8.0 embarquait Boto3 sans AWS Common Runtime (CRT). Un profil
`login_session` créé par `aws login` provoquait `MissingDependencyException`,
masquée par le message générique `AWS_SDK_ERROR`.

La version 0.8.1 installe `boto3[crt]>=1.41`, embarque explicitement les modules
CRT et leur extension native dans les exécutables, et distingue les composants
manquants des sessions absentes ou expirées dans les diagnostics.

Le binaire Windows est désormais testé avec `--check-aws-login` : le fournisseur
réel Botocore charge des identifiants synthétiques dans un cache isolé, sans
réseau et sans lire les profils ou sessions de l'utilisateur. Ce contrôle
s'ajoute au test du parcours de démonstration dans l'application empaquetée.
Il ne remplace pas une validation STS AssumeRole sur le compte AWS réel.

Fermer AegisShield puis installer 0.8.1. Les données et la configuration locale
sont conservées. Le profil AWS reste `default` si c'est celui déjà configuré.
