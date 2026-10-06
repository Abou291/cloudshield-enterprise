# AegisShield 0.8 — décisions produit

Objectif : un audit AWS lisible et exploitable pour une petite équipe. Pas de promesse de détection d’attaques en temps réel, de multicloud ou de remédiation automatique.

## Parcours

1. Connexion AWS locale : profil SSO déjà configuré, rôle AssumeRole, External ID, contrôle du compte avant enregistrement.
2. Audit AWS : bouton explicite ; la démonstration ne s’active jamais automatiquement à la place d’AWS dans l’application PC.
3. Plan de correction : priorité, preuve, recommandation et état de suivi.
4. Vérification : nouvel audit en lecture seule. « En cours » ne signifie jamais « corrigé ».
5. Export : JSON des alertes actives de la source, sans troncature à 500.

## Design

Minimal SaaS : fond #f6f8fb, surfaces blanches, accent #183e70, typographie système, navigation latérale, tableaux sobres. Une seule vue à la fois. Transition 190 ms, déplacement 9 px ; préférence de réduction des animations respectée. Pas de police distante. Dialogue natif : focus contenu, Échap, retour au contrôle précédent.

## Règles de suivi

Un audit incomplet n’efface aucune alerte précédente. Un audit complet ne ferme que les alertes des ressources effectivement retrouvées et réinspectées, identifiées par compte/région/type/identifiant. Les ressources disparues restent ouvertes pour ne pas confondre suppression et perte de visibilité. Les anciens statuts fermés peuvent provenir d’une action manuelle ; l’interface ne les présente pas comme une certification.

## Application Windows

Backend PyInstaller embarqué et démarré avant le renderer ; interface Electron avec sandbox et jeton local par lancement. NSIS avec raccourcis Bureau/Démarrer et préservation des données. Délai de démarrage porté à 45 s. Réouvrir le raccourci restaure la fenêtre existante. Arrêt de l’arbre du backend sous Windows pour éviter un port occupé après fermeture.

## Limites de validation

Les tests automatisés locaux et Windows n’attestent pas du fonctionnement sur le PC de l’utilisateur ni de la pertinence de chaque contrôle sur un vrai environnement AWS. Le pilote AWS réel et la signature Authenticode sont distincts de la compilation. Le build interne non signé ne contourne pas le gate de signature des releases publiques.
