# BrainMaster Pro — Backend + App intégrée

Cette version est préparée pour déployer **le backend et l'interface BrainMaster dans le même projet Vercel**. L'interface est dans `public/index.html`; les API sont dans `api/index.js`.

## Routes vérifiées dans le code

- `GET /` — page/API status, évite un 404 sur la racine API
- `GET /api` — status
- `GET /api/health` — health check
- `GET /api/bootstrap` — catégories, réglages et questions
- `POST /api/auth/register`
- `POST /api/auth/verify-email`
- `POST /api/auth/resend-verification`
- `POST /api/auth/login`
- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`
- `POST /api/admin/request-otp`
- `POST /api/admin/verify-otp`
- `GET /api/me`
- `PUT /api/me/state`
- `POST /api/quiz/complete`
- `POST /api/admin/password`
- `GET /api/admin/stats`
- `GET /api/admin/users`
- `PATCH /api/admin/users/:id` — owner seulement: promote/demote
- `DELETE /api/admin/users/:id` — owner seulement
- `GET /api/admin/active-users`
- `GET/PUT /api/admin/data`

## Sécurité ajoutée

- JWT obligatoire pour les routes privées.
- `owner` est protégé: un admin ne peut pas devenir owner, modifier ou supprimer le owner.
- Seul le `owner` peut promouvoir/rétrograder les admins.
- OTP admin lié à un `challengeId`, donc deux admins ne se mélangent pas.
- Rate limiting léger sur login/register/OTP.
- Hash bcrypt des mots de passe et codes.
- Déduplication des résultats de quiz via `clientQuizId`.
- Cache court du bootstrap pour éviter de recharger la banque entière à chaque requête.
- Statut `active` basé sur les 5 dernières minutes.

## Déploiement Vercel

1. Décompresser le dossier.
2. Importer le dossier `brainmaster-backend` dans Vercel.
3. Ajouter les variables d'environnement de `.env.example` dans **Vercel → Settings → Environment Variables**.
4. Connecter une base PostgreSQL et mettre `DATABASE_URL`.
5. Mettre un vrai `JWT_SECRET` long et aléatoire.
6. Mettre ton vrai Gmail dans `ADMIN_EMAIL` et un **Google App Password** dans `SMTP_PASS` si tu veux les codes OTP par Gmail.
7. Déployer.
8. Ouvrir `https://TON-DOMAIN.vercel.app/api/health`. Tu dois obtenir un JSON avec `ok: true`.
9. Ouvrir `https://TON-DOMAIN.vercel.app/` pour l'app BrainMaster.

## Important sur le premier login Owner

Au démarrage, le backend crée/met à jour le compte `ADMIN_EMAIL` comme `owner`. Le mot de passe est celui de `ADMIN_PASSWORD`.

Après le premier déploiement, connecte-toi dans **Admin Core** avec:
- Admin ID = `ADMIN_ID` ou l'email owner
- Mot de passe = `ADMIN_PASSWORD`
- puis le code OTP reçu par Gmail

## Vérification de l'app

Le frontend intégré appelle le même domaine (`/api/...`) quand il est servi depuis `public/index.html`, donc il n'a pas besoin d'une URL API externe et évite le problème classique de mauvais `BRAINMASTER_API_URL`/404.

Le frontend a aussi été corrigé pour:
- envoyer le `challengeId` avec l'OTP admin;
- ne plus envoyer les 4 800 questions au serveur toutes les 5 secondes;
- synchroniser les modifications Admin seulement lorsqu'elles sont enregistrées;
- rafraîchir les utilisateurs et statistiques à intervalle raisonnable.

### APK

Aucun fichier APK binaire n'était joint à cette conversation, donc la vérification effectuée ici porte sur **l'interface web BrainMaster + le backend** et leurs routes. Pour tester une APK réelle (installation, WebView, certificat, deep links, réseau), il faut le fichier APK ou le projet Android.
