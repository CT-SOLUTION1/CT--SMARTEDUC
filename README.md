# CT-SMART EDUC — secure Founder code management

This backend stores the Founder, Teacher and Learner access codes as salted scrypt hashes in Firestore. The plain-text codes are never stored in Firestore.

## Files

- `functions/index.js` — secure callable Cloud Functions.
- `functions/package.json` — Node 22 dependencies.
- `index.html` — patched client so Founder/Teacher/Learner sign in with Firebase custom tokens after the Cloud Function verifies the code.
- `firestore-rules-snippet.txt` — rule for preventing direct client access to the access-code document.

## Deploy

From the Firebase project root:

```bash
firebase login
firebase use ct-e-school-solutions
cd functions
npm install
cd ..
firebase deploy --only functions
```

The frontend is already configured for `us-central1`, so the deployed functions use the same region.

## First use

1. Open the website.
2. The First-Time Setup asks the Founder to create all three codes.
3. `initializeSchoolAccess` hashes and stores the codes securely.
4. The Founder enters the Founder code.
5. The Founder Panel can then change Teacher and Learner codes.
6. Other devices call the verification functions and receive Firebase-authenticated custom tokens.

## Important

Do not put the code values or their hashes in `index.html`, GitHub, Vercel environment variables, or localStorage.

For stronger abuse protection in production, enable Firebase App Check enforcement for these callable functions. Firebase callable functions automatically carry Firebase Authentication and App Check tokens when available.
