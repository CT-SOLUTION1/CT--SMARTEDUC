# CT-SMART EDUC — Firebase Spark Access System

This version is designed to remain on the Firebase **Spark (no-cost) plan**.

## What it provides

- No anonymous Firebase Authentication accounts.
- One real Firebase Authentication account is used for the Founder:
  `founder@ctsmart.educ`
- The Founder enters only the Founder code; the email is internal.
- Teacher and Learner have system-generated application identities:
  - `teacher@ctsmart.educ`
  - `learner@ctsmart.educ`
- Teacher and Learner enter only their access codes.
- The Founder can set/change Teacher and Learner codes from the Founder Panel.
- Codes are salted and SHA-256 hashed before being saved in Firestore.
- The current code hashes and salts are stored in `schoolAccess/public`.
- Only the Founder can write `schoolAccess/public` and `schoolAccess/admin`.
- Other devices read the current public verification record and therefore use the latest saved codes.
- No Cloud Functions are used.

## Important security limitation

Because this is Spark-only and has no trusted server-side Admin SDK, Teacher/Learner code verification must happen in the browser. That means the verification hash is readable by the browser. This is why the access codes MUST be long and randomly generated (preferably 24–32+ characters), not short PINs such as `1234`.

This design is appropriate for an access gate, but it is not equivalent to server-side password authentication.

## Firebase setup

1. Keep the project on Spark.
2. In Firebase Console, enable **Authentication > Email/Password**.
3. Create the Founder account:
   `founder@ctsmart.educ`
   using the Founder code you want initially.
4. Create/enable Firestore.
5. Publish `firestore.rules`.
6. Deploy the `index.html` through your existing GitHub/Vercel workflow.
7. Open the site and complete first-time setup if `schoolAccess/public` has not yet been configured.

## Founder code changes

After initial setup:

Founder Panel
→ enter new Teacher code
→ enter new Learner code
→ Save

The browser generates a new random salt for each code, hashes the codes, and writes the new values to Firestore. Other devices retrieve the new record and verify the new codes.

## Do not

- Do not use short codes.
- Do not publish the actual codes in GitHub.
- Do not add a broad `allow read, write: if true` Firestore rule.
- Do not enable anonymous authentication.
- Do not put the raw codes into Firestore.

## Why no Cloud Functions?

Firebase's current pricing documentation lists Cloud Functions as unavailable on Spark; access to Cloud Functions requires Blaze. Firestore and most Firebase Authentication options have no-cost Spark usage.
