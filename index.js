const { onCall, HttpsError } = require("firebase-functions/v2/https");
const logger = require("firebase-functions/logger");
const { initializeApp } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");
const crypto = require("crypto");

initializeApp();

const db = getFirestore();
const auth = getAuth();

const REGION = "us-central1";
const ACCESS_DOC = db.collection("schoolAccess").doc("main");
const FOUNDER_UID = "ctsmart-founder";
const TEACHER_UID = "ctsmart-shared-teacher";
const LEARNER_UID = "ctsmart-shared-learner";

const MIN_CODE_LENGTH = 4;
const MAX_CODE_LENGTH = 64;

function normalizeCode(value) {
  return String(value || "")
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9_-]/g, "");
}

function validateCode(value, label) {
  const code = normalizeCode(value);
  if (code.length < MIN_CODE_LENGTH || code.length > MAX_CODE_LENGTH) {
    throw new HttpsError(
      "invalid-argument",
      `${label} must contain ${MIN_CODE_LENGTH}-${MAX_CODE_LENGTH} letters, numbers, hyphens or underscores.`
    );
  }
  return code;
}

function randomSalt() {
  return crypto.randomBytes(16).toString("hex");
}

function hashCode(code, salt = randomSalt()) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(code, salt, 64, { N: 16384, r: 8, p: 1 }, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(`scrypt$${salt}$${derivedKey.toString("hex")}`);
    });
  });
}

function verifyHash(code, stored) {
  return new Promise((resolve, reject) => {
    try {
      const parts = String(stored || "").split("$");
      if (parts.length !== 3 || parts[0] !== "scrypt") return resolve(false);
      const salt = parts[1];
      const expected = Buffer.from(parts[2], "hex");
      crypto.scrypt(code, salt, expected.length, { N: 16384, r: 8, p: 1 }, (err, derived) => {
        if (err) return reject(err);
        if (derived.length !== expected.length) return resolve(false);
        resolve(crypto.timingSafeEqual(derived, expected));
      });
    } catch (err) {
      reject(err);
    }
  });
}

async function getSettings() {
  const snap = await ACCESS_DOC.get();
  return snap.exists ? snap.data() : null;
}

function requireFounder(request, settings) {
  const token = request.auth && request.auth.token;
  if (!token || token.role !== "founder" || request.auth.uid !== FOUNDER_UID) {
    throw new HttpsError("permission-denied", "Founder authentication is required.");
  }
  if (!settings || !settings.configured) {
    throw new HttpsError("failed-precondition", "School access is not configured.");
  }
  if (Number(token.founderSessionVersion || 0) !== Number(settings.founderSessionVersion || 0)) {
    throw new HttpsError("permission-denied", "Founder session expired. Sign in again.");
  }
}

async function mintRoleToken(uid, role, displayName) {
  const claims = { role };
  return auth.createCustomToken(uid, { ...claims });
}

exports.initializeSchoolAccess = onCall({ region: REGION }, async (request) => {
  const founderCode = validateCode(request.data?.founderCode, "Founder code");
  const teacherCode = validateCode(request.data?.teacherCode, "Teacher code");
  const learnerCode = validateCode(request.data?.learnerCode, "Learner code");

  if (new Set([founderCode, teacherCode, learnerCode]).size !== 3) {
    throw new HttpsError("invalid-argument", "Founder, Teacher and Learner codes must be different.");
  }

  const existing = await getSettings();
  if (existing?.configured) {
    throw new HttpsError("already-exists", "School access has already been configured.");
  }

  // Create the stable Auth users used by custom-token sessions.
  // If a previous interrupted setup created them, reuse them.
  for (const [uid, displayName] of [
    [FOUNDER_UID, "CT-SMART Founder"],
    [TEACHER_UID, "CT-SMART Teacher"],
    [LEARNER_UID, "CT-SMART Learner"],
  ]) {
    try {
      await auth.getUser(uid);
    } catch (err) {
      if (err.code === "auth/user-not-found") {
        await auth.createUser({ uid, displayName, disabled: false });
      } else {
        throw err;
      }
    }
  }

  const founderHash = await hashCode(founderCode);
  const teacherHash = await hashCode(teacherCode);
  const learnerHash = await hashCode(learnerCode);

  await ACCESS_DOC.create({
    configured: true,
    founderHash,
    teacherHash,
    learnerHash,
    teacherLocked: false,
    learnerLocked: false,
    founderSessionVersion: 1,
    updatedAt: FieldValue.serverTimestamp(),
    initializedAt: FieldValue.serverTimestamp(),
  });

  await auth.setCustomUserClaims(FOUNDER_UID, {
    role: "founder",
    founderSessionVersion: 1,
  });

  await auth.setCustomUserClaims(TEACHER_UID, { role: "teacher" });
  await auth.setCustomUserClaims(LEARNER_UID, { role: "learner" });

  logger.info("School access initialized.");
  return { ok: true };
});

exports.verifyFounderAccess = onCall({ region: REGION }, async (request) => {
  const code = validateCode(request.data?.code, "Founder code");
  const settings = await getSettings();

  if (!settings?.configured) {
    throw new HttpsError("failed-precondition", "School access has not been configured.");
  }

  const valid = await verifyHash(code, settings.founderHash);
  if (!valid) {
    throw new HttpsError("permission-denied", "Incorrect Founder access code.");
  }

  const customToken = await auth.createCustomToken(FOUNDER_UID, {
    role: "founder",
    founderSessionVersion: Number(settings.founderSessionVersion || 1),
  });

  return { ok: true, customToken };
});

exports.verifySharedAccessCode = onCall({ region: REGION }, async (request) => {
  const role = String(request.data?.role || "").toLowerCase();
  if (role !== "teacher" && role !== "learner") {
    throw new HttpsError("invalid-argument", "Role must be teacher or learner.");
  }

  const code = validateCode(request.data?.code, `${role} access code`);
  const settings = await getSettings();

  if (!settings?.configured) {
    throw new HttpsError("failed-precondition", "School access has not been configured.");
  }

  if (role === "teacher" && settings.teacherLocked) {
    throw new HttpsError("permission-denied", "Teacher access is currently locked.");
  }
  if (role === "learner" && settings.learnerLocked) {
    throw new HttpsError("permission-denied", "Learner access is currently locked.");
  }

  const hash = role === "teacher" ? settings.teacherHash : settings.learnerHash;
  const valid = await verifyHash(code, hash);
  if (!valid) {
    throw new HttpsError("permission-denied", "Incorrect access code.");
  }

  const uid = role === "teacher" ? TEACHER_UID : LEARNER_UID;
  const customToken = await mintRoleToken(uid, role, `CT-SMART ${role}`);

  return {
    ok: true,
    role,
    uid,
    customToken,
  };
});

exports.getSchoolAccessSettings = onCall({ region: REGION }, async (request) => {
  const settings = await getSettings();
  if (!settings?.configured) {
    return {
      configured: false,
      teacherLocked: false,
      learnerLocked: false,
      teacherCodeMasked: "",
      learnerCodeMasked: "",
    };
  }

  // Only the Founder may see the current masked values and lock state.
  requireFounder(request, settings);

  return {
    configured: true,
    teacherLocked: !!settings.teacherLocked,
    learnerLocked: !!settings.learnerLocked,
    teacherCodeMasked: "••••••••",
    learnerCodeMasked: "••••••••",
  };
});

async function setCodes(request, teacherCode, learnerCode) {
  const settings = await getSettings();
  requireFounder(request, settings);

  const newTeacher = teacherCode ? validateCode(teacherCode, "Teacher code") : null;
  const newLearner = learnerCode ? validateCode(learnerCode, "Learner code") : null;

  if (newTeacher && newLearner && newTeacher === newLearner) {
    throw new HttpsError("invalid-argument", "Teacher and Learner codes must be different.");
  }

  if (newTeacher) {
    if (await verifyHash(newTeacher, settings.founderHash)) {
      throw new HttpsError("invalid-argument", "Teacher code cannot be the Founder code.");
    }
    if (await verifyHash(newTeacher, settings.learnerHash)) {
      throw new HttpsError("invalid-argument", "Teacher code cannot equal the current Learner code.");
    }
  }

  if (newLearner) {
    if (await verifyHash(newLearner, settings.founderHash)) {
      throw new HttpsError("invalid-argument", "Learner code cannot be the Founder code.");
    }
    if (await verifyHash(newLearner, settings.teacherHash)) {
      throw new HttpsError("invalid-argument", "Learner code cannot equal the current Teacher code.");
    }
  }

  const update = {
    updatedAt: FieldValue.serverTimestamp(),
  };
  if (newTeacher) update.teacherHash = await hashCode(newTeacher);
  if (newLearner) update.learnerHash = await hashCode(newLearner);

  await ACCESS_DOC.update(update);
  return { ok: true };
}

exports.setSchoolAccessCodes = onCall({ region: REGION }, async (request) => {
  return setCodes(request, request.data?.teacherCode, request.data?.learnerCode);
});

exports.setTeacherAccessCode = onCall({ region: REGION }, async (request) => {
  return setCodes(request, request.data?.teacherCode, null);
});

exports.setLearnerAccessCode = onCall({ region: REGION }, async (request) => {
  return setCodes(request, null, request.data?.learnerCode);
});

exports.setSchoolAccessLocks = onCall({ region: REGION }, async (request) => {
  const settings = await getSettings();
  requireFounder(request, settings);

  if (typeof request.data?.teacherLocked !== "boolean" ||
      typeof request.data?.learnerLocked !== "boolean") {
    throw new HttpsError("invalid-argument", "Both lock values must be true or false.");
  }

  await ACCESS_DOC.update({
    teacherLocked: request.data.teacherLocked,
    learnerLocked: request.data.learnerLocked,
    updatedAt: FieldValue.serverTimestamp(),
  });

  return { ok: true };
});
