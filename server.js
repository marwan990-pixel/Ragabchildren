/**
 * cashier-auth-backend/server.js
 *
 * Express backend for Phase B-1: Firebase Auth-based roles (owner/representative).
 * Uses a SEPARATE Firebase project from the cashier-backend activation/payment system.
 *
 * Endpoints:
 *   POST /api/create-business  — create owner account + business document
 *   POST /api/create-representative — owner-only: create rep account
 */

const express = require("express");
const cors    = require("cors");
const admin   = require("firebase-admin");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

// ── Firebase Admin Initialization (separate project) ──────────────────────
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId:  process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY
        ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n")
        : undefined,
    }),
  });
}
const db = admin.firestore();

// ── Auth helper: extract + verify ID token ─────────────────────────────────
async function verifyOwner(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }
  const idToken = authHeader.split("Bearer ")[1];
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    return decoded;
  } catch {
    return null;
  }
}

// ── POST /api/create-business ──────────────────────────────────────────────
// Creates a new business owner account.
// Body: { email, password, businessName }
// Returns: { uid, businessId }
app.post("/api/create-business", async (req, res) => {
  const { email, password, businessName } = req.body;

  if (!email || !password || !businessName) {
    return res.status(400).json({ error: "Missing email, password, or businessName" });
  }

  try {
    // 1. Create Firebase Auth user
    const userRecord = await admin.auth().createUser({
      email,
      password,
      displayName: businessName,
    });
    const uid = userRecord.uid;

    // 2. Create business document
    const businessRef = db.collection("businesses").doc();
    const businessId = businessRef.id;

    await businessRef.set({
      ownerUid: uid,
      businessName,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // 3. Create user profile under the business
    await businessRef.collection("users").doc(uid).set({
      role: "owner",
      email,
      name: businessName,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.json({ uid, businessId });
  } catch (error) {
    console.error("[create-business] Error:", error);
    if (error.code === "auth/email-already-exists") {
      return res.status(409).json({ error: "Email already exists" });
    }
    return res.status(500).json({ error: error.message });
  }
});

// ── POST /api/create-representative ────────────────────────────────────────
// OWNER-ONLY. Must include Firebase Auth ID token in Authorization header.
// Body: { businessId, repName, repEmail, repPassword, locationId }
// Returns: { uid }
app.post("/api/create-representative", async (req, res) => {
  // 1. Verify the caller is a verified owner
  const decoded = await verifyOwner(req);
  if (!decoded) {
    return res.status(401).json({ error: "Unauthorized — invalid or missing ID token" });
  }

  const { businessId, repName, repEmail, repPassword, locationId } = req.body;

  if (!businessId || !repName || !repEmail || !repPassword || !locationId) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  // 2. Verify caller is the owner of this business
  const userDoc = await db
    .collection("businesses")
    .doc(businessId)
    .collection("users")
    .doc(decoded.uid)
    .get();

  if (!userDoc.exists || userDoc.data().role !== "owner") {
    return res.status(403).json({ error: "Forbidden — only the business owner can create representatives" });
  }

  try {
    // 3. Create Firebase Auth user for the rep
    const userRecord = await admin.auth().createUser({
      email: repEmail,
      password: repPassword,
      displayName: repName,
    });
    const repUid = userRecord.uid;

    // 4. Create rep profile under the business
    await db
      .collection("businesses")
      .doc(businessId)
      .collection("users")
      .doc(repUid)
      .set({
        role: "representative",
        email: repEmail,
        name: repName,
        locationId,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

    return res.json({ uid: repUid });
  } catch (error) {
    console.error("[create-representative] Error:", error);
    if (error.code === "auth/email-already-exists") {
      return res.status(409).json({ error: "Email already exists" });
    }
    return res.status(500).json({ error: error.message });
  }
});

// ── Health ─────────────────────────────────────────────────────────────────
app.get("/health", (_, res) => res.json({ status: "ok" }));
app.get("/api/health", (_, res) => res.json({ status: "ok" }));

// ── Local dev & Vercel export ──────────────────────────────────────────────
if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () =>
    console.log(`cashier-auth-backend running on port ${PORT}`)
  );
}

module.exports = app;
