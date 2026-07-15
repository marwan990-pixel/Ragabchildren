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

// ── E-1: Sale Invoice Endpoint (atomic Firestore transaction) ──────────────
app.post("/api/create-sale-invoice", async (req, res) => {
  try {
    const decoded = await verifyOwner(req);
    if (!decoded) {
      return res.status(401).json({ error: "Unauthorized — invalid or missing ID token" });
    }

    const { businessId, locationId, items, paidAmount, paymentMethod, partyId, partyName, dueDate, notes } = req.body;

    if (!businessId || !locationId || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    for (const item of items) {
      if (!item.productId || !item.productName || !item.quantity || !item.unitPrice) {
        return res.status(400).json({ error: "Each item must have productId, productName, quantity, unitPrice" });
      }
    }

    const now = new Date().toISOString();
    const paid = Number(paidAmount) || 0;

    const result = await db.runTransaction(async (tx) => {
      // 1. Read stock docs and check availability
      const stockData = [];
      for (const item of items) {
        const stockRef = db.collection("businesses").doc(businessId).collection("stock").doc(`${item.locationId ?? locationId}_${item.productId}`);
        const stockSnap = await tx.get(stockRef);
        if (!stockSnap.exists) {
          throw new Error(`Stock not found for product ${item.productName}`);
        }
        const stockQty = stockSnap.data().quantity ?? 0;
        if (stockQty < item.quantity) {
          throw new Error(`Insufficient stock for ${item.productName}: available ${stockQty}, requested ${item.quantity}`);
        }
        // Read product cost price
        const productRef = db.collection("businesses").doc(businessId).collection("products").doc(item.productId);
        const productSnap = await tx.get(productRef);
        const costPrice = productSnap.exists ? (productSnap.data().costPrice ?? 0) : 0;
        stockData.push({ ref: stockRef, currentQty: stockQty, costPrice });
      }

      // 2. Compute totals
      let subtotal = 0;
      for (let i = 0; i < items.length; i++) {
        const it = items[i];
        subtotal += it.quantity * it.unitPrice - (it.discount ?? 0);
      }
      const discountTotal = Number(req.body.discountTotal) || 0;
      const taxTotal = Number(req.body.taxTotal) || 0;
      const returnTotal = Number(req.body.returnTotal) || 0;
      const netTotal = subtotal - discountTotal + taxTotal - returnTotal;

      // 3. Status
      let status = "unpaid";
      if (paid <= 0) status = "unpaid";
      else if (paid >= netTotal) status = "paid";
      else status = "partial";

      // 4. Next invoice number
      const invoicesRef = db.collection("businesses").doc(businessId).collection("invoices");
      const numSnap = await tx.get(
        invoicesRef.where("type", "==", "sale").orderBy("number", "desc").limit(1)
      );
      let nextNumber = 1;
      if (!numSnap.empty) {
        nextNumber = (numSnap.docs[0].data().number ?? 0) + 1;
      }

      // 5. Build invoice doc
      const invoiceId = `inv_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
      const invoiceRef = invoicesRef.doc(invoiceId);
      const embeddedItems = items.map((it, i) => ({
        productId: it.productId,
        productName: it.productName,
        quantity: it.quantity,
        unitPrice: it.unitPrice,
        unitCost: stockData[i].costPrice,
        discount: it.discount ?? 0,
        total: it.quantity * it.unitPrice - (it.discount ?? 0),
      }));

      tx.set(invoiceRef, {
        type: "sale",
        number: nextNumber,
        partyId: partyId ?? null,
        partyName: partyName ?? null,
        subtotal,
        discountTotal,
        taxTotal,
        returnTotal,
        netTotal,
        paidAmount: paid,
        status,
        paymentMethod: paymentMethod ?? "cash",
        dueDate: dueDate ?? null,
        notes: notes ?? null,
        locationId,
        sellerId: decoded.uid ?? null,
        sellerName: partyName ?? null,
        items: embeddedItems,
        createdAt: now,
        syncedAt: now,
        sourceDeviceId: "dashboard",
      });

      // 6. Decrement stock
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        const stockDocId = `${item.locationId ?? locationId}_${item.productId}`;
        const stockRef = db.collection("businesses").doc(businessId).collection("stock").doc(stockDocId);
        tx.update(stockRef, {
          quantity: stockData[i].currentQty - item.quantity,
          syncedAt: now,
          sourceDeviceId: "dashboard",
        });

        // Also decrement global product quantity
        const productRef = db.collection("businesses").doc(businessId).collection("products").doc(item.productId);
        tx.update(productRef, {
          quantity: admin.firestore.FieldValue.increment(-item.quantity),
        });
      }

      // 7. Customer balance update (sale → unpaid remainder = debt)
      if (partyId && (netTotal - paid) !== 0) {
        const unpaidRemainder = netTotal - paid;
        const custRef = db.collection("businesses").doc(businessId).collection("customers").doc(partyId);
        tx.update(custRef, {
          balance: admin.firestore.FieldValue.increment(unpaidRemainder),
        });
      }

      // 8. Treasury transaction
      if (paid > 0) {
        const treasuryRef = db.collection("businesses").doc(businessId).collection("treasury").doc();
        tx.set(treasuryRef, {
          direction: "in",
          amount: paid,
          reason: `دفعة فاتورة بيع #${nextNumber}`,
          relatedInvoiceId: invoiceId,
          createdAt: now,
          sourceDeviceId: "dashboard",
        });
      }

      return { id: invoiceId, subtotal, netTotal, status };
    });

    res.json(result);
  } catch (err) {
    console.error("[create-sale-invoice] Error:", err);
    res.status(500).json({ error: err.message || "Failed to create invoice" });
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
