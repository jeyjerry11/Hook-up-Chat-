// server.js
// Run with: node server.js
// Uses ES module syntax (Node 18+ recommended)

import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import fetch from "node-fetch"; // npm i node-fetch@2 or use native fetch in Node 18+
import nodemailer from "nodemailer";
import crypto from "crypto";
import fs from "fs/promises";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json()); // parse JSON bodies
app.use(express.urlencoded({ extended: true }));

// Serve static frontend files from /public
app.use(express.static(path.join(__dirname, "public")));

/*
  REQUIRED: Set these in your .env file (see .env.example below)
  - PAYSTACK_SECRET  => Your Paystack SECRET key (sk_test_xxx or sk_live_xxx)
  - PAYSTACK_PUBLIC  => Your Paystack PUBLIC key (pk_test_xxx or pk_live_xxx) (not used server-side but helpful)
  - ADMIN_EMAIL      => Where admin notifications will be sent
  - GMAIL_USER       => Gmail address used to send emails (or any SMTP user)
  - GMAIL_PASS       => App password or SMTP password
  - PORT (optional)  => Server port (defaults to 5000)
*/

const PORT = process.env.PORT || 5000;
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET;
const PAYSTACK_PUBLIC = process.env.PAYSTACK_PUBLIC || "";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_PASS = process.env.GMAIL_PASS;

// Basic checks
if (!PAYSTACK_SECRET) {
  console.warn("⚠️  PAYSTACK_SECRET is not set in .env — verification will fail until you add it.");
}
if (!GMAIL_USER || !GMAIL_PASS) {
  console.warn("⚠️  GMAIL_USER or GMAIL_PASS missing — email sending will fail until configured.");
}

// Simple storage file for demo purposes (replace with DB later)
const TX_DB_FILE = path.join(__dirname, "tx_history.json");

/* ---------------------------
   Nodemailer setup
   --------------------------- */
const transporter = nodemailer.createTransport({
  service: "gmail", // change if using another SMTP
  auth: {
    user: GMAIL_USER,
    pass: GMAIL_PASS,
  },
});

/* ---------------------------
   Helper: save transaction to local JSON file
   --------------------------- */
async function saveTransaction(tx) {
  let arr = [];
  try {
    const raw = await fs.readFile(TX_DB_FILE, "utf8");
    arr = JSON.parse(raw || "[]");
  } catch (e) {
    // file likely doesn't exist yet — will create
  }
  arr.push(tx);
  await fs.writeFile(TX_DB_FILE, JSON.stringify(arr, null, 2), "utf8");
}

/* ---------------------------
   Route: POST /verify-payment
   Purpose: Frontend callback can call this after user completes Paystack popup.
            You pass { reference: "...", expectedAmount: 100 } in body (expectedAmount optional).
   --------------------------- */
app.post("/verify-payment", async (req, res) => {
  try {
    const { reference, expectedAmount, email: frontendEmail, metadata } = req.body || {};

    if (!reference) {
      return res.status(400).json({ status: "error", message: "Missing reference" });
    }
    // Verify with Paystack
    const resp = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET}`,
        "Content-Type": "application/json",
      },
    });
    const json = await resp.json();

    if (!json.status) {
      // Paystack returned failure
      return res.status(400).json({ status: "failed", message: "Verification failed", detail: json });
    }

    const data = json.data;
    const amountKobo = data.amount; // amount in kobo
    const amountNgn = (amountKobo / 100).toFixed(2);
    const status = data.status; // "success" expected
    const customerEmail = data.customer?.email || frontendEmail || "unknown";
    const txRef = data.reference;
    const channel = data.channel || "unknown";
    const authorization = data.authorization || {}; // may contain last4, card type, etc.

    // Optional protection: check expected amount (frontend may send expectedAmount)
    if (expectedAmount) {
      const expectedKobo = Math.round(Number(expectedAmount) * 100);
      if (expectedKobo !== amountKobo) {
        console.warn("Amount mismatch! expected:", expectedKobo, "got:", amountKobo);
        // still continue but mark flagged
      }
    }

    // Only accept 'success' status
    if (status !== "success") {
      return res.status(400).json({ status: "failed", message: "Transaction not successful", data });
    }

    // Build a safe transaction object to store
    const txRecord = {
      reference: txRef,
      amount: amountNgn,
      email: customerEmail,
      channel,
      authorization: {
        last4: authorization.last4 || null,
        brand: authorization.brand || null,
        card_type: authorization.card_type || null,
      },
      metadata: data.metadata || metadata || null,
      paid_at: data.paid_at || new Date().toISOString(),
      verified_at: new Date().toISOString(),
    };

    // Save locally (replace this with DB code in production)
    await saveTransaction(txRecord);

    // Send emails: to customer and admin
    // 1) Customer email
    const userMail = {
      from: GMAIL_USER,
      to: customerEmail,
      subject: "Payment received — Your Talktime purchase",
      text:
        `Hi,\n\nWe received your payment of ₦${txRecord.amount} (ref: ${txRecord.reference}).\n` +
        `Your call will start in ~10 minutes. Keep your phone close.\n\n` +
        `If you have questions, reply to this email.\n\nThank you.`,
    };

    // 2) Admin email (safe info only)
    const adminMail = {
      from: GMAIL_USER,
      to: ADMIN_EMAIL,
      subject: `New Talktime Payment — ₦${txRecord.amount} — ${txRecord.reference}`,
      text:
        `New payment received:\n\n` +
        `Amount: ₦${txRecord.amount}\n` +
        `Reference: ${txRecord.reference}\n` +
        `Customer: ${txRecord.email}\n` +
        `Card last4: ${txRecord.authorization.last4 || "N/A"}\n` +
        `Card brand: ${txRecord.authorization.brand || "N/A"}\n` +
        `Channel: ${txRecord.channel}\n\n` +
        `Metadata: ${JSON.stringify(txRecord.metadata || {})}\n\n` +
        `--\nPayments managed via Paystack. Sensitive card data is not stored here.`,
    };

    // Send emails (best-effort; don't block on failure)
    transporter.sendMail(userMail).catch((err) => console.warn("User email failed:", err));
    transporter.sendMail(adminMail).catch((err) => console.warn("Admin email failed:", err));

    // Respond success
    return res.json({ status: "success", message: "Payment verified and recorded", tx: txRecord });
  } catch (err) {
    console.error("verify-payment error:", err);
    return res.status(500).json({ status: "error", message: "Server error" });
  }
});

/* ---------------------------
   Route: POST /paystack-webhook
   Purpose: Stronger server-to-server notification from Paystack (recommended)
   Paystack will POST to this endpoint when transaction status changes.
   Verify signature using your PAYSTACK_SECRET (HMAC SHA512 of raw body).
   --------------------------- */
app.post("/paystack-webhook", express.raw({ type: "*/*" }), async (req, res) => {
  try {
    // Read signature header from Paystack
    const signature = req.headers["x-paystack-signature"];
    const body = req.body; // raw buffer

    // Validate signature
    const expectedSig = crypto.createHmac("sha512", PAYSTACK_SECRET).update(body).digest("hex");
    if (signature !== expectedSig) {
      console.warn("⚠️ Invalid Paystack webhook signature");
      return res.status(400).send("Invalid signature");
    }

    // Parse JSON payload
    const payload = JSON.parse(body.toString("utf8"));
    // Important event types: "charge.success", "transfer.success", etc.
    const event = payload.event;
    const data = payload.data;

    // For example handle charge.success
    if (event === "charge.success" || event === "payment.success") {
      const reference = data.reference;
      const amountNgn = (data.amount / 100).toFixed(2);
      const customerEmail = data.customer?.email || "unknown";

      // Save minimal transaction info
      const txRecord = {
        reference,
        amount: amountNgn,
        email: customerEmail,
        channel: data.channel || null,
        metadata: data.metadata || null,
        webhook_received_at: new Date().toISOString(),
      };
      await saveTransaction(txRecord);

      // Send emails (best-effort)
      const userMail = {
        from: GMAIL_USER,
        to: customerEmail,
        subject: "Payment confirmed (via webhook)",
        text: `We confirmed your payment of ₦${amountNgn}. Ref: ${reference}.`
      };
      const adminMail = {
        from: GMAIL_USER,
        to: ADMIN_EMAIL,
        subject: `Webhook payment: ₦${amountNgn} — ${reference}`,
        text: `Webhook payment received.\n\nRef: ${reference}\nEmail: ${customerEmail}\nEvent: ${event}`
      };
      transporter.sendMail(userMail).catch(e => console.warn("userMail failed", e));
      transporter.sendMail(adminMail).catch(e => console.warn("adminMail failed", e));
    }

    // Respond quickly to Paystack with 200
    res.status(200).send("OK");
  } catch (err) {
    console.error("webhook error", err);
    res.status(500).send("server error");
  }
});

/* ---------------------------
   Small helper route so you can fetch tx history in dev
   --------------------------- */
app.get("/tx-history", async (req, res) => {
  try {
    const content = await fs.readFile(TX_DB_FILE, "utf8").catch(() => "[]");
    const arr = JSON.parse(content || "[]");
    res.json({ status: "ok", count: arr.length, data: arr });
  } catch (err) {
    res.status(500).json({ status: "error", message: "Could not read history" });
  }
});

/* ---------------------------
   Start server
   --------------------------- */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`Serving frontend from ${path.join(__dirname, "public")}`);
});