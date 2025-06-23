/* eslint-disable max-len */
/* eslint-disable indent */
/* eslint-disable object-curly-spacing */

// File: functions/index.js (Versi Final Koreksi)

// --- BAGIAN IMPORT MODUL (Menggunakan require) ---
const { onDocumentCreated, onDocumentUpdated } = require("firebase-functions/v2/firestore");
const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { defineString } = require("firebase-functions/params");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");
const crypto = require("crypto");
const logger = require("firebase-functions/logger");

// Inisialisasi Firebase Admin SDK sekali saja
initializeApp();

// --- KONSTANTA ---
const aesKey = defineString("AES_KEY");
const aesIv = defineString("AES_IV");
const ALGORITHM = "aes-256-cbc";

// --- BAGIAN HELPER FUNCTIONS (Enkripsi & Dekripsi) ---

/**
 * Encrypts a given text using AES-256-CBC.
 * @param {string} text The text to encrypt.
 * @return {string} The encrypted text in hex format.
 */
function encrypt(text) {
    const key = Buffer.from(aesKey.value(), "hex");
    const iv = Buffer.from(aesIv.value(), "hex");

    if (key.length !== 32 || iv.length !== 16) {
        logger.error(`Enkripsi gagal: Panjang key = ${key.length}, iv = ${iv.length}`);
        throw new Error("AES_KEY (hex) harus 64 char dan AES_IV (hex) harus 32 char.");
    }

    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    return encrypted;
}

/**
 * Decrypts a given hex-encoded text using AES-256-CBC.
 * @param {string} encryptedHex The encrypted hex string.
 * @return {string} The decrypted text.
 */
function decrypt(encryptedHex) {
    const key = Buffer.from(aesKey.value(), "hex");
    const iv = Buffer.from(aesIv.value(), "hex");

    if (key.length !== 32 || iv.length !== 16) {
        throw new Error("AES_KEY harus 32 byte dan AES_IV harus 16 byte untuk AES-256-CBC.");
    }

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    let decrypted = decipher.update(encryptedHex, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
}

// --- BAGIAN CLOUD FUNCTIONS ---

/**
 * Terpicu saat dokumen baru dibuat di koleksi 'rentals'.
 * Tugasnya: membuat PIN, mengenkripsi, dan mendistribusikannya.
 */
exports.onRentalStart = onDocumentCreated("rentals/{rentalId}", async (event) => {
    const snapshot = event.data;
    if (!snapshot) {
        logger.error("onRentalStart: No data associated with the event.");
        return;
    }

    const rentalData = snapshot.data();
    const rentalId = event.params.rentalId;
    const lockerId = rentalData.locker_id;

    // 1. Generate PIN acak 4 digit
    const pin = Math.floor(1000 + Math.random() * 9000).toString();
    logger.info(`Locker ${lockerId}: PIN generated -> ${pin}`);

    // 2. Enkripsi PIN
    let encryptedPin;
    try {
        encryptedPin = encrypt(pin);
    } catch (err) {
        logger.error(`Enkripsi gagal: ${err.message}`);
        return;
    }

    // 3. Simpan ke Firestore
    const rentalRef = getFirestore().collection("rentals").doc(rentalId);
    const lockerRef = getFirestore().collection("lockers").doc(lockerId);

    try {
        await Promise.all([
            rentalRef.set({ encrypted_pin: encryptedPin }, { merge: true }),
            lockerRef.set({ active_pin: pin }, { merge: true }),
        ]);
        logger.info(`Locker ${lockerId}: PIN successfully distributed for rental ${rentalId}.`);
    } catch (error) {
        logger.error(`Gagal update Firestore: ${error.message}`);
    }
});

/**
 * Fungsi yang dipanggil oleh Flutter untuk mendapatkan PIN.
 */
exports.getDecryptedPin = onCall(async (request) => {
    if (!request.auth) {
        throw new HttpsError("unauthenticated", "Anda harus login untuk melihat PIN.");
    }

    const userId = request.auth.uid;
    const rentalId = request.data.rentalId;

    if (!rentalId) {
        throw new HttpsError("invalid-argument", "ID rental harus disertakan.");
    }

    const rentalRef = getFirestore().collection("rentals").doc(rentalId);
    const rentalDoc = await rentalRef.get();

    if (!rentalDoc.exists) {
        throw new HttpsError("not-found", "Sesi rental tidak ditemukan.");
    }

    if (rentalDoc.data().user_id !== userId) {
        throw new HttpsError("permission-denied", "Anda tidak berhak melihat PIN ini.");
    }

    const encryptedPin = rentalDoc.data().encrypted_pin;
    if (!encryptedPin) {
        throw new HttpsError("not-found", "PIN untuk rental ini belum dibuat.");
    }

    try {
        const decryptedPin = decrypt(encryptedPin);
        return { pin: decryptedPin };
    } catch (err) {
        throw new HttpsError("internal", `Gagal dekripsi PIN: ${err.message}`);
    }
});

/**
 * Terpicu saat dokumen rental diupdate, untuk membersihkan PIN.
 */
exports.onRentalEnd = onDocumentUpdated("rentals/{rentalId}", async (event) => {
    const afterData = event.data.after.data();
    const beforeData = event.data.before.data();

    // Cek jika status berubah dari selain 'finished' menjadi 'finished'
    if (beforeData.status !== "finished" && afterData.status === "finished") {
        const lockerId = afterData.locker_id;
        const lockerRef = getFirestore().collection("lockers").doc(lockerId);

        logger.info(
            `Rental ${event.params.rentalId} finished. Clearing active_pin for locker ${lockerId}.`,
        );

        try {
            await lockerRef.update({
                active_pin: FieldValue.delete(),
            });
        } catch (err) {
            logger.error(`Gagal menghapus PIN: ${err.message}`);
        }
    }

    return null;
});
