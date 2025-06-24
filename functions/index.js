/* eslint-disable max-len */
/* eslint-disable indent */
/* eslint-disable object-curly-spacing */

// File: functions/index.js (Versi Final Koreksi)

// --- BAGIAN IMPORT MODUL ---
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
    if (!text || typeof text !== "string") {
        logger.error("Enkripsi gagal: Text harus string dan tidak kosong.");
        throw new HttpsError("invalid-argument", "Text untuk enkripsi tidak valid.");
    }

    const key = Buffer.from(aesKey.value(), "hex");
    const iv = Buffer.from(aesIv.value(), "hex");

    if (key.length !== 32 || iv.length !== 16) {
        logger.error(`Enkripsi gagal: Panjang key = ${key.length}, iv = ${iv.length}`);
        throw new HttpsError("failed-precondition", "AES_KEY harus 64 char (hex) dan AES_IV harus 32 char (hex).");
    }

    try {
        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
        let encrypted = cipher.update(text, "utf8", "hex");
        encrypted += cipher.final("hex");
        logger.info(`Enkripsi berhasil untuk text: ${text.substring(0, 4)}...`);
        return encrypted;
    } catch (err) {
        logger.error(`Enkripsi gagal: ${err.message}`);
        throw new HttpsError("internal", "Gagal melakukan enkripsi.", err.message);
    }
}

/**
 * Decrypts a given hex-encoded text using AES-256-CBC.
 * @param {string} encryptedHex The encrypted hex string.
 * @return {string} The decrypted text.
 */
function decrypt(encryptedHex) {
    if (!encryptedHex || typeof encryptedHex !== "string") {
        logger.error("Dekripsi gagal: Encrypted text harus string dan tidak kosong.");
        throw new HttpsError("invalid-argument", "Encrypted text tidak valid.");
    }

    const key = Buffer.from(aesKey.value(), "hex");
    const iv = Buffer.from(aesIv.value(), "hex");

    if (key.length !== 32 || iv.length !== 16) {
        logger.error(`Dekripsi gagal: Panjang key = ${key.length}, iv = ${iv.length}`);
        throw new HttpsError("failed-precondition", "AES_KEY harus 64 char (hex) dan AES_IV harus 32 char (hex).");
    }

    try {
        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        let decrypted = decipher.update(encryptedHex, "hex", "utf8");
        decrypted += decipher.final("utf8");
        logger.info(`Dekripsi berhasil untuk encryptedHex: ${encryptedHex.substring(0, 8)}...`);
        return decrypted;
    } catch (err) {
        logger.error(`Dekripsi gagal: ${err.message}`);
        throw new HttpsError("internal", "Gagal melakukan dekripsi.", err.message);
    }
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
        throw new HttpsError("internal", "No data associated with the event.");
    }

    const rentalData = snapshot.data();
    const rentalId = event.params.rentalId;
    const lockerId = rentalData.locker_id;

    if (!lockerId) {
        logger.error(`onRentalStart: locker_id missing for rental ${rentalId}.`);
        throw new HttpsError("invalid-argument", "Locker ID is required.");
    }

    // Generate PIN acak 4 digit
    const pin = Math.floor(1000 + Math.random() * 9000).toString();
    logger.info(`Locker ${lockerId}: PIN generated -> ${pin}`);

    // Enkripsi PIN
    let encryptedPin;
    try {
        encryptedPin = encrypt(pin);
    } catch (err) {
        logger.error(`Enkripsi gagal untuk rental ${rentalId}: ${err.message}`);
        throw new HttpsError("internal", "Gagal mengenkripsi PIN.", err.message);
    }

    // Simpan ke Firestore menggunakan transaction
    const db = getFirestore();
    const rentalRef = db.collection("rentals").doc(rentalId);
    const lockerRef = db.collection("lockers").doc(lockerId);

    try {
        await db.runTransaction(async (transaction) => {
            transaction.set(rentalRef, { encrypted_pin: encryptedPin }, { merge: true });
            transaction.set(lockerRef, { active_pin: pin }, { merge: true });
        });
        logger.info(`Locker ${lockerId}: PIN successfully distributed for rental ${rentalId}.`);
    } catch (error) {
        logger.error(`Gagal update Firestore untuk rental ${rentalId}: ${error.message}`);
        throw new HttpsError("internal", "Gagal menyimpan PIN ke Firestore.", error.message);
    }
});

/**
 * Fungsi yang dipanggil oleh Flutter untuk mendapatkan PIN.
 */
exports.getDecryptedPin = onCall({ enforceAppCheck: false }, async (request) => {
    // Validasi auth
    if (!request.auth || !request.auth.uid) {
        logger.error("getDecryptedPin: Unauthenticated request.");
        throw new HttpsError("unauthenticated", "Anda harus login terlebih dahulu!");
    }

    const userId = request.auth.uid;
    const rentalId = request.data.rentalId;

    if (!rentalId) {
        logger.error("getDecryptedPin: Missing rentalId.");
        throw new HttpsError("invalid-argument", "Parameter rentalId diperlukan.");
    }

    // Gunakan transaction untuk konsistensi data
    const db = getFirestore();
    try {
        const rentalDoc = await db.runTransaction(async (transaction) => {
            const rentalRef = db.collection("rentals").doc(rentalId);
            const rentalDoc = await transaction.get(rentalRef);

            if (!rentalDoc.exists) {
                logger.error(`getDecryptedPin: Rental ${rentalId} not found.`);
                throw new HttpsError("not-found", "Rental tidak ditemukan.");
            }

            const rentalData = rentalDoc.data();
            if (rentalData.user_id !== userId) {
                logger.error(`getDecryptedPin: User ${userId} does not have access to rental ${rentalId}.`);
                throw new HttpsError("permission-denied", "Anda tidak memiliki akses.");
            }

            if (!rentalData.encrypted_pin) {
                logger.error(`getDecryptedPin: No encrypted_pin found for rental ${rentalId}.`);
                throw new HttpsError("not-found", "PIN untuk rental ini belum dibuat.");
            }

            return rentalDoc;
        });

        // Decrypt PIN
        const encryptedPin = rentalDoc.data().encrypted_pin;
        logger.info(`Decrypting PIN for rental ${rentalId}: ${encryptedPin.substring(0, 8)}...`);
        const decryptedPin = decrypt(encryptedPin);

        return { pin: decryptedPin };
    } catch (error) {
        logger.error(`getDecryptedPin error for rental ${rentalId}: ${error.message}`);
        throw new HttpsError(error.code || "internal", error.message || "Gagal memproses PIN.");
    }
});

/**
 * Terpicu saat dokumen rental diupdate, untuk membersihkan PIN.
 */
exports.onRentalEnd = onDocumentUpdated("rentals/{rentalId}", async (event) => {
    const afterData = event.data.after.data();
    const beforeData = event.data.before.data();
    const rentalId = event.params.rentalId;

    // Cek jika status berubah ke 'finished'
    if (beforeData.status !== "finished" && afterData.status === "finished") {
        const lockerId = afterData.locker_id;
        if (!lockerId) {
            logger.error(`onRentalEnd: locker_id missing for rental ${rentalId}.`);
            throw new HttpsError("invalid-argument", "Locker ID is required.");
        }

        const lockerRef = getFirestore().collection("lockers").doc(lockerId);
        try {
            await lockerRef.update({
                active_pin: FieldValue.delete(),
            });
            logger.info(`Locker ${lockerId}: active_pin cleared for rental ${rentalId}.`);
        } catch (err) {
            logger.error(`Gagal menghapus PIN untuk locker ${lockerId}: ${err.message}`);
            throw new HttpsError("internal", "Gagal menghapus PIN.", err.message);
        }
    } else {
        logger.info(`onRentalEnd: No action needed for rental ${rentalId}.`);
    }
});
