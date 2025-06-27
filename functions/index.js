/* eslint-disable brace-style */
/* eslint-disable block-spacing */
/* eslint-disable comma-dangle */
/* eslint-disable no-undef */
/* eslint-disable no-unused-vars */
/* eslint-disable camelcase */
/* eslint-disable max-len */
/* eslint-disable indent */
/* eslint-disable object-curly-spacing */

// File: functions/index.js (Versi Final dengan Lockers dan ESP32)

// --- BAGIAN IMPORT MODUL ---
const { onDocumentCreated, onDocumentUpdated } = require("firebase-functions/v2/firestore");
const { onCall, onRequest, HttpsError } = require("firebase-functions/v2/https");
const { defineString } = require("firebase-functions/params");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, FieldValue, Timestamp } = require("firebase-admin/firestore");
const crypto = require("crypto");
const logger = require("firebase-functions/logger");
const midtransClient = require("midtrans-client");

// Inisialisasi Firebase Admin SDK
initializeApp();

// Inisialisasi Snap API dari Midtrans
const MIDTRANS_SERVER_KEY = defineString("MIDTRANS_SERVER_KEY");
const MIDTRANS_CLIENT_KEY = defineString("MIDTRANS_CLIENT_KEY");

const snap = new midtransClient.Snap({
    isProduction: false,
    serverKey: MIDTRANS_SERVER_KEY.value(),
    clientKey: MIDTRANS_CLIENT_KEY.value(),
});

// --- KONSTANTA ---
const aesKey = defineString("AES_KEY");
const aesIv = defineString("AES_IV");
const ALGORITHM = "aes-256-cbc";

// --- BAGIAN HELPER FUNCTIONS ---

/**
 * Generates a unique Midtrans order ID.
 * @param {string} rentalId The rental ID.
 * @param {string} paymentType The payment type ('initial_fee' or 'fine').
 * @return {string} Unique order ID.
 */
function generateMidtransOrderId(rentalId, paymentType) {
    const timestamp = Date.now();
    return `${rentalId}_${paymentType}_${timestamp}`;
}

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
 * Fungsi yang dipanggil Flutter untuk membuat transaksi pembayaran.
 */
exports.createTransaction = onCall({ enforceAppCheck: false }, async (request) => {
    if (!request.auth || !request.auth.uid) {
        logger.error("createTransaction: Unauthenticated request.");
        throw new HttpsError("unauthenticated", "Anda harus login terlebih dahulu!");
    }

    const userId = request.auth.uid;
    const userEmail = request.auth.token.email;
    const userName = request.auth.token.name || "User";
    const { rentalId, amount, paymentType } = request.data;

    if (!rentalId || typeof rentalId !== "string") {
        logger.error("createTransaction: Missing or invalid rentalId.");
        throw new HttpsError("invalid-argument", "Parameter rentalId diperlukan dan harus string.");
    }
    if (!amount || typeof amount !== "number" || amount <= 0) {
        logger.error("createTransaction: Missing or invalid amount.");
        throw new HttpsError("invalid-argument", "Parameter amount diperlukan dan harus angka positif.");
    }
    if (!paymentType || !["initial_fee", "fine"].includes(paymentType)) {
        logger.error("createTransaction: Missing or invalid paymentType.");
        throw new HttpsError("invalid-argument", "Parameter paymentType harus 'initial_fee' atau 'fine'.");
    }
    if (!userEmail) {
        logger.error("createTransaction: User email not available.");
        throw new HttpsError("invalid-argument", "Email pengguna diperlukan.");
    }

    const db = getFirestore();
    const rentalRef = db.collection("rentals").doc(rentalId);
    const rentalDoc = await rentalRef.get();
    if (!rentalDoc.exists || rentalDoc.data().user_id !== userId) {
        logger.error(`createTransaction: Rental ${rentalId} not found or user ${userId} has no access.`);
        throw new HttpsError("permission-denied", "Rental tidak ditemukan atau Anda tidak memiliki akses.");
    }

    // --- PERBAIKAN LOGIKA UTAMA ---
    // Pengecekan ketersediaan loker HANYA dilakukan untuk sewa awal.
    if (paymentType === "initial_fee") {
        const lockerId = rentalDoc.data().locker_id;
        const lockerRef = db.collection("lockers").doc(lockerId);
        const lockerDoc = await lockerRef.get();
        if (!lockerDoc.exists || lockerDoc.data().status !== "available") {
            throw new HttpsError("failed-precondition", "Loker tidak tersedia untuk disewa.");
        }
    }

    const midtransOrderId = generateMidtransOrderId(rentalId, paymentType);
    const parameter = {
        transaction_details: {
            order_id: midtransOrderId,
            gross_amount: amount,
        },
        customer_details: {
            first_name: userName,
            email: userEmail,
        },
        enabled_payments: ["bank_transfer", "gopay", "shopeepay", "credit_card"],
        expiry: { duration: 24, unit: "hours" },
    };

    try {
        const transaction = await snap.createTransaction(parameter);
        const transactionToken = transaction.token;
        logger.info(`Transaction token created for order ${midtransOrderId}: ${transactionToken}`);

        const paymentRef = db.collection("payments").doc(midtransOrderId);
        await paymentRef.set({
            rental_id: rentalId,
            user_id: userId,
            midtrans_order_id: midtransOrderId,
            amount: amount,
            payment_type: paymentType,
            status: "pending",
            created_at: Timestamp.now(),
            updated_at: Timestamp.now(),
            response_data: transaction,
        });

        return { token: transactionToken, orderId: midtransOrderId };
    } catch (error) {
        logger.error(`Gagal membuat transaksi Midtrans untuk rental ${rentalId}: ${error.message}`, {
            error: error.response ? error.response.data : error.message,
            statusCode: error.response ? error.response.status : 500
        });
        throw new HttpsError("internal", "Gagal memproses pembayaran.", error.message);
    }
});

/**
 * Fungsi yang menerima notifikasi dari Midtrans.
 */
// exports.midtransNotificationHandler = onRequest(async (request, response) => {
//     const notificationJson = request.body;
//     logger.info(`Menerima notifikasi dari Midtrans: ${JSON.stringify(notificationJson)}`);

//     try {
//         // --- Langkah 1: Validasi Input Dasar & Signature Key ---
//         const { order_id, status_code, gross_amount, signature_key, transaction_status } = notificationJson;

//         // Validasi apakah notifikasi memiliki data minimal yang dibutuhkan
//         if (!order_id || !status_code || !gross_amount || !signature_key || !transaction_status) {
//             logger.warn("Notifikasi tidak lengkap dari Midtrans.", notificationJson);
//             // Memberi respon 200 agar Midtrans tidak mengirim ulang notifikasi yang rusak.
//             return response.status(200).json({ message: "Incomplete notification received." });
//         }

//         const serverKey = MIDTRANS_SERVER_KEY.value(); // Pastikan menggunakan .value()

//         const expectedSignature = crypto.createHash("sha512")
//             .update(`${order_id}${status_code}${gross_amount}${serverKey}`)
//             .digest("hex");

//         if (signature_key !== expectedSignature) {
//             logger.error(`Signature tidak valid untuk order_id: ${order_id}.`);
//             return response.status(403).json({ error: "Forbidden. Invalid signature." });
//         }

//         // --- Langkah 2: Verifikasi Status Transaksi ke API Midtrans (Lapisan Keamanan Kedua) ---
//         logger.info(`Signature valid. Memverifikasi status transaksi untuk order_id: ${order_id}`);
//         // Kita gunakan nama variabel yang berbeda untuk menghindari konflik
//         const midtransStatusResponse = await snap.transaction.notification(notificationJson);
//         const { fraud_status, transaction_id, payment_type: paymentMethod } = midtransStatusResponse;

//         // transaction_status kita ambil dari notifikasi awal karena sudah divalidasi signature-nya
//         logger.info(`Notifikasi terverifikasi untuk order ${order_id}: status=${transaction_status}, fraud=${fraud_status}`);

//         // --- Langkah 3: Proses Logika Bisnis (Update Firestore) ---
//         const db = getFirestore();
//         const paymentRef = db.collection("payments").doc(order_id);

//         // Gunakan Transaksi Firestore untuk memastikan konsistensi data
//         await db.runTransaction(async (t) => {
//             const paymentDoc = await t.get(paymentRef);
//             if (!paymentDoc.exists) {
//                 // Jika dokumen pembayaran tidak ada, kita tidak bisa melanjutkan.
//                 // Ini bisa terjadi jika notifikasi datang sebelum dokumen dibuat.
//                 // Sebaiknya log sebagai error dan hentikan proses.
//                 throw new Error(`Payment document with order_id: ${order_id} not found.`);
//             }

//             const paymentData = paymentDoc.data();
//             const rentalRef = db.collection("rentals").doc(paymentData.rental_id);
//             const rentalDoc = await t.get(rentalRef);
//             if (!rentalDoc.exists) {
//                 throw new Error(`Rental document with id: ${paymentData.rental_id} not found.`);
//             }

//             const lockerId = rentalDoc.data().locker_id;
//             const lockerRef = db.collection("lockers").doc(lockerId);

//             // Menentukan status pembayaran internal kita
//             let paymentStatus;
//             if (transaction_status === "capture" || transaction_status === "settlement") {
//                 paymentStatus = fraud_status === "accept" ? "success" : "failed";
//             } else if (["deny", "cancel", "expire"].includes(transaction_status)) {
//                 paymentStatus = transaction_status === "deny" ? "failed" : transaction_status;
//             } else {
//                 paymentStatus = transaction_status; // pending, refund, dll.
//             }

//             // Update dokumen pembayaran
//             t.update(paymentRef, {
//                 status: paymentStatus,
//                 midtrans_transaction_id: transaction_id,
//                 payment_method: paymentMethod,
//                 updated_at: Timestamp.now(),
//                 response_data: midtransStatusResponse,
//             });

//             // Update dokumen rental dan loker jika pembayaran sukses atau gagal
//             if (paymentStatus === "success") {
//                 // Periksa TIPE pembayaran dari data di Firestore
//                 const paymentType = paymentData.payment_type;

//                 if (paymentType === "initial_fee") {
//                     // --- LOGIKA UNTUK SEWA AWAL ---
//                     logger.info(`Pembayaran sewa awal untuk rental ${paymentData.rental_id} berhasil.`);
//                     t.update(rentalRef, {
//                         payment_status: "paid",
//                         status: "active",
//                         updated_at: Timestamp.now(),
//                     });
//                     t.update(lockerRef, {
//                         status: "occupied",
//                         current_rental_id: paymentData.rental_id,
//                         last_updated: Timestamp.now(),
//                     });
//                 } else if (paymentType === "fine") {
//                     // --- LOGIKA UNTUK PEMBAYARAN DENDA ---
//                     logger.info(`Pembayaran denda untuk rental ${paymentData.rental_id} berhasil. Membuat PIN sementara...`);

//                     const temporaryPin = Math.floor(1000 + Math.random() * 9000).toString();
//                     const encryptedTemporaryPin = encrypt(temporaryPin);

//                     t.update(rentalRef, {
//                         payment_status: "fine_paid",
//                         status: "pending_retrieval",
//                         encrypted_pin: encryptedTemporaryPin,
//                         updated_at: Timestamp.now(),
//                     });

//                     t.update(lockerRef, {
//                         active_pin: temporaryPin,
//                         last_updated: Timestamp.now(),
//                     });
//                 }
//             } else if (["failed", "expired", "cancelled"].includes(paymentStatus)) {
//                 const currentLockerDoc = await t.get(lockerRef);
//                 // Hanya reset loker jika loker tersebut masih terasosiasi dengan rental ini
//                 if (currentLockerDoc.exists && currentLockerDoc.data().current_rental_id === paymentData.rental_id) {
//                     t.update(rentalRef, {
//                         payment_status: paymentStatus,
//                         status: "cancelled",
//                         updated_at: Timestamp.now(),
//                     });
//                     t.update(lockerRef, {
//                         status: "available",
//                         current_rental_id: null,
//                         last_updated: Timestamp.now(),
//                     });
//                 }
//             }
//         });

//         logger.info(`Payment ${order_id} berhasil diproses dengan status: ${paymentStatus}`);
//         return response.status(200).json({ message: "Notification processed successfully." });
//     } catch (error) {
//         logger.error(`Gagal memproses notifikasi Midtrans: ${error.message}`, {
//             errorDetails: error,
//             requestBody: notificationJson,
//         });
//         // Kirim respon 500 agar Midtrans mencoba mengirim notifikasi lagi nanti (jika error bersifat sementara)
//         return response.status(500).json({ error: "Gagal memproses notifikasi", details: error.message });
//     }
// });

/**
 * fungsi midtransNotificationHandler dari Gemini (kalo ga works ganti aja pake fungsi yg lama)
 */
exports.midtransNotificationHandler = onRequest(async (request, response) => {
    const notificationJson = request.body;
    logger.info(`Menerima notifikasi dari Midtrans: ${JSON.stringify(notificationJson)}`);

    try {
        // --- Langkah 1: Validasi Signature (Sudah Benar) ---
        const { order_id, status_code, gross_amount, signature_key, transaction_status } = notificationJson;
        if (!order_id || !status_code || !gross_amount || !signature_key || !transaction_status) {
            return response.status(200).json({ message: "Incomplete notification received." });
        }
        const serverKey = MIDTRANS_SERVER_KEY.value();
        const expectedSignature = crypto.createHash("sha512").update(`${order_id}${status_code}${gross_amount}${serverKey}`).digest("hex");
        if (signature_key !== expectedSignature) {
            return response.status(403).json({ error: "Forbidden. Invalid signature." });
        }

        // --- Langkah 2: Verifikasi ke API Midtrans (Sudah Benar) ---
        const midtransStatusResponse = await snap.transaction.notification(notificationJson);
        const { fraud_status, transaction_id } = midtransStatusResponse;

        // --- Langkah 3: Tentukan Status Internal (Sudah Benar) ---
        let paymentStatus;
        if ((transaction_status === "capture" || transaction_status === "settlement") && fraud_status === "accept") {
            paymentStatus = "success";
        } else if (["deny", "cancel", "expire"].includes(transaction_status)) {
            paymentStatus = "failed";
        } else {
            paymentStatus = transaction_status; // contoh: "pending"
        }

        const db = getFirestore();
        const paymentRef = db.collection("payments").doc(order_id);
        await db.runTransaction(async (t) => {
            const paymentDoc = await t.get(paymentRef);
            if (!paymentDoc.exists) {
                throw new Error(`Dokumen pembayaran ${order_id} tidak ditemukan.`);
            }

            const paymentData = paymentDoc.data();
            const rentalRef = db.collection("rentals").doc(paymentData.rental_id);
            const rentalDoc = await t.get(rentalRef);
            if (!rentalDoc.exists) { throw new Error(`Dokumen rental ${paymentData.rental_id} tidak ditemukan.`); }

            const rentalData = rentalDoc.data();
            const lockerRef = db.collection("lockers").doc(rentalData.locker_id);

            // Update dokumen pembayaran terlebih dahulu
            t.update(paymentRef, {
                status: paymentStatus,
                midtrans_transaction_id: transaction_id,
                updated_at: Timestamp.now(),
                response_data: midtransStatusResponse,
            });

            // --- PERBAIKAN LOGIKA UTAMA DI SINI ---
            // Hanya jalankan logika bisnis jika pembayaran SUKSES.
            if (paymentStatus === "success") {
                const paymentType = paymentData.payment_type;

                // Cek status rental saat ini untuk mencegah aktivasi ulang yang tidak diinginkan
                if (paymentType === "initial_fee" && rentalData.status === "pending_payment") {
                    logger.info(`Pembayaran sewa awal untuk rental ${paymentData.rental_id} berhasil. Mengaktifkan...`);
                    t.update(rentalRef, { payment_status: "paid", status: "active", updated_at: Timestamp.now() });
                    t.update(lockerRef, { status: "occupied", current_rental_id: paymentData.rental_id, last_updated: Timestamp.now() });
                } else if (paymentType === "fine" && rentalData.status === "locked_due_to_fine") {
                    logger.info(`Pembayaran denda untuk rental ${paymentData.rental_id} berhasil. Membuat PIN sementara...`);
                    const temporaryPin = Math.floor(1000 + Math.random() * 9000).toString();
                    const encryptedTemporaryPin = encrypt(temporaryPin);
                    t.update(rentalRef, { payment_status: "fine_paid", status: "pending_retrieval", encrypted_pin: encryptedTemporaryPin, updated_at: Timestamp.now() });
                    t.update(lockerRef, { active_pin: temporaryPin, last_updated: Timestamp.now() });
                } else {
                    logger.warn(`Menerima notifikasi sukses untuk rental ${paymentData.rental_id} yang statusnya sudah '${rentalData.status}'. Notifikasi diabaikan untuk mencegah race condition.`);
                }
            }
            // Tidak ada lagi blok "else if" di sini. Logika untuk pembayaran gagal
            // sudah ditangani oleh variabel paymentStatus di atas.
        });

        // Log terakhir dipindahkan ke luar transaksi untuk memastikan selalu berjalan
        logger.info(`Notifikasi untuk order ${order_id} selesai diproses dengan status akhir: ${paymentStatus}`);
        return response.status(200).json({ message: "Notification processed successfully." });
    } catch (error) {
        logger.error(`Gagal memproses notifikasi Midtrans: ${error.message}`, { errorDetails: error });
        return response.status(500).json({ error: "Gagal memproses notifikasi", details: error.message });
    }
});

/**
 * (API untuk Hardware) - Mengupdate status kunci loker dan memvalidasi PIN.
 * Versi ini menggabungkan semua logika keamanan dan alur penyelesaian sewa.
 */
// exports.updateLockerStatus = onRequest(async (request, response) => {
//     // --- BAGIAN 1: VALIDASI INPUT DASAR ---
//     // Logika ini sudah benar. Memastikan semua parameter yang dibutuhkan
//     // dari ESP32 telah dikirim.
//     const { esp32_id, locker_id, isLocked, input_pin } = request.body;

//     if (!esp32_id || !locker_id || isLocked === undefined) {
//         logger.error("updateLockerStatus: Parameter yang dibutuhkan tidak lengkap.");
//         return response.status(400).send("Parameter esp32_id, locker_id, dan isLocked diperlukan.");
//     }

//     // Mengambil referensi ke dokumen loker di Firestore.
//     const lockerRef = db.collection("lockers").doc(locker_id);

//     try {
//         // Menggunakan Transaksi Firestore untuk memastikan semua operasi
//         // (baca dan tulis) terjadi secara konsisten.
//         await db.runTransaction(async (t) => {
//             // --- BAGIAN 2: VALIDASI LOKER & PERANGKAT ---
//             // Logika ini sudah benar. Memastikan loker ada dan
//             // request datang dari ESP32 yang sah.
//             const lockerDoc = await t.get(lockerRef);
//             if (!lockerDoc.exists) {
//                 throw new Error("Locker tidak ditemukan.");
//             }

//             const lockerData = lockerDoc.data();
//             if (lockerData.esp32_id !== esp32_id) {
//                 throw new Error("Akses ditolak: ESP32 ID tidak cocok.");
//             }

//             // --- BAGIAN 3: LOGIKA UTAMA SAAT ADA INPUT PIN ---
//             // Blok ini hanya berjalan jika ESP32 mengirimkan PIN,
//             // yang berarti ada percobaan untuk membuka loker.
//             if (input_pin) {
//                 // KOREKSI: Mengambil data rental terkait. Ini sudah benar.
//                 const rentalId = lockerData.current_rental_id;
//                 if (!rentalId) {
//                     throw new Error("Loker tidak dalam masa sewa aktif untuk validasi PIN.");
//                 }

//                 const rentalRef = db.collection("rentals").doc(rentalId);
//                 const rentalDoc = await t.get(rentalRef);
//                 if (!rentalDoc.exists) {
//                     throw new Error("Data rental terkait tidak ditemukan.");
//                 }
//                 const rentalData = rentalDoc.data();

//                 // KOREKSI: Pengecekan status denda. Logika ini penting dan sudah benar.
//                 // Ini harus dilakukan SEBELUM validasi PIN.
//                 if (rentalData.status === "locked_due_to_fine") {
//                     throw new Error("Akses ditolak. Harap selesaikan pembayaran denda.");
//                 }

//                 // KOREKSI: Validasi PIN. Ini adalah satu-satunya tempat kita perlu
//                 // memeriksa PIN. Pengecekan PIN ganda yang ada di kode Anda sebelumnya
//                 // telah dihapus untuk efisiensi.
//                 if (lockerData.active_pin !== input_pin) {
//                     throw new Error("PIN salah.");
//                 }

//                 // --- LOGIKA BARU YANG DITAMBAHKAN ---
//                 // Setelah PIN dipastikan benar, kita cek apakah ini adalah
//                 // akses terakhir untuk mengambil barang setelah bayar denda.
//                 if (rentalData.status === "pending_retrieval") {
//                     logger.info(`Akses terakhir untuk rental ${rentalId}. Menyelesaikan sewa...`);
//                     // Jika ya, ubah status rental menjadi 'finished'.
//                     // Perubahan ini akan secara otomatis memicu fungsi 'onRentalEnd'
//                     // untuk membersihkan data loker.
//                     t.update(rentalRef, {
//                         status: "finished",
//                         actual_end_time: Timestamp.now() // Catat waktu selesai sebenarnya
//                     });
//                 }
//             }

//             // --- BAGIAN 4: UPDATE STATUS KUNCI LOKER ---
//             // Logika ini sudah benar. Ini akan selalu berjalan untuk melaporkan
//             // status terakhir dari kunci loker (terkunci/terbuka) yang dikirim oleh ESP32.
//             t.update(lockerRef, {
//                 isLocked: isLocked,
//                 last_lock_change: Timestamp.now(),
//                 last_updated: Timestamp.now(),
//             });
//         });

//         // Jika transaksi berhasil, kirim respons sukses.
//         response.status(200).send("Locker status updated successfully.");
//     } catch (error) {
//         // Jika ada error di dalam transaksi, tangkap dan kirim sebagai respons error.
//         logger.error(`Gagal update status locker ${locker_id}: ${error.message}`);
//         response.status(400).send(error.message);
//     }
// });

/**
 * fungsi updateLockerStatus dari Gemini (kalo ga works ganti aja pake fungsi yg lama)
 */
exports.updateLockerStatus = onRequest(async (request, response) => {
    const { esp32_id, locker_id, isLocked, input_pin } = request.body;

    if (!esp32_id || !locker_id || isLocked === undefined) {
        return response.status(400).send("Parameter yang dibutuhkan tidak lengkap.");
    }

    const lockerRef = db.collection("lockers").doc(locker_id);

    try {
        await db.runTransaction(async (t) => {
            const lockerDoc = await t.get(lockerRef);
            if (!lockerDoc.exists) {
                throw new Error("Locker tidak ditemukan.");
            }

            const lockerData = lockerDoc.data();
            if (lockerData.esp32_id !== esp32_id) {
                throw new Error("Akses ditolak: ESP32 ID tidak cocok.");
            }

            // Blok ini hanya berjalan jika ada percobaan untuk membuka loker dengan PIN.
            if (input_pin) {
                const rentalId = lockerData.current_rental_id;
                if (!rentalId) {
                    throw new Error("Loker tidak dalam masa sewa aktif.");
                }

                const rentalRef = db.collection("rentals").doc(rentalId);
                const rentalDoc = await t.get(rentalRef);
                if (!rentalDoc.exists) {
                    throw new Error("Data rental terkait tidak ditemukan.");
                }

                const rentalData = rentalDoc.data();
                if (rentalData.status === "locked_due_to_fine") {
                    throw new Error("Akses ditolak. Harap selesaikan pembayaran denda.");
                }

                // Validasi PIN dilakukan di sini.
                if (lockerData.active_pin !== input_pin) {
                    throw new Error("PIN salah.");
                }

                // --- INI ADALAH BAGIAN PENTING ---
                // KITA MEMICU DARI SINI: Setelah PIN dipastikan benar, bukan saat isLocked: false.
                // Ini lebih andal karena didasarkan pada aksi user (validasi PIN),
                // bukan pada laporan status hardware yang bisa tertunda atau gagal.
                if (rentalData.status === "pending_retrieval") {
                    logger.info(`Akses terakhir untuk rental ${rentalId}. Menyelesaikan sewa...`);
                    // Langsung ubah status rental menjadi 'finished' dalam transaksi yang sama.
                    t.update(rentalRef, {
                        status: "finished",
                        actual_end_time: Timestamp.now()
                    });
                }
            }

            // Update status isLocked dari laporan ESP32 akan selalu berjalan,
            // terlepas dari apakah ada input PIN atau tidak.
            t.update(lockerRef, {
                isLocked: isLocked,
                last_lock_change: Timestamp.now(),
                last_updated: Timestamp.now(),
            });
        });

        response.status(200).send("Locker status updated successfully.");
    } catch (error) {
        logger.error(`Gagal update status locker ${locker_id}: ${error.message}`);
        response.status(400).send(error.message);
    }
});

/**
 * Terpicu saat dokumen rental di-update, spesifiknya saat status menjadi 'active'.
 * Fungsi ini bertanggung jawab untuk membuat PIN setelah pembayaran berhasil.
 */
exports.onRentalActive = onDocumentUpdated("rentals/{rentalId}", async (event) => {
    const afterData = event.data.after.data();
    const beforeData = event.data.before.data();
    const rentalId = event.params.rentalId;

    // Cek kondisi: Apakah status berubah dari BUKAN 'active' menjadi 'active'?
    if (beforeData.status !== "active" && afterData.status === "active") {
        logger.info(`Rental ${rentalId} menjadi aktif, membuat PIN...`);

        const lockerId = afterData.locker_id;
        const db = getFirestore();
        const lockerRef = db.collection("lockers").doc(lockerId);
        const rentalRef = db.collection("rentals").doc(rentalId);

        // Buat PIN acak 4 digit
        const pin = Math.floor(1000 + Math.random() * 9000).toString();
        const encryptedPin = encrypt(pin); // Gunakan fungsi encrypt yang sudah ada

        try {
            // Gunakan transaksi untuk memastikan update ke rental dan locker konsisten
            await db.runTransaction(async (transaction) => {
                transaction.update(rentalRef, {
                    encrypted_pin: encryptedPin
                });
                transaction.update(lockerRef, {
                    active_pin: pin,
                    pin_expiry: afterData.expected_end_time // Ambil dari data rental
                });
            });
            logger.info(`PIN untuk rental ${rentalId} berhasil dibuat dan didistribusikan ke loker ${lockerId}.`);
        } catch (error) {
            logger.error(`Gagal membuat PIN untuk rental ${rentalId}: ${error.message}`);
        }
    } else {
        // Jika tidak ada perubahan status ke 'active', tidak ada yang perlu dilakukan.
        logger.info(`Update pada rental ${rentalId} tidak memerlukan pembuatan PIN.`);
    }
});

/**
 * Fungsi yang dipanggil oleh Flutter untuk mendapatkan PIN.
 */
exports.getDecryptedPin = onCall({ enforceAppCheck: false }, async (request) => {
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
 * Terpicu saat dokumen rental selesai.
 */
// exports.onRentalEnd = onDocumentUpdated("rentals/{rentalId}", async (event) => {
//     const afterData = event.data.after.data();
//     const beforeData = event.data.before.data();
//     const rentalId = event.params.rentalId;
//     const db = getFirestore();
//     const rentalRef = db.collection("rentals").doc(rentalId);

//     if (beforeData.status !== "finished" && afterData.status === "finished") {
//         const lockerId = afterData.locker_id;
//         if (!lockerId) {
//             logger.error(`onRentalEnd: locker_id missing.`);
//             throw new HttpsError("invalid-argument", "Locker ID is required.");
//         }

//         const lockerRef = db.collection("lockers").doc(lockerId);
//         try {
//             await db.runTransaction(async (transaction) => {
//                 transaction.update(lockerRef, {
//                     active_pin: null,
//                     pin_expiry: null,
//                     status: "available",
//                     current_rental_id: null,
//                     last_lock_change: null,
//                     last_updated: Timestamp.now(),
//                 });
//                 transaction.update(rentalRef, {
//                     encrypted_pin: null,
//                     actual_end_time: Timestamp.now(),
//                     updated_at: Timestamp.now(),
//                 });
//             });
//             logger.info(`Locker ${lockerId}: PIN cleared for rental ${rentalId}.`);
//         } catch (err) {
//             logger.error(`Gagal menghapus PIN untuk locker ${lockerId}: ${err.message}`);
//             throw new HttpsError("internal", err.message);
//         }
//     } else {
//         logger.info(`No action needed for rental ${rentalId}.`);
//     }
// });

/**
 * fungsi onRentalEnd dari Gemini (kalo ga works ganti aja pake fungsi yg lama)
 */
exports.onRentalEnd = onDocumentUpdated("rentals/{rentalId}", async (event) => {
    const afterData = event.data.after.data();
    const beforeData = event.data.before.data();

    // --- KONDISI YANG SUDAH DIPERBAIKI ---
    // Kita hanya perlu memeriksa apakah statusnya berubah menjadi 'finished'.
    // Ini akan menangani kasus selesai tepat waktu (fine_amount=0)
    // dan kasus selesai setelah bayar denda (fine_amount > 0).
    if (beforeData.status !== "finished" && afterData.status === "finished") {
        const lockerId = afterData.locker_id;
        if (!lockerId) {
            logger.error(`onRentalEnd: locker_id tidak ditemukan untuk rental ${event.params.rentalId}.`);
            return;
        }

        logger.info(`Rental ${event.params.rentalId} telah selesai. Membersihkan dan mereset loker ${lockerId}...`);

        const db = getFirestore();
        const lockerRef = db.collection("lockers").doc(lockerId);

        // Lakukan pembersihan: reset status loker, hapus PIN, dan hapus rental terkait.
        await lockerRef.update({
            status: "available",
            active_pin: null,
            pin_expiry: null,
            current_rental_id: null,
            last_updated: Timestamp.now(),
        });

        logger.info(`Loker ${lockerId} berhasil direset dan kini tersedia.`);

        // Opsional: Anda juga bisa menghapus field 'encrypted_pin' dari dokumen rental
        // untuk kebersihan data, meskipun lokernya sudah tidak bisa dibuka.
        await event.data.after.ref.update({
            encrypted_pin: null,
            actual_end_time: Timestamp.now(),
        });
    }
});

/**
 * Terpicu saat dokumen rental di-update.
 * Bertugas menghitung denda DAN MENONAKTIFKAN PIN jika terlambat.
 */
exports.calculateFineOnFinish = onDocumentUpdated("rentals/{rentalId}", async (event) => {
    const afterData = event.data.after.data();
    const beforeData = event.data.before.data();

    if (beforeData.status === "active" && afterData.status === "finished") {
        if (!afterData.expected_end_time || !afterData.actual_end_time) {
            logger.error(`Rental ${event.params.rentalId} tidak memiliki data waktu yang lengkap.`);
            return null;
        }

        const expectedEndTime = afterData.expected_end_time.toDate();
        const actualEndTime = afterData.actual_end_time.toDate();

        if (actualEndTime >= expectedEndTime) {
            const initialCost = afterData.initial_cost;
            if (initialCost === undefined || typeof initialCost !== "number") {
                logger.error(`Rental ${event.params.rentalId} tidak memiliki 'initial_cost' yang valid.`);
                return null;
            }

            const calculatedFine = 1.5 * initialCost;
            logger.info(`Rental ${event.params.rentalId} terlambat. Denda: ${calculatedFine}. Menonaktifkan PIN...`);

            // Dapatkan referensi ke dokumen loker
            const db = getFirestore();
            const lockerId = afterData.locker_id;
            const lockerRef = db.collection("lockers").doc(lockerId);

            // Jalankan kedua update secara bersamaan
            const updateRentalPromise = event.data.after.ref.update({
                fine_amount: calculatedFine,
                payment_status: "unpaid_fine",
                status: "locked_due_to_fine" // Status baru yang lebih deskriptif
            });

            const updateLockerPromise = lockerRef.update({
                active_pin: null // <-- KUNCI DARI SOLUSI INI: HAPUS PIN AKTIF
            });

            // Tunggu kedua proses update selesai
            return Promise.all([updateRentalPromise, updateLockerPromise]);
        } else {
            logger.info(`Rental ${event.params.rentalId} selesai tepat waktu.`);
            return event.data.after.ref.update({ fine_amount: 0 });
        }
    } else {
        // Log ini membantu debugging, memberitahu kita mengapa fungsi ini tidak melakukan apa-apa.
        logger.info(`Fungsi calculateFineOnFinish dilewati untuk rental ${event.params.rentalId} karena transisi status bukan dari 'active' ke 'finished'. (Dari: ${beforeData.status}, Ke: ${afterData.status})`);
    }
});

/**
 * Cloud Function untuk memperpanjang waktu sewa loker.
 * Memerlukan data: { rentalId: string, extensionInHours: number }
 */
exports.extendRentalTime = onCall({ region: "asia-southeast2" }, async (request) => {
    const db = getFirestore();

    // 1. Validasi Panggilan (Guard Clauses)
    // Di v2, context.auth diakses melalui request.auth
    if (!request.auth) {
        throw new HttpsError("unauthenticated", "Anda harus login untuk melakukan aksi ini.");
    }

    const { rentalId, extensionInHours } = request.data; // Data ada di dalam request.data

    if (!rentalId || typeof rentalId !== "string") {
        throw new HttpsError("invalid-argument", "ID Rental tidak valid.");
    }
    if (!extensionInHours || typeof extensionInHours !== "number" || extensionInHours <= 0) {
        throw new HttpsError("invalid-argument", "Jumlah jam perpanjangan harus angka positif.");
    }

    // 2. & 3. Pengambilan Data, Verifikasi Kepemilikan dan Aturan
    try {
        const rentalRef = db.collection("rentals").doc(rentalId);
        const rentalDoc = await rentalRef.get();

        if (!rentalDoc.exists) {
            throw new HttpsError("not-found", "Data sewa tidak ditemukan.");
        }

        const rentalData = rentalDoc.data();
        const loggedInUid = request.auth.uid; // UID pengguna ada di request.auth.uid

        if (rentalData.user_id.trim() !== loggedInUid) {
            throw new HttpsError("permission-denied", "Anda tidak memiliki izin untuk memperpanjang sewa ini.");
        }

        const currentEndTime = rentalData.expected_end_time.toDate();
        const now = new Date(); // Waktu server saat ini

        if (now >= currentEndTime) {
            throw new HttpsError("failed-precondition", "Waktu sewa sudah habis dan tidak dapat diperpanjang.");
        }

        // 4. Eksekusi Perpanjangan Waktu
        const extensionInMillis = extensionInHours * 60 * 60 * 1000;
        const newEndTime = new Date(currentEndTime.getTime() + extensionInMillis);

        // Gunakan Timestamp yang sudah di-import dari 'firebase-admin/firestore'
        await rentalRef.update({
            expected_end_time: Timestamp.fromDate(newEndTime)
        });

        // 5. Kirim Respons Sukses
        return {
            success: true,
            message: "Waktu sewa berhasil diperpanjang!",
            newEndTime: newEndTime.toISOString(),
        };
    } catch (error) {
        logger.error("Error extending rental time:", error); // Gunakan logger dari 'firebase-functions/logger'
        if (error instanceof HttpsError) {
            throw error;
        }
        throw new HttpsError("internal", "Terjadi kesalahan di server.");
    }
});
