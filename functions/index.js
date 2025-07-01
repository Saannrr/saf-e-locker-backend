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
const { onSchedule } = require("firebase-functions/v2/scheduler");
const { getMessaging } = require("firebase-admin/messaging");
const { getAuth } = require("firebase-admin/auth");
const nodemailer = require("nodemailer");

// Inisialisasi Firebase Admin SDK
initializeApp();

// Inisialisasi Snap API dari Midtrans
const MIDTRANS_SERVER_KEY = defineString("MIDTRANS_SERVER_KEY");
const MIDTRANS_CLIENT_KEY = defineString("MIDTRANS_CLIENT_KEY");
const SENDER_EMAIL = defineString("SENDER_EMAIL");
const SENDER_PASSWORD = defineString("SENDER_PASSWORD");

const snap = new midtransClient.Snap({
    isProduction: false,
    serverKey: MIDTRANS_SERVER_KEY.value(),
    clientKey: MIDTRANS_CLIENT_KEY.value(),
});

// --- KONSTANTA ---
const aesKey = defineString("AES_KEY");
const aesIv = defineString("AES_IV");
const ALGORITHM = "aes-256-cbc";
const db = getFirestore();

// --- BAGIAN HELPER FUNCTIONS ---

/**
 * Membuat Order ID unik untuk Midtrans.
 * FUNGSI INI TELAH DIPERBAIKI untuk memastikan panjang tidak melebihi 50 karakter.
 * @param {string} rentalId - ID dari dokumen rental.
 * @param {string} paymentType - Jenis pembayaran ('initial_fee', 'fine', dll).
 * @return {string} Order ID yang unik dan aman.
 */
function generateMidtransOrderId(rentalId, paymentType) {
    const timestamp = Date.now();
    // Midtrans memiliki batas maksimal 50 karakter untuk order_id.
    // Untuk memastikan tidak melebihi batas, kita potong bagian rentalId.
    // 20 (rentalId) + 13 (paymentType terpanjang) + 13 (timestamp) + 2 (underscore) = 48 karakter. Aman!
    const truncatedRentalId = rentalId.substring(0, 20);
    return `${truncatedRentalId}_${paymentType}_${timestamp}`;
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

/**
 * Helper function internal untuk membuat entri log.
 * Tidak bisa dipanggil langsung dari klien.
 * @param {object} logData Data log yang akan disimpan.
 */
async function createLogEntry(logData) {
    try {
        // Menambahkan data log ke koleksi 'logs' dengan ID acak
        await db.collection("logs").add(logData);
        logger.info("Log entry created:", logData.details);
    } catch (error) {
        logger.error("Failed to create log entry:", error);
        // Kita tidak melempar error di sini agar aksi utama tidak gagal
        // hanya karena logging gagal. Tapi kita mencatatnya.
    }
}

// Fungsi untuk memvalidasi format email
// eslint-disable-next-line require-jsdoc
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// --- BAGIAN API UNTUK FRONTEND (User) ---

/**
 * (API untuk User) - Memulai proses sewa dengan mencari loker yang tersedia,
 * mereservasinya, dan membuat dokumen rental. Ini adalah langkah pertama
 * sebelum melakukan pembayaran.
 * Memerlukan data: { durationInHours: number }
 */
exports.initiateRental = onCall({ region: "asia-southeast2" }, async (request) => {
    // 1. Verifikasi pengguna sudah login
    if (!request.auth) {
        throw new HttpsError("unauthenticated", "Anda harus login untuk memulai sewa.");
    }
    const userId = request.auth.uid;

    // 2. Validasi input
    const { durationInHours } = request.data;
    if (!durationInHours || typeof durationInHours !== "number" || durationInHours <= 0) {
        throw new HttpsError("invalid-argument", "Durasi sewa (durationInHours) harus angka positif.");
    }

    // 3. Gunakan Transaksi Firestore untuk keamanan dan konsistensi
    try {
        const rentalId = await db.runTransaction(async (t) => {
            // --- PERUBAHAN DIMULAI DI SINI ---
            // 1. Ambil konfigurasi harga terlebih dahulu.
            const pricingRef = db.collection("config").doc("pricing");
            const pricingDoc = await t.get(pricingRef);
            if (!pricingDoc.exists || !pricingDoc.data().hourly_rate) {
                throw new HttpsError("internal", "Konfigurasi harga tidak ditemukan. Hubungi administrator.");
            }
            const hourlyRate = pricingDoc.data().hourly_rate;
            // --- AKHIR PERUBAHAN ---

            // Cari loker yang tersedia
            const lockersRef = db.collection("lockers");
            const availableLockerQuery = lockersRef.where("status", "==", "available").limit(1);
            const lockerSnapshot = await t.get(availableLockerQuery);

            if (lockerSnapshot.empty) {
                throw new HttpsError("not-found", "Maaf, tidak ada loker yang tersedia saat ini.");
            }

            const lockerDoc = lockerSnapshot.docs[0];
            const lockerId = lockerDoc.id;
            const lockerRef = lockerDoc.ref;

            // --- PERUBAHAN DIMULAI DI SINI ---
            // Hitung biaya berdasarkan harga dari database, bukan hardcode.
            const initialCost = durationInHours * hourlyRate;
            // --- AKHIR PERUBAHAN ---

            const startTime = new Date();
            const expectedEndTime = new Date(startTime.getTime() + durationInHours * 60 * 60 * 1000);

            // Buat dokumen rental baru
            const rentalRef = db.collection("rentals").doc();
            t.set(rentalRef, {
                user_id: userId,
                locker_id: lockerId,
                start_time: Timestamp.fromDate(startTime),
                duration_hours: durationInHours,
                status: "pending_payment",
                payment_status: "unpaid",
                expected_end_time: Timestamp.fromDate(expectedEndTime),
                initial_cost: initialCost, // Gunakan biaya yang sudah dihitung
                fine_amount: 0,
            });

            return rentalRef.id;
        });

        // Jika transaksi berhasil, kirim kembali rentalId ke klien
        return {
            success: true,
            rentalId: rentalId,
            message: "Loker berhasil direservasi. Silakan lanjutkan ke pembayaran."
        };
    } catch (error) {
        logger.error("Gagal memulai proses sewa:", error);
        // Jika error sudah HttpsError (seperti 'not-found'), lemparkan kembali.
        if (error instanceof HttpsError) {
            throw error;
        }
        // Untuk error lainnya, kirim pesan generik.
        throw new HttpsError("internal", "Terjadi kesalahan saat mencoba menyewa loker.");
    }
});

/**
 * (API untuk User) - Meminta pembukaan loker dengan langsung mengubah field 'isLocked'.
 * Ini adalah pendekatan yang lebih sederhana.
 * Memerlukan data: { rentalId: string }
 */
exports.openLockerByApp = onCall({ region: "asia-southeast2" }, async (request) => {
    // 1. Verifikasi pengguna sudah login
    if (!request.auth) {
        throw new HttpsError("unauthenticated", "Anda harus login untuk melakukan aksi ini.");
    }
    const userId = request.auth.uid;

    // 2. Validasi input
    const { rentalId } = request.data;
    if (!rentalId) {
        throw new HttpsError("invalid-argument", "Parameter 'rentalId' diperlukan.");
    }

    const db = getFirestore();

    try {
        // 3. Gunakan Transaksi Firestore untuk keamanan
        await db.runTransaction(async (t) => {
            const rentalRef = db.collection("rentals").doc(rentalId);
            const rentalDoc = await t.get(rentalRef);

            if (!rentalDoc.exists) {
                throw new HttpsError("not-found", "Data sewa tidak ditemukan.");
            }
            const rentalData = rentalDoc.data();

            // Verifikasi kepemilikan dan status sewa (logika ini sudah benar)
            if (rentalData.user_id !== userId) {
                throw new HttpsError("permission-denied", "Anda tidak memiliki izin untuk loker ini.");
            }
            if (!["active", "pending_retrieval"].includes(rentalData.status)) {
                throw new HttpsError(
                    "failed-precondition",
                    `Loker tidak dapat dibuka saat status sewa adalah '${rentalData.status}'.`
                );
            }

            // Dapatkan referensi loker
            const lockerId = rentalData.locker_id;
            const lockerRef = db.collection("lockers").doc(lockerId);

            // --- INI ADALAH LOGIKA UTAMA (DIRECT TRIGGER) ---
            // Langsung perintahkan loker untuk membuka dengan mengubah 'isLocked' menjadi false.
            logger.info(`Pengguna ${userId} mengirim perintah buka ke loker ${lockerId}`);
            t.update(lockerRef, {
                isLocked: false,
                last_lock_change: Timestamp.now(),
            });
            // ---------------------------------------------
        });

        // 4. Kirim respons sukses ke aplikasi
        return {
            success: true,
            message: "Perintah untuk membuka loker telah dikirim."
        };
    } catch (error) {
        logger.error("Gagal meminta pembukaan loker:", error);
        if (error instanceof HttpsError) {
            throw error;
        }
        throw new HttpsError("internal", "Terjadi kesalahan di server.");
    }
});

/**
 * (API untuk User) - Dipanggil oleh aplikasi saat pengguna menekan tombol "Terminate"
 * untuk menyelesaikan sesi sewa mereka.
 * Memerlukan data: { rentalId: string }
 */
exports.terminateRentalByUser = onCall({ region: "asia-southeast2" }, async (request) => {
    // 1. Verifikasi pengguna sudah login
    if (!request.auth) {
        throw new HttpsError("unauthenticated", "Anda harus login untuk melakukan aksi ini.");
    }
    const userId = request.auth.uid;

    // 2. Validasi input
    const { rentalId } = request.data;
    if (!rentalId) {
        throw new HttpsError("invalid-argument", "Parameter 'rentalId' diperlukan.");
    }

    const db = getFirestore();
    const rentalRef = db.collection("rentals").doc(rentalId);

    try {
        // 3. Gunakan Transaksi Firestore untuk keamanan dan konsistensi
        await db.runTransaction(async (t) => {
            const rentalDoc = await t.get(rentalRef);

            if (!rentalDoc.exists) {
                throw new HttpsError("not-found", "Data sewa tidak ditemukan.");
            }
            const rentalData = rentalDoc.data();

            // Verifikasi kepemilikan
            if (rentalData.user_id !== userId) {
                throw new HttpsError("permission-denied", "Anda tidak memiliki izin untuk mengakhiri sewa ini.");
            }

            // --- LOGIKA PENGAMAN PENTING ---
            // Pastikan sewa hanya bisa diakhiri jika statusnya 'active'.
            // Ini mencegah pengguna mengakhiri sewa yang sudah selesai atau terkunci.
            if (rentalData.status !== "active") {
                throw new HttpsError(
                    "failed-precondition",
                    `Sewa tidak dapat diakhiri karena statusnya adalah '${rentalData.status}', bukan 'active'.`
                );
            }

            // 4. Lakukan update: ubah status menjadi 'finished'.
            // Perubahan ini akan secara otomatis memicu 'calculateFineOnFinish'.
            logger.info(`Pengguna ${userId} mengakhiri sewa ${rentalId}. Memicu proses penyelesaian...`);
            t.update(rentalRef, {
                actual_end_time: Timestamp.now(), // Catat waktu selesai sebenarnya
                status: "finished",
            });
        });

        // 5. Kirim respons sukses ke aplikasi
        return {
            success: true,
            message: "Permintaan untuk mengakhiri sewa telah diterima dan sedang diproses."
        };
    } catch (error) {
        logger.error(`Gagal mengakhiri sewa ${rentalId}:`, error);
        if (error instanceof HttpsError) {
            throw error;
        }
        throw new HttpsError("internal", "Terjadi kesalahan di server.");
    }
});

/**
 * (API untuk User) - Mengambil data profil lengkap untuk pengguna yang sedang login.
 * Fungsi ini tidak memerlukan parameter karena ID pengguna diambil secara otomatis
 * dari konteks autentikasi.
 */
exports.getUserProfile = onCall({ region: "asia-southeast2" }, async (request) => {
    // 1. Verifikasi bahwa pengguna sudah login. Ini adalah langkah keamanan utama.
    if (!request.auth) {
        throw new HttpsError("unauthenticated", "Anda harus login untuk melihat profil.");
    }
    const uid = request.auth.uid;

    try {
        // 2. Ambil data dari Firebase Authentication
        const userRecord = await getAuth().getUser(uid);

        // 3. Ambil data tambahan dari koleksi 'users' di Firestore
        const userDocRef = db.collection("users").doc(uid);
        const userDoc = await userDocRef.get();

        // 4. Gabungkan data dari kedua sumber
        let username = "Belum diatur"; // Nilai default jika tidak ada di Firestore
        if (userDoc.exists) {
            username = userDoc.data().username || username;
        }

        // Siapkan objek profil yang akan dikirim kembali ke aplikasi
        const userProfile = {
            uid: userRecord.uid,
            email: userRecord.email,
            username: username, // Diambil dari Firestore
            displayName: userRecord.displayName, // Biasanya null jika tidak diatur
            photoURL: userRecord.photoURL,
            creationTime: userRecord.metadata.creationTime,
            lastSignInTime: userRecord.metadata.lastSignInTime,
        };

        logger.info(`Profil berhasil diambil untuk pengguna: ${uid}`);

        // 5. Kirim data profil yang sudah lengkap
        return {
            success: true,
            profile: userProfile
        };
    } catch (error) {
        logger.error(`Gagal mengambil profil untuk pengguna ${uid}:`, error);
        if (error.code === "auth/user-not-found") {
            throw new HttpsError("not-found", "Data autentikasi pengguna tidak ditemukan.");
        }
        throw new HttpsError("internal", "Terjadi kesalahan saat mengambil data profil.");
    }
});

/**
 * (API untuk User) - Mengambil riwayat sewa untuk pengguna yang sedang login.
 * Diurutkan dari yang terbaru, dengan batasan jumlah untuk performa.
 * Tidak memerlukan parameter.
 */
exports.getRentalHistory = onCall({ region: "asia-southeast2" }, async (request) => {
    // 1. Verifikasi bahwa pengguna sudah login.
    if (!request.auth) {
        throw new HttpsError("unauthenticated", "Anda harus login untuk melihat riwayat sewa.");
    }
    const uid = request.auth.uid;

    try {
        // 2. Query ke koleksi 'rentals'.
        const rentalsRef = db.collection("rentals");
        const querySnapshot = await rentalsRef
            // Filter hanya untuk dokumen yang 'user_id'-nya cocok dengan pengguna yang login.
            .where("user_id", "==", uid)
            // Urutkan berdasarkan waktu mulai, yang terbaru di atas.
            .orderBy("start_time", "desc")
            // Batasi 50 data terbaru untuk mencegah overload.
            .limit(50)
            .get();

        // 3. Format data untuk dikirim ke frontend.
        const history = [];
        querySnapshot.forEach((doc) => {
            const data = doc.data();
            history.push({
                id: doc.id, // Sertakan ID dokumen rental
                ...data,
                // Ubah format timestamp agar mudah dibaca di frontend
                start_time: data.start_time ? data.start_time.toDate().toISOString() : null,
                expected_end_time: data.expected_end_time ? data.expected_end_time.toDate().toISOString() : null,
                actual_end_time: data.actual_end_time ? data.actual_end_time.toDate().toISOString() : null,
            });
        });

        // 4. Kirim data kembali.
        logger.info(`Riwayat rental berhasil diambil untuk pengguna: ${uid}. Ditemukan ${history.length} item.`);
        return {
            success: true,
            history: history
        };
    } catch (error) {
        logger.error(`Gagal mengambil riwayat rental untuk pengguna ${uid}:`, error);
        throw new HttpsError("internal", "Gagal mengambil data riwayat sewa.");
    }
});

/**
 * (API untuk User) - Mengambil riwayat pembayaran untuk pengguna yang sedang login.
 * Diurutkan dari yang terbaru, dengan batasan jumlah untuk performa.
 * Tidak memerlukan parameter.
 */
exports.getPaymentHistory = onCall({ region: "asia-southeast2" }, async (request) => {
    // 1. Verifikasi bahwa pengguna sudah login.
    if (!request.auth) {
        throw new HttpsError("unauthenticated", "Anda harus login untuk melihat riwayat pembayaran.");
    }
    const uid = request.auth.uid;

    try {
        // 2. Query ke koleksi 'payments'.
        const paymentsRef = db.collection("payments");
        const querySnapshot = await paymentsRef
            // Filter hanya untuk dokumen yang 'user_id'-nya cocok dengan pengguna yang login.
            .where("user_id", "==", uid)
            // Urutkan berdasarkan waktu dibuat, yang terbaru di atas.
            .orderBy("created_at", "desc")
            // Batasi 50 data terbaru untuk mencegah overload.
            .limit(50)
            .get();

        // 3. Format data untuk dikirim ke frontend.
        const history = [];
        querySnapshot.forEach((doc) => {
            const data = doc.data();
            // Kita tidak perlu mengirim ulang semua 'response_data' yang besar.
            // Cukup kirim data yang paling relevan.
            history.push({
                id: doc.id,
                rental_id: data.rental_id,
                amount: data.amount,
                payment_type: data.payment_type,
                status: data.status,
                // Ubah format timestamp agar mudah dibaca di frontend
                created_at: data.created_at || admin.firestore.FieldValue.serverTimestamp(),
            });
        });

        // 4. Kirim data kembali.
        logger.info(`Riwayat pembayaran berhasil diambil untuk pengguna: ${uid}. Ditemukan ${history.length} item.`);
        return {
            success: true,
            history: history
        };
    } catch (error) {
        logger.error(`Gagal mengambil riwayat pembayaran untuk pengguna ${uid}:`, error);
        throw new HttpsError("internal", "Gagal mengambil data riwayat pembayaran.");
    }
});

// --- BAGIAN API UNTUK FRONTEND (Admin) ---

/**
 * Cloud Function untuk menetapkan custom claim 'admin' ke seorang pengguna.
 * Hanya bisa dipanggil oleh admin yang sudah ada.
 * Memerlukan data: { email: string }
 */
exports.addAdminRole = onCall({ region: "asia-southeast2" }, async (request) => {
    // 1. Verifikasi bahwa yang memanggil fungsi ini adalah admin
    if (request.auth.token.admin !== true) {
        throw new HttpsError(
            "permission-denied",
            "Hanya admin yang bisa menambahkan admin baru."
        );
    }

    // 2. Dapatkan email dari data yang dikirim dan setel claim
    const email = request.data.email;
    try {
        const user = await admin.auth().getUserByEmail(email); // Menggunakan admin SDK
        await admin.auth().setCustomUserClaims(user.uid, { admin: true });

        // 3. Kirim respons sukses
        return {
            message: `Sukses! ${email} sekarang telah menjadi admin.`,
        };
    } catch (error) {
        logger.error("Gagal menambahkan admin baru:", error);
        throw new HttpsError("internal", "Gagal menetapkan peran admin.");
    }
});

/**
 * Cloud Function untuk admin mereset PIN sebuah loker.
 * FUNGSI INI TELAH DIPERBAIKI dengan logika enkripsi AES.
 * Memerlukan data: { lockerId: string }
 */
exports.resetLockerPinByAdmin = onCall({ region: "asia-southeast2" }, async (request) => {
    // 1. Verifikasi bahwa yang memanggil fungsi ini adalah admin (Logika Anda sudah benar)
    if (request.auth.token.admin !== true) {
        throw new HttpsError(
            "permission-denied",
            "Hanya admin yang bisa menjalankan fungsi ini."
        );
    }

    const { lockerId } = request.data;
    if (!lockerId) {
        throw new HttpsError("invalid-argument", "lockerId harus disediakan.");
    }

    try {
        // 2. Logika untuk mereset PIN
        // Cari dokumen rental yang aktif untuk loker ini.
        // KOREKSI: Status yang benar adalah 'active', 'locked_due_to_fine', atau 'pending_retrieval'.
        const rentalsRef = db.collection("rentals");
        const querySnapshot = await rentalsRef
            .where("locker_id", "==", lockerId)
            .where("status", "in", ["active", "locked_due_to_fine", "pending_retrieval"])
            .limit(1)
            .get();

        if (querySnapshot.empty) {
            throw new HttpsError("not-found", `Tidak ada sewa yang dapat direset untuk loker ${lockerId}.`);
        }

        const rentalDoc = querySnapshot.docs[0];
        const newPin = Math.floor(1000 + Math.random() * 9000).toString(); // Generate 4 digit PIN baru

        // --- KOREKSI LOGIKA ENKRIPSI DIMULAI DI SINI ---

        // Panggil fungsi 'encrypt' yang sudah Anda buat untuk mengenkripsi PIN baru.
        // Ini adalah inti dari penerapan keamanan AES Anda.
        const encryptedNewPin = encrypt(newPin);
        logger.info(`PIN baru untuk Loker ${lockerId} adalah ${newPin}. Versi terenkripsi dibuat.`);

        // Dapatkan referensi ke dokumen loker yang sesuai.
        const lockerRef = db.collection("lockers").doc(lockerId);

        // Gunakan Promise.all untuk menjalankan kedua update secara bersamaan.
        // Ini memastikan konsistensi data antara rental dan loker.
        await Promise.all([
            // Update dokumen rental dengan PIN yang sudah dienkripsi.
            // Ini yang akan dilihat oleh pengguna di aplikasi.
            rentalDoc.ref.update({ encrypted_pin: encryptedNewPin }),

            // Update dokumen loker dengan PIN teks biasa (plain text).
            // Ini yang akan dibaca dan divalidasi oleh hardware ESP32.
            lockerRef.update({ active_pin: newPin })
        ]);

        // --- AKHIR KOREKSI ---

        // 3. Panggil helper function untuk MENCATAT LOG (Logika Anda sudah benar)
        await createLogEntry({
            timestamp: Timestamp.now(),
            adminId: request.auth.uid,
            adminEmail: request.auth.token.email,
            action: "RESET_PIN",
            details: `Admin mereset PIN untuk Loker ${lockerId}.`,
            targetId: lockerId,
            targetType: "LOCKER"
        });

        // 4. Kirim respons sukses
        return {
            success: true,
            message: `PIN untuk loker ${lockerId} berhasil direset.`,
            newPin: newPin // Kirim PIN baru (plain text) ke admin untuk keadaan darurat
        };
    } catch (error) {
        logger.error("Gagal mereset PIN oleh admin:", error);
        if (error instanceof HttpsError) {
            throw error;
        }
        throw new HttpsError("internal", "Terjadi kesalahan di server.");
    }
});

/**
 * Cloud Function untuk mengambil daftar log aktivitas admin.
 * Diurutkan dari yang terbaru.
 */
exports.getAdminLogs = onCall({ region: "asia-southeast2" }, async (request) => {
    // Verifikasi bahwa yang memanggil fungsi ini adalah admin
    if (request.auth.token.admin !== true) {
        throw new HttpsError(
            "permission-denied",
            "Hanya admin yang bisa melihat log aktivitas."
        );
    }

    try {
        const logsRef = db.collection("logs");
        const querySnapshot = await logsRef
            .orderBy("timestamp", "desc") // Urutkan dari yang paling baru
            .limit(50) // Batasi 50 log terbaru untuk awal
            .get();

        const logs = [];
        querySnapshot.forEach((doc) => {
            const data = doc.data();
            logs.push({
                id: doc.id,
                ...data,
                // Konversi timestamp ke format yang lebih mudah dibaca di klien
                timestamp: data.timestamp.toDate().toISOString()
            });
        });

        return { logs };
    } catch (error) {
        logger.error("Gagal mengambil log admin:", error);
        throw new HttpsError("internal", "Gagal mengambil data log.");
    }
});

/**
 * (API untuk Admin) - Mengambil daftar semua riwayat sewa (rentals).
 * Diurutkan dari yang terbaru, dengan batasan jumlah untuk performa.
 */
exports.getAllRentalsByAdmin = onCall({ region: "asia-southeast2" }, async (request) => {
    // Langkah 1: Verifikasi bahwa pemanggil adalah admin.
    if (request.auth.token.admin !== true) {
        throw new HttpsError("permission-denied", "Hanya admin yang bisa menjalankan fungsi ini.");
    }

    try {
        // Langkah 2: Query ke koleksi 'rentals'.
        const rentalsRef = db.collection("rentals");
        const querySnapshot = await rentalsRef
            .orderBy("start_time", "desc") // Urutkan berdasarkan waktu mulai, yang terbaru di atas.
            .limit(100) // Batasi 100 data terbaru untuk mencegah overload.
            .get();

        // Langkah 3: Format data untuk dikirim ke frontend.
        const rentals = [];
        querySnapshot.forEach((doc) => {
            const data = doc.data();
            rentals.push({
                id: doc.id, // Sertakan ID dokumen
                ...data,
                // Ubah format timestamp agar mudah dibaca di frontend
                start_time: data.start_time ? data.start_time.toDate().toISOString() : null,
                expected_end_time: data.expected_end_time ? data.expected_end_time.toDate().toISOString() : null,
                actual_end_time: data.actual_end_time ? data.actual_end_time.toDate().toISOString() : null,
                updated_at: data.updated_at ? data.updated_at.toDate().toISOString() : null,
            });
        });

        // Langkah 4: Kirim data kembali.
        logger.info(`Admin ${request.auth.token.email} mengambil ${rentals.length} data rental.`);
        return { rentals };
    } catch (error) {
        logger.error("Gagal mengambil semua data rental oleh admin:", error);
        throw new HttpsError("internal", "Gagal mengambil data rental.");
    }
});

/**
 * (API untuk Admin) - Mengambil daftar dan status semua loker.
 */
exports.getAllLockersByAdmin = onCall({ region: "asia-southeast2" }, async (request) => {
    // Langkah 1: Verifikasi bahwa pemanggil adalah admin.
    if (request.auth.token.admin !== true) {
        throw new HttpsError("permission-denied", "Hanya admin yang bisa menjalankan fungsi ini.");
    }

    try {
        // Langkah 2: Query ke koleksi 'lockers'.
        const lockersRef = db.collection("lockers");
        const querySnapshot = await lockersRef.get();

        // Langkah 3: Format data untuk dikirim ke frontend.
        const lockers = [];
        querySnapshot.forEach((doc) => {
            lockers.push({
                id: doc.id,
                ...doc.data(),
            });
        });

        // Langkah 4: Kirim data kembali.
        logger.info(`Admin ${request.auth.token.email} mengambil ${lockers.length} data loker.`);
        return { lockers };
    } catch (error) {
        logger.error("Gagal mengambil semua data loker oleh admin:", error);
        throw new HttpsError("internal", "Gagal mengambil data loker.");
    }
});

/**
 * (API untuk Admin) - Mengambil daftar semua pengguna yang terdaftar di sistem.
 * Fungsi ini menggunakan Firebase Authentication API.
 */
exports.getAllUsersByAdmin = onCall({ region: "asia-southeast2" }, async (request) => {
    // Langkah 1: Verifikasi bahwa pemanggil adalah seorang admin.
    if (request.auth.token.admin !== true) {
        throw new HttpsError("permission-denied", "Hanya admin yang bisa menjalankan fungsi ini.");
    }

    try {
        // Langkah 2: Panggil Admin Auth API untuk mengambil daftar pengguna.
        // Kita batasi 1000 pengguna pertama untuk performa.
        // Untuk aplikasi yang lebih besar, perlu implementasi pagination.
        const listUsersResult = await getAuth().listUsers(1000);

        // Langkah 3: Format data agar lebih mudah digunakan di frontend.
        // Kita hanya mengambil informasi yang paling relevan.
        const users = listUsersResult.users.map((userRecord) => {
            return {
                uid: userRecord.uid,
                email: userRecord.email,
                displayName: userRecord.displayName || "Tidak Ada Nama",
                photoURL: userRecord.photoURL || null,
                disabled: userRecord.disabled,
                creationTime: userRecord.metadata.creationTime,
                lastSignInTime: userRecord.metadata.lastSignInTime,
                // Kita juga bisa melihat apakah seorang user adalah admin atau bukan
                customClaims: userRecord.customClaims || {}
            };
        });

        // Langkah 4: Kirim data kembali.
        logger.info(`Admin ${request.auth.token.email} mengambil ${users.length} data pengguna.`);
        return { users };
    } catch (error) {
        logger.error("Gagal mengambil daftar pengguna oleh admin:", error);
        throw new HttpsError("internal", "Gagal mengambil data pengguna.");
    }
});

/**
 * (API untuk Admin) - Mengambil daftar semua riwayat pembayaran dari semua pengguna.
 * Diurutkan dari yang terbaru.
 */
exports.getAllPaymentsByAdmin = onCall({ region: "asia-southeast2" }, async (request) => {
    // Langkah 1: Verifikasi bahwa pemanggil adalah seorang admin.
    if (request.auth.token.admin !== true) {
        throw new HttpsError("permission-denied", "Hanya admin yang bisa menjalankan fungsi ini.");
    }

    try {
        // Langkah 2: Query ke koleksi 'payments'.
        const paymentsRef = db.collection("payments");
        const querySnapshot = await paymentsRef
            .orderBy("created_at", "desc") // Urutkan berdasarkan waktu dibuat, yang terbaru di atas.
            .limit(100) // Batasi 100 data terbaru untuk awal.
            .get();

        // Langkah 3: Format data untuk dikirim ke frontend.
        const payments = [];
        querySnapshot.forEach((doc) => {
            const data = doc.data();
            payments.push({
                id: doc.id, // ID dokumen pembayaran (order_id dari Midtrans)
                ...data,
                // Ubah format timestamp agar mudah dibaca di frontend
                created_at: data.created_at ? data.created_at.toDate().toISOString() : null,
                updated_at: data.updated_at ? data.updated_at.toDate().toISOString() : null,
            });
        });

        // Langkah 4: Kirim data kembali.
        logger.info(`Admin ${request.auth.token.email} mengambil ${payments.length} data pembayaran.`);
        return { payments };
    } catch (error) {
        logger.error("Gagal mengambil semua data pembayaran oleh admin:", error);
        throw new HttpsError("internal", "Gagal mengambil data pembayaran.");
    }
});

/**
 * (API untuk Admin) - Mengambil data konfigurasi aplikasi saat ini,
 * seperti tarif harga sewa.
 * Tidak memerlukan parameter.
 */
exports.getConfigByAdmin = onCall({ region: "asia-southeast2" }, async (request) => {
    // 1. Verifikasi bahwa pemanggil adalah seorang admin.
    if (request.auth.token.admin !== true) {
        throw new HttpsError("permission-denied", "Hanya admin yang bisa menjalankan fungsi ini.");
    }

    const db = getFirestore();
    const pricingRef = db.collection("config").doc("pricing");

    try {
        // 2. Ambil dokumen konfigurasi harga.
        const pricingDoc = await pricingRef.get();

        if (!pricingDoc.exists) {
            throw new HttpsError("not-found", "Dokumen konfigurasi harga tidak ditemukan.");
        }

        const configData = pricingDoc.data();
        logger.info(`Admin ${request.auth.token.email} berhasil mengambil data konfigurasi.`);

        // 3. Kirim data konfigurasi kembali.
        return {
            success: true,
            config: configData
        };
    } catch (error) {
        logger.error("Gagal mengambil data konfigurasi oleh admin:", error);
        if (error instanceof HttpsError) {
            throw error;
        }
        throw new HttpsError("internal", "Terjadi kesalahan di server.");
    }
});

/**
 * (API untuk Admin) - Memicu pengiriman email reset password ke seorang pengguna.
 * FUNGSI INI TELAH DIPERBAIKI untuk mengirim email secara manual.
 */
exports.resetUserPasswordByAdmin = onCall({ region: "asia-southeast2" }, async (request) => {
    // 1. Verifikasi admin (logika Anda sudah benar)
    if (request.auth.token.admin !== true) {
        throw new HttpsError("permission-denied", "Hanya admin yang bisa menjalankan fungsi ini.");
    }

    const { getAuth } = require("firebase-admin/auth");
    const email = request.data.email;
    if (!email || typeof email !== "string") {
        throw new HttpsError("invalid-argument", "Parameter 'email' diperlukan.");
    }

    if (!isValidEmail(email)) {
        logger.error("Invalid email format", { email });
        throw new HttpsError("invalid-argument", "Format email tidak valid.");
    }

    try {
        // --- LANGKAH A: BUAT LINK RESET (seperti sebelumnya) ---
        const resetLink = await getAuth().generatePasswordResetLink(email);
        logger.info(`Link reset password berhasil dibuat untuk: ${email}`);

        // --- LANGKAH B: KIRIM EMAIL MENGGUNAKAN NODEMAILER ---
        // Konfigurasi transporter email menggunakan kredensial dari Secret Manager
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: SENDER_EMAIL.value(),
                pass: SENDER_PASSWORD.value(), // Gunakan App Password di sini
            },
        });

        // Konfigurasi isi email
        const mailOptions = {
            from: `"SAF-E Locker Admin" <${SENDER_EMAIL.value()}>`,
            to: email, // Kirim ke email pengguna target
            subject: "Reset Password untuk Akun SAF-E Locker Anda",
            html: `
                <p>Halo,</p>
                <p>Anda menerima email ini karena ada permintaan reset password untuk akun Anda dari admin.</p>
                <p>Silakan klik link di bawah ini untuk membuat password baru:</p>
                <a href="${resetLink}">Reset Password Anda</a>
                <p>Jika Anda tidak merasa meminta ini, silakan abaikan email ini.</p>
                <p>Terima kasih,</p>
                <p>Tim SAF-E Locker</p>
            `,
        };

        // Kirim email
        await transporter.sendMail(mailOptions);
        logger.info(`Email reset password berhasil dikirim ke ${email}`);

        // Kirim pesan sukses kembali ke antarmuka admin
        return {
            success: true,
            message: `Email reset password telah berhasil dikirim ke ${email}.`,
        };
    } catch (error) {
        logger.error(`Gagal memproses reset password untuk ${email}:`, error);
        if (error.code === "auth/user-not-found") {
            throw new HttpsError("not-found", `Pengguna dengan email ${email} tidak ditemukan.`);
        }
        throw new HttpsError("internal", "Terjadi kesalahan di server.");
    }
});

/**
 * (API untuk Admin) - Mengubah status loker antara 'available' dan 'maintenance'.
 * Fungsi ini memiliki pengaman untuk mencegah menonaktifkan loker yang sedang digunakan.
 * Memerlukan data: { lockerId: string, newStatus: 'available' | 'maintenance' }
 */
exports.toggleLockerStatusByAdmin = onCall({ region: "asia-southeast2" }, async (request) => {
    // Langkah 1: Verifikasi bahwa pemanggil adalah seorang admin.
    if (request.auth.token.admin !== true) {
        throw new HttpsError("permission-denied", "Hanya admin yang bisa menjalankan fungsi ini.");
    }

    // Langkah 2: Validasi input dari request.
    const { lockerId, newStatus } = request.data;
    if (!lockerId || !newStatus) {
        throw new HttpsError("invalid-argument", "Parameter 'lockerId' dan 'newStatus' diperlukan.");
    }
    // Pastikan status baru yang dikirim valid.
    if (!["available", "maintenance"].includes(newStatus)) {
        throw new HttpsError("invalid-argument", "Nilai 'newStatus' hanya boleh 'available' atau 'maintenance'.");
    }

    const lockerRef = db.collection("lockers").doc(lockerId);

    try {
        // Langkah 3: Periksa status loker saat ini sebelum mengubahnya.
        const lockerDoc = await lockerRef.get();
        if (!lockerDoc.exists) {
            throw new HttpsError("not-found", `Loker dengan ID ${lockerId} tidak ditemukan.`);
        }

        const currentStatus = lockerDoc.data().status;

        // --- INI ADALAH LOGIKA PENGAMAN PENTING ---
        // Hanya izinkan perubahan jika loker dalam kondisi 'available' atau 'maintenance'.
        // Ini mencegah admin menonaktifkan loker yang sedang 'occupied', 'locked_due_to_fine', dll.
        if (currentStatus !== "available" && currentStatus !== "maintenance") {
            throw new HttpsError(
                "failed-precondition",
                `Loker sedang digunakan (status: ${currentStatus}) dan tidak dapat diubah statusnya.`
            );
        }

        // Langkah 4: Jika aman, update status loker.
        await lockerRef.update({
            status: newStatus,
            last_updated: Timestamp.now()
        });

        const logDetails = `Admin mengubah status Loker ${lockerId} menjadi '${newStatus}'.`;
        logger.info(logDetails);

        // Langkah 5: Catat aktivitas ini di log admin.
        await createLogEntry({
            timestamp: Timestamp.now(),
            adminId: request.auth.uid,
            adminEmail: request.auth.token.email,
            action: "TOGGLE_LOCKER_STATUS",
            details: logDetails,
            targetId: lockerId,
            targetType: "LOCKER"
        });

        // Langkah 6: Kirim pesan sukses kembali.
        return {
            success: true,
            message: `Status untuk loker ${lockerId} berhasil diubah menjadi '${newStatus}'.`,
        };
    } catch (error) {
        logger.error(`Gagal mengubah status loker ${lockerId} oleh admin:`, error);
        if (error instanceof HttpsError) {
            throw error;
        }
        throw new HttpsError("internal", "Terjadi kesalahan di server.");
    }
});

/**
 * (API untuk Admin) - Memberikan akses "kunci master" untuk membuka loker apapun.
 * Ini adalah fungsi dengan hak akses tinggi dan setiap penggunaannya akan dicatat.
 * Memerlukan data: { lockerId: string }
 */
exports.openAnyLockerByAdmin = onCall({ region: "asia-southeast2" }, async (request) => {
    // 1. Verifikasi bahwa pemanggil adalah seorang admin.
    if (request.auth.token.admin !== true) {
        throw new HttpsError("permission-denied", "Hanya admin yang bisa menjalankan fungsi ini.");
    }

    // 2. Validasi input dari request.
    const { lockerId } = request.data;
    if (!lockerId) {
        throw new HttpsError("invalid-argument", "Parameter 'lockerId' diperlukan.");
    }

    const db = getFirestore();
    const lockerRef = db.collection("lockers").doc(lockerId);

    try {
        // 3. Periksa apakah loker benar-benar ada.
        const lockerDoc = await lockerRef.get();
        if (!lockerDoc.exists) {
            throw new HttpsError("not-found", `Loker dengan ID ${lockerId} tidak ditemukan.`);
        }

        // 4. Langsung kirim perintah buka dengan mengubah 'isLocked' menjadi false.
        // Karena ini adalah override dari admin, kita tidak perlu memeriksa status loker saat ini.
        await lockerRef.update({
            isLocked: false
        });

        const logDetails = `Admin membuka paksa Loker ${lockerId}.`;
        logger.info(logDetails);

        // 5. WAJIB: Catat aktivitas ini di log admin untuk audit.
        await createLogEntry({
            timestamp: Timestamp.now(),
            adminId: request.auth.uid,
            adminEmail: request.auth.token.email,
            action: "ADMIN_OPEN_LOCKER",
            details: logDetails,
            targetId: lockerId,
            targetType: "LOCKER"
        });

        // 6. Kirim pesan sukses kembali.
        return {
            success: true,
            message: `Perintah buka untuk loker ${lockerId} telah berhasil dikirim.`,
        };
    } catch (error) {
        logger.error(`Gagal membuka loker ${lockerId} oleh admin:`, error);
        if (error instanceof HttpsError) {
            throw error;
        }
        throw new HttpsError("internal", "Terjadi kesalahan di server.");
    }
});

/**
 * (API untuk Admin) - Mengatur atau memperbarui tarif harga sewa per jam.
 * Memerlukan data: { hourlyRate: number }
 */
exports.setPricingByAdmin = onCall({ region: "asia-southeast2" }, async (request) => {
    // 1. Verifikasi bahwa pemanggil adalah seorang admin.
    if (request.auth.token.admin !== true) {
        throw new HttpsError("permission-denied", "Hanya admin yang bisa menjalankan fungsi ini.");
    }

    // 2. Validasi input dari request.
    const { hourlyRate } = request.data;
    if (!hourlyRate || typeof hourlyRate !== "number" || hourlyRate < 0) {
        throw new HttpsError("invalid-argument", "Parameter 'hourlyRate' diperlukan dan harus angka non-negatif.");
    }

    const db = getFirestore();
    const pricingRef = db.collection("config").doc("pricing");

    try {
        // 3. Update dokumen konfigurasi harga.
        await pricingRef.set({
            hourly_rate: hourlyRate,
            last_updated_by: request.auth.token.email,
            last_updated_at: Timestamp.now()
        }, { merge: true }); // Gunakan merge untuk update, bukan menimpa seluruh dokumen.

        const logDetails = `Admin mengubah tarif per jam menjadi Rp${hourlyRate}.`;
        logger.info(logDetails);

        // 4. Catat aktivitas ini di log admin.
        await createLogEntry({
            timestamp: Timestamp.now(),
            adminId: request.auth.uid,
            adminEmail: request.auth.token.email,
            action: "SET_PRICING",
            details: logDetails,
            targetId: "pricing",
            targetType: "CONFIG"
        });

        // 5. Kirim pesan sukses kembali.
        return {
            success: true,
            message: `Tarif harga berhasil diubah menjadi Rp${hourlyRate} per jam.`,
        };
    } catch (error) {
        logger.error("Gagal mengubah tarif harga oleh admin:", error);
        throw new HttpsError("internal", "Terjadi kesalahan di server.");
    }
});

// --- BAGIAN CLOUD FUNCTIONS ---

/**
 * (Scheduled Trigger) - Berjalan setiap 30 menit untuk membersihkan
 * dokumen rental dan pembayaran yang "terbengkalai" (status pending).
 */
exports.cleanupPendingTransactions = onSchedule("every 30 minutes", async (event) => {
    logger.info("Menjalankan tugas terjadwal: Membersihkan transaksi pending yang terbengkalai...");

    const db = getFirestore();

    // Tentukan batas waktu. Dokumen yang dibuat sebelum waktu ini akan dianggap terbengkalai.
    // Kita set 30 menit yang lalu untuk memberikan cukup waktu bagi pengguna menyelesaikan pembayaran.
    const cutoffTime = new Date(Date.now() - 30 * 60 * 1000);
    const cutoffTimestamp = Timestamp.fromDate(cutoffTime);

    // Kita akan query koleksi 'payments' karena itu adalah titik awal dari sebuah transaksi.
    const paymentsRef = db.collection("payments");
    const query = paymentsRef
        .where("status", "==", "pending")
        .where("created_at", "<=", cutoffTimestamp);

    try {
        const snapshot = await query.get();
        if (snapshot.empty) {
            logger.info("Tidak ada transaksi pending yang terbengkalai ditemukan.");
            return null;
        }

        logger.warn(`Ditemukan ${snapshot.size} transaksi pending yang akan dibersihkan.`);

        // Gunakan Batch Write untuk melakukan beberapa operasi sekaligus secara efisien.
        const batch = db.batch();

        snapshot.forEach((doc) => {
            const paymentData = doc.data();
            const rentalId = paymentData.rental_id;

            logger.info(`- Menyiapkan pembersihan untuk payment: ${doc.id} dan rental: ${rentalId}`);

            // 1. Hapus dokumen pembayaran yang pending.
            batch.delete(doc.ref);

            // 2. Update status dokumen rental terkait menjadi 'cancelled'.
            // Ini lebih baik daripada menghapus, agar ada jejak riwayat.
            if (rentalId) {
                const rentalRef = db.collection("rentals").doc(rentalId);
                batch.update(rentalRef, {
                    status: "cancelled_unpaid",
                    payment_status: "expired"
                });
            }
        });

        // Jalankan semua operasi dalam batch.
        await batch.commit();
        logger.info(`Berhasil membersihkan ${snapshot.size} transaksi yang terbengkalai.`);
    } catch (error) {
        logger.error("Error saat membersihkan transaksi pending:", error);
    }

    return null;
});

/**
 * (Scheduled Trigger) - Berjalan setiap 1 menit untuk secara otomatis
 * menyelesaikan sewa yang statusnya 'pending_retrieval' terlalu lama.
 * Ini untuk kasus di mana pengguna sudah bayar denda dan mengambil barang,
 * tetapi lupa menekan tombol "Selesaikan Sewa".
 */
exports.autoFinishAbandonedRetrievals = onSchedule("every 1 minutes", async (event) => {
    logger.info("Menjalankan tugas terjadwal: Menyelesaikan sewa 'pending_retrieval' yang terlantar...");

    // Tentukan batas waktu. Sewa yang masuk ke status 'pending_retrieval'
    // sebelum waktu ini akan dianggap terlantar. Kita beri waktu 5 menit.
    const cutoffTime = new Date(Date.now() - 5 * 60 * 1000);
    const cutoffTimestamp = Timestamp.fromDate(cutoffTime);

    // Query untuk mencari semua dokumen rental yang memenuhi kriteria:
    // 1. Statusnya adalah 'pending_retrieval'.
    // 2. Waktu terakhir di-update (saat menjadi 'pending_retrieval') sudah lebih dari 30 menit yang lalu.
    const rentalsRef = db.collection("rentals");
    const query = rentalsRef
        .where("status", "==", "pending_retrieval")
        .where("updated_at", "<=", cutoffTimestamp);

    try {
        const snapshot = await query.get();
        if (snapshot.empty) {
            logger.info("Tidak ada sewa 'pending_retrieval' yang terlantar ditemukan.");
            return null; // Tidak ada yang perlu dilakukan, keluar dari fungsi.
        }

        logger.warn(`Ditemukan ${snapshot.size} sewa terlantar yang akan diselesaikan secara otomatis.`);

        // Kumpulkan semua promise update ke dalam sebuah array.
        const promises = [];
        snapshot.forEach((doc) => {
            const rentalId = doc.id;
            logger.info(`- Menyiapkan penyelesaian otomatis untuk rental ${rentalId}...`);

            // Aksi yang kita lakukan adalah mengubah statusnya menjadi 'finished'.
            // Perubahan ini akan secara otomatis memicu fungsi 'onRentalEnd'
            // untuk melakukan pembersihan loker (menghapus PIN, mengubah status loker, dll).
            const updatePromise = doc.ref.update({
                status: "finished",
                // Opsional: Tambahkan catatan bahwa ini diselesaikan oleh sistem.
                notes: "Sewa diselesaikan secara otomatis oleh sistem karena tidak aktif."
            });
            promises.push(updatePromise);
        });

        // Jalankan semua update secara bersamaan.
        await Promise.all(promises);
        logger.info(`Berhasil menyelesaikan ${snapshot.size} sewa yang terlantar.`);
    } catch (error) {
        logger.error("Error saat menjalankan tugas pembersihan 'pending_retrieval':", error);
    }

    return null;
});

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
    // 'amount' dari request sekarang hanya digunakan untuk 'extension_fee'.
    const { rentalId, paymentType, extensionInHours } = request.data;
    const amountFromRequest = request.data.amount;

    // Validasi paymentType
    if (!paymentType || !["initial_fee", "fine", "extension_fee"].includes(paymentType)) {
        throw new HttpsError("invalid-argument", "Parameter paymentType tidak valid.");
    }

    // Validasi extensionInHours untuk extension_fee
    if (paymentType === "extension_fee" && (!extensionInHours || typeof extensionInHours !== "number" || extensionInHours <= 0)) {
        throw new HttpsError("invalid-argument", "Untuk perpanjangan, 'extensionInHours' harus angka positif.");
    }

    // Validasi rentalId
    if (!rentalId || typeof rentalId !== "string") {
        logger.error("createTransaction: Missing or invalid rentalId.");
        throw new HttpsError("invalid-argument", "Parameter rentalId diperlukan dan harus string.");
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

    const rentalData = rentalDoc.data();

    // --- KOREKSI LOGIKA UTAMA DI SINI ---
    let transactionAmount;

    if (paymentType === "initial_fee") {
        // Untuk sewa awal, ambil biaya dari dokumen rental yang sudah dibuat oleh initiateRental.
        if (!rentalData.initial_cost || rentalData.initial_cost <= 0) {
            throw new HttpsError("failed-precondition", "Biaya sewa awal tidak valid pada data rental.");
        }
        transactionAmount = rentalData.initial_cost;
        logger.info(`Membuat transaksi sewa awal untuk rental ${rentalId} sebesar Rp${transactionAmount} (diambil dari server).`);
    } else if (paymentType === "extension_fee") {
        // --- PERUBAHAN UTAMA DIMULAI DI SINI ---

        // 1. Validasi input 'extensionInHours' dari client
        if (!extensionInHours || typeof extensionInHours !== "number" || extensionInHours <= 0) {
            throw new HttpsError("invalid-argument", "Untuk perpanjangan, 'extensionInHours' harus angka positif.");
        }

        // 2. Ambil harga per jam (hourly_rate) terbaru dari database
        const pricingRef = db.collection("config").doc("pricing");
        const pricingDoc = await pricingRef.get();
        if (!pricingDoc.exists || !pricingDoc.data().hourly_rate) {
            throw new HttpsError("internal", "Konfigurasi harga tidak ditemukan. Hubungi administrator.");
        }
        const hourlyRate = pricingDoc.data().hourly_rate;

        // 3. Hitung total biaya di server. Inilah langkah kuncinya.
        transactionAmount = hourlyRate * extensionInHours;

        logger.info(`Membuat transaksi perpanjangan untuk rental ${rentalId} selama ${extensionInHours} jam dengan tarif Rp${hourlyRate}/jam. Total: Rp${transactionAmount}`);
        // --- AKHIR PERUBAHAN UTAMA ---
    } else if (paymentType === "fine") {
        // Untuk denda, ambil dari Firestore.
        if (!rentalData.fine_amount || rentalData.fine_amount <= 0) {
            throw new HttpsError("failed-precondition", "Tidak ada denda yang perlu dibayar untuk sewa ini.");
        }
        transactionAmount = rentalData.fine_amount;
    }
    // --- AKHIR KOREKSI ---

    // Pengecekan ketersediaan loker hanya untuk initial_fee
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
            gross_amount: transactionAmount,
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
        const paymentPayload = {
            rental_id: rentalId,
            user_id: userId,
            midtrans_order_id: midtransOrderId,
            amount: transactionAmount,
            payment_type: paymentType,
            status: "pending",
            created_at: Timestamp.now(),
            updated_at: Timestamp.now(),
            response_data: transaction,
        };

        if (paymentType === "extension_fee") {
            paymentPayload.extension_in_hours = extensionInHours;
        }

        await paymentRef.set(paymentPayload);

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
                    const fiveMinutesLater = new Date(Date.now() + 5 * 60 * 1000);

                    // Update dokumen rental (ini sudah benar)
                    t.update(rentalRef, {
                        payment_status: "fine_paid",
                        status: "pending_retrieval",
                        encrypted_pin: encryptedTemporaryPin,
                        updated_at: Timestamp.now()
                    });

                    // --- KOREKSI DI SINI ---
                    // Update dokumen loker, sekarang dengan menambahkan kembali current_rental_id
                    t.update(lockerRef, {
                        active_pin: temporaryPin,
                        last_updated: Timestamp.now(),
                        status: "occupied", // Pastikan statusnya kembali 'occupied'
                        current_rental_id: paymentData.rental_id, // Ambil rental_id dari data pembayaran
                        pin_expiry: fiveMinutesLater,
                    });
                } else if (paymentType === "extension_fee" && rentalData.status === "active") {
                    logger.info(`Pembayaran perpanjangan untuk rental ${paymentData.rental_id} berhasil. Memperpanjang waktu...`);

                    // Ambil jumlah jam perpanjangan dari dokumen 'payments'.
                    const extensionInHours = paymentData.extension_in_hours;
                    if (!extensionInHours) {
                        throw new Error("Data 'extension_in_hours' tidak ditemukan pada dokumen pembayaran.");
                    }

                    // Ambil waktu selesai saat ini.
                    const currentEndTime = rentalData.expected_end_time.toDate();

                    // Hitung waktu selesai yang baru.
                    const extensionInMillis = extensionInHours * 60 * 60 * 1000;
                    const newEndTime = new Date(currentEndTime.getTime() + extensionInMillis);

                    // Update dokumen rental dengan waktu selesai yang baru.
                    t.update(rentalRef, {
                        expected_end_time: Timestamp.fromDate(newEndTime),
                        payment_status: "paid", // Set kembali ke 'paid' jika ada status lain
                        updated_at: Timestamp.now(),
                    });

                    // PENTING: Update juga pin_expiry di dokumen loker agar konsisten.
                    t.update(lockerRef, {
                        pin_expiry: Timestamp.fromDate(newEndTime),
                        last_updated: Timestamp.now(),
                    });

                    logger.info(`Waktu sewa untuk rental ${paymentData.rental_id} berhasil diperpanjang hingga ${newEndTime.toISOString()}`);
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
 * (Scheduled Trigger) - Berjalan setiap menit untuk memeriksa PIN sementara yang kedaluwarsa.
 */
exports.checkExpiredPins = onSchedule("every 1 minutes", async (event) => {
    logger.info("Menjalankan tugas terjadwal: Memeriksa PIN yang kedaluwarsa...");

    const now = Timestamp.now();
    const lockersRef = db.collection("lockers");

    // Query untuk mencari semua loker yang memiliki pin_expiry dan sudah terlewat.
    const query = lockersRef.where("pin_expiry", "<=", now);

    try {
        const snapshot = await query.get();
        if (snapshot.empty) {
            logger.info("Tidak ada PIN yang kedaluwarsa ditemukan.");
            return null;
        }

        const promises = [];
        snapshot.forEach((doc) => {
            const lockerId = doc.id;
            const lockerData = doc.data();
            const rentalId = lockerData.current_rental_id;

            logger.warn(`PIN untuk loker ${lockerId} (rental: ${rentalId}) telah kedaluwarsa! Menonaktifkan akses...`);

            // Siapkan update untuk menonaktifkan PIN di loker
            const lockerUpdatePromise = doc.ref.update({
                active_pin: null,
                pin_expiry: null // Hapus expiry setelah diproses
            });
            promises.push(lockerUpdatePromise);

            // Siapkan update untuk mengembalikan status rental ke 'locked_due_to_fine'
            if (rentalId) {
                const rentalRef = db.collection("rentals").doc(rentalId);
                const rentalUpdatePromise = rentalRef.update({
                    encrypted_pin: null, // Hapus PIN dari rental juga
                });
                promises.push(rentalUpdatePromise);
            }
        });

        await Promise.all(promises);
        logger.info(`Berhasil memproses ${snapshot.size} PIN yang kedaluwarsa.`);
    } catch (error) {
        logger.error("Error saat memeriksa PIN yang kedaluwarsa:", error);
    }
    return null;
});

/**
 * Terpicu saat dokumen rental selesai.
 */
exports.onRentalEnd = onDocumentUpdated("rentals/{rentalId}", async (event) => {
    const afterData = event.data.after.data();
    const beforeData = event.data.before.data();

    // --- KONDISI 1: SEWA SELESAI TEPAT WAKTU ---
    // Ini berjalan jika pengguna menyelesaikan sewa (active -> finished) DAN
    // fungsi calculateFineOnFinish menentukan tidak ada denda (fine_amount: 0).
    if (beforeData.status === "active" && afterData.status === "finished" && afterData.fine_amount === 0) {
        logger.info(`Rental ${event.params.rentalId} selesai tepat waktu. Mereset loker...`);

        const lockerId = afterData.locker_id;
        if (!lockerId) { return; }
        const lockerRef = db.collection("lockers").doc(lockerId);

        // Lakukan reset total: loker menjadi tersedia untuk pengguna lain.
        await lockerRef.update({
            status: "available",
            active_pin: null,
            pin_expiry: null,
            current_rental_id: null,
            last_updated: Timestamp.now(),
        });

        // --- KOREKSI DI SINI ---
        // Hapus encrypted_pin HANYA di dalam kondisi ini.
        await event.data.after.ref.update({ encrypted_pin: null });
        logger.info(`Loker ${lockerId} berhasil direset.`);
    }
    // --- KONDISI 2: SELESAI SETELAH MENGAMBIL BARANG (PASCA-DENDA) ---
    // Ini berjalan jika pengguna membuka loker dengan PIN sementara, yang mengubah
    // status dari 'pending_retrieval' menjadi 'finished'.
    else if (beforeData.status === "pending_retrieval" && afterData.status === "finished") {
        logger.info(`Rental ${event.params.rentalId} selesai setelah pengambilan barang. Mereset loker...`);

        const lockerId = afterData.locker_id;
        if (!lockerId) { return; }
        const lockerRef = db.collection("lockers").doc(lockerId);

        // Lakukan reset total yang sama.
        await lockerRef.update({
            status: "available",
            active_pin: null,
            pin_expiry: null,
            current_rental_id: null,
            last_updated: Timestamp.now(),
        });

        // --- KOREKSI DI SINI ---
        // Hapus encrypted_pin HANYA di dalam kondisi ini juga.
        await event.data.after.ref.update({ encrypted_pin: null });
        logger.info(`Loker ${lockerId} berhasil direset.`);
    }
});

/**
 * (Scheduled Trigger - "Polisi Denda")
 * Berjalan setiap 5 menit untuk secara otomatis menerapkan denda pada sewa yang kedaluwarsa.
 * FUNGSI INI SEKARANG MENJADI OTORITAS UTAMA UNTUK PENERAPAN DENDA.
 */
exports.checkExpiredRentals = onSchedule("every 1 minutes", async (event) => {
    logger.info("Menjalankan tugas terjadwal: Memeriksa sewa yang kedaluwarsa...");

    const db = getFirestore();
    const now = Timestamp.now();
    const rentalsRef = db.collection("rentals");

    // Query untuk mencari semua dokumen rental yang aktif dan sudah melewati expected_end_time.
    const query = rentalsRef
        .where("status", "==", "active")
        .where("expected_end_time", "<=", now);

    try {
        const snapshot = await query.get();
        if (snapshot.empty) {
            logger.info("Tidak ada sewa aktif yang kedaluwarsa ditemukan.");
            return null;
        }

        logger.warn(`Ditemukan ${snapshot.size} sewa kedaluwarsa yang akan diproses.`);

        const promises = [];
        snapshot.forEach((doc) => {
            const rentalData = doc.data();
            const rentalId = doc.id;

            // --- LOGIKA DARI 'calculateFineOnFinish' DIPINDAHKAN KE SINI ---
            const initialCost = rentalData.initial_cost;
            if (initialCost === undefined || typeof initialCost !== "number") {
                logger.error(`Rental ${rentalId} tidak memiliki 'initial_cost' yang valid. Melewati...`);
                return; // Lanjut ke dokumen berikutnya
            }

            const calculatedFine = 1.5 * initialCost; // Atau 1.5 * initialCost sesuai aturan Anda
            logger.info(`Rental ${rentalId} kedaluwarsa. Menerapkan denda: ${calculatedFine} dan menonaktifkan PIN...`);

            const lockerRef = db.collection("lockers").doc(rentalData.locker_id);

            // Siapkan update untuk rental dan loker dalam satu batch per dokumen
            const rentalUpdatePromise = doc.ref.update({
                fine_amount: calculatedFine,
                payment_status: "unpaid_fine",
                status: "locked_due_to_fine",
                actual_end_time: now,
                notes: "Denda diterapkan secara otomatis oleh sistem."
            });

            const lockerUpdatePromise = lockerRef.update({
                active_pin: null
            });

            promises.push(rentalUpdatePromise, lockerUpdatePromise);
            // --- AKHIR LOGIKA YANG DIPINDAHKAN ---
        });

        // Jalankan semua update secara bersamaan.
        await Promise.all(promises);
        logger.info(`Berhasil memproses ${snapshot.size} sewa yang kedaluwarsa.`);
    } catch (error) {
        logger.error("Error saat menjalankan tugas pemeriksaan sewa kedaluwarsa:", error);
    }

    return null;
});

/**
 * (Background Trigger - "Petugas Selesai Tepat Waktu")
 * Terpicu saat pengguna menekan "Selesaikan Sewa".
 * TUGASNYA SEKARANG JAUH LEBIH SEDERHANA.
 */
exports.calculateFineOnFinish = onDocumentUpdated("rentals/{rentalId}", async (event) => {
    const afterData = event.data.after.data();
    const beforeData = event.data.before.data();

    // Kondisi pemicu tetap sama: hanya berjalan saat pengguna secara manual
    // mengubah status dari 'active' menjadi 'finished'.
    if (beforeData.status === "active" && afterData.status === "finished") {
        // Karena scheduler sudah menangani kasus terlambat, kita bisa asumsikan
        // jika fungsi ini berjalan, pengguna pasti tepat waktu.
        // Pengecekan waktu di sini menjadi lapisan pengaman kedua (best practice).
        const expectedEndTime = afterData.expected_end_time.toDate();
        const actualEndTime = afterData.actual_end_time.toDate();

        if (actualEndTime < expectedEndTime) {
            // Pengguna selesai tepat waktu.
            logger.info(`Rental ${event.params.rentalId} selesai tepat waktu. Tidak ada denda.`);
            // Cukup set denda menjadi 0. Perubahan ini akan memicu onRentalEnd.
            await event.data.after.ref.update({ fine_amount: 0 });
        } else {
            // Blok ini seharusnya jarang sekali berjalan, karena scheduler sudah menangani kasus ini.
            // Ini berfungsi sebagai fallback jika scheduler gagal berjalan tepat waktu.
            logger.warn(`calculateFineOnFinish mendeteksi keterlambatan untuk rental ${event.params.rentalId}. Seharusnya ini ditangani oleh scheduler.`);
            // Biarkan saja, karena scheduler akan menanganinya di siklus berikutnya.
        }
    }
});

/**
 * Cloud Function untuk memperpanjang waktu sewa loker.
 * Memerlukan data: { rentalId: string, extensionInHours: number }
 */
// exports.extendRentalTime = onCall({ region: "asia-southeast2" }, async (request) => {
//     const db = getFirestore();

//     // 1. Validasi Panggilan (Guard Clauses)
//     // Di v2, context.auth diakses melalui request.auth
//     if (!request.auth) {
//         throw new HttpsError("unauthenticated", "Anda harus login untuk melakukan aksi ini.");
//     }

//     const { rentalId, extensionInHours } = request.data; // Data ada di dalam request.data

//     if (!rentalId || typeof rentalId !== "string") {
//         throw new HttpsError("invalid-argument", "ID Rental tidak valid.");
//     }
//     if (!extensionInHours || typeof extensionInHours !== "number" || extensionInHours <= 0) {
//         throw new HttpsError("invalid-argument", "Jumlah jam perpanjangan harus angka positif.");
//     }

//     // 2. & 3. Pengambilan Data, Verifikasi Kepemilikan dan Aturan
//     try {
//         const rentalRef = db.collection("rentals").doc(rentalId);
//         const rentalDoc = await rentalRef.get();

//         if (!rentalDoc.exists) {
//             throw new HttpsError("not-found", "Data sewa tidak ditemukan.");
//         }

//         const rentalData = rentalDoc.data();
//         const loggedInUid = request.auth.uid; // UID pengguna ada di request.auth.uid

//         if (rentalData.user_id.trim() !== loggedInUid) {
//             throw new HttpsError("permission-denied", "Anda tidak memiliki izin untuk memperpanjang sewa ini.");
//         }

//         const currentEndTime = rentalData.expected_end_time.toDate();
//         const now = new Date(); // Waktu server saat ini

//         if (now >= currentEndTime) {
//             throw new HttpsError("failed-precondition", "Waktu sewa sudah habis dan tidak dapat diperpanjang.");
//         }

//         // 4. Eksekusi Perpanjangan Waktu
//         const extensionInMillis = extensionInHours * 60 * 60 * 1000;
//         const newEndTime = new Date(currentEndTime.getTime() + extensionInMillis);

//         // Gunakan Timestamp yang sudah di-import dari 'firebase-admin/firestore'
//         await rentalRef.update({
//             expected_end_time: Timestamp.fromDate(newEndTime)
//         });

//         // 5. Kirim Respons Sukses
//         return {
//             success: true,
//             message: "Waktu sewa berhasil diperpanjang!",
//             newEndTime: newEndTime.toISOString(),
//         };
//     } catch (error) {
//         logger.error("Error extending rental time:", error); // Gunakan logger dari 'firebase-functions/logger'
//         if (error instanceof HttpsError) {
//             throw error;
//         }
//         throw new HttpsError("internal", "Terjadi kesalahan di server.");
//     }
// });

/**
 * (API untuk Hardware) - Dipanggil oleh ESP32 ketika sensor PIR mendeteksi gerakan.
 * Fungsi ini akan mencari pengguna terkait dan semua admin, lalu mengirim notifikasi.
 * Memerlukan data: { lockerId: string, esp32_id: string }
 */
exports.reportSuspiciousMotion = onRequest(async (request, response) => {
    // Langkah 1: Validasi request dari ESP32
    const { lockerId, esp32_id } = request.body;
    if (!lockerId || !esp32_id) {
        return response.status(400).send("Parameter lockerId dan esp32_id diperlukan.");
    }

    logger.warn(`Gerakan terdeteksi di loker ${lockerId} dari ESP32 ${esp32_id}! Memulai proses notifikasi...`);

    try {
        // Validasi bahwa ESP32 ini sah untuk loker tersebut
        const lockerRef = db.collection("lockers").doc(lockerId);
        const lockerDoc = await lockerRef.get();
        if (!lockerDoc.exists || lockerDoc.data().esp32_id !== esp32_id) {
            throw new Error(`Akses ditolak: ESP32 ${esp32_id} tidak sah untuk loker ${lockerId}.`);
        }

        const lockerData = lockerDoc.data();
        const rentalId = lockerData.current_rental_id;

        // Siapkan daftar penerima notifikasi
        const recipients = [];

        // Langkah 2: Cari pengguna yang sedang menyewa loker tersebut
        if (rentalId) {
            const rentalRef = db.collection("rentals").doc(rentalId);
            const rentalDoc = await rentalRef.get();
            if (rentalDoc.exists) {
                recipients.push(rentalDoc.data().user_id);
            }
        }

        // Langkah 3: Cari semua admin
        const listUsersResult = await getAuth().listUsers(1000);
        listUsersResult.users.forEach((userRecord) => {
            if (userRecord.customClaims && userRecord.customClaims.admin === true) {
                // Hindari duplikasi jika admin adalah penyewa loker
                if (!recipients.includes(userRecord.uid)) {
                    recipients.push(userRecord.uid);
                }
            }
        });

        if (recipients.length === 0) {
            logger.warn(`Tidak ditemukan penerima notifikasi untuk loker ${lockerId}.`);
            return response.status(200).send("Gerakan terdeteksi, tetapi tidak ada penerima.");
        }

        // Langkah 4: Kirim notifikasi ke semua penerima
        const notificationPayload = {
            title: "Peringatan Keamanan Loker!",
            body: `Terdeteksi gerakan mencurigakan di dekat Loker ${lockerId}.`,
            locker_id: lockerId,
            type: "SECURITY_ALERT",
            timestamp: Timestamp.now(),
            is_read: false
        };

        const promises = recipients.map(async (uid) => {
            // 4a. Simpan notifikasi ke Firestore untuk riwayat
            await db.collection("notifications").add({
                user_id: uid, // Target notifikasi
                ...notificationPayload
            });

            // 4b. Kirim Push Notification (FCM)
            // Ambil FCM token dari dokumen user (ini harus disimpan oleh aplikasi Flutter)
            const userDoc = await db.collection("users").doc(uid).get();
            if (userDoc.exists && userDoc.data().fcmToken) {
                const fcmToken = userDoc.data().fcmToken;
                const message = {
                    notification: {
                        title: notificationPayload.title,
                        body: notificationPayload.body,
                    },
                    token: fcmToken,
                    // Anda bisa menambahkan data lain di sini jika perlu
                    data: { lockerId: lockerId }
                };
                await getMessaging().send(message);
            }
        });

        await Promise.all(promises);
        logger.info(`Berhasil mengirim ${recipients.length} notifikasi untuk loker ${lockerId}.`);
        return response.status(200).send("Notifikasi berhasil dikirim.");
    } catch (error) {
        logger.error(`Gagal memproses notifikasi gerakan untuk loker ${lockerId}:`, error);
        return response.status(500).send("Terjadi kesalahan di server.");
    }
});

