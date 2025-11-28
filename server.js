require("dotenv").config();
const express = require("express");
const cors = require("cors");
const db = require("./db.js"); // modul db untuk menghubungkan ke database neon nya
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;
const { authenticateToken, authorizeRole } = require("./middleware/auth.js");
const app = express();
const PORT = process.env.PORT || 3300;

app.use(cors());
app.use(express.json());

// === RUTE STATUS ===
app.get("/status", (req, res) => {
  res.json({ ok: true, service: "api-warungklontong" });
});

// === AUTH RUTES ===

// POST: Register User Biasa
app.post("/auth/register", async (req, res, next) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 6) {
    return res
      .status(400)
      .json({ error: "Username dan password (min 6 char) harus diisi" });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const sql =
      "INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username";
    const result = await db.query(sql, [
      username.toLowerCase(),
      hashedPassword,
      "user",
    ]);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      // Kode error unik PostgreSQL (Unique violation)
      return res.status(409).json({ error: "Username sudah digunakan" });
    }
    next(err);
  }
});

// POST: Register Admin
app.post("/auth/register-admin", async (req, res, next) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 6) {
    return res
      .status(400)
      .json({ error: "Username dan password (min 6 char) harus diisi" });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const sql =
      "INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username";
    const result = await db.query(sql, [
      username.toLowerCase(),
      hashedPassword,
      "admin",
    ]);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Username sudah digunakan" });
    }
    next(err);
  }
});

// POST: Login
app.post("/auth/login", async (req, res, next) => {
  const { username, password } = req.body;
  try {
    const sql = `SELECT * FROM users WHERE username=$1`;
    const result = await db.query(sql, [username.toLowerCase()]);
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: "Kredensial tidak valid" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Kredensial tidak valid" });
    }
    const payload = {
      user: { id: user.id, username: user.username, role: user.role },
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
    res.json({ message: "Login berhasil", token: token });
  } catch (err) {
    next(err);
  }
});

// === RUTE PRODUK (CRUD PostgreSQL) ===

// GET: Semua produk
app.get("/produk", async (req, res, next) => {
  const sql = `
    SELECT kd_produk, nm_brg, hrg, ket_stok
    FROM produk
    ORDER BY kd_produk ASC
    `;
  try {
    const result = await db.query(sql);
    res.json(result.rows);
  } catch (err) {
    next(err);
  }
});

// GET: Produk berdasarkan Kode Produk
app.get("/produk/:kd_produk", async (req, res, next) => {
  const sql = `
    SELECT kd_produk, nm_brg, hrg, ket_stok
    FROM produk
    WHERE kd_produk = $1
    `;
  try {
    const result = await db.query(sql, [req.params.kd_produk.toUpperCase()]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Produk tidak ditemukan" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

// POST: Menambahkan produk baru (Hanya untuk pengguna terautentikasi)
app.post("/produk", authenticateToken, async (req, res, next) => {
  // Menggunakan nm_brg sesuai skema DB Anda
  const { kd_produk, nm_brg, hrg, ket_stok } = req.body; // Validasi input wajib

  if (!kd_produk || !nm_brg || !hrg || !ket_stok) {
    return res
      .status(400)
      .json({ error: "kd_produk, nm_brg, hrg, dan ket_stok wajib diisi." });
  } // Validasi stok

  if (ket_stok !== "ada" && ket_stok !== "habis") {
    return res
      .status(400)
      .json({ error: "ket_stok harus 'ada' atau 'habis'." });
  } // Menggunakan nm_brg di query SQL

  const sql =
    `INSERT INTO produk (kd_produk, nm_brg, hrg, ket_stok) VALUES ($1, $2, $3, $4) RETURNING *`;
  try {
    const result = await db.query(sql, [
      kd_produk.toUpperCase(),
      nm_brg, // Variabel yang benar: nm_brg
      hrg,
      ket_stok,
    ]);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    // Menangani error jika kd_produk sudah ada (Unique violation)
    if (err.code === "23505") {
      return res.status(409).json({ error: "Kode produk sudah digunakan" });
    }
    next(err);
  }
});

// PUT: Memperbarui produk yang sudah ada (Hanya untuk Admin)
app.put(
  "/produk/:kd_produk",
  [authenticateToken, authorizeRole("admin")],
  async (req, res, next) => {
    // Menggunakan nm_barang di destructring karena ini adalah nama field dari req.body
    // Anda harus memastikan klien mengirim 'nm_brg' atau 'nm_barang' di body.
    // Saya asumsikan klien mengirim 'nm_barang' (karena kode Anda memakainya)
    // Namun, jika klien menggunakan nama kolom DB, maka harusnya nm_brg.
    // Saya ubah variabel di sini ke nm_brg agar konsisten dengan DB.
    const { nm_brg, hrg, ket_stok } = req.body;
    const kdProduk = req.params.kd_produk.toUpperCase(); // Validasi stok jika ada

    if (ket_stok && ket_stok !== "ada" && ket_stok !== "habis") {
      return res
        .status(400)
        .json({ error: "ket_stok harus 'ada' atau 'habis'." });
    } // Periksa apakah ada field yang diisi untuk diupdate

    if (
      nm_brg === undefined && // Variabel diubah ke nm_brg
      hrg === undefined &&
      ket_stok === undefined
    ) {
      return res.status(400).json({
        error:
          "Setidaknya satu field (nm_brg, hrg, atau ket_stok) harus diisi untuk update.",
      });
    }

    let updateFields = [];
    let queryParams = [];
    let paramCounter = 1;

    if (nm_brg !== undefined) {
      // Cek variabel nm_brg
      updateFields.push(`nm_brg = $${paramCounter++}`); // Nama kolom DB: nm_brg
      queryParams.push(nm_brg);
    }
    if (hrg !== undefined) {
      updateFields.push(`hrg = $${paramCounter++}`);
      queryParams.push(hrg);
    }
    if (ket_stok !== undefined) {
      updateFields.push(`ket_stok = $${paramCounter++}`);
      queryParams.push(ket_stok);
    }

    const sql = `
        UPDATE produk SET ${updateFields.join(", ")} 
        WHERE kd_produk = $${paramCounter} 
        RETURNING *`;

    queryParams.push(kdProduk);

    try {
      const result = await db.query(sql, queryParams);
      if (result.rowCount === 0) {
        return res
          .status(404)
          .json({ error: "Produk tidak ditemukan untuk diperbarui." });
      }
      res.json(result.rows[0]);
    } catch (err) {
      next(err);
    }
  }
);

// DELETE: Menghapus produk (Hanya untuk Admin)
app.delete(
  "/produk/:kd_produk",
  [authenticateToken, authorizeRole("admin")],
  async (req, res, next) => {
    const kdProduk = req.params.kd_produk.toUpperCase();
    const sql = "DELETE FROM produk WHERE kd_produk = $1 RETURNING *";
    try {
      const result = await db.query(sql, [kdProduk]);
      if (result.rowCount === 0) {
        return res
          .status(404)
          .json({ error: "Produk tidak ditemukan untuk dihapus." });
      }
      res.status(204).send(); // 204 No Content
    } catch (err) {
      next(err);
    }
  }
);

// === RUTE UTAMA & FALLBACK ===

app.get("/", (req, res) => {
  res.send("API Warung Klontong berjalan. Akses /produk untuk data produk.");
});

app.use((req, res) => {
  res.status(404).json({ error: "Rute tidak ditemukan" });
});

app.use((err, req, res, next) => {
  console.error("[SERVER ERROR]", err.stack);
  res.status(500).json({ error: "Terjadi kesalahan pada server" });
});

// Menjalankan server
app.listen(PORT, () => {
  console.log(`API Warung Klontong berjalan di http://localhost:${PORT}`);
});