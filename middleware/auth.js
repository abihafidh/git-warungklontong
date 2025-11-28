const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) {
    return res
      .status(401)
      .json({ error: "Akses ditolak, token tidak ditemukan" });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedPayload) => {
    if (err) {
      console.error("JWT Verify Error:", err.message);
      return res
        .status(403)
        .json({ error: "Token tidak valid atau kedaluwarsa" });
    }
    req.user = decodedPayload.user;
    next();
  });
}

// Middleware otorisasi berdasarkan role
function authorizeRole(role) {
  return (req, res, next) => {
    // Middleware ini harus dijalankan SETELAH authenticateToken
    if (req.user && req.user.role === role) {
      next(); // Peran cocok, lanjutkan
    } else {
      // Pengguna terautentikasi, tetapi tidak memiliki izin
      return res.status(403).json({ error: "Akses Dilarang: Peran tidak memadai" });
    }
  };
}

module.exports = {
  authenticateToken,
  authorizeRole,
};
