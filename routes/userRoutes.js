const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const router = express.Router();
const jwtSecret = process.env.JWT_SECRET;

// ✅ Registro de Usuário
router.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: "❌ Usuário e senha são obrigatórios!" });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ message: "❌ Nome de usuário já está em uso!" });
    }

    const newUser = new User({ username, password });
    await newUser.save();

    res.status(201).json({ message: "✅ Usuário registrado com sucesso!" });
  } catch (error) {
    console.error("❌ Erro ao registrar usuário:", error);
    res.status(500).json({ message: "❌ Erro interno ao registrar usuário." });
  }
});

// ✅ Login de Usuário
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "❌ Usuário ou senha incorretos." });
    }

    const token = jwt.sign({ username: user.username, id: user._id }, jwtSecret, { expiresIn: "1h" });
    res.json({ message: "✅ Login bem-sucedido!", token });
  } catch (error) {
    console.error("❌ Erro ao realizar login:", error);
    res.status(500).json({ message: "❌ Erro interno no login." });
  }
});

// ✅ Perfil do Usuário (Rota Protegida)
router.get("/profile", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ message: "❌ Acesso negado! Token não encontrado." });
    }

    const decoded = jwt.verify(token, jwtSecret);
    const user = await User.findById(decoded.id).select("-password"); // Remove a senha dos dados retornados

    if (!user) {
      return res.status(404).json({ message: "❌ Usuário não encontrado." });
    }

    res.json(user);
  } catch (error) {
    console.error("❌ Erro ao buscar perfil do usuário:", error);
    res.status(500).json({ message: "❌ Erro interno ao buscar perfil." });
  }
});

module.exports = router;
