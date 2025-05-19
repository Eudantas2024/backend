// 🚀 Servidor Backend - Configurado para Render e Netlify

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// 🔗 Importação do modelo User
const User = require("./models/User"); // Certifique-se de que o caminho está correto

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ✅ Configuração do MongoDB
const mongoURI = process.env.MONGO_URI;
const jwtSecret = process.env.JWT_SECRET;

mongoose
  .connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ Conectado ao MongoDB!"))
  .catch((err) => console.error("❌ Erro na conexão:", err));

// ✅ Middleware de autenticação JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ message: "❌ Acesso negado! Token não encontrado." });

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) return res.status(403).json({ message: "❌ Token inválido!" });
    req.user = user;
    next();
  });
}

// ✅ Rota de Conteúdo Protegido
app.get("/conteudo", authenticateToken, (req, res) => {
  res.json({ message: "✅ Bem-vindo à área restrita!", user: req.user });
});

// ✅ Rota de Registro de Usuário
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "❌ Usuário e senha são obrigatórios!" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, password: hashedPassword });

  await newUser.save();
  res.json({ message: "✅ Usuário registrado com sucesso!" });
});

// ✅ Rota de Login com geração de Token JWT
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (user && (await bcrypt.compare(password, user.password))) {
    const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: "1h" });

    res.json({ message: "✅ Login bem-sucedido!", token });
  } else {
    res.status(401).json({ message: "❌ Usuário ou senha incorretos." });
  }
});

// ✅ Rotas de opiniões
const opinioesRoute = require("./routes/opinioes");
app.use("/api/opinioes", opinioesRoute);

// ✅ Configuração correta da porta para Render
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`🚀 Servidor rodando na porta ${port}`);
  console.log(`🔗 Acesse a API em: https://backend-yv4g.onrender.com`);
});
