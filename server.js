// 🚀 Servidor Backend - Configurado para Render e Netlify

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const User = require("./models/User"); // Importando o modelo diretamente

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ✅ Configuração do MongoDB
const mongoURI = process.env.MONGO_URI;
const jwtSecret = process.env.JWT_SECRET;

mongoose.connect(mongoURI)
  .then(() => console.log("✅ Conectado ao MongoDB!"))
  .catch((err) => {
    console.error("❌ Erro na conexão:", err);
    process.exit(1); // Encerra a aplicação se não conectar ao banco
  });

// ✅ Middleware de autenticação JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "❌ Acesso negado! Token não encontrado." });
  }

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) {
      console.error("❌ Erro ao validar token:", err);
      return res.status(403).json({ message: "❌ Token inválido!" });
    }
    req.user = user;
    next();
  });
}

// ✅ Rotas de Usuário
const userRoutes = require("./routes/userRoutes");
app.use("/api/users", userRoutes);

// ✅ Rotas de opiniões
const opinioesRoute = require("./routes/opinioes");
app.use("/api/opinioes", opinioesRoute);

// ✅ Configuração correta da porta para Render
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`🚀 Servidor rodando na porta ${port}`);
  console.log(`🔗 Acesse a API em: https://backend-goaq.onrender.com`);
});
