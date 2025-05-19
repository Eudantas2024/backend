// Aqui é a central onde todos os comandos são conectados e formam o Servidor.

require("dotenv").config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(bodyParser.json());

const mongoURI = process.env.MONGO_URI;
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET;

mongoose.connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("✅ Conectado ao MongoDB!"))
  .catch(err => console.error("❌ Erro na conexão:", err));

const userSchema = new mongoose.Schema({
    username: String,
    password: String
});  


const User = mongoose.model("User", userSchema);

// ✅ Middleware para verificar token
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Pega apenas o token sem "Bearer"

    if (!token) return res.status(401).json({ message: "❌ Acesso negado! Token não encontrado." });

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.status(403).json({ message: "❌ Token inválido!" });
        req.user = user;
        next();
    });
}

// ✅ Rota de conteúdo protegido (corrigida)
app.get("/conteudo", authenticateToken, (req, res) => {
    res.json({ message: "✅ Bem-vindo à área restrita!", user: req.user });
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(401).json({ message: "❌ Acesso negado! Token não encontrado." });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "❌ Token inválido!" });
        req.user = user;
        next();
    });
}


// ✅ Rota de Registro com senha criptografada
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

// ✅ Rota de Login com geração de token JWT
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: "1h" });

        res.json({ message: "✅ Login bem-sucedido!", token });
    } else {
        res.status(401).json({ message: "❌ Usuário ou senha incorretos." });
    }
});

const opinioesRoute = require('./routes/opinioes');
app.use('/api/opinioes', opinioesRoute);

// ✅ Servidor rodando
app.listen(port, () => {
    console.log(`🚀 Servidor rodando na porta ${port}`);
});
