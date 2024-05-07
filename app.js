const express = require("express");
const jwt = require("jsonwebtoken");
const session = require("express-session");

const { hashedSecret } = require("./crypto/config");


const app = express();
const PORT = 3001;

app.use(express.urlencoded({ extended: true}));
app.use(express.json());

const { users } = require("./data/users");

// Configuración de sesiones
app.use(
  session({
    secret: hashedSecret,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  })
);

app.get("/", (req, res) => {
  const loginForm = `
  <form action="/login" method="post">
    <label for="username">Usuario:</label>
    <input type="text" id="username" name="username"</br>

    <label for="password">Contraseña:</label>
    <input type="password" id="password" name="password"</br>

    <button type="submit">Iniciar sesión</button>
  </form>
  <a href="/dashboard">dashboard del usuario logeado</a>
`;
    res.send(loginForm);
  
});

//Generar el token
function generateToken(user) {
    return jwt.sign({user: user.id}, hashedSecret , {expiresIn: '1h'})
}

//generar verificacion
function verifyToken (req,res,next) {
    const token = req.session.token
    if(!token)  {
        return res.status(401).json({mensaje: 'token no generado'})
    }

    jwt.verify(token, hashedSecret, (err, decoded) => {
        if(err) {
            return res.status(401).json({mensaje: 'token invalido'});
        }
        req.user = decoded.user;
        next();       
    })
}

app.get('/dashboard', verifyToken, (req, res) => {
    const userId = req.user;
    const user = users.find(user => user.id === userId)
    if(user) {
        res.send(`
            <h1>Bienvenido, ${user.name}</h1>
            <p>ID: ${user.id}</p>
            <p>Nombre de usuario: ${user.username}</p>
            <a href="/">HOME</a>
            <form action="/logout" method="post">
            <button type="submit">Cerrar sesion</button>
            </form> 
        `)
    } else {
        return res.status(401).json({mensaje: 'Usuario no encontrado'});
    }
});

//LOGIN
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(
    (user) => user.username === username && user.password === password
  );
  if(user) {
    const token = generateToken(user)
    req.session.token = token;
    res.redirect('/dashboard')
  } else {
    res.status(401).json({mensaje: 'Credencionales incorrectos'})
  }
});

app.post('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/')
})


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
