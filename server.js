const {createServer} = require("http"),
  {readFileSync} = require("fs"),
  {DatabaseSync} = require("node:sqlite"),
  db = new DatabaseSync(":memory:"),
  {argon2Sync, randomBytes} = require("crypto");


// Avec MYSQL :

// CREATE TABLE IF NOT EXISTS users (
//   id INT AUTO_INCREMENT NOT NULL PRIMARY KEY,
//   email VARCHAR(100) NOT NULL,
//   password VARCHAR(500) NOT NULL
// );

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(500) NOT NULL
  );
`);

setInterval(() => console.log(db.prepare("SELECT * FROM users;").all()), 10_000);

const createUserReq = db.prepare("INSERT INTO users (email, password) VALUES (?, ?);"),
  getUserByEmailReq = db.prepare("SELECT * FROM users WHERE email = ?;"),
  chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789&é~\"#'{([-|è`_\\ç^à@°)]=+}¨£$¤%²ùµ*?,.;/:§!<>",
  blacklist = [
    "zyxwvutsrqponmlkjihgfedcba",
    "ZYXWVUTSRQPONMLKJIHGFEDCBA",
    "abcde0123456789",
    "9876543210abcd",
    "admin",
    "motdepasse",
    "password",
    "unsupermotdepasse"
  ].map(pwd => pwd.toLowerCase());

/**
 * @param {string} password 
 * @returns {true | string}
 */
function checkPasswordCNIL(password) {
  if (password.split("").filter(char => !chars.includes(char)).length !== 0)
    return `Le mot de passe contient un caractère invalide, la liste des caractères acceptées est :\n\n${chars}`
  if (Math.log2(chars.length ** password.length) < 80) return "Entropie du mot de passe trop faible (< 80), augmenter le nombre de caractères";
  if (!/[a-z]/.test(password)) return "Le mot de passe doit inclure une minuscule"
  if (!/[A-Z]/.test(password)) return "Le mot de passe doit inclure une majuscule"
  if (!/\d/.test(password)) return "Le mot de passe doit inclure un chiffre"
  if (!/[&é~\"#'{([-|è`_\\ç^à@°)\]=+}¨£$¤%ùµ*?,.;/:§!<></>]/.test(password)) return "Le mot de passe doit inclure un symbole"

  if (
    blacklist.includes(password.toLowerCase()) /* Mdp défini comme interdit */ ||
    chars.toLowerCase().includes(password.toLowerCase()) /* Évite certains mdp simple comme abc, 123, ... */
  ) return "Mot de passe trop simple"

  if (password.trim() !== password) return "Le mot de passe ne doit pas commencer ou terminer par un espace"

  return true;
}

/**
 * Renvoi le hash d'un mot de passe avec les paramètres utilisés
 * @param {string} password 
 * @param {Omit<import.Argon2Parameters, "message" | "nonce">} parameters 
 * @returns {Promise<string>}
 */
function hashPassword(password, parameters) {
  return new Promise((resolve, reject) => {
    const nonce = randomBytes(16),
      algorithm = "argon2id";

    try {
      const hash = argon2Sync(algorithm, {
        ...parameters,
        nonce,
        message: password,
      }).toString("hex");

      resolve(
        `algo=${algorithm}$nonce=${nonce.toString("hex")}$${Object.entries(
          parameters,
        )
          .map(([k, v]) => `${k}=${v}$`)
          .join("")}hash=${hash}`,
      );
    } catch (error) {
      reject(error);
    }
  });
}

createServer((req, res) => {  
  if (req.url === "/") res.end(readFileSync("./index.html"));
  else if (req.url === "/inscription" && req.method === "POST") {
    let data = "";
    
    req.on("data", chunk => data += chunk).on("end", () => {
      const params = new URLSearchParams(data), email = params.get("email"), password = params.get("password");

      if (!email || !password)
        return res.writeHead(400, { "content-type": "text/plain; charset=utf8" }).end("Mot de passe ou email vide");

      if (getUserByEmailReq.get(email)) return res.writeHead(400, { "content-type": "text/plain; charset=utf8" }).end("Email déjà utilisée");

      const isValidPwd = checkPasswordCNIL(password);

      if (isValidPwd !== true) return res.writeHead(400, { "content-type": "text/plain; charset=utf8" }).end(isValidPwd); 

      hashPassword(password, {parallelism: 2, tagLength: 64, memory: 65536, passes: 3})
        .then(hash => {
          try {
            createUserReq.run(email, hash);

            return res.writeHead(200, { "content-type": "text/plain; charset=utf8" }).end("Compte créé")
          } catch (error) {
            console.error(error);
        
            return res.writeHead(500, { "content-type": "text/plain; charset=utf8" }).end("Erreur lors de la création du compte")
          }
        })
        .catch(reason => {
          console.error(reason);
        
          return res.writeHead(500, { "content-type": "text/plain; charset=utf8" }).end("Erreur lors de la création du compte")
        })
    })
  } else res.end();
}).listen(8080, () => console.log("http://localhost:8080"));