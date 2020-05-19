"use strict";
const path = require("path");
const bcrypt = require("bcrypt");
const { Database } = require("sqlite3").verbose();
const db = new Database(path.join(__dirname, "..", "secrets.db"));
const saltRounds = 5;

const queries = {
  tableUsers: `
    CREATE  TABLE IF NOT EXISTS users (
      user TEXT PRIMARY KEY,
      password TEXT NOT NULL
    )
  `,
  tableSecrets: `
    CREATE  TABLE IF NOT EXISTS secrets (
      user  TEXT,
      name  TEXT NOT NULL,
      value TEXT NOT NULL,
      PRIMARY KEY (user, name),
      FOREIGN KEY (user)
        REFERENCES users (user)
          ON DELETE CASCADE
          ON UPDATE NO ACTION
    )
  `,
};

async function createDb() {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      db.run(queries.tableUsers);
      db.run(queries.tableSecrets, (err) => {
        if (err) reject(err);
        resolve({
          db: db,
          createUser,
          listUsers,
          createSecret,
          listSecrets,
          getSecret,
          updateSecret,
          deleteSecret,
        });
      });
    });
  });
}

async function createUser(user, pass) {
  const securePass = await bcrypt.hash(pass, saltRounds);
  return new Promise((resolve, reject) => {
    const stmt = db.prepare("INSERT INTO users VALUES (?,?)");
    stmt.run(user, securePass);
    stmt.finalize((err) => {
      if (err) reject(err);
      resolve();
    });
  });
}
async function listUsers() {
  return new Promise((resolve, reject) => {
    const users = [];
    db.each(
      "SELECT user from users",
      (err, row) => {
        if (err) return reject(err);
        users.push(row);
      },
      (err, count) => {
        if (err) return reject(err);
        resolve({ count, users });
      }
    );
  });
}

async function createSecret(user, name, value) {
  new Promise((resolve, reject) => {
    const stmt = db.prepare("INSERT INTO secrets VALUES (?,?,?)");
    stmt.run(user, name, value);
    stmt.finalize((err) => {
      if (err) reject(err);
      resolve();
    });
  });
}
async function listSecrets(user) {
  return new Promise((resolve, reject) => {
    const stmt = db.prepare(`SELECT name FROM secrets WHERE user = ?`);
    stmt.all(user, (err, rows) => {
      if (err) reject(err);
      resolve(rows);
    });
  });
}

async function getSecret(user, name) {
  return new Promise((resolve, reject) => {
    const stmt = db.prepare(`
      SELECT value FROM secrets 
      WHERE user = ? AND name = ?
    `);

    stmt.get(user, name, (err, row) => {
      if (err) return reject(err);

      stmt.finalize(() => {
        resolve(row);
      });
    });
  });
}

async function updateSecret(user, name, value) {
  return new Promise((resolve, reject) => {
    const stmt = db.prepare(
      `
      UPDATE secrets
      SET value = ?
      WHERE user = ? AND name = ?
      `
    );
    stmt.run(value, user, name, (err) => {
      if (err) return reject(err);

      resolve();
    });
  });
}

async function deleteSecret(user, name) {
  return new Promise((resolve, reject) => {
    const stmt = db.prepare(
      `
      DELETE FROM secrets WHERE user = ? AND name = ?
      `
    );
    stmt.run(user, name, (err) => {
      if (err) return reject(err);

      resolve();
    });
  });
}

module.exports = {
  createDb,
};
