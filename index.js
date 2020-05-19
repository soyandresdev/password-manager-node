#!/usr/bin/env node
"use strict";

const minimist = require("minimist");
const { createDb } = require("./lib/db");

const argv = minimist(process.argv.slice(2));

async function main() {
  const db = await createDb();
  const command = argv._.shift();
  switch (command) {
    case "users:create":
      try {
        const { user, pass } = argv;
        await db.createUser(user, pass);
        console.log(`${user} created`);
      } catch (err) {
        throw new Error("Cannot create user");
      }
      break;
    case "users:list":
      try {
        const result = await db.listUsers();
        console.log(result);
        if (!result || !result.users || !result.users.length)
          return console.log("No users found");
        result.users.forEach((u) => {
          console.log(`- ${u.user}`);
        });
        console.log(`\tTotal: ${result.count}`);
      } catch (error) {
        throw new Error("Cannot list user");
      }
      break;
    case "secrets:create":
      try {
        const { user, name, value } = argv;
        await db.createSecret(user, name, value);
        console.log(`Secret: ${name} created`);
      } catch (err) {
        throw new Error("Cannot create secret");
      }
      break;
    case "secrets:list":
      try {
        const { user } = argv;
        const secrets = await db.listSecrets(user);
        secrets.forEach((s) => {
          console.log(`- ${s.name}`);
        });
        if (secrets) {
          console.log(`Secret: ${secrets.length}`);
        }
      } catch (err) {
        console.log(err);
        throw new Error("Cannot list secret");
      }
      break;
    case "secrets:get":
      try {
        const { user, name } = argv;
        const secret = await db.getSecret(user, name);
        if (!secret) return console.log(`secret ${name} not found`);
        console.log(`- ${name} = ${secret.value}`);
      } catch (err) {
        console.log(err);
        throw new Error("Cannot get secret");
      }
      break;
    case "secrets:update":
      try {
        const { user, name, value } = argv;
        await db.updateSecret(user, name, value);
        console.log(`secret ${name} updated`);
      } catch (err) {
        throw new Error("Cannot update secret");
      }
      break;
    case "secrets:delete":
      try {
        const { user, name } = argv;
        await db.deleteSecret(user, name);
        console.log(`secret ${name} deleted`);
      } catch (err) {
        throw new Error("Cannot delete secret");
      }
      break;
    default:
      console.log(`Command not found: ${command}`);
      break;
  }
}

main().catch((err) => console.log(err));
