const crypto = require("crypto");
const saltBytes = 16;
const iterations = 872791;
const hashBytes = 64;
const hashFunction = "sha512";
function hashPassword(password){
    const salt = crypto.randomBytes(saltBytes).toString("hex");
    const hash = crypto
    .pbkdf2Sync(password, salt, iterations, hashBytes, hashFunction)
    .toString("hex");
    return [salt, hash].join(":");
}
function verifyPassword(password, storedHash){
    const [salt, originalHash] = storedHash.split(":");
    const hash = crypto
    .pbkdf2Sync(password, salt, iterations, hashBytes, digest)
    .toString("hex");
    return hash === originalHash;
}
module.exports = {  hashPassword, verifyPassword };