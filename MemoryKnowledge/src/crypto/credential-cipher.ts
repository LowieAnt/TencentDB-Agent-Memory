/**
 * CredentialCipher — AES-256-GCM 加密/解密私有仓库凭据（PAT）。
 *
 * 凭据（如 Azure DevOps / GitHub / GitLab Personal Access Token）落库前必须
 * 加密，密钥来自 KNOWLEDGE_CREDENTIAL_KEY（32 字节，base64 或 hex 编码）。
 * 未配置密钥时加密直接抛错（不静默明文落库、不静默跳过）。
 *
 * 密文落库格式：`iv:authTag:ciphertext`（三段均为 base64），单字段自包含，
 * 无需额外列存 iv/authTag。
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const ALGO = "aes-256-gcm";
const IV_LENGTH = 12;

function loadKey(): Buffer {
  const raw = process.env.KNOWLEDGE_CREDENTIAL_KEY;
  if (!raw) {
    throw new Error(
      "KNOWLEDGE_CREDENTIAL_KEY is not set — cannot encrypt/decrypt repo credentials. " +
        "Generate one with `openssl rand -base64 32` and set it in the environment.",
    );
  }
  // 32 字节的十六进制编码固定为 64 个 [0-9a-f] 字符；其余一律按 base64 解析。
  const isHex = /^[0-9a-fA-F]{64}$/.test(raw);
  const key = Buffer.from(raw, isHex ? "hex" : "base64");
  if (key.length !== 32) {
    throw new Error(
      `KNOWLEDGE_CREDENTIAL_KEY must decode to 32 bytes (got ${key.length}); ` +
        "generate one with `openssl rand -base64 32`.",
    );
  }
  return key;
}

/** 加密明文凭据，返回 `iv:authTag:ciphertext`（base64）。 */
export function encryptCredential(plaintext: string): string {
  const key = loadKey();
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGO, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString("base64")}:${authTag.toString("base64")}:${ciphertext.toString("base64")}`;
}

/** 解密 `iv:authTag:ciphertext` 格式的密文，返回明文凭据。 */
export function decryptCredential(stored: string): string {
  const key = loadKey();
  const parts = stored.split(":");
  if (parts.length !== 3) {
    throw new Error("malformed stored credential (expected iv:authTag:ciphertext)");
  }
  const [ivB64, authTagB64, ciphertextB64] = parts;
  const iv = Buffer.from(ivB64, "base64");
  const authTag = Buffer.from(authTagB64, "base64");
  const ciphertext = Buffer.from(ciphertextB64, "base64");
  const decipher = createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString("utf8");
}
