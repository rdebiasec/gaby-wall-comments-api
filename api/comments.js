import { MongoClient } from "mongodb";
import { z } from "zod";

const config = validateConfig({
  uri: process.env.MONGODB_URI,
  dbName: process.env.DB_NAME || "Comments",
  collectionName: process.env.COLLECTION_NAME || "Comments",
});
const apiKey = process.env.API_KEY; // optional simple protection
const allowedOrigins = parseAllowedOrigins(process.env.ALLOWED_ORIGINS || "*");

const BODY_BYTE_LIMIT = 2 * 1024; // 2 KB payload ceiling
const MAX_MESSAGE_LENGTH = 1024;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 10;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;

const commentSchema = z.object({
  fullName: z
    .string()
    .min(1, "fullName is required")
    .max(120, "fullName must be <= 120 characters")
    .transform(normalizeWhitespace),
  message: z
    .string()
    .min(1, "message is required")
    .max(MAX_MESSAGE_LENGTH, "message must be <= 1024 characters")
    .transform(sanitizeContent),
});

let cachedClient = null;
let cachedDb = null;
const rateLimitBuckets = new Map();

// Reuse the Mongo client between invocations (important for serverless)
async function connectToDatabase() {
  if (cachedClient && cachedDb) {
    return { client: cachedClient, db: cachedDb };
  }

  const client = new MongoClient(config.uri);
  await client.connect();
  const db = client.db(config.dbName);

  cachedClient = client;
  cachedDb = db;

  return { client, db };
}

function checkApiKey(req, res) {
  if (!apiKey) return true; // no key set → open
  const headerKey = req.headers["x-api-key"];
  if (headerKey !== apiKey) {
    res.status(401).json({ error: "Unauthorized" });
    return false;
  }
  return true;
}

export default async function handler(req, res) {
  applyCors(req, res);

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  const requestMeta = getRequestContext(req);

  if (!checkApiKey(req, res)) return;
  if (!enforceRateLimit(requestMeta, res)) return;

  if (req.method === "POST") {
    return handlePost(req, res, requestMeta);
  } else if (req.method === "GET") {
    return handleGet(req, res, requestMeta);
  } else {
    res.setHeader("Allow", ["GET", "POST", "OPTIONS"]);
    return res.status(405).json({ error: "Method Not Allowed" });
  }
}

async function handlePost(req, res, meta) {
  try {
    const payloadSize = Buffer.byteLength(
      JSON.stringify(req.body ?? {}),
      "utf8"
    );
    if (payloadSize > BODY_BYTE_LIMIT) {
      return res.status(413).json({ error: "Payload too large" });
    }

    const validation = commentSchema.safeParse(req.body ?? {});
    if (!validation.success) {
      return res.status(400).json({
        error: "Invalid input",
        details: validation.error.flatten().fieldErrors,
      });
    }

    const sanitizedInput = validation.data;

    const { db } = await connectToDatabase();
    const comments = db.collection(config.collectionName);

    const doc = {
      ...sanitizedInput,
      createdAt: new Date(),
    };

    const result = await comments.insertOne(doc);

    logInfo("Created comment", {
      ...meta,
      commentId: result.insertedId.toString(),
    });

    return res.status(201).json({
      id: result.insertedId.toString(),
      ...doc,
    });
  } catch (err) {
    logError("POST /comments error", err, meta);
    return res.status(500).json({ error: "Internal server error" });
  }
}

async function handleGet(req, res, meta) {
  try {
    const queryParams = extractQuery(req);
    const { page, limit, skip } = parsePagination(queryParams);

    const { db } = await connectToDatabase();
    const comments = db.collection(config.collectionName);

    const docs = await comments
      .find({})
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();

    const total = await comments.countDocuments();
    const normalized = docs.map(normalizeCommentRecord);
    const response = {
      data: normalized,
      meta: {
        page,
        limit,
        count: normalized.length,
        total,
        hasMore: skip + normalized.length < total,
      },
    };

    logInfo("Fetched comments", { ...meta, page, limit });

    return res.status(200).json(response);
  } catch (err) {
    logError("GET /comments error", err, meta);
    return res.status(500).json({ error: "Internal server error" });
  }
}

function enforceRateLimit(meta, res) {
  const ip = meta.ip || "unknown";
  const now = Date.now();
  const bucket = rateLimitBuckets.get(ip);

  if (!bucket || now > bucket.expiresAt) {
    rateLimitBuckets.set(ip, {
      count: 1,
      expiresAt: now + RATE_LIMIT_WINDOW_MS,
    });
    return true;
  }

  if (bucket.count >= RATE_LIMIT_MAX) {
    logInfo("Rate limit hit", { ip });
    res.status(429).json({ error: "Too many requests" });
    return false;
  }

  bucket.count += 1;
  rateLimitBuckets.set(ip, bucket);
  return true;
}

function getRequestContext(req) {
  const forwardedFor = req.headers["x-forwarded-for"];
  const ip = Array.isArray(forwardedFor)
    ? forwardedFor[0]
    : typeof forwardedFor === "string"
    ? forwardedFor.split(",")[0].trim()
    : req.socket?.remoteAddress || "unknown";

  return {
    ip,
    method: req.method,
    path: req.url,
    userAgent: req.headers["user-agent"],
    requestId: req.headers["x-request-id"],
  };
}

function extractQuery(req) {
  if (req.query && typeof req.query === "object") {
    return req.query;
  }

  if (!req.url) return {};

  try {
    const parsed = new URL(req.url, "http://localhost");
    return Object.fromEntries(parsed.searchParams.entries());
  } catch {
    return {};
  }
}

function parsePagination(query = {}) {
  const rawPage = getQueryValue(query, "page");
  const rawLimit = getQueryValue(query, "limit");

  let page = Number.parseInt(rawPage ?? "1", 10);
  if (!Number.isFinite(page) || page < 1) {
    page = 1;
  }

  let limit = Number.parseInt(rawLimit ?? `${DEFAULT_LIMIT}`, 10);
  if (!Number.isFinite(limit) || limit < 1) {
    limit = DEFAULT_LIMIT;
  }
  limit = Math.min(limit, MAX_LIMIT);

  return { page, limit, skip: (page - 1) * limit };
}

function normalizeCommentRecord(doc) {
  return {
    id: doc._id.toString(),
    fullName: doc.fullName,
    message: doc.message,
    createdAt: doc.createdAt,
  };
}

function normalizeWhitespace(value) {
  return value.replace(/\s+/g, " ").trim();
}

function sanitizeContent(value) {
  const normalized = normalizeWhitespace(value);
  return normalized.replace(/[<>]/g, "");
}

function getQueryValue(query, key) {
  const value = query[key];
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

function validateConfig({ uri, dbName, collectionName }) {
  if (!uri) {
    throw new Error("MONGODB_URI must be defined.");
  }

  return { uri, dbName, collectionName };
}

function logInfo(message, meta = {}) {
  log("info", message, meta);
}

function logError(message, err, meta = {}) {
  const errorPayload = err instanceof Error ? err : new Error(String(err));
  log("error", message, {
    ...meta,
    errorMessage: errorPayload.message,
    stack: errorPayload.stack,
  });
}

function log(level, message, meta = {}) {
  const payload = {
    level,
    message,
    timestamp: new Date().toISOString(),
    ...meta,
  };
  const serialized = JSON.stringify(payload);
  if (level === "error") {
    console.error(serialized);
  } else {
    console.log(serialized);
  }
}

function parseAllowedOrigins(raw) {
  return raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function applyCors(req, res) {
  const origin = req.headers.origin;
  const allowlist = allowedOrigins.length > 0 ? allowedOrigins : ["*"];
  const allowedOrigin =
    origin && (allowlist.includes("*") || allowlist.includes(origin))
      ? origin
      : allowlist.includes("*")
      ? "*"
      : allowlist[0];

  res.setHeader("Access-Control-Allow-Origin", allowedOrigin || "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,X-API-Key"
  );
  res.setHeader("Access-Control-Max-Age", "86400");
  res.setHeader("Vary", "Origin");
}
