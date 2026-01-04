// server.js — PRODUCTION READY FOR manamingle.site
const MAX_USERS = 300; // Maximum concurrent users
const MAX_QUEUE_SIZE = 100; // Maximum users in queue
const RATE_LIMIT_WINDOW = 60000; // 1 minute in milliseconds
const RATE_LIMIT_MAX = 100; // Max requests per window
const MESSAGE_HISTORY_SIZE = 50; // Store last 50 messages per room
const MAX_TEXT_USERS = 6;
const MAX_VIDEO_USERS = 4;

const express = require("express");
const http = require("http");
const cors = require("cors");
const path = require("path");
const helmet = require("helmet");
const { Server } = require("socket.io");
const fs = require("fs").promises;
const rateLimit = require("express-rate-limit");
const compression = require("compression");
const geoip = require("geoip-lite"); // For IP geolocation
require("dotenv").config(); // Load environment variables

const app = express();

/* ================= CONFIG ================= */
const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";
const NODE_ENV = process.env.NODE_ENV || "development";
const DOMAIN = process.env.DOMAIN || "manamingle.site";

// Admin credentials from environment variables
const ADMIN_CREDENTIALS = {
  username: process.env.ADMIN_USER || "admin",
  password: process.env.ADMIN_PASS || "ChangeMe123!",
  adminKey: process.env.ADMIN_KEY || "secure-admin-key-2024"
};

// STUN/TURN servers configuration


// Add TURN servers if configured


// Validate required environment variables
if (NODE_ENV === "production") {
  const requiredVars = ["ADMIN_USER", "ADMIN_PASS", "ADMIN_KEY"];
  for (const varName of requiredVars) {
    if (!process.env[varName]) {
      console.error(`❌ ERROR: ${varName} is required in production!`);
      process.exit(1);
    }
  }
}

/* ================= PATHS ================= */
const publicPath = path.join(__dirname, "public");
const logsPath = path.join(__dirname, "logs");
const backupPath = path.join(__dirname, "backups");

/* ================= LOGGING SETUP ================= */
async function setupLogging() {
  try {
    await fs.mkdir(logsPath, { recursive: true });
    await fs.mkdir(backupPath, { recursive: true });
    console.log("✅ Logs and backups directories ready");
  } catch (error) {
    console.error("❌ Failed to create directories:", error);
  }
}

async function logToFile(filename, data) {
  try {
    const logFile = path.join(logsPath, filename);
    const timestamp = new Date().toISOString();
    const logEntry = `${timestamp} - ${JSON.stringify(data)}\n`;
    await fs.appendFile(logFile, logEntry);
  } catch (error) {
    console.error("Failed to write log:", error);
  }
}

/* ================= BACKUP SYSTEM ================= */
async function backupState() {
  try {
    const backupData = {
      timestamp: Date.now(),
      rooms: Array.from(state.rooms.entries()),
      users: Array.from(state.users.entries()),
      reports: state.reports,
      blockedUsers: Array.from(state.blockedUsers),
      blockedIPs: Array.from(state.blockedIPs),
      blockedTokens: Array.from(state.blockedTokens)
    };
    
    const backupFile = path.join(backupPath, `backup_${Date.now()}.json`);
    await fs.writeFile(backupFile, JSON.stringify(backupData, null, 2));
    
    // Keep only last 10 backups
    const files = await fs.readdir(backupPath);
    if (files.length > 10) {
      const sortedFiles = files.sort();
      const filesToDelete = sortedFiles.slice(0, files.length - 10);
      for (const file of filesToDelete) {
        await fs.unlink(path.join(backupPath, file));
      }
    }
  } catch (error) {
    console.error("Backup failed:", error);
  }
}

/* ================= MIDDLEWARE ================= */
// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.socket.io"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "wss:", "ws:", "https:"],
      imgSrc: ["'self'", "data:", "https:"],
      mediaSrc: ["'self'", "blob:", "mediastream:"],

    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Rate limiting for API endpoints
const apiLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW,
  max: RATE_LIMIT_MAX,
  message: { error: "Too many requests, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

// IP-based rate limiting
const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // limit each IP to 1000 requests per window
  message: { error: "Too many requests from this IP." },
  keyGenerator: (req) => req.ip
});

// CORS configuration
const corsOptions = {
  origin: NODE_ENV === "production" 
    ? [`https://${DOMAIN}`, `https://www.${DOMAIN}`]
    : true,
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"]
};

app.use(cors(corsOptions));
app.use(compression()); // Enable gzip compression
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(express.static(publicPath, { 
  maxAge: NODE_ENV === "production" ? "1d" : "0",
  setHeaders: (res, path) => {
    if (path.endsWith(".html")) {
      res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    }
  }
}));
app.use(ipLimiter); // Apply IP-based rate limiting

/* ================= ADMIN AUTH MIDDLEWARE ================= */
function authenticateAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authentication required" });
  }
  
  const token = authHeader.substring(7);
  if (token !== ADMIN_CREDENTIALS.adminKey) {
    return res.status(403).json({ error: "Invalid admin key" });
  }
  
  next();
}

/* ================= ROUTES ================= */
/* ================= ICE / TURN ENDPOINT ================= */
app.get("/api/turn", (req, res) => {
  if (!process.env.TURN_USERNAME || !process.env.TURN_PASSWORD) {
    return res.status(500).json({ error: "TURN not configured" });
  }

  res.json({
    iceServers: [
      { urls: "stun:stun.l.google.com:19302" },
      {
        urls: "turn:global.relay.metered.ca:443",
        username: process.env.TURN_USERNAME,
        credential: process.env.TURN_PASSWORD
      },
      {
        urls: "turns:global.relay.metered.ca:443?transport=tcp",
        username: process.env.TURN_USERNAME,
        credential: process.env.TURN_PASSWORD
      }
    ]
  });
});

// Health check endpoint
app.get("/health", (req, res) => {
  const memoryUsage = process.memoryUsage();
  const rooms = Array.from(state.rooms.values());
  
  res.json({
    status: "healthy",
    uptime: process.uptime(),
    timestamp: Date.now(),
    memory: {
      heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024) + "MB",
      heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024) + "MB",
      rss: Math.round(memoryUsage.rss / 1024 / 1024) + "MB"
    },
    connections: {
      users: state.users.size,
      queue: state.connectionQueue.length,
      rooms: rooms.length,
      activeRooms: rooms.filter(r => r.status === 'active').length
    },
    environment: NODE_ENV,
    version: "1.0.0"
  });
});

// Admin panel (protected)
app.get("/admin", authenticateAdmin, (req, res) => {
  res.sendFile(path.join(publicPath, "admin.html"));
});

// Admin login endpoint
app.post("/admin/login", apiLimiter, (req, res) => {
  const { username, password } = req.body;

  if (username === ADMIN_CREDENTIALS.username && 
      password === ADMIN_CREDENTIALS.password) {
    res.json({ 
      success: true, 
      token: ADMIN_CREDENTIALS.adminKey,
      expiresIn: "24h"
    });
  } else {
    res.status(401).json({ 
      success: false, 
      error: "Invalid credentials" 
    });
  }
});

// Admin API endpoints (protected)
app.get("/admin/stats", authenticateAdmin, (req, res) => {
  res.json(getPublicStateForAdmin());
});

app.post("/admin/ban", authenticateAdmin, apiLimiter, (req, res) => {
  const { type, value, reason, duration } = req.body;
  
  if (!type || !value) {
    return res.status(400).json({ error: "Missing type or value" });
  }
  
  const banData = {
    type,
    value,
    reason: reason || "No reason provided",
    bannedAt: Date.now(),
    bannedBy: req.ip,
    duration: duration || null,
    expiresAt: duration ? Date.now() + (duration * 1000) : null
  };
  
  switch (type) {
    case "user":
      state.blockedUsers.set(value, banData);
      break;
    case "ip":
      state.blockedIPs.set(value, banData);
      break;
    case "token":
      state.blockedTokens.set(value, banData);
      break;
    default:
      return res.status(400).json({ error: "Invalid ban type" });
  }
  
  logAdminAction(req.ip, "BAN_ADDED", banData);
  res.json({ success: true, message: `Banned ${type}: ${value}`, data: banData });
});

app.delete("/admin/ban/:type/:value", authenticateAdmin, (req, res) => {
  const { type, value } = req.params;
  
  let success = false;
  switch (type) {
    case "user":
      success = state.blockedUsers.delete(value);
      break;
    case "ip":
      success = state.blockedIPs.delete(value);
      break;
    case "token":
      success = state.blockedTokens.delete(value);
      break;
    default:
      return res.status(400).json({ error: "Invalid ban type" });
  }
  
  if (success) {
    logAdminAction(req.ip, "BAN_REMOVED", { type, value });
    res.json({ success: true, message: `Unbanned ${type}: ${value}` });
  } else {
    res.status(404).json({ error: `${type} not found in ban list` });
  }
});

// Debug endpoint for room status
app.get("/debug/room/:roomId", authenticateAdmin, (req, res) => {
  const roomId = req.params.roomId;
  const room = state.rooms.get(roomId);
  
  if (!room) {
    return res.status(404).json({ error: "Room not found" });
  }
  
  const socketStatus = Array.from(room.users).map(socketId => {
    const socket = io.sockets.sockets.get(socketId);
    const userData = state.users.get(socketId);
    return {
      socketId,
      connected: socket?.connected || false,
      userId: userData?.id,
      userName: userData?.name,
      userAgent: userData?.userAgent,
      ip: userData?.ip
    };
  });
  
  res.json({
    roomId,
    mode: room.mode,
    status: room.status,
    users: socketStatus,
    totalUsers: room.users.size,
    maxSize: ROOM_MAX_SIZE[room.mode],
    createdAt: room.createdAt,
    lastActivity: room.lastActivity,
    messages: room.messages?.length || 0,
    isBanned: room.isBanned
  });
});

// ICE servers endpoint

// Load testing endpoint (admin only)
app.post("/admin/load-test", authenticateAdmin, (req, res) => {
  const { action, count = 10 } = req.body;
  
  if (action === "simulate") {
    const stats = {
      before: {
        users: state.users.size,
        rooms: state.rooms.size,
        memory: process.memoryUsage().heapUsed
      },
      simulated: count
    };
    
    // Simulate load by creating test rooms
    for (let i = 0; i < Math.min(count, 50); i++) {
      const roomId = `test_${Date.now()}_${i}`;
      state.rooms.set(roomId, {
        id: roomId,
        mode: 'text',
        users: new Set(),
        participants: [],
        tags: ['test'],
        createdAt: Date.now(),
        lastActivity: Date.now(),
        status: "active",
        isBanned: false
      });
    }
    
    stats.after = {
      users: state.users.size,
      rooms: state.rooms.size,
      memory: process.memoryUsage().heapUsed
    };
    
    res.json({ success: true, stats });
  } else {
    res.json({ error: "Invalid action" });
  }
});

// Main page
app.get("/", (req, res) => {
  res.sendFile(path.join(publicPath, "manamingle.html"));
});

// 404 handler
app.use((req, res) => {
  res.status(404).sendFile(path.join(publicPath, "404.html"));
});

// Error handler
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  logToFile("server-errors.log", {
    error: err.message,
    stack: err.stack,
    timestamp: Date.now(),
    url: req.url,
    ip: req.ip
  });
  
  res.status(500).json({ 
    error: NODE_ENV === "production" ? "Internal server error" : err.message 
  });
});

/* ================= SERVER SETUP ================= */
const server = http.createServer(app);

const io = new Server(server, {
  transports: ["websocket", "polling"],
  pingInterval: 25000,
  pingTimeout: 20000,
  connectTimeout: 30000,
  maxHttpBufferSize: 10e6, // 10MB

  cors: corsOptions,
  allowEIO3: true,
  serveClient: false,
  connectionStateRecovery: {
    maxDisconnectionDuration: 2 * 60 * 1000, // 2 minutes
    skipMiddlewares: true
  }
});

/* ================= GLOBAL STATE ================= */
const state = {
  waiting: {
    text: new Map(),
    video: new Map(),
    audio: new Map(),
    group_text: new Map(),
    group_video: new Map()
  },
  
  rooms: new Map(),
  users: new Map(),
  reports: [],
  
  blockedUsers: new Map(), // Changed to Map to store ban details
  blockedIPs: new Map(),
  blockedTokens: new Map(),
  
  admins: new Set(),
  securityLogs: [],
  
  // Rate limiting per socket
  socketRateLimits: new Map(),
  
  // Queue system for when server is full
  connectionQueue: [],
  
  // Message history for rooms
  messageHistory: new Map()
};

// Room size limits
const ROOM_MAX_SIZE = {
  text: 2,
  video: 2,
  audio: 2,
  group_text: MAX_TEXT_USERS,
  group_video: MAX_VIDEO_USERS
};


// Room timeout configurations (in milliseconds)
const ROOM_TIMEOUTS = {
  text: 30 * 60 * 1000,      // 30 minutes
  video: 60 * 60 * 1000,     // 1 hour
  audio: 60 * 60 * 1000,     // 1 hour
  group_text: 120 * 60 * 1000, // 2 hours
  group_video: 90 * 60 * 1000  // 1.5 hours
};

/* ================= HELPER FUNCTIONS ================= */
function generateRoomId() {
  return `room_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
}

function generateUserId() {
  return `usr_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
}

function getUserIP(socket) {
  const forwardedFor = socket.handshake.headers['x-forwarded-for'];
  return forwardedFor 
    ? forwardedFor.split(',')[0].trim() 
    : socket.handshake.address;
}

function getUserCountry(ip) {
  try {
    const geo = geoip.lookup(ip);
    return geo ? geo.country : null;
  } catch (e) {
    return null;
  }
}

function isRateLimited(socketId, type = "message") {
  const now = Date.now();
  const userLimits = state.socketRateLimits.get(socketId) || {};
  
  if (!userLimits[type]) {
    userLimits[type] = { count: 1, firstRequest: now, lastRequest: now };
    state.socketRateLimits.set(socketId, userLimits);
    return false;
  }
  
  const limit = userLimits[type];
  
  // Reset if window has passed
  if (now - limit.firstRequest > 60000) { // 1 minute window
    limit.count = 1;
    limit.firstRequest = now;
    limit.lastRequest = now;
    return false;
  }
  
  // Check limits based on type
  const maxRequests = {
    message: 60, // 60 messages per minute
    join: 10,
    skip: 20,
    signal: 200,
    typing: 30,
    media: 10
  };
  
  limit.count++;
  limit.lastRequest = now;
  
  if (limit.count > (maxRequests[type] || 30)) {
    logSecurityEvent('RATE_LIMIT_EXCEEDED', { socketId, type, count: limit.count });
    return true;
  }
  
  return false;
}

function logSecurityEvent(event, details = {}) {
  const log = {
    timestamp: Date.now(),
    event,
    ...details,
    environment: NODE_ENV
  };
  
  state.securityLogs.unshift(log);
  
  // Keep only last 2000 logs in memory
  if (state.securityLogs.length > 2000) {
    state.securityLogs.pop();
  }
  
  // Log to file in production
  if (NODE_ENV === "production") {
    logToFile("security.log", log);
  }
  
  console.log(`🔒 ${event}`, Object.keys(details).length > 0 ? details : "");
}

function logAdminAction(adminId, action, details = {}) {
  const log = {
    timestamp: Date.now(),
    adminId,
    action,
    ...details
  };
  
  console.log(`👮 ADMIN: ${action} by ${adminId}`);
  
  // Emit to all admins
  io.to('admins').emit('admin-action-log', log);
  
  // Log to file
  logToFile("admin.log", log);
}

function isUserBlocked(userId, ip, token) {
  // Check if user is blocked
  if (state.blockedUsers.has(userId)) {
    const ban = state.blockedUsers.get(userId);
    if (ban.expiresAt && Date.now() > ban.expiresAt) {
      state.blockedUsers.delete(userId); // Ban expired
      return false;
    }
    return true;
  }
  
  // Check if IP is blocked
  if (state.blockedIPs.has(ip)) {
    const ban = state.blockedIPs.get(ip);
    if (ban.expiresAt && Date.now() > ban.expiresAt) {
      state.blockedIPs.delete(ip); // Ban expired
      return false;
    }
    return true;
  }
  
  // Check if token is blocked
  if (token && state.blockedTokens.has(token)) {
    const ban = state.blockedTokens.get(token);
    if (ban.expiresAt && Date.now() > ban.expiresAt) {
      state.blockedTokens.delete(token); // Ban expired
      return false;
    }
    return true;
  }
  
  return false;
}

function hasCommonInterest(userTags = [], roomTags = []) {
  if (!userTags.length || !roomTags.length) return false;
  const roomTagSet = new Set(roomTags.map(t => t.toLowerCase()));
  return userTags.some(tag => roomTagSet.has(tag.toLowerCase()));
}

function findMatchForUser(selfSocketId, mode, userTags = []) {
  const waitingUsers = Array.from(state.waiting[mode].entries());
  
  if (waitingUsers.length === 0) {
    return null;
  }
  
  // Try to find interest match
  let bestInterestMatch = null;
  let bestInterestScore = -1;
  let randomMatch = null;
  
  for (const [socketId, userData] of waitingUsers) {
    if (socketId === selfSocketId) continue;
    
    // Calculate tag similarity for interest matching
    if (userTags.length > 0 && userData.tags && userData.tags.length > 0) {
      const userTagSet = new Set(userTags.map(t => t.toLowerCase()));
      const otherTagSet = new Set(userData.tags.map(t => t.toLowerCase()));
      
      let matchScore = 0;
      const commonTags = [];
      
      for (const tag of userTagSet) {
        if (otherTagSet.has(tag)) {
          matchScore += 2;
          commonTags.push(tag);
        }
      }
      
      // Found interest match - prioritize this
      if (matchScore > 0 && matchScore > bestInterestScore) {
        bestInterestScore = matchScore;
        bestInterestMatch = { 
          socketId, 
          userData: { ...userData, commonTags },
          matchScore 
        };
      }
    }
    
    // Also collect random match candidates
    if (!randomMatch) {
      randomMatch = { socketId, userData };
    }
  }
  
  // Return interest match if found, otherwise random match
  if (bestInterestMatch && bestInterestScore > 0) {
    return bestInterestMatch;
  }
  
  return randomMatch;
}

function findGroupForUser(selfSocketId, mode, userTags = []) {
  // Try to find an existing active group with space
  for (const [roomId, room] of state.rooms) {
    if (
      room.mode === mode &&
      room.status === "active" &&
      !room.isBanned &&
      room.users.size < ROOM_MAX_SIZE[mode]
    ) {
      // Check interest matching
      if (
        userTags.length === 0 ||
        hasCommonInterest(userTags, room.tags || [])
      ) {
        return { roomId, room };
      }
    }
  }

  // No group found → create a new group
  return {
    newGroup: true,
    members: []
  };
}

function createRoom(mode, creatorSocketId, creatorData, ...otherUsers) {
  const roomId = generateRoomId();
  const allUsers = [{ socketId: creatorSocketId, data: creatorData }, ...otherUsers];
  
  // Collect all tags
  const allTags = [];
  const allTokens = [];
  const participants = [];
  
  for (const user of allUsers) {
    allTags.push(...(user.data.tags || []));
    if (user.data.token) allTokens.push(user.data.token);
    
    participants.push({
      id: user.socketId,
      userId: user.data.id,
      name: user.data.name || 'Anonymous',
      tags: user.data.tags || [],
      joinedAt: Date.now(),
      ip: user.data.ip,
      country: getUserCountry(user.data.ip)
    });
  }
  
  const roomTags = [...new Set(allTags)];
  
  const room = {
    id: roomId,
    mode: mode,
    users: new Set(allUsers.map(u => u.socketId)),
    participants: participants,
    tags: roomTags,
    tokens: allTokens,
    createdAt: Date.now(),
    lastActivity: Date.now(),
    status: "active",
    isBanned: false,
    messages: [],

    timeout: setTimeout(() => {
      endRoom(roomId, "timeout");
    }, ROOM_TIMEOUTS[mode] || 3600000)
  };
  
  state.rooms.set(roomId, room);
  state.messageHistory.set(roomId, []);
  
  return roomId;
}

function addUserToRoom(socketId, roomId, userData) {
  const room = state.rooms.get(roomId);
  if (!room) return false;
  
  // Check room capacity
  const maxSize = ROOM_MAX_SIZE[room.mode];
  if (room.users.size >= maxSize) {
    return false;
  }
  
  room.users.add(socketId);
  room.participants.push({
    id: socketId,
    userId: userData.id,
    name: userData.name || 'Anonymous',
    tags: userData.tags || [],
    joinedAt: Date.now(),
    ip: userData.ip,
    country: getUserCountry(userData.ip)
  });
  
  if (userData.token) room.tokens.push(userData.token);
  
  // Update last activity
  room.lastActivity = Date.now();
  
  return true;
}

function removeUserFromRoom(socketId, roomId, reason = "left") {
  const room = state.rooms.get(roomId);
  if (!room) return false;

  room.users.delete(socketId);

  // Remove participant
  const participantIndex = room.participants.findIndex(p => p.id === socketId);
  if (participantIndex !== -1) {
    room.participants.splice(participantIndex, 1);
  }

  // Notify all remaining users about disconnection
  const remainingUsers = Array.from(room.users);
  if (remainingUsers.length > 0) {
    remainingUsers.forEach(remainingSocketId => {
      io.to(remainingSocketId).emit("peer-disconnected", {
        peerId: socketId,
        roomId,
        reason,
        remainingCount: remainingUsers.length
      });
    });
  }

  // Update room status
  if (room.users.size === 0) {
    endRoom(roomId, reason);
  } else if (room.mode.startsWith('group_') && room.users.size === 1) {
    // If group has only 1 user left, notify them
    const remainingUser = Array.from(room.users)[0];
    const remainingSocket = io.sockets.sockets.get(remainingUser);
    if (remainingSocket) {
      remainingSocket.emit("group-emptying", { roomId });
    }
  }

  // Update last activity
  room.lastActivity = Date.now();

  return true;
}

function endRoom(roomId, reason = "ended") {
  const room = state.rooms.get(roomId);
  if (!room) return;

  // Clear timeout
  if (room.timeout) {
    clearTimeout(room.timeout);
  }

  room.status = 'ended';
  room.endedAt = Date.now();
  room.endReason = reason;
  
  // Save message history before deleting
  backupRoomHistory(roomId);
  const history = state.messageHistory.get(roomId) || [];

  setTimeout(() => {
    state.rooms.delete(roomId);
    state.messageHistory.delete(roomId);
  }, 10000); // Keep for 10 seconds after ending

  // Notify all users in room
  const roomSockets = io.in(roomId);
  roomSockets.emit("room-ended", { reason, roomId });
  
  // Force disconnect all sockets from room
  roomSockets.socketsLeave(roomId);

  logSecurityEvent('ROOM_ENDED', {
    roomId,
    mode: room.mode,
    reason,
    participantCount: room.participants.length,
    duration: room.endedAt - room.createdAt,
    messageCount: room.messages?.length || 0
  });
}

async function backupRoomHistory(roomId) {
  try {
    const room = state.rooms.get(roomId);
    if (!room || !room.messages) return;
    
    const history = {
      roomId,
      mode: room.mode,
      participants: room.participants,
      messages: room.messages,
      createdAt: room.createdAt,
      endedAt: room.endedAt,
      duration: room.endedAt - room.createdAt
    };
    
    await logToFile("room-history.log", history);
  } catch (error) {
    console.error("Failed to backup room history:", error);
  }
}

function getRoomStats() {
  const stats = {
    total: state.rooms.size,
    active: 0,
    text: 0,
    video: 0,
    audio: 0,
    group_text: 0,
    group_video: 0,
    banned: 0,
    ended: 0,
    waiting: {
      text: state.waiting.text.size,
      video: state.waiting.video.size,
      audio: state.waiting.audio.size,
      group_text: state.waiting.group_text.size,
      group_video: state.waiting.group_video.size
    }
  };
  
  for (const room of state.rooms.values()) {
    if (room.status === 'active') stats.active++;
    if (room.status === 'ended') stats.ended++;
    if (room.isBanned) stats.banned++;
    
    stats[room.mode] = (stats[room.mode] || 0) + 1;
  }
  
  return stats;
}

function getPublicStateForAdmin() {
  const roomsArray = [];
  
  for (const [roomId, room] of state.rooms) {
    roomsArray.push({
      id: roomId,
      mode: room.mode,
      status: room.status,
      isBanned: room.isBanned,
      participants: room.participants,
      userCount: room.users.size,
      maxSize: ROOM_MAX_SIZE[room.mode],
      tags: room.tags,
      tokens: room.tokens.length,
      createdAt: room.createdAt,
      lastActivity: room.lastActivity,
      endedAt: room.endedAt,
      duration: room.endedAt 
        ? room.endedAt - room.createdAt 
        : Date.now() - room.createdAt,
      messageCount: room.messages?.length || 0
    });
  }
  
  roomsArray.sort((a, b) => b.createdAt - a.createdAt);
  
  // Get blocked lists with details
  const blockedUsers = Array.from(state.blockedUsers.entries()).map(([id, data]) => ({ id, ...data }));
  const blockedIPs = Array.from(state.blockedIPs.entries()).map(([ip, data]) => ({ ip, ...data }));
  const blockedTokens = Array.from(state.blockedTokens.entries()).map(([token, data]) => ({ token, ...data }));
  
  return {
    serverInfo: {
      domain: DOMAIN,
      environment: NODE_ENV,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      nodeVersion: process.version,
      timestamp: Date.now()
    },
    rooms: roomsArray.slice(0, 100),
    reports: state.reports.slice(0, 50),
    online: state.users.size,
    stats: getRoomStats(),
    blocked: {
      users: blockedUsers,
      ips: blockedIPs,
      tokens: blockedTokens
    },
    waiting: getRoomStats().waiting,
    securityLogs: state.securityLogs.slice(0, 50),
    queue: {
      size: state.connectionQueue.length,
      users: state.connectionQueue.map(s => ({ 
        id: s.id, 
        connected: s.connected 
      }))
    }
  };
}

/* ================= QUEUE MANAGEMENT ================= */
function processQueue() {
  // Process queue when space becomes available
  while (state.connectionQueue.length > 0 && state.users.size < MAX_USERS) {
    const queuedSocket = state.connectionQueue.shift();
    
    if (queuedSocket && queuedSocket.connected && !state.users.has(queuedSocket.id)) {
      acceptConnection(queuedSocket);
    }
  }
  
  // Update queue positions
  state.connectionQueue.forEach((queuedSocket, index) => {
    if (queuedSocket && queuedSocket.connected) {
      queuedSocket.emit("queue-position", {
        position: index + 1,
        totalInQueue: state.connectionQueue.length,
        estimatedWait: Math.ceil((index + 1) * 2) // Rough estimate: 2 seconds per person
      });
    }
  });
}

function acceptConnection(socket) {
  state.connectionQueue = state.connectionQueue.filter(s => s.id !== socket.id);

  const wasQueued = Boolean(socket.queued);
  socket.queued = false;
  socket.queuedAt = null;

  const userIP = getUserIP(socket);
  const userId = generateUserId();

  // Initialize user state
  state.users.set(socket.id, {
    id: userId,
    ip: userIP,
    name: 'Anonymous',
    nickname: 'Anonymous',
    mode: null,
    tags: [],
    token: null,
    coins: 0,
    badges: null,
    isAdmin: false,
    isCreator: false,
    rooms: new Set(),
    connectedAt: Date.now(),
    userAgent: socket.handshake.headers['user-agent'],
    queuedAt: null,
    country: getUserCountry(userIP),
    lastActivity: Date.now()
  });

  socket.emit("queue-accepted", {
    message: "You're now connected!",
    userId,
    
  });

  io.emit("online_count", { count: state.users.size });

  logSecurityEvent('USER_CONNECTED', { 
    socketId: socket.id, 
    userId, 
    ip: userIP,
    country: getUserCountry(userIP),
    userAgent: socket.handshake.headers['user-agent'],
    wasQueued
  });
}

/* ================= SOCKET.IO EVENT HANDLERS ================= */
io.on('connection', (socket) => {
  console.log(`New connection: ${socket.id}`);
  
  // 🚦 USER LIMIT ENFORCEMENT WITH QUEUE
  if (state.users.size >= MAX_USERS) {
    // Queue full → reject
    if (state.connectionQueue.length >= MAX_QUEUE_SIZE) {
      socket.emit("server-full", {
        max: MAX_USERS,
        queueFull: true,
        message: "Server and queue are full. Please try again later."
      });
      socket.disconnect(true);
      return;
    }
  
    // Add to queue
    const queuePosition = state.connectionQueue.length + 1;
    
    socket.queued = true;
    socket.queuedAt = Date.now();
    state.connectionQueue.push(socket);
  
    socket.emit("server-full", {
      max: MAX_USERS,
      queued: true,
      position: queuePosition,
      totalInQueue: state.connectionQueue.length,
      estimatedWait: Math.ceil(queuePosition * 2),
      message: `Server is full. You are #${queuePosition} in queue.`
    });
  
    logSecurityEvent('USER_QUEUED', {
      socketId: socket.id,
      position: queuePosition,
      totalInQueue: state.connectionQueue.length
    });
  
    socket.on('disconnect', () => {
      state.connectionQueue = state.connectionQueue.filter(s => s.id !== socket.id);
      processQueue();
    });
  
    return;
  }
  
  // Server has space, accept connection immediately
  acceptConnection(socket);
  state.connectionQueue = state.connectionQueue.filter(s => s.id !== socket.id);

  /* ===== JOIN CHAT EVENT ===== */
  socket.on("join_chat", (data) => {
    const userData = state.users.get(socket.id);
    if (!userData) {
      socket.emit('error', { message: 'User session not found' });
      return;
    }
    
    if (userData.mode) {
      // User already in a chat, skip
      return;
    }
    
    const { mode = 'text', nickname, tags = [], token, userAgent } = data;
    
    // Validate mode
    const validModes = ['text', 'video', 'audio', 'group_text', 'group_video'];
    const validMode = validModes.includes(mode) ? mode : 'text';
    
    // Get user IP and ID
    const userIP = userData.ip;
    const userId = userData.id;
    
    // Check if user is blocked
    if (isUserBlocked(userId, userIP, token)) {
      socket.emit('error', { 
        message: 'Your account has been blocked. Contact support if you believe this is an error.' 
      });
      socket.disconnect();
      return;
    }
    
    // Validate nickname
    const cleanNickname = (nickname || 'Anonymous')
      .toString()
      .slice(0, 30)
      .replace(/[<>]/g, ''); // Basic XSS protection
    
    // Validate tags
    const cleanTags = Array.isArray(tags) 
      ? tags.slice(0, 10).map(tag => tag.toString().slice(0, 20).toLowerCase())
      : [];
    
    // Update user data
    userData.name = cleanNickname;
    userData.nickname = cleanNickname;
    userData.tags = cleanTags;
    userData.token = token;
    userData.mode = validMode;
    userData.userAgent = userAgent;
    userData.lastActivity = Date.now();
    
    // Remove from any existing waiting queue
    for (const m of validModes) {
      state.waiting[m].delete(socket.id);
    }
    
    // Find or create match/group
    if (validMode.startsWith('group_')) {
      handleGroupJoin(socket, validMode, userData);
    } else {
      handleOneOnOneJoin(socket, validMode, userData);
    }
    
    // Update admin panel
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
  });
  
  function handleOneOnOneJoin(socket, mode, userData) {
    // Try to find match immediately
    const match = findMatchForUser(socket.id, mode, userData.tags);
  
    if (match) {
      const matchedUserData = match.userData;
      const isInterestMatch = match.matchScore > 0;
      const commonTags = matchedUserData.commonTags || [];
  
      // Create room
      const roomId = createRoom(mode, socket.id, userData, {
        socketId: match.socketId,
        data: matchedUserData
      });
  
      // Remove both users from waiting queue
      state.waiting[mode].delete(socket.id);
      state.waiting[mode].delete(match.socketId);
  
      // Track rooms
      userData.rooms.add(roomId);
      const matchedUser = state.users.get(match.socketId);
      if (matchedUser) {
        matchedUser.rooms.add(roomId);
      }
  
      // Join sockets to room
      socket.join(roomId);
      const matchedSocket = io.sockets.sockets.get(match.socketId);
      if (matchedSocket) {
        matchedSocket.join(roomId);
      }
  
      // Get user countries
      const userCountry = userData.country;
      const partnerCountry = matchedUserData.country;
  
      // Send to initiator
      socket.emit("matched", {
        roomId,
        partner: matchedUserData.name,
        partnerName: matchedUserData.name,
        partnerId: matchedUserData.id,
        mode,
        tags: matchedUserData.tags || [],
        partnerTags: matchedUserData.tags || [],
        matchType: isInterestMatch ? "interest" : "random",
        partnerCountry,
        commonTags,
        isInitiator: true,
        
      });
  
      // Send to receiver
      if (matchedSocket) {
        matchedSocket.emit("matched", {
          roomId,
          partner: userData.name,
          partnerName: userData.name,
          partnerId: userData.id,
          mode,
          tags: userData.tags || [],
          partnerTags: userData.tags || [],
          matchType: isInterestMatch ? "interest" : "random",
          partnerCountry: userCountry,
          commonTags,
          isInitiator: false,
         
        });
      }
  
      logSecurityEvent("USERS_MATCHED", {
        roomId,
        user1: { id: userData.id, name: userData.name },
        user2: { id: matchedUserData.id, name: matchedUserData.name },
        mode,
        isInterestMatch
      });
  
    } else {
      // No match → add to waiting queue
      state.waiting[mode].set(socket.id, userData);
      userData.waitingSince = Date.now();
  
      socket.emit("waiting", {
        mode,
        estimatedWait: Math.max(2, state.waiting[mode].size * 1),
        
      });
  
      logSecurityEvent("USER_WAITING", {
        userId: userData.id,
        mode,
        name: userData.name,
        waitingCount: state.waiting[mode].size
      });
    }
  }
  
  function handleGroupJoin(socket, mode, userData) {
    const maxSize = ROOM_MAX_SIZE[mode];
  if (!maxSize) {
    socket.emit("error", { message: "Invalid group mode" });
    return;
  }
    const group = findGroupForUser(socket.id, mode, userData.tags);
    let roomId;
  
    if (group?.roomId) {
      // Join existing group
      roomId = group.roomId;
    
      const room = state.rooms.get(roomId);
      if (!room) {
        socket.emit("error", { message: "Room not found" });
        return;
      }
    
      // 🔒 HARD LIMIT ENFORCEMENT (ABSOLUTE)
      if (room.users.size >= ROOM_MAX_SIZE[mode]) {
        socket.emit("room-full", {
          roomId,
          mode,
          max: ROOM_MAX_SIZE[mode],
          type: mode === "group_video" ? "video" : "text"
        });
        return;
      }
    
      const success = addUserToRoom(socket.id, roomId, userData);
      if (!success) {
        // Safety fallback (should never happen)
        socket.emit("room-full", {
          roomId,
          mode,
          max: ROOM_MAX_SIZE[mode],
          type: mode === "group_video" ? "video" : "text"
        });
        return;
      }
    
    } else if (group?.newGroup) {
      // Create new group with single user
      roomId = createRoom(mode, socket.id, userData);
    
    } else {
      // Fallback → waiting
      state.waiting[mode].set(socket.id, userData);
      socket.emit("waiting", { mode });
      return;
    }
    
    // ✅ Remove from waiting
    state.waiting[mode].delete(socket.id);
    userData.rooms.add(roomId);
    socket.join(roomId);
    
    const room = state.rooms.get(roomId);
    
    // Existing peers (excluding current user)
    const existingPeers = Array.from(room.users).filter(
      id => id !== socket.id
    );
    
    // Message history
    const messageHistory = state.messageHistory.get(roomId) || [];
    
    // ✅ Notify new joiner
    socket.emit("group-joined", {
      roomId,
      mode,
      participants: room.participants.map(p => p.name),
      participantCount: room.users.size,

      maxSize: ROOM_MAX_SIZE[mode],
      existingPeers,
      isNewGroup: Boolean(group?.newGroup),
      messageHistory: messageHistory.slice(-MESSAGE_HISTORY_SIZE),
      
    });
    
    // ✅ Notify existing peers
    if (existingPeers.length > 0) {
      socket.to(roomId).emit("new-peer", {
        peerId: socket.id,
        peerName: userData.name,
        peerUserId: userData.id,
        roomId,
        totalParticipants: room.users.size
      });
    }
    
    logSecurityEvent("GROUP_JOINED", {
      roomId,
      userId: userData.id,
      userName: userData.name,
      mode,
      groupSize: room.users.size
    });
    
  }
  
  /* ===== MESSAGE HANDLING ===== */
  /* ===== MESSAGE HANDLING ===== */
  socket.on("send_message", (data) => {
    if (isRateLimited(socket.id, "message")) return;
  
    const { room, roomId, message, messageId, type = "text", timestamp } = data;
    const targetRoomId = room || roomId;
    const userData = state.users.get(socket.id);
  
    if (!targetRoomId || !message || !messageId || !userData) return;
  
    const roomData = state.rooms.get(targetRoomId);
    if (!roomData || !roomData.users.has(socket.id)) return;
  
    const cleanMessage = String(message).trim().slice(0, 2000);
    if (!cleanMessage) return;
  
    const messageData = {
      messageId,
      message: cleanMessage,
      senderId: userData.id,     // NOT socket.id
senderSocketId: socket.id, // optional but useful

      senderName: userData.nickname || userData.name,
      roomId: targetRoomId,
      type,
      timestamp: timestamp || Date.now()
    };
  
    // Save history
 
    const history = state.messageHistory.get(targetRoomId) || [];
    history.push(messageData);
if (history.length > MESSAGE_HISTORY_SIZE) history.shift();

state.messageHistory.set(targetRoomId, history);

  
    // Send to others
    // send to everyone else
socket.to(targetRoomId).emit("receive_message", messageData);

// send to sender explicitly
socket.emit("receive_message", {
  ...messageData,
  self: true
});


  
    
    
  });
  

  

  
  /* ===== USER DATA UPDATES ===== */
  socket.on("user-data", (data) => {
    const { roomId, userId, nickname, coins, badges, isAdmin, isCreator } = data;
    const userData = state.users.get(socket.id);
    
    if (!userData) return;
    
    // Update user data
    userData.nickname = nickname || userData.name;
    userData.coins = coins || 0;
    userData.badges = badges || null;
    userData.isAdmin = isAdmin || false;
    userData.isCreator = isCreator || false;
    userData.lastActivity = Date.now();
    
    // Store in global state
    state.users.set(socket.id, userData);
    
    // Broadcast to room
    if (roomId) {
      const room = state.rooms.get(roomId);
      if (room && room.users.has(socket.id)) {
        socket.to(roomId).emit("user-data-update", {
          userId: userData.id,
          nickname: userData.nickname,
          coins: userData.coins,
          badges: userData.badges,
          isAdmin: userData.isAdmin,
          isCreator: userData.isCreator
        });
      }
    }
    
    logSecurityEvent('USER_DATA_UPDATE', {
      userId: userData.id,
      nickname: userData.nickname,
      coins: userData.coins,
      badges: userData.badges,
      roomId
    });
  });
  
  
  /* ===== MEDIA CHUNK HANDLER (FINAL) ===== */
  

 
  
  socket.on("media_chunk", data => {
    if (isRateLimited(socket.id, "media")) return;
  
    const userData = state.users.get(socket.id);
    if (!userData) return;
  
    const room = state.rooms.get(data.roomId);
    if (!room || !room.users.has(socket.id)) return;
  
    socket.mediaBuffers = socket.mediaBuffers || new Map();
    const mediaBuffers = socket.mediaBuffers;
  
    const {
      roomId,
      mediaId,
      chunkIndex,
      totalChunks,
      chunk,
      mediaType,
      fileName,
      fileSize,
      cost
    } = data;
  
    if (!mediaBuffers.has(mediaId)) {
      mediaBuffers.set(mediaId, {
        chunks: [],
        totalChunks,
        createdAt: Date.now()
      });
    }
  
    const entry = mediaBuffers.get(mediaId);
    entry.chunks[chunkIndex] = Buffer.from(chunk);
  
    if (entry.chunks.filter(Boolean).length === totalChunks) {
      const buffer = Buffer.concat(entry.chunks);
  
      const mimeType =
  mediaType === "photo"
    ? "image/jpeg"
    : "video/mp4";

      const dataUrl = `data:${mimeType};base64,${buffer.toString("base64")}`;
  
      io.to(roomId).emit("receive_media", {
        mediaId,
        mediaType,
        dataUrl,
        fileName,
        fileSize,
        senderId: userData.id,
        nickname: userData.nickname,
        cost
      });
  
      mediaBuffers.delete(mediaId);
    }
  });
  
    
    

  

  /* ===== COIN TRANSFER (OPO Emoji) ===== */
  socket.on("coin-transfer", (data) => {
    const { roomId, fromUserId, toUserId, amount, type } = data;
    const userData = state.users.get(socket.id);
    
    if (!userData || userData.id !== fromUserId) {
      socket.emit('error', { message: 'Unauthorized transfer' });
      return;
    }
    
    const room = state.rooms.get(roomId);
    if (!room || !room.users.has(socket.id)) {
      socket.emit('error', { message: 'Not in room' });
      return;
    }
    
    // Check if user has enough coins
    if (userData.coins < amount) {
      socket.emit('error', { message: 'Insufficient coins' });
      return;
    }
    
    // Find receiver in room
    let receiverSocketId = null;
    let receiverData = null;
    
    for (const roomSocketId of room.users) {
      const roomUserData = state.users.get(roomSocketId);
      if (roomUserData && roomUserData.id === toUserId) {
        receiverSocketId = roomSocketId;
        receiverData = roomUserData;
        break;
      }
    }
    
    if (!receiverData) {
      socket.emit('error', { message: 'Receiver not found' });
      return;
    }
    
    // Update sender's coins
    userData.coins = (userData.coins || 0) - amount;
    userData.lastActivity = Date.now();
    state.users.set(socket.id, userData);
    
    // Update receiver's coins
    receiverData.coins = (receiverData.coins || 0) + amount;
    receiverData.lastActivity = Date.now();
    
    if (receiverSocketId) {
      state.users.set(receiverSocketId, receiverData);
    }
    
    // Emit coin updates
    socket.emit("coin-update", {
      userId: userData.id,
      coins: userData.coins,
      change: -amount,
      type: 'transfer'
    });
    
    if (receiverSocketId) {
      const receiverSocket = io.sockets.sockets.get(receiverSocketId);
      if (receiverSocket) {
        receiverSocket.emit("coin-update", {
          userId: receiverData.id,
          coins: receiverData.coins,
          change: amount,
          type: 'transfer'
        });
        
        receiverSocket.emit("coin-transfer", {
          fromUserId: userData.id,
          fromNickname: userData.nickname,
          toUserId: receiverData.id,
          amount: amount,
          type: type,
          remainingCoins: receiverData.coins
        });
      }
    }
    
    // Broadcast to room
    socket.to(roomId).emit("coin-transfer", {
      fromUserId: userData.id,
      fromNickname: userData.nickname,
      toUserId: receiverData.id,
      amount: amount,
      type: type
    });
    
    logSecurityEvent('COIN_TRANSFER', {
      roomId,
      fromUserId: userData.id,
      toUserId: receiverData.id,
      amount,
      type,
      senderCoins: userData.coins,
      receiverCoins: receiverData.coins
    });
    
    // Update admin panel
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
  });
  
  /* ===== COINS DEDUCTED (for media uploads) ===== */
  socket.on("coins-deducted", (data) => {
    const { amount, type, newBalance, roomId, userId } = data;
    const userData = state.users.get(socket.id);
    
    if (!userData || userData.id !== userId) {
      socket.emit('error', { message: 'Unauthorized' });
      return;
    }
    
    // Update user coins
    userData.coins = newBalance || ((userData.coins || 0) - amount);
    userData.lastActivity = Date.now();
    state.users.set(socket.id, userData);
    
    // Broadcast to room
    if (roomId) {
      socket.to(roomId).emit("user-data-update", {
        userId: userData.id,
        coins: userData.coins
      });
    }
    
    logSecurityEvent('COINS_DEDUCTED', {
      userId: userData.id,
      amount,
      type,
      newBalance: userData.coins,
      roomId
    });
  });
  
  /* ===== SEND MEDIA ===== */
  
  
  /* ===== ASSIGN BADGE (Admin function) ===== */
  socket.on("assign-badge", (data) => {
    const { roomId, targetUserId, badge, adminId } = data;
    const userData = state.users.get(socket.id);
    
    if (!userData || !userData.isAdmin) {
      socket.emit('error', { message: 'Not authorized' });
      return;
    }
    
    // Find target user in state.users
    let targetSocketId = null;
    let targetUserData = null;
    
    for (const [socketId, user] of state.users) {
      if (user.id === targetUserId) {
        targetSocketId = socketId;
        targetUserData = user;
        break;
      }
    }
    
    if (!targetUserData) {
      socket.emit('error', { message: 'User not found' });
      return;
    }
    
    // Update badge
    targetUserData.badges = badge;
    targetUserData.lastActivity = Date.now();
    
    // Update in state
    if (targetSocketId) {
      state.users.set(targetSocketId, targetUserData);
    }
    
    // Emit badge assignment
    if (targetSocketId) {
      const targetSocket = io.sockets.sockets.get(targetSocketId);
      if (targetSocket) {
        targetSocket.emit("badge-assigned", {
          userId: targetUserData.id,
          badge: badge,
          assignedBy: userData.id,
          assignedAt: Date.now()
        });
      }
    }
    
    // Broadcast to room if applicable
    if (roomId) {
      io.to(roomId).emit("badge-assigned", {
        userId: targetUserData.id,
        badge: badge
      });
    }
    
    logAdminAction(socket.id, "ASSIGN_BADGE", {
      targetUserId,
      badge,
      roomId
    });
    
    // Update admin panel
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
  });
  
  /* ===== SUBMIT REPORT (Updated) ===== */
  socket.on("submit-report", (data) => {
    const { 
      roomId, 
      targetUserId, 
      reason, 
      description, 
      reporterId, 
      reporterNickname 
    } = data;
    
    const userData = state.users.get(socket.id);
    
    if (!userData) {
      socket.emit('error', { message: 'User session not found' });
      return;
    }
    
    // Find target user
    let targetUserData = null;
    for (const [_, user] of state.users) {
      if (user.id === targetUserId) {
        targetUserData = user;
        break;
      }
    }
    
    const report = {
      id: `report_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      reporterId: reporterId,
      reporterNickname: reporterNickname,
      reporterSocketId: socket.id,
      targetUserId: targetUserId,
      targetNickname: targetUserData?.nickname || 'Unknown',
      reason: (reason || 'No reason provided').slice(0, 500),
      description: (description || '').slice(0, 1000),
      roomId: roomId,
      reporterIP: userData.ip,
      reporterToken: userData.token,
      timestamp: Date.now(),
      status: 'pending'
    };
    
    state.reports.unshift(report);
    
    // Notify admins
    io.to('admins').emit('new-report', report);
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
    
    // Confirm to reporter
    socket.emit("report-received", { 
      success: true, 
      reportId: report.id,
      message: 'Report submitted successfully'
    });
    
    // Notify target if in same room
    if (roomId) {
      const room = state.rooms.get(roomId);
      if (room) {
        // Find target socket in room
        for (const roomSocketId of room.users) {
          const roomUserData = state.users.get(roomSocketId);
          if (roomUserData && roomUserData.id === targetUserId) {
            const targetSocket = io.sockets.sockets.get(roomSocketId);
            if (targetSocket) {
              targetSocket.emit("report-notification", {
                message: 'You have been reported by another user',
                reason: reason,
                reportId: report.id
              });
            }
            break;
          }
        }
      }
    }
    
    logSecurityEvent('USER_REPORTED', report);
    
    // Log to file
    logToFile("reports.log", report);
  });
  
  /* ===== WEBRTC SIGNALING ===== */
  
  
  socket.on("signal", (data) => {
    
    
    if (isRateLimited(socket.id, "signal")) {
      console.warn(`Signal rate limited: ${socket.id}`);
      return;
    }
  
    // Normalize payload
    const { room, roomId, to, sdp, candidate, type } = data;
    const targetRoom = room || roomId;
  
    const userData = state.users.get(socket.id);
    if (!userData) return;
  
    // Validate SDP type
    if (sdp && !["offer", "answer"].includes(sdp.type)) {
      console.warn(`Invalid SDP type: ${sdp.type}`);
      return;
    }
  
    // Validate room membership if room-based signaling
    if (targetRoom) {
      const roomData = state.rooms.get(targetRoom);
      if (!roomData || !roomData.users.has(socket.id)) {
        console.warn(`User ${socket.id} not in room ${targetRoom}`);
        return;
      }
      roomData.lastActivity = Date.now();
    }
  
    /* =======================
       🔹 DIRECT PEER SIGNALING
       ======================= */
    if (to) {
      // Send to specific peer
      const targetSocket = io.sockets.sockets.get(to);
      if (targetSocket && targetSocket.connected) {
        targetSocket.emit("signal", {
          from: socket.id,
          roomId: targetRoom,
          sdp,
          candidate,
          type: type || "webrtc",
          timestamp: Date.now()
        });
      }
      return;
    }
  
    /* =======================
       🔹 GROUP MESH SIGNALING
       ======================= */
    if (targetRoom) {
      const roomData = state.rooms.get(targetRoom);
      if (!roomData) return;
  
      // Send to ALL other peers in the room (mesh networking)
      for (const peerSocketId of roomData.users) {
        if (peerSocketId !== socket.id) {
          const peerSocket = io.sockets.sockets.get(peerSocketId);
          if (peerSocket && peerSocket.connected) {
            peerSocket.emit("signal", {
              from: socket.id,
              roomId: targetRoom,
              sdp,
              candidate,
              type: type || "webrtc",
              timestamp: Date.now()
            });
          }
        }
      }
    }
  });
  
  /* ===== REQUEST PEER LIST ===== */
  socket.on("request-peers", (data) => {
    const { roomId } = data;
    const userData = state.users.get(socket.id);
    
    if (!userData || !roomId) return;
    
    const room = state.rooms.get(roomId);
    if (!room || !room.users.has(socket.id)) return;
    
    // Get all other peers in the room with their data
    const peers = Array.from(room.users)
      .filter(id => id !== socket.id)
      .map(peerId => {
        const peerData = state.users.get(peerId);
        return {
          socketId: peerId,
          userId: peerData?.id,
          nickname: peerData?.nickname || 'Anonymous',
          coins: peerData?.coins || 0,
          badges: peerData?.badges || null,
          isAdmin: peerData?.isAdmin || false,
          isCreator: peerData?.isCreator || false,
          country: peerData?.country
        };
      });
    
    socket.emit("existing-peers", {
      roomId,
      peers,
      total: peers.length,
      
    });
  });
  
  /* ===== SKIP/LEAVE ===== */
  socket.on("skip", (data) => {
    if (isRateLimited(socket.id, "skip")) {
      socket.emit('error', { 
        message: 'Too many skips. Please wait a moment.' 
      });
      return;
    }
    
    const userData = state.users.get(socket.id);
    if (!userData) return;
    
    const mode = data?.mode || userData.mode || 'text';
    const tags = data?.tags || userData.tags || [];
    
    // Leave all rooms
    userData.rooms.forEach(roomId => {
      const roomData = state.rooms.get(roomId);
      if (roomData) {
        // Notify other users
        socket.to(roomId).emit("partner-left", {
          partnerId: userData.id,
          partnerName: userData.name,
          roomId: roomId
        });
        
        // Remove from room
        removeUserFromRoom(socket.id, roomId, "skipped");
        socket.leave(roomId);
      }
    });
    
    // Clear user rooms
    userData.rooms.clear();
    
    // Remove from waiting queues
    for (const modeKey in state.waiting) {
      state.waiting[modeKey].delete(socket.id);
    }
    
    // Rejoin matching queue with same mode and tags
    if (mode && userData) {
      userData.mode = mode;
      userData.tags = tags;
      userData.lastActivity = Date.now();
      
      if (mode.startsWith('group_')) {
        handleGroupJoin(socket, mode, userData);
      } else {
        handleOneOnOneJoin(socket, mode, userData);
      }
    } else {
      // Send waiting status if no mode
      socket.emit("waiting");
    }
    
    logSecurityEvent('USER_SKIPPED', {
      userId: userData.id,
      name: userData.name,
      mode: mode
    });
    
    // Update admin panel
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
  });
  
  /* ===== GROUP CHAT EVENTS (UPDATED) ===== */
  socket.on("create-group", (data) => {
    const { 
      mode = 'group_text', 
      nickname = 'Anonymous', 
      tags = [], 
      coins = 0, 
      badges = null, 
      userId, 
      isCreator = false 
    } = data;
    
    const userData = state.users.get(socket.id);
    
    if (!userData) {
      socket.emit('error', { message: 'User session not found' });
      return;
    }
    
    userData.nickname = nickname;
    userData.coins = coins || userData.coins || 0;
    userData.badges = badges || userData.badges || null;
    userData.mode = mode;
    
    userData.isCreator = isCreator || false;
    userData.lastActivity = Date.now();
    
    handleGroupJoin(socket, mode, userData);
  });
  
  socket.on("join-group", (data) => {
    const { 
      roomId, 
      mode = 'group_text', 
      nickname = 'Anonymous', 
      coins = 0, 
      badges = null, 
      userId, 
      isCreator = false 
    } = data;
    
    const userData = state.users.get(socket.id);
    
    if (!userData) {
      socket.emit('error', { message: 'User session not found' });
      return;
    }
    
    // Update user data with provided values
    userData.nickname = nickname;
    userData.mode = mode;
    userData.coins = coins || userData.coins || 0;
    userData.badges = badges || userData.badges || null;
    
    userData.isCreator = isCreator || false;
    userData.lastActivity = Date.now();
    
    const room = state.rooms.get(roomId);
    if (room && room.status === 'active' && room.users.size < ROOM_MAX_SIZE[room.mode]) {
      if (addUserToRoom(socket.id, roomId, userData)) {
        userData.rooms.add(roomId);
        socket.join(roomId);
        
        // Get message history
        const messageHistory = state.messageHistory.get(roomId) || [];
        
        // Get existing peers info
        const existingPeers = Array.from(room.users)
          .filter(id => id !== socket.id)
          .map(peerId => {
            const peerData = state.users.get(peerId);
            return {
              socketId: peerId,
              userId: peerData?.id,
              nickname: peerData?.nickname || 'Anonymous',
              coins: peerData?.coins || 0,
              badges: peerData?.badges || null
            };
          });
        
        // Check admin status
        const isAdmin = userData.isAdmin || false;
        
        socket.emit("group-joined", { 
          roomId, 
          mode: room.mode,
          nickname: userData.nickname,
          coins: userData.coins,
          badges: userData.badges,
          participants: room.participants.map(p => p.name),
          participantCount: room.users.size,

          maxSize: ROOM_MAX_SIZE[room.mode],
          existingPeers: existingPeers,
          messageHistory: messageHistory.slice(-MESSAGE_HISTORY_SIZE),
          isAdmin: isAdmin,
          isCreator: userData.isCreator,
          
        });
        
        // Notify others
        socket.to(roomId).emit("user-joined", {
          userId: userData.id,
          nickname: userData.nickname,
          coins: userData.coins,
          badges: userData.badges,
          participantCount: room.users.size,
          socketId: socket.id
        });
        
        // Broadcast user data update
        socket.to(roomId).emit("user-data-update", {
          userId: userData.id,
          nickname: userData.nickname,
          coins: userData.coins,
          badges: userData.badges,
          isAdmin: isAdmin,
          isCreator: userData.isCreator
        });
        
      } else {
        socket.emit('error', { message: 'Room is full' });
      }
    } else {
      socket.emit('error', { message: 'Room not found or unavailable' });
    }
  });
  
  /* ===== LEAVE GROUP ===== */
  socket.on("leave-group", (data) => {
    const { roomId, userId } = data;
    const userData = state.users.get(socket.id);
    
    if (!userData) return;
    
    if (roomId) {
      const room = state.rooms.get(roomId);
      if (room && room.users.has(socket.id)) {
        // Notify others in room
        socket.to(roomId).emit("user-left", {
          userId: userData.id,
          nickname: userData.nickname,
          participantCount: room.users.size - 1,
          roomId: roomId
        });
        
        // Remove from room
        removeUserFromRoom(socket.id, roomId, "left");
        socket.leave(roomId);
        userData.rooms.delete(roomId);
        
        // Clear user mode
        userData.mode = null;
        userData.lastActivity = Date.now();
      }
    } else {
      // Leave all rooms
      userData.rooms.forEach(roomId => {
        const roomData = state.rooms.get(roomId);
        if (roomData) {
          socket.to(roomId).emit("user-left", {
            userId: userData.id,
            nickname: userData.nickname,
            participantCount: roomData.users.size - 1,
            roomId: roomId
          });
          
          removeUserFromRoom(socket.id, roomId, "left");
          socket.leave(roomId);
        }
      });
      
      // Clear all rooms
      userData.rooms.clear();
      userData.mode = null;
      userData.lastActivity = Date.now();
    }
    
    // Update admin panel
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
  });
  
  /* ===== TYPING INDICATOR ===== */
  socket.on("typing", (data) => {
    if (isRateLimited(socket.id, "typing")) return;
    
    const { room, isTyping } = data;
    const roomId = room;
    const userData = state.users.get(socket.id);
    
    if (!roomId || !userData) return;
    
    const roomData = state.rooms.get(roomId);
    if (!roomData || !roomData.users.has(socket.id)) return;
    
    socket.to(roomId).emit("user-typing", {
      userId: socket.id,
      userName: userData.name,
      isTyping: Boolean(isTyping)
    });
  });
  
  /* ===== REQUEST MESSAGE HISTORY ===== */
  socket.on("request-history", (data) => {
    const { roomId, limit = MESSAGE_HISTORY_SIZE } = data;
    const userData = state.users.get(socket.id);
    
    if (!userData || !roomId) return;
    
    const room = state.rooms.get(roomId);
    if (!room || !room.users.has(socket.id)) return;
    
    const history = state.messageHistory.get(roomId) || [];
    socket.emit("message-history", {
      roomId,
      messages: history.slice(-limit),
      total: history.length
    });
  });
  
  /* ===== ADMIN EVENTS ===== */
  socket.on("admin-auth", (data) => {
    const { username, password, adminKey } = data;
    
    if (username === ADMIN_CREDENTIALS.username && 
        password === ADMIN_CREDENTIALS.password &&
        adminKey === ADMIN_CREDENTIALS.adminKey) {
      
      state.admins.add(socket.id);
      socket.join('admins');
      
      socket.emit("admin-auth-success", {
        message: "Admin authentication successful",
        permissions: ["view", "ban", "unban", "view_logs", "view_reports", "end_rooms"],
        
      });
      
      // Send current state
      socket.emit("admin-state", getPublicStateForAdmin());
      
      logAdminAction(socket.id, "ADMIN_LOGIN", { 
        ip: getUserIP(socket),
        userAgent: socket.handshake.headers['user-agent'] 
      });
      
    } else {
      socket.emit("admin-auth-failed", {
        error: "Invalid admin credentials"
      });
      
      logSecurityEvent('FAILED_ADMIN_LOGIN', {
        socketId: socket.id,
        ip: getUserIP(socket),
        attemptedUsername: username
      });
    }
  });
  
  socket.on("admin-command", (data) => {
    if (!state.admins.has(socket.id)) {
      socket.emit("error", { message: "Not authorized" });
      return;
    }
    
    const { command, ...params } = data;
    
    switch (command) {
      case "get-stats":
        socket.emit("admin-stats", getPublicStateForAdmin());
        break;
        
      case "ban-user":
        if (params.userId) {
          const banData = {
            type: "user",
            value: params.userId,
            reason: params.reason || "Admin action",
            bannedAt: Date.now(),
            bannedBy: socket.id,
            duration: params.duration || null,
            expiresAt: params.duration ? Date.now() + (params.duration * 1000) : null
          };
          state.blockedUsers.set(params.userId, banData);
          logAdminAction(socket.id, "BAN_USER", params);
          socket.emit("command-success", { command, ...params });
        }
        break;
        
      case "unban-user":
        if (params.userId) {
          const success = state.blockedUsers.delete(params.userId);
          if (success) {
            logAdminAction(socket.id, "UNBAN_USER", params);
            socket.emit("command-success", { command, ...params });
          } else {
            socket.emit("error", { message: "User not found in ban list" });
          }
        }
        break;
        
      case "get-logs":
        const limit = params.limit || 100;
        socket.emit("admin-logs", {
          security: state.securityLogs.slice(0, limit),
          totalLogs: state.securityLogs.length
        });
        break;
        
      case "end-room":
        if (params.roomId) {
          const room = state.rooms.get(params.roomId);
          if (room) {
            endRoom(params.roomId, "admin_terminated");
            logAdminAction(socket.id, "END_ROOM", params);
            socket.emit("command-success", { command, ...params });
          } else {
            socket.emit("error", { message: "Room not found" });
          }
        }
        break;
        
      case "kick-user":
        if (params.roomId && params.userId) {
          const room = state.rooms.get(params.roomId);
          if (room) {
            const userSocket = Array.from(room.users).find(socketId => {
              const user = state.users.get(socketId);
              return user && user.id === params.userId;
            });
            
            if (userSocket) {
              const userSocketObj = io.sockets.sockets.get(userSocket);
              if (userSocketObj) {
                userSocketObj.emit("kicked", { reason: params.reason || "Admin action" });
                userSocketObj.leave(params.roomId);
              }
              
              removeUserFromRoom(userSocket, params.roomId, "kicked_by_admin");
              logAdminAction(socket.id, "KICK_USER", params);
              socket.emit("command-success", { command, ...params });
            } else {
              socket.emit("error", { message: "User not found in room" });
            }
          } else {
            socket.emit("error", { message: "Room not found" });
          }
        }
        break;
        
      default:
        socket.emit("error", { message: "Unknown command" });
    }
    
    // Update all admins
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
  });
  
  /* ===== PING/PONG ===== */
  socket.on("ping", () => {
    const userData = state.users.get(socket.id);
    if (userData) {
      userData.lastActivity = Date.now();
    }
    socket.emit("pong", { timestamp: Date.now() });
  });
  
  /* ===== DISCONNECT HANDLER ===== */
  socket.on("disconnect", (reason) => {
    const userData = state.users.get(socket.id);
    
    if (userData) {
      // Leave all rooms
      userData.rooms.forEach(roomId => {
        const roomData = state.rooms.get(roomId);
        if (roomData) {
          // Notify other users
          socket.to(roomId).emit("partner-disconnected", {
            partnerId: userData.id,
            partnerName: userData.name,
            roomId: roomId,
            reason: reason
          });
          
          // Remove from room
          removeUserFromRoom(socket.id, roomId, "disconnected");
        }
      });
      
      // Remove from waiting queues
      for (const mode in state.waiting) {
        state.waiting[mode].delete(socket.id);
      }
      
      // Remove from admins
      if (state.admins.has(socket.id)) {
        state.admins.delete(socket.id);
        socket.leave('admins');
        logAdminAction(socket.id, "ADMIN_LOGOUT", { reason });
      }
      
      // Remove rate limit tracking
      state.socketRateLimits.delete(socket.id);
      
      // Remove user
      state.users.delete(socket.id);
      
      logSecurityEvent('USER_DISCONNECTED', {
        userId: userData.id,
        socketId: socket.id,
        ip: userData.ip,
        reason: reason,
        duration: Date.now() - userData.connectedAt,
        rooms: Array.from(userData.rooms)
      });
    }
    
    // Remove from queue if present
    state.connectionQueue = state.connectionQueue.filter(s => s.id !== socket.id);
    
    // Update online count and admin panel
    io.emit("online_count", { count: state.users.size });
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
    
    // Process queue if space is available
    if (state.users.size < MAX_USERS) {
      processQueue();
    }
  });
});

/* ================= PERIODIC CLEANUP ================= */
setInterval(() => {
  const now = Date.now();
  const oneHourAgo = now - (60 * 60 * 1000);
  const fiveMinutesAgo = now - (5 * 60 * 1000);
  const thirtyMinutesAgo = now - (30 * 60 * 1000);
  const twentyFourHoursAgo = now - (24 * 60 * 60 * 1000);
  
  // Clean up old rooms
  for (const [roomId, room] of state.rooms) {
    if (room.status === 'ended' && room.endedAt < oneHourAgo) {
      state.rooms.delete(roomId);
      state.messageHistory.delete(roomId);
    }
    
    // Clean up inactive rooms (no activity for 30 minutes)
    if (room.status === 'active' && room.lastActivity < thirtyMinutesAgo) {
      endRoom(roomId, "inactivity");
    }
  }
  
  // Clean up users waiting too long (5+ minutes)
  for (const mode in state.waiting) {
    for (const [socketId, userData] of state.waiting[mode].entries()) {
      if (userData.waitingSince && userData.waitingSince < fiveMinutesAgo) {
        state.waiting[mode].delete(socketId);
      
        const socket = io.sockets.sockets.get(socketId);
        if (socket) {
          socket.emit('waiting-timeout');
        }
      }
    }
  }
  
  // Clean up old rate limit data (older than 2 minutes)
  for (const [socketId, limits] of state.socketRateLimits.entries()) {
    for (const type in limits) {
      if (now - limits[type].firstRequest > 120000) {
        delete limits[type];
      }
    }
    if (Object.keys(limits).length === 0) {
      state.socketRateLimits.delete(socketId);
    }
  }
  
  // Clean up expired bans
  for (const [userId, banData] of state.blockedUsers.entries()) {
    if (banData.expiresAt && now > banData.expiresAt) {
      state.blockedUsers.delete(userId);
    }
  }
  
  for (const [ip, banData] of state.blockedIPs.entries()) {
    if (banData.expiresAt && now > banData.expiresAt) {
      state.blockedIPs.delete(ip);
    }
  }
  
  for (const [token, banData] of state.blockedTokens.entries()) {
    if (banData.expiresAt && now > banData.expiresAt) {
      state.blockedTokens.delete(token);
    }
  }
  
  // Clean up old reports and logs
  if (state.reports.length > 1000) {
    state.reports = state.reports.slice(0, 1000);
  }
  
  if (state.securityLogs.length > 2000) {
    // Archive old logs before removing
    const logsToArchive = state.securityLogs.slice(1000);
    state.securityLogs = state.securityLogs.slice(0, 2000);
    
    // Async archive
    logToFile("security-archive.log", {
      archivedAt: now,
      logs: logsToArchive
    });
  }
  
  // Clean up inactive users (no activity for 1 hour but still connected)
  for (const [socketId, userData] of state.users.entries()) {
    if (userData.lastActivity && (now - userData.lastActivity) > 3600000) {
      const socket = io.sockets.sockets.get(socketId);
      if (socket) {
        socket.disconnect(true);
      }
    }
  }
  
  // Backup state every hour
  if (now % (60 * 60 * 1000) < 5000) { // Roughly every hour
    backupState();
  }
  
  // Update admin panel
  io.to('admins').emit('admin-state', getPublicStateForAdmin());
  
  // Log memory usage periodically
  const memoryUsage = process.memoryUsage();
  if (memoryUsage.heapUsed > 500 * 1024 * 1024) { // 500MB threshold
    console.warn(`⚠️  High memory usage: ${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`);
    logSecurityEvent('HIGH_MEMORY_USAGE', {
      heapUsed: memoryUsage.heapUsed,
      heapTotal: memoryUsage.heapTotal,
      rss: memoryUsage.rss
    });
  }
  
  // Log server stats every 5 minutes
  if (now % (5 * 60 * 1000) < 5000) {
    console.log(`📊 Server Stats: Users=${state.users.size}, Rooms=${state.rooms.size}, Queue=${state.connectionQueue.length}`);
  }
  
}, 30 * 1000); // Run every 30 seconds

/* ================= START SERVER ================= */
async function startServer() {
  await setupLogging();
  
  server.listen(PORT, HOST, () => {
    console.log(`
    🚀 ManaMingle Server Started!
    ==============================
    👉 Environment: ${NODE_ENV}
    👉 Domain: ${DOMAIN}
    👉 Main URL: http://${HOST}:${PORT}
    👉 Admin Panel: http://${HOST}:${PORT}/admin
    👉 Health Check: http://${HOST}:${PORT}/health
    👉 👉 TURN Endpoint: http://${HOST}:${PORT}/api/turn
 Servers: http://${HOST}:${PORT}/ice-servers
    
    📊 Room Limits:
    • 1-on-1 Text/Video/Audio: 2 users
    • Group Text Chat: 6 users
    • Group Video Chat: 4 users
    
    ⚠️  ${NODE_ENV === 'production' ? 'PRODUCTION MODE' : 'DEVELOPMENT MODE'}
    ⚠️  ${ADMIN_CREDENTIALS.password === 'ChangeMe123!' ? 'CHANGE DEFAULT ADMIN CREDENTIALS!' : 'Admin credentials set'}
    
    📈 Starting with:
    • Max Users: ${MAX_USERS}
    • Queue Size: ${MAX_QUEUE_SIZE}
    • Rate Limit: ${RATE_LIMIT_MAX} req/${RATE_LIMIT_WINDOW/1000}s
    `);
  });
}

startServer().catch(console.error);

/* ================= ERROR HANDLING ================= */
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err);
  logSecurityEvent('SERVER_ERROR', { 
    error: err.message, 
    stack: err.stack 
  });
  logToFile("errors.log", { 
    type: 'uncaughtException', 
    error: err.message, 
    stack: err.stack,
    timestamp: Date.now() 
  });
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('UNHANDLED REJECTION at:', promise, 'reason:', reason);
  logSecurityEvent('UNHANDLED_REJECTION', { 
    reason: String(reason) 
  });
  logToFile("errors.log", { 
    type: 'unhandledRejection', 
    reason: String(reason),
    timestamp: Date.now() 
  });
});

// Graceful shutdown
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

function gracefulShutdown() {
  console.log('🛑 Received shutdown signal. Closing server...');
  
  // Notify all users
  io.emit('server-shutdown', { 
    message: 'Server is restarting. Please reconnect in a moment.',
    timestamp: Date.now(),
    reconnectDelay: 5000
  });
  
  // Close all rooms
  for (const [roomId, room] of state.rooms) {
    if (room.status === 'active') {
      endRoom(roomId, 'server_maintenance');
    }
  }
  
  // Save final backup
  backupState();
  
  logToFile("shutdown.log", {
    timestamp: Date.now(),
    rooms: state.rooms.size,
    users: state.users.size,
    reports: state.reports.length,
    reason: "graceful_shutdown"
  });
  
  // Give time for cleanup
  setTimeout(() => {
    io.close(() => {
      console.log('✅ Socket.IO closed');
    });
    
    server.close(() => {
      console.log('✅ HTTP server closed gracefully');
      process.exit(0);
    });
  }, 5000);
}

module.exports = { server, io, state };