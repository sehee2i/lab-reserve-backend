const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const prisma = new PrismaClient();

const JWT_SECRET = process.env.JWT_SECRET || "secretkey";

// --- CORS ---
const allowedOrigin = process.env.FRONTEND_ORIGIN; 
app.use(
  cors({
    origin: allowedOrigin ? [allowedOrigin] : true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: false,
  })
);

app.use(express.json());

// ---------- 과정 정규화 ----------
const COURSE_MAP = {
  "학부연구생": "UNDERGRAD",
  "석사과정": "MASTER",
  "박사과정": "PHD",
  "박사님": "DOCTOR",
  "교수님": "PROFESSOR",
  UNDERGRAD: "UNDERGRAD",
  MASTER: "MASTER",
  PHD: "PHD",
  DOCTOR: "DOCTOR",
  PROFESSOR: "PROFESSOR",
};
function normalizeCourse(raw) {
  if (!raw) return null;
  const trimmed = String(raw).trim();
  const compact = trimmed.replace(/\s+/g, "");
  const upper = compact.toUpperCase();
  if (COURSE_MAP[trimmed]) return COURSE_MAP[trimmed];
  if (COURSE_MAP[compact]) return COURSE_MAP[compact];
  if (COURSE_MAP[upper]) return COURSE_MAP[upper];
  const lower = trimmed.toLowerCase();
  if (lower.includes("학부") || lower.includes("undergrad")) return "UNDERGRAD";
  if (lower.includes("석사") || lower.includes("master")) return "MASTER";
  if (lower.includes("박사과정") || lower.includes("phd")) return "PHD";
  if (lower.includes("박사") || lower.includes("doctor")) return "DOCTOR";
  if (lower.includes("교수") || lower.includes("prof")) return "PROFESSOR";
  return null;
}

// ---------- 인증 미들웨어 ----------
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (!authHeader) {
    req.user = null;
    req.userId = null;
    return next();
  }
  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    req.user = null;
    req.userId = null;
    return next();
  }
  try {
    const payload = jwt.verify(parts[1], JWT_SECRET);
    req.user = payload;
    req.userId = Number(payload.userId);
  } catch {
    req.user = null;
    req.userId = null;
  }
  return next();
}

// ---------- 회원가입 / 로그인 ----------
app.post("/signup", async (req, res) => {
  try {
    let { name = "", studentId = "", email = "", course = "", username, userId, password = "", passwordConfirm } =
      req.body || {};

    const finalUserId = (username ?? userId ?? "").trim();
    if (!finalUserId) return res.status(400).json({ error: "userId(또는 username) 필수" });
    if (!String(studentId).trim()) return res.status(400).json({ error: "studentId 필수" });
    if (!password) return res.status(400).json({ error: "password 필수" });
    if (passwordConfirm !== undefined && password !== passwordConfirm) {
      return res.status(400).json({ error: "비밀번호가 일치하지 않습니다." });
    }

    const normCourse = normalizeCourse(course);
    if (!normCourse) {
      return res.status(400).json({ error: "course 값 불명" });
    }

    const hashed = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: {
        name: name.trim(),
        studentId: String(studentId).trim(),
        email: email.trim().toLowerCase(),
        course: normCourse,
        userId: finalUserId,
        passwordHash: hashed,
      },
      select: { id: true, userId: true, studentId: true, course: true },
    });
    res.json({ message: "회원가입 성공", user });
  } catch (err) {
    if (err?.code === "P2002") return res.status(409).json({ error: "학번/아이디/이메일 중복" });
    res.status(400).json({ error: err.message || "서버 오류" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, userId, password, email } = req.body || {};
    if (!password) return res.status(400).json({ error: "password 필수" });
    const lookup = (username ?? userId ?? email ?? "").trim();
    if (!lookup) return res.status(400).json({ error: "userId(또는 username/email) 필수" });

    const user = await prisma.user.findFirst({
      where: { OR: [{ userId: lookup }, { studentId: lookup }, { email: lookup }] },
    });
    if (!user) return res.status(401).json({ error: "아이디 또는 비밀번호 오류" });
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: "아이디 또는 비밀번호 오류" });

    const token = jwt.sign({ userId: user.id, studentId: user.studentId }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ message: "로그인 성공", token, userId: user.id });
  } catch {
    res.status(500).json({ error: "서버 오류" });
  }
});

app.get("/me", authMiddleware, async (req, res) => {
  if (!req.userId) return res.status(401).json({ error: "토큰 필요" });
  const u = await prisma.user.findUnique({
    where: { id: req.userId },
    select: { id: true, userId: true, studentId: true, name: true, email: true, course: true, createdAt: true },
  });
  if (!u) return res.status(404).json({ error: "사용자 없음" });
  res.json({ user: u });
});

app.get("/healthz", (_, res) => res.send("ok"));

// ---------- 좌석 ----------
app.get("/seats", async (req, res) => {
  const seats = await prisma.seat.findMany({
    where: req.query.room ? { room: String(req.query.room) } : {},
    orderBy: [{ room: "asc" }, { seatNumber: "asc" }],
  });
  res.json({ count: seats.length, seats });
});

// ---------- 예약 ----------
app.get("/reservations", authMiddleware, async (req, res) => {
  const { room, userId, status, from, to, limit, offset } = req.query;
  const where = {};
  if (room) where.seat = { room: String(room) };
  if (userId) where.userId = Number(userId);
  if (status) where.status = String(status);
  if (from || to) {
    where.AND = [];
    if (from) where.AND.push({ endTime: { gte: new Date(String(from)) } });
    if (to) where.AND.push({ startTime: { lte: new Date(String(to)) } });
  }

  const list = await prisma.reservation.findMany({
    where,
    include: { seat: true },
    orderBy: { startTime: "asc" },
    take: limit ? Number(limit) : 200,
    skip: offset ? Number(offset) : 0,
  });

  const formatted = list.map(r => ({
    id: r.id,
    room: r.seat.room,
    seat: String(r.seat.seatNumber),
    userId: r.userId,
    status: r.status,
    startTime: r.startTime,
    endTime: r.endTime,
  }));
  res.json({ count: formatted.length, reservations: formatted });
});

app.post("/reservations", authMiddleware, async (req, res) => {
  try {
    const authUserId = req.userId || req.body.userId;
    if (!authUserId) return res.status(401).json({ error: "인증된 사용자 필요" });
    const { seatId, startTime, endTime } = req.body || {};
    if (!seatId || !startTime || !endTime) return res.status(400).json({ error: "seatId/startTime/endTime 필수" });

    const start = new Date(startTime), end = new Date(endTime);
    if (isNaN(start) || isNaN(end) || start >= end) return res.status(400).json({ error: "시간 불량" });

    const seat = await prisma.seat.findUnique({ where: { id: Number(seatId) } });
    if (!seat) return res.status(404).json({ error: "Seat 없음" });

    const MS20MIN = 20 * 60 * 1000;
    const pinPlain = String(Math.floor(100000 + Math.random() * 900000));
    const pinHash = await bcrypt.hash(pinPlain, 10);
    const pinExpiresAt = new Date(start.getTime() + MS20MIN);

    const result = await prisma.$transaction(async tx => {
      const r = await tx.reservation.create({ data: { seatId: seat.id, userId: Number(authUserId), startTime: start, endTime: end } });
      await tx.pin.create({ data: { reservationId: r.id, pinHash, expiresAt: pinExpiresAt } });
      return r;
    });

    const resp = { message: "예약 생성됨", reservation: result };
    if (req.query.dev === "1") resp.devPin = pinPlain;
    res.status(201).json(resp);
  } catch {
    res.status(500).json({ error: "서버 오류" });
  }
});

// ---------- 체크인 ----------
app.post("/checkin", authMiddleware, async (req, res) => {
  try {
    const { reservationId, pin } = req.body || {};
    if (!reservationId || !pin) return res.status(400).json({ error: "reservationId/pin 필수" });

    const reservation = await prisma.reservation.findUnique({ where: { id: Number(reservationId) } });
    if (!reservation) return res.status(404).json({ error: "Invalid PIN" });

    const pins = await prisma.pin.findMany({
      where: { reservationId: reservation.id, used: false, expiresAt: { gt: new Date() } },
      orderBy: { createdAt: "desc" }, take: 10,
    });
    let matched = null;
    for (const p of pins) {
      if (await bcrypt.compare(String(pin), p.pinHash)) { matched = p; break; }
    }
    if (!matched) return res.status(401).json({ error: "Invalid PIN" });

    await prisma.$transaction(async tx => {
      await tx.pin.update({ where: { id: matched.id }, data: { used: true } });
      await tx.reservation.update({ where: { id: reservation.id }, data: { status: "CHECKED_IN" } });
      await tx.checkin.create({ data: { reservationId: reservation.id, userId: req.userId } });
    });
    res.json({ message: "체크인 성공" });
  } catch {
    res.status(500).json({ error: "서버 오류" });
  }
});

// ---------- 퇴실 ----------
app.post("/checkout", authMiddleware, async (req, res) => {
  try {
    const { reservationId, password } = req.body || {};
    if (!reservationId || !password) return res.status(400).json({ error: "reservationId/password 필수" });

    const reservation = await prisma.reservation.findUnique({ where: { id: Number(reservationId) }, include: { user: true } });
    if (!reservation) return res.status(404).json({ error: "예약 없음" });
    if (reservation.userId !== req.userId) return res.status(403).json({ error: "권한 없음" });

    const ok = await bcrypt.compare(password, reservation.user.passwordHash || "");
    if (!ok) return res.status(401).json({ error: "비밀번호가 올바르지 않습니다." });

    const updated = await prisma.reservation.update({
      where: { id: reservation.id },
      data: { status: "FINISHED", endedAt: new Date() },
      include: { seat: true, user: true },
    });
    res.json({ message: "Checkout success", reservation: updated });
  } catch {
    res.status(500).json({ error: "서버 오류" });
  }
});

// ---------- 자동 상태 업데이트 ----------
async function expireReservationsJob() {
  try {
    const now = new Date();

    // 1. PENDING → 20분 지나면 EXPIRED
    const result1 = await prisma.reservation.updateMany({
      where: {
        status: "PENDING",
        startTime: { lt: new Date(now.getTime() - 20 * 60 * 1000) }, // 시작 +20분 초과
      },
      data: { status: "EXPIRED", endedAt: now },
    });

    // 2. CHECKED_IN → 4시간 지나면 FINISHED
    const result2 = await prisma.reservation.updateMany({
      where: {
        status: "CHECKED_IN",
        checkins: {
          some: { checkinTime: { lt: new Date(now.getTime() - 4 * 60 * 60 * 1000) } },
        },
      },
      data: { status: "FINISHED", endedAt: now },
    });

    // 3. 예약 종료시간이 지난데도 여전히 열려있는 경우도 마무리
    const result3 = await prisma.reservation.updateMany({
      where: {
        status: { in: ["PENDING", "CHECKED_IN"] },
        endTime: { lt: now },
      },
      data: { status: "EXPIRED", endedAt: now },
    });

    if (result1.count || result2.count || result3.count) {
      console.log(`[expireJob] expired=${result1.count}, finished=${result2.count}, forced=${result3.count}`);
    }
  } catch (err) {
    console.error("[expireJob] error:", err);
  }
}
// ---------- 서버 시작 ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => console.log(`🚀 서버 실행 중: http://localhost:${PORT}`));

// ---------- 종료 처리 ----------
process.on("SIGINT", async () => { await prisma.$disconnect(); process.exit(0); });
process.on("SIGTERM", async () => { await prisma.$disconnect(); process.exit(0); });

// ---------- 에러 핸들러 ----------
app.use((err, req, res, next) => {
  console.error("[UNCAUGHT ERROR]", err?.stack || err);
  res.status(500).json({ error: "서버 오류" });
});
