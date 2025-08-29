// index.js
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");

const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "secretkey";

/** 과정 정규화(간단) */
const COURSE_MAP = {
  "학부연구생": "UNDERGRAD",
  "석사과정":   "MASTER",
  "박사과정":   "PHD",
  "박사님":     "DOCTOR",
  "교수님":     "PROFESSOR",
  "UNDERGRAD":  "UNDERGRAD",
  "MASTER":     "MASTER",
  "PHD":        "PHD",
  "DOCTOR":     "DOCTOR",
  "PROFESSOR":  "PROFESSOR",
};
function normalizeCourse(raw) {
  if (raw === null || raw === undefined) return null;
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

/** -----------------------
 * Authentication middleware
 * ---------------------*/
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

  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // payload expected to include { userId, studentId } when token was signed
    req.user = payload;
    req.userId = Number(payload.userId); // ensure numeric
    // console.log("[AUTH] token valid, payload:", payload);
    return next();
  } catch (err) {
    console.log("[AUTH] token verify failed:", err.message);
    req.user = null;
    req.userId = null;
    return next();
  }
}

/** -----------------------
 *  회원가입 / 로그인
 *  ---------------------*/
app.post("/signup", async (req, res) => {
  console.log("[SIGNUP] body:", req.body);
  let {
    name = "",
    studentId = "",
    email = "",
    course = "",
    username,
    userId,
    password = "",
    passwordConfirm,
  } = req.body || {};

  try {
    const finalUserId = (username ?? userId ?? "").toString().trim();
    if (!finalUserId) return res.status(400).json({ error: "userId(또는 username) 필수" });
    if (!String(studentId).trim()) return res.status(400).json({ error: "studentId 필수" });
    if (!password) return res.status(400).json({ error: "password 필수" });
    if (passwordConfirm !== undefined && password !== passwordConfirm) {
      return res.status(400).json({ error: "비밀번호가 일치하지 않습니다." });
    }
    const normCourse = normalizeCourse(course);
    if (!normCourse) {
      return res.status(400).json({ error: "course 값 불명(학부연구생/석사과정/박사과정/박사님/교수님 또는 영문)" });
    }
    const hashed = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: {
        name: (name || "").toString().trim(),
        studentId: String(studentId).trim(),
        email: (email || "").toString().trim().toLowerCase(),
        course: normCourse,
        userId: finalUserId,
        passwordHash: hashed,
      },
      // 가입 응답에 기본 식별자만 내려줌. 프론트는 /me로 추가 정보(이름 등)를 가져가면 됨.
      select: { id: true, userId: true, studentId: true, course: true },
    });
    res.json({ message: "회원가입 성공", user });
  } catch (err) {
    if (err && err.code === "P2002") return res.status(409).json({ error: "학번/아이디/이메일 중복" });
    console.error("[SIGNUP] error:", err && err.stack ? err.stack : err);
    res.status(400).json({ error: err.message || String(err) });
  }
});

// 추천 로그인 핸들러
app.post("/login", async (req, res) => {
  console.log("[LOGIN] body:", req.body);
  try {
    const { username, userId, password, email } = req.body || {};
    if (!password) return res.status(400).json({ error: "password 필수" });

    const lookup = (username ?? userId ?? email ?? "").toString().trim();
    if (!lookup) return res.status(400).json({ error: "userId(또는 username/email) 필수" });

    const user = await prisma.user.findFirst({
      where: { OR: [{ userId: lookup }, { studentId: lookup }, { email: lookup }] }
    });

    if (!user) {
      console.log("[LOGIN] user not found for lookup:", lookup);
      return res.status(401).json({ error: "아이디 또는 비밀번호 오류" });
    }

    if (!user.passwordHash) {
      console.error("[LOGIN] missing passwordHash for userId:", user.id);
      return res.status(500).json({ error: "서버 오류" });
    }

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: "아이디 또는 비밀번호 오류" });

    const token = jwt.sign({ userId: user.id, studentId: user.studentId }, JWT_SECRET, { expiresIn: "7d" });

    // Return token and user id for convenience. Front should call /me to get full user (incl. name).
    res.json({ message: "로그인 성공", token, userId: user.id });
  } catch (err) {
    console.error("[LOGIN] error:", err && err.stack ? err.stack : err);
    res.status(500).json({ error: "서버 오류" });
  }
});

// current user endpoint (프론트가 토큰으로 사용자 정보 조회할 때 사용)
app.get("/me", authMiddleware, async (req, res) => {
  try {
    if (!req.userId) return res.status(401).json({ error: "토큰 필요" });
    const u = await prisma.user.findUnique({
      where: { id: Number(req.userId) },
      select: { id: true, userId: true, studentId: true, name: true, email: true, course: true, createdAt: true }
    });
    if (!u) return res.status(404).json({ error: "사용자 없음" });
    res.json({ user: u });
  } catch (err) {
    console.error("[ME] error:", err && err.stack ? err.stack : err);
    res.status(500).json({ error: "서버 오류" });
  }
});

app.get("/healthz", (_, res) => res.send("ok"));

/** 개발용: 유저 확인 */
app.get("/debug/users", async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      take: 100,
      select: { id: true, userId: true, studentId: true, email: true, course: true, createdAt: true },
      orderBy: { id: "asc" },
    });
    res.json({ count: users.length, users });
  } catch (err) {
    console.error("[DEBUG USERS] error:", err && err.stack ? err.stack : err);
    res.status(500).json({ error: "서버 오류" });
  }
});

/** -----------------------
 *  좌석 / 예약 / PIN / 체크인 API
 *  ---------------------*/

/** 좌석 목록 (프론트용) */
app.get("/seats", async (req, res) => {
  try {
    const { room } = req.query;
    const where = room ? { room: String(room) } : {};
    const seats = await prisma.seat.findMany({
      where,
      orderBy: [{ room: "asc" }, { seatNumber: "asc" }],
    });
    res.json({ count: seats.length, seats });
  } catch (err) {
    console.error("[GET /seats] error:", err && err.stack ? err.stack : err);
    res.status(500).json({ error: "서버 오류" });
  }
});

/**
 * GET /reservations
 * optional query: room, userId, status, from, to, limit, offset
 * returns reservations with seat and user included
 */
app.get('/reservations', authMiddleware, async (req, res) => {
  try {
    const { room, userId, status, from, to, limit, offset } = req.query;

    const where = {};
    if (room) {
      // filter by seat.room
      where.seat = { room: String(room) };
    }
    if (userId) where.userId = Number(userId);
    if (status) where.status = String(status);

    if (from || to) {
      where.AND = [];
      if (from) where.AND.push({ endTime: { gte: new Date(String(from)) } });
      if (to) where.AND.push({ startTime: { lte: new Date(String(to)) } });
    }

    const take = limit ? Number(limit) : 200;
    const skip = offset ? Number(offset) : 0;

    const list = await prisma.reservation.findMany({
      where,
      include: {
        seat: true,
        user: { select: { id: true, userId: true, name: true, email: true } },
        pins: true,
      },
      orderBy: { startTime: 'asc' },
      take,
      skip,
    });

    res.json({ count: list.length, reservations: list });
  } catch (err) {
    console.error('[GET /reservations] error:', err && err.stack ? err.stack : err);
    res.status(500).json({ error: '서버 오류' });
  }
});

/** GET single reservation */
app.get('/reservations/:id', authMiddleware, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: "id 필수" });
    const r = await prisma.reservation.findUnique({
      where: { id },
      include: { seat: true, user: { select: { id: true, userId: true, name: true } }, pins: true, checkins: true }
    });
    if (!r) return res.status(404).json({ error: "예약 없음" });
    res.json({ reservation: r });
  } catch (err) {
    console.error('[GET /reservations/:id] error:', err && err.stack ? err.stack : err);
    res.status(500).json({ error: '서버 오류' });
  }
});

/**
 * 예약 생성
 * body: { seatId, startTime, endTime }
 * 인증: 권장 (토큰) -> token에서 userId 추출하여 사용
 * returns: reservation + (개발용으로 pin 반환하려면 ?dev=1)
 */
app.post("/reservations", authMiddleware, async (req, res) => {
  try {
    // auth user id 우선 사용, 없으면 body.userId 사용 (호환성)
    const authUserId = req.userId ? Number(req.userId) : (req.body.userId ? Number(req.body.userId) : null);
    if (!authUserId) return res.status(401).json({ error: "인증된 사용자 필요" });

    const { seatId, startTime, endTime } = req.body || {};
    if (!seatId || !startTime || !endTime) {
      return res.status(400).json({ error: "seatId/startTime/endTime 필수" });
    }

    const start = new Date(startTime);
    const end = new Date(endTime);
    if (isNaN(start) || isNaN(end) || start >= end) {
      return res.status(400).json({ error: "startTime/endTime 불량" });
    }

    // seat 고정석 여부 확인
    const seat = await prisma.seat.findUnique({ where: { id: Number(seatId) } });
    if (!seat) return res.status(404).json({ error: "Seat 없음" });
    if (seat.fixed) return res.status(400).json({ error: "이 좌석은 고정석(예약불가)입니다." });

    // 동일 좌석의 PENDING/CHECKED_IN 예약들 조사 (취소/종료된 건 제외)
    const existing = await prisma.reservation.findMany({
      where: {
        seatId: Number(seatId),
        status: { in: ["PENDING", "CHECKED_IN"] },
        AND: [
          { startTime: { lt: end } },
          { endTime: { gt: start } },
        ],
      },
    });

    // 허용 규칙: 겹치는 '총 겹친 시간'이 20분 이상이면 충돌로 간주
    const MS20MIN = 20 * 60 * 1000;
    for (const ex of existing) {
      const exStart = new Date(ex.startTime).getTime();
      const exEnd = new Date(ex.endTime).getTime();
      const overlapMs = Math.max(0, Math.min(exEnd, end.getTime()) - Math.max(exStart, start.getTime()));
      if (overlapMs >= MS20MIN) {
        return res.status(409).json({ error: "해당 시간대에 이미 예약이 있어 겹침(20분 이상)으로 예약 불가" });
      }
    }

    // 예약 생성 + PIN 발급 (트랜잭션)
    const pinPlain = String(Math.floor(100000 + Math.random() * 900000)); // 6자리 숫자
    const pinHash = await bcrypt.hash(pinPlain, 10);
    const pinExpiresAt = new Date(start.getTime() + MS20MIN); // 예약 시작부터 20분 유효

    const result = await prisma.$transaction(async (tx) => {
      const r = await tx.reservation.create({
        data: {
          seatId: Number(seatId),
          userId: Number(authUserId),
          startTime: start,
          endTime: end,
        },
      });
      await tx.pin.create({
        data: {
          reservationId: r.id,
          pinHash,
          expiresAt: pinExpiresAt,
        },
      });
      return r;
    });

    const dev = req.query.dev === "1" || req.query.dev === "true";
    const resp = { message: "예약 생성됨", reservation: result };
    if (dev) resp.devPin = pinPlain;
    res.status(201).json(resp);
  } catch (err) {
    console.error("[RESERVE] error:", err && err.stack ? err.stack : err);
    res.status(500).json({ error: "서버 오류" });
  }
});

/**
 * 체크인 (PIN 확인)
 * body: { reservationId, pin }
 * 인증: 권장 (토큰) -> token에서 userId를 우선 사용(입실 기록에 사용)
 */
app.post("/checkin", authMiddleware, async (req, res) => {
  try {
    const { reservationId, pin, userId: bodyUserId } = req.body || {};
    if (!reservationId || !pin) return res.status(400).json({ error: "reservationId/pin 필수" });

    // 예약 존재 확인 (그리고 reservation의 실제 userId 확보)
    const reservation = await prisma.reservation.findUnique({ where: { id: Number(reservationId) } });
    if (!reservation) return res.status(404).json({ error: "해당 예약 없음" });

    // 유효한(사용안된, 만료 안된) PIN 찾기 (reservationId에 속한 최근 PIN들)
    const pins = await prisma.pin.findMany({
      where: { reservationId: Number(reservationId), used: false, expiresAt: { gt: new Date() } },
      orderBy: { createdAt: "desc" },
      take: 10,
    });
    if (!pins || pins.length === 0) return res.status(400).json({ error: "사용 가능한 PIN 없음(만료되었거나 사용됨)" });

    // PIN 비교
    let matched = null;
    for (const p of pins) {
      const ok = await bcrypt.compare(String(pin), p.pinHash);
      if (ok) { matched = p; break; }
    }
    if (!matched) return res.status(401).json({ error: "PIN 불일치" });

    // 체크인 처리: 트랜잭션으로 pin.used = true, reservation.status = CHECKED_IN, checkin 레코드 생성
    // checkin.userId는 요청 바디(bodyUserId)가 있으면 그걸 우선, 없으면 토큰(req.userId) 사용, 없으면 reservation.userId
    const checkinUserId = bodyUserId ? Number(bodyUserId) : (req.userId ? Number(req.userId) : reservation.userId);

    const result = await prisma.$transaction(async (tx) => {
      await tx.pin.update({ where: { id: matched.id }, data: { used: true } });
      await tx.reservation.update({ where: { id: Number(reservationId) }, data: { status: "CHECKED_IN" } });
      const c = await tx.checkin.create({
        data: {
          reservationId: Number(reservationId),
          userId: Number(checkinUserId),
        },
      });
      return c;
    });

    return res.json({ message: "체크인 성공", checkin: result });
  } catch (err) {
    console.error("[CHECKIN] error:", err && err.stack ? err.stack : err);
    res.status(500).json({ error: "서버 오류" });
  }
});

/**
 * 퇴실 처리 (예약 상태 FINISHED, endedAt 업데이트)
 * body: { reservationId }
 * 인증: 권장
 */
app.post("/checkout", authMiddleware, async (req, res) => {
  try {
    const { reservationId } = req.body || {};
    if (!reservationId) return res.status(400).json({ error: "reservationId 필수" });

    const r = await prisma.reservation.update({
      where: { id: Number(reservationId) },
      data: { status: "FINISHED", endedAt: new Date() },
    });
    res.json({ message: "퇴실 처리 완료", reservation: r });
  } catch (err) {
    console.error("[CHECKOUT] error:", err && err.stack ? err.stack : err);
    res.status(500).json({ error: "서버 오류" });
  }
});

/** 개발용: 예약/핀 확인 */
app.get("/debug/reservations", async (req, res) => {
  try {
    const list = await prisma.reservation.findMany({
      include: { pins: true, seat: true, user: true },
      orderBy: { id: "asc" },
      take: 200,
    });
    res.json({ count: list.length, reservations: list });
  } catch (err) {
    console.error("[DBG RES] error:", err && err.stack ? err.stack : err);
    res.status(500).json({ error: "서버 오류" });
  }
});

/** 예약 만료 작업 (개발용 - 간단한 주기 작업) */
async function expireReservationsJob() {
  try {
    const now = new Date();
    // PENDING 또는 CHECKED_IN 이지만 endTime 지남 -> EXPIRED (endedAt 기록)
    const result = await prisma.reservation.updateMany({
      where: {
        endTime: { lt: now },
        status: { in: ['PENDING', 'CHECKED_IN'] },
      },
      data: {
        status: 'EXPIRED',
        endedAt: now,
      }
    });
    if (result.count && result.count > 0) {
      console.log(`[expireJob] expired ${result.count} reservations`);
    }
  } catch (err) {
    console.error('[expireJob] error:', err && err.stack ? err.stack : err);
  }
}
// 개발/테스트: 1분마다 실행. 운영에서는 cron/worker로 옮기세요.
setInterval(expireReservationsJob, 60 * 1000);

/** -----------------------
 * 정적 파일 서빙 (SPA)
 *  - public/ 디렉터리에 빌드된 프론트 파일을 넣으세요.
 *  - 이 블록은 app.listen 호출 이전에 위치해야 합니다.
 * ---------------------*/
const publicDir = path.join(__dirname, 'public');
app.use(express.static(publicDir));

// SPA fallback: API 루트로 보이는 경로들은 건너뛰고, 그 외 GET 요청은 index.html로 응답
app.get('*', (req, res, next) => {
  const apiPrefixes = [
    '/signup', '/login', '/me', '/healthz', '/debug',
    '/seats', '/reservations', '/checkin', '/checkout'
  ];
  if (apiPrefixes.some(p => req.path.startsWith(p))) return next();
  if (req.method !== 'GET') return next();
  // 파일 요청(확장자 있는 경우)은 static handler에 맡김(404 등)
  if (path.extname(req.path)) return next();
  res.sendFile(path.join(publicDir, 'index.html'), err => {
    if (err) next(err);
  });
});

/** LAN 접근 허용 */
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 서버 실행 중: http://localhost:${PORT}`);
});

// 프로세스 종료 처리
process.on("SIGINT", async () => {
  console.log("Graceful shutdown - disconnecting prisma...");
  await prisma.$disconnect();
  process.exit(0);
});
