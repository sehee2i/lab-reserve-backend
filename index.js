// index.js (완전 대체본 — 기존 파일 덮어쓰기 가능)
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const prisma = new PrismaClient();

const JWT_SECRET = process.env.JWT_SECRET || "secretkey";

/* -------------------------------- CORS ---------------------------------- */
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

/* ------------------------------ 유틸 함수 ------------------------------- */
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
  const t = String(raw).trim();
  const c = t.replace(/\s+/g, "");
  const u = c.toUpperCase();
  if (COURSE_MAP[t]) return COURSE_MAP[t];
  if (COURSE_MAP[c]) return COURSE_MAP[c];
  if (COURSE_MAP[u]) return COURSE_MAP[u];
  const l = t.toLowerCase();
  if (l.includes("학부") || l.includes("undergrad")) return "UNDERGRAD";
  if (l.includes("석사") || l.includes("master")) return "MASTER";
  if (l.includes("박사과정") || l.includes("phd")) return "PHD";
  if (l.includes("박사") || l.includes("doctor")) return "DOCTOR";
  if (l.includes("교수") || l.includes("prof")) return "PROFESSOR";
  return null;
}
const iso = (d) => (d?.toISOString ? d.toISOString() : d);

/* ----------------------------- 인증 미들웨어 ---------------------------- */
function authMiddleware(req, res, next) {
  const h = req.headers.authorization || req.headers.Authorization;
  if (!h) {
    req.user = null;
    req.userId = null;
    return next();
  }
  const parts = h.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    req.user = null;
    req.userId = null;
    return next();
  }
  try {
    const payload = jwt.verify(parts[1], JWT_SECRET);
    req.user = payload;
    req.userId = Number(payload.userId);
  } catch (e) {
    req.user = null;
    req.userId = null;
  }
  return next();
}

/* ---------------------------- 회원가입 / 로그인 --------------------------- */
app.post("/signup", async (req, res) => {
  try {
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

    const finalUserId = (username ?? userId ?? "").trim();
    if (!finalUserId) return res.status(400).json({ error: "userId(또는 username) 필수" });
    if (!String(studentId).trim()) return res.status(400).json({ error: "studentId 필수" });
    if (!password) return res.status(400).json({ error: "password 필수" });
    if (passwordConfirm !== undefined && password !== passwordConfirm) {
      return res.status(400).json({ error: "비밀번호가 일치하지 않습니다." });
    }

    const normCourse = normalizeCourse(course);
    if (!normCourse) return res.status(400).json({ error: "course 값 불명" });

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

/* -------------------------------- 헬스체크 -------------------------------- */
app.get("/healthz", (_, res) => res.send("ok"));

/* --------------------------------- 좌석 ---------------------------------- */
app.get("/seats", async (req, res) => {
  const seats = await prisma.seat.findMany({
    where: req.query.room ? { room: String(req.query.room) } : {},
    orderBy: [{ room: "asc" }, { seatNumber: "asc" }],
  });
  res.json({ count: seats.length, seats });
});

/* ------------------------- 설정 상수 (TTL/제한값) ------------------------- */
const PENDING_TTL_MIN = 20; // PENDING 생성 후 20분 지나면 만료로 간주(재예약 허용)
const MAX_RESERVATION_HOURS = 3; // 예약(연장 포함) 최대 길이(시작부터)

/* -------------------------------- 예약 ----------------------------------- */
/* GET /reservations (unchanged signature) */
app.get("/reservations", async (req, res) => {
  try {
    const { room, userId, status, from, to, limit, offset } = req.query;

    const where = {};
    if (room) where.seat = { room: String(room) }; // note: filter by Seat.room
    if (userId) where.userId = Number(userId);
    if (status) where.status = String(status);
    if (from || to) {
      where.AND = [];
      if (from) where.AND.push({ endTime: { gte: new Date(String(from)) } });
      if (to) where.AND.push({ startTime: { lte: new Date(String(to)) } });
    }

    const list = await prisma.reservation.findMany({
      where,
      include: { Seat: true },
      orderBy: { startTime: "asc" },
      take: limit ? Number(limit) : 200,
      skip: offset ? Number(offset) : 0,
    });

    const formatted = list.map((r) => ({
      id: r.id,
      room: r.Seat?.room ?? null,
      seat: r.Seat ? String(r.Seat.seatNumber) : null,
      userId: r.userId,
      status: r.status,
      extended: r.extended, // include extended flag
      startTime: iso(r.startTime),
      endTime: iso(r.endTime),
    }));
    res.json({ count: formatted.length, reservations: formatted });
  } catch (err) {
    console.error("[RESERVATIONS GET] error:", err);
    res.status(500).json({ error: "서버 오류" });
  }
});

/* POST /reservations : 예약 생성 (기존 로직 유지 + 겹침 검사 개선) */
app.post("/reservations", authMiddleware, async (req, res) => {
  try {
    const authUserId = req.userId || req.body.userId;
    if (!authUserId) return res.status(401).json({ error: "인증된 사용자 필요" });

    const { seatId: rawSeatId, startTime: rawStart, endTime: rawEnd } = req.body || {};
    if (!rawSeatId || !rawStart || !rawEnd) {
      return res.status(400).json({ error: "seatId/startTime/endTime 필수" });
    }

    const seatId = Number(rawSeatId);
    const start = new Date(rawStart);
    const end = new Date(rawEnd);
    if (isNaN(start) || isNaN(end) || start >= end) {
      return res.status(400).json({ error: "시간 형식 불량" });
    }

    const seat = await prisma.seat.findUnique({ where: { id: Number(seatId) } });
    if (!seat) return res.status(404).json({ error: "Seat 없음" });
    if (seat.fixed) return res.status(400).json({ error: "이 좌석은 고정석(예약불가)입니다." });

    // --- PENDING TTL 처리: 오래된 PENDING은 만료로 정리(선택적 최적화)
    const pendingCutoff = new Date(Date.now() - PENDING_TTL_MIN * 60 * 1000);
    await prisma.reservation.updateMany({
      where: { status: "PENDING", createdAt: { lt: pendingCutoff } },
      data: { status: "EXPIRED" },
    });

    // --- 겹침 검사: CHECKED_IN 또는 (PENDING && createdAt within TTL)
    const blocking = await prisma.reservation.findFirst({
      where: {
        seatId,
        startTime: { lt: end }, // [start, end) 겹침 판정
        endTime: { gt: start },
        OR: [
          { status: "CHECKED_IN" },
          { status: "PENDING", createdAt: { gte: pendingCutoff } },
        ],
      },
      select: { id: true, status: true, createdAt: true },
    });

    if (blocking) {
      return res.status(409).json({
        error: "해당 시간대에 이미 예약이 있어 겹침(입실중 또는 20분 내 대기)으로 예약 불가",
      });
    }

    // --- 생성 및 PIN 발급 (원래 로직 유지)
    const MS20 = 20 * 60 * 1000;
    const pinPlain = String(Math.floor(100000 + Math.random() * 900000));
    const pinHash = await bcrypt.hash(pinPlain, 10);
    const pinExpiresAt = new Date(start.getTime() + MS20);

    const created = await prisma.$transaction(async (tx) => {
      const r = await tx.reservation.create({
        data: {
          seatId: seat.id,
          userId: Number(authUserId),
          startTime: start,
          endTime: end,
        },
        include: { Seat: true },
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

    const reservationForClient = {
      id: created.id,
      seatId: created.seatId,
      room: created.Seat?.room ?? null,
      seat: created.Seat ? String(created.Seat.seatNumber) : null,
      startTime: iso(created.startTime),
      endTime: iso(created.endTime),
      status: created.status,
    };

    const resp = { message: "예약 생성됨", reservation: reservationForClient };
    const dev = req.query.dev === "1" || req.query.dev === "true";
    if (dev) resp.devPin = pinPlain;

    res.status(201).json(resp);
  } catch (err) {
    console.error("[RESERVE] error:", err);
    res.status(500).json({ error: "서버 오류" });
  }
});

/* --------------------------------- 연장 ---------------------------------- */
/*
  POST /reservations/:id/extend
  - 인증된 본인 예약만
  - 예약 상태가 CHECKED_IN 이어야 함 (입실된 사람만 연장 가능)
  - 연장 허용 시간: (endTime - 20m) <= now <= endTime
  - 연장 한도: 시작시간으로부터 최대 3시간, 그리고 다음 예약 시작 직전까지
*/
app.post("/reservations/:id/extend", authMiddleware, async (req, res) => {
  try {
    if (!req.userId) return res.status(401).json({ error: "토큰 필요" });

    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: "유효한 예약 id 필요" });

    const reservation = await prisma.reservation.findUnique({
      where: { id },
      include: { Seat: true },
    });
    if (!reservation) return res.status(404).json({ error: "예약 없음" });

    if (reservation.userId !== req.userId) return res.status(403).json({ error: "권한 없음" });

    if (reservation.status !== "CHECKED_IN") {
      return res.status(400).json({ error: "체크인된 예약만 연장 가능합니다." });
    }

    const now = new Date();
    const endTime = new Date(reservation.endTime);
    const startTime = new Date(reservation.startTime);

    // 허용 윈도우: 종료 20분 전 ~ 종료 사이
    const earliest = new Date(endTime.getTime() - PENDING_TTL_MIN * 60 * 1000); // end - 20min
    if (now < earliest || now > endTime) {
      return res.status(400).json({ error: "연장은 종료 20분 전부터 종료 시까지 가능합니다." });
    }

    // max by 3 hours from start
    const maxBy3h = new Date(startTime.getTime() + MAX_RESERVATION_HOURS * 60 * 60 * 1000);

    // 다음 예약(같은 좌석) 확인 — startTime > current end, 상태는 PENDING 또는 CHECKED_IN
    const nextRes = await prisma.reservation.findFirst({
      where: {
        seatId: reservation.seatId,
        startTime: { gt: reservation.endTime },
        status: { in: ["PENDING", "CHECKED_IN"] },
      },
      orderBy: { startTime: "asc" },
      select: { id: true, startTime: true, status: true },
    });

    let maxByNext = maxBy3h;
    if (nextRes && nextRes.startTime) {
      // next 시작 바로 직전까지만 허용(1ms 전)
      const nextStart = new Date(nextRes.startTime);
      maxByNext = new Date(Math.min(maxBy3h.getTime(), nextStart.getTime() - 1));
    }

    if (maxByNext.getTime() <= endTime.getTime()) {
      return res.status(400).json({ error: "연장 가능한 여유 시간이 없습니다 (다음 예약과 충돌)." });
    }

    // Update reservation endTime and mark extended true
    const updated = await prisma.reservation.update({
      where: { id: reservation.id },
      data: {
        endTime: maxByNext,
        extended: true,
      },
      include: { Seat: true },
    });

    return res.json({
      message: "연장 성공",
      reservation: {
        id: updated.id,
        room: updated.Seat?.room ?? null,
        seat: updated.Seat ? String(updated.Seat.seatNumber) : null,
        startTime: iso(updated.startTime),
        endTime: iso(updated.endTime),
        extended: updated.extended,
        status: updated.status,
      },
    });
  } catch (err) {
    console.error("[EXTEND] error:", err);
    res.status(500).json({ error: "서버 오류" });
  }
});

/* -------------------------------- 체크인 --------------------------------- */
app.post("/checkin", authMiddleware, async (req, res) => {
  try {
    const { reservationId, pin, userId: bodyUserId } = req.body || {};
    if (!reservationId || !pin) return res.status(400).json({ error: "reservationId/pin 필수" });

    const reservation = await prisma.reservation.findUnique({
      where: { id: Number(reservationId) },
      include: { Seat: true, User: true },
    });
    if (!reservation) return res.status(404).json({ error: "예약이 존재하지 않습니다." });

    const pins = await prisma.pin.findMany({
      where: { reservationId: reservation.id, used: false, expiresAt: { gt: new Date() } },
      orderBy: { createdAt: "desc" },
      take: 10,
    });

    let matched = null;
    for (const p of pins) {
      if (await bcrypt.compare(String(pin), p.pinHash)) {
        matched = p;
        break;
      }
    }
    if (!matched) return res.status(401).json({ error: "Invalid PIN" });

    const checkinUserId = bodyUserId ? Number(bodyUserId) : (req.userId || reservation.userId);

    // transaction: set pin used, update reservation status & startedAt, create checkin row
    const [, updatedReservation] = await prisma.$transaction([
      prisma.pin.update({ where: { id: matched.id }, data: { used: true } }),
      prisma.reservation.update({
        where: { id: reservation.id },
        data: { status: "CHECKED_IN", startedAt: new Date() },
        include: { Seat: true, User: true },
      }),
      prisma.checkin.create({ data: { reservationId: reservation.id, userId: Number(checkinUserId) } }),
    ]);

    // return reservation for client (sanitized)
    const resObj = {
      id: updatedReservation.id,
      room: updatedReservation.Seat?.room ?? null,
      seat: updatedReservation.Seat ? String(updatedReservation.Seat.seatNumber) : null,
      userId: updatedReservation.userId,
      status: updatedReservation.status,
      startTime: iso(updatedReservation.startTime),
      endTime: iso(updatedReservation.endTime),
      startedAt: iso(updatedReservation.startedAt),
    };

    return res.json({ message: "Checkin success", reservation: resObj });
  } catch (err) {
    console.error("[CHECKIN] error:", err);
    res.status(500).json({ error: "서버 오류" });
  }
});

/* -------------------------------- 퇴실 ---------------------------------- */
app.post("/checkout", authMiddleware, async (req, res) => {
  try {
    const { reservationId, password } = req.body || {};
    if (!reservationId || !password) return res.status(400).json({ error: "reservationId/password 필수" });
    if (!req.userId) return res.status(401).json({ error: "인증 필요" });

    const reservation = await prisma.reservation.findUnique({
      where: { id: Number(reservationId) },
      include: { User: true, Seat: true },
    });
    if (!reservation) return res.status(404).json({ error: "예약 없음" });
    if (reservation.userId !== req.userId) return res.status(403).json({ error: "권한 없음" });

    const ok = await bcrypt.compare(String(password), reservation.User.passwordHash || "");
    if (!ok) return res.status(401).json({ error: "비밀번호가 올바르지 않습니다." });

    if (["FINISHED", "CANCELED", "EXPIRED"].includes(reservation.status)) {
      // 이미 끝난 예약은 그대로 성공 응답 (프론트 일관성)
      return res.json({
        message: "이미 퇴실 처리된 예약입니다.",
        reservation: {
          id: reservation.id,
          room: reservation.Seat?.room ?? null,
          seat: reservation.Seat ? String(reservation.Seat.seatNumber) : null,
          userId: reservation.userId,
          status: reservation.status,
          startTime: iso(reservation.startTime),
          endTime: iso(reservation.endTime),
          endedAt: iso(reservation.endedAt),
        },
      });
    }

    const updated = await prisma.reservation.update({
      where: { id: reservation.id },
      data: { status: "FINISHED", endedAt: new Date() },
      include: { Seat: true },
    });

    res.json({
      message: "Checkout success",
      reservation: {
        id: updated.id,
        room: updated.Seat?.room ?? null,
        seat: updated.Seat ? String(updated.Seat.seatNumber) : null,
        userId: updated.userId,
        status: updated.status,
        startTime: iso(updated.startTime),
        endTime: iso(updated.endTime),
        endedAt: iso(updated.endedAt),
      },
    });
  } catch (err) {
    console.error("[CHECKOUT] error:", err);
    res.status(500).json({ error: "서버 오류" });
  }
});

/* ------------------------- 자동 상태 업데이트(잡) ------------------------- */
async function expireReservationsJob() {
  try {
    const now = new Date();

    // 0) 오래된 PENDING(생성시간 기준) -> EXPIRED (PENDING TTL)
    const pendingCutoff = new Date(Date.now() - PENDING_TTL_MIN * 60 * 1000);
    const oldPending = await prisma.reservation.updateMany({
      where: { status: "PENDING", createdAt: { lt: pendingCutoff } },
      data: { status: "EXPIRED", endedAt: now },
    });

    // 1) PENDING → start+20min 지나면 EXPIRED (원래의 안전망)
    const exp1 = await prisma.reservation.updateMany({
      where: {
        status: "PENDING",
        startTime: { lt: new Date(now.getTime() - PENDING_TTL_MIN * 60 * 1000) },
      },
      data: { status: "EXPIRED", endedAt: now },
    });

    // 2) CHECKED_IN → 체크인 시간으로부터 4시간 경과하면 FINISHED
    const exp2 = await prisma.reservation.updateMany({
      where: {
        status: "CHECKED_IN",
        Checkin: { some: { checkinTime: { lt: new Date(now.getTime() - 4 * 60 * 60 * 1000) } } },
      },
      data: { status: "FINISHED", endedAt: now },
    });

    // 3) 예약 종료시간이 지났다면 정리
    const exp3 = await prisma.reservation.updateMany({
      where: {
        status: { in: ["PENDING", "CHECKED_IN"] },
        endTime: { lt: now },
      },
      data: { status: "EXPIRED", endedAt: now },
    });

    if (oldPending.count || exp1.count || exp2.count || exp3.count) {
      console.log(
        `[expireJob] oldPending=${oldPending.count}, expiredByStart=${exp1.count}, finished=${exp2.count}, forced=${exp3.count}`
      );
    }
  } catch (err) {
    console.error("[expireJob] error:", err);
  }
}
setInterval(expireReservationsJob, 60 * 1000);

/* ------------------------------- 서버 시작 -------------------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => console.log(`🚀 서버 실행 중: http://localhost:${PORT}`));

process.on("SIGINT", async () => { await prisma.$disconnect(); process.exit(0); });
process.on("SIGTERM", async () => { await prisma.$disconnect(); process.exit(0); });

app.use((err, req, res, next) => {
  console.error("[UNCAUGHT ERROR]", err?.stack || err);
  res.status(500).json({ error: "서버 오류" });
});
