-- safe migration: add startedAt, pinHash; create Pin and Checkin if not exists

-- 컬럼 추가 (존재하면 무시)
ALTER TABLE IF EXISTS "Reservation" ADD COLUMN IF NOT EXISTS "startedAt" TIMESTAMPTZ;
ALTER TABLE IF EXISTS "Reservation" ADD COLUMN IF NOT EXISTS "pinHash" TEXT;

-- Pin 테이블 생성
CREATE TABLE IF NOT EXISTS "Pin" (
  id            SERIAL PRIMARY KEY,
  reservationId INTEGER NOT NULL,
  pinHash       TEXT NOT NULL,
  createdAt     TIMESTAMPTZ DEFAULT now() NOT NULL,
  expiresAt     TIMESTAMPTZ NOT NULL,
  used          BOOLEAN DEFAULT false NOT NULL
);

-- FK & 인덱스 안전하게 추가
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'pin_reservation_fk') THEN
    ALTER TABLE "Pin"
      ADD CONSTRAINT pin_reservation_fk FOREIGN KEY ("reservationId") REFERENCES "Reservation"(id) ON DELETE CASCADE;
  END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_pin_expiresAt ON "Pin"(expiresAt);
CREATE INDEX IF NOT EXISTS idx_pin_reservationId ON "Pin"("reservationId");

-- Checkin 테이블 생성
CREATE TABLE IF NOT EXISTS "Checkin" (
  id            SERIAL PRIMARY KEY,
  reservationId INTEGER NOT NULL,
  userId        INTEGER NOT NULL,
  checkinTime   TIMESTAMPTZ DEFAULT now() NOT NULL
);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'checkin_reservation_fk') THEN
    ALTER TABLE "Checkin"
      ADD CONSTRAINT checkin_reservation_fk FOREIGN KEY ("reservationId") REFERENCES "Reservation"(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'checkin_user_fk') THEN
    ALTER TABLE "Checkin"
      ADD CONSTRAINT checkin_user_fk FOREIGN KEY ("userId") REFERENCES "User"(id) ON DELETE CASCADE;
  END IF;
END$$;
