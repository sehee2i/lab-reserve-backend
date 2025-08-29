const { PrismaClient } = require('@prisma/client');
const p = new PrismaClient();

(async () => {
  try {
    const data = [
      // 901호: seatNumber 1..13 (예약가능)
      ...Array.from({ length: 13 }, (_, i) => ({ room: '901', seatNumber: i + 1 })),

      // 907호: 14 고정석, 15 예약가능
      { room: '907', seatNumber: 14, label: '고정석', fixed: true },
      { room: '907', seatNumber: 15 },
    ];

    // createMany: 이미 같은 (room,seatNumber)가 있으면 건너뜀 (skipDuplicates)
    await p.seat.createMany({ data, skipDuplicates: true });

    const all = await p.seat.findMany({ orderBy: [{ room: 'asc' }, { seatNumber: 'asc' }] });
    console.log('Seeded seats:', all.map(x => ({ id: x.id, room: x.room, seatNumber: x.seatNumber, fixed: x.fixed })));
  } catch (e) {
    console.error('Seed error', e);
  } finally {
    await p.$disconnect();
  }
})();
