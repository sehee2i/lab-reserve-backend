const { PrismaClient } = require('@prisma/client');
const p = new PrismaClient();

(async () => {
  try {
    const seats = await p.seat.findMany({ orderBy: [{ room: 'asc' }, { seatNumber: 'asc' }] });
    console.log(`found ${seats.length} seats:`);
    console.log(JSON.stringify(seats.map(s => ({ id: s.id, room: s.room, seatNumber: s.seatNumber, fixed: s.fixed })), null, 2));
  } catch (e) {
    console.error('ERR', e);
  } finally {
    await p.$disconnect();
  }
})();
