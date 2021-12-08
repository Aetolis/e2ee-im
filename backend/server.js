// import { WebSocketServer } from 'ws';
// import Prisma from '@prisma/client';

// const { PrismaClient } = Prisma;
// const prisma = new PrismaClient()

// const wss = new WebSocketServer({ port: 8080 });

// const user = await prisma.user.create({
//   data: {
//     IK_B: new Buffer.from("!", 'utf8'),
//     SPK_B: new Buffer.from("!", 'utf8'),
//     Sig: new Buffer.from("!", 'utf8')
//   },
// })

// wss.on('connection', function connection(ws) {
//   ws.on('message', function message(data) {
//     console.log('received: %b', data);

//   });

//   ws.send('something');
// });

// import WebSocket from 'ws';
import { createServer } from "http";
import { Server } from "socket.io";

const httpServer = createServer();
const io = new Server(httpServer, { /* options */ });

io.on("connection", (socket) => {
  console.log("Client connected: ", socket.id);
  console.log("Client connected: ", io.of("/").sockets.keys());
  

  socket.emit("message", "Hello from server");

  socket.on("message", (data) => {
    console.log('received: %b', data);
  });

  socket.on("disconnect", () => {
    console.log("Client disconnected");
  });
});



httpServer.listen(8080);