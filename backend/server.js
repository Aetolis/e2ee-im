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
import Prisma from "@prisma/client";
import crypto from "crypto";

const { PrismaClient } = Prisma;
const prisma = new PrismaClient();

const httpServer = createServer();
const io = new Server(httpServer, {
  /* options */
});

async function get_user(socket, username, pubKey_c) {
  const user = await prisma.user.findUnique({
    where: {
      username: username,
    },
  });
  if (user == null) {
    console.log("Add new user:", username, pubKey_c);
    await prisma.user.create({
      data: {
        username: username,
        pubKey_c: pubKey_c,
      },
    });
    socket.send("New user created.");
    return 0;
  } else {
    console.log("User already exists:", username, pubKey_c);
    if (user.pubKey_c != pubKey_c) {
      console.log("User pubKey_c does not match:", username, pubKey_c);
      return 1;
    }
    return 0;
  }
}

// Define authentication middleware
io.use((socket, next) => {
  // Get username and pubKey_C
  const username = socket.handshake.auth.username;
  const pubKey_c = socket.handshake.auth.pubKey_c;

  console.log("Get username and pubKey_C", username, pubKey_c);

  // Check if user exists
  if (get_user(socket, username, pubKey_c) == 1) {
    console.log("Authentication error: public key does not match user!");
    const err = new Error(
      "Authentication error: public key does not match user!"
    );
    err.data = { content: "Please try another username." };
    next(err);
  } else {
    next();
  }
});

io.on("connection", (socket) => {
  console.log("New client connected: ", socket.id);
  console.log("Clients connected: ", io.of("/").sockets.keys());

  const rand_buf = crypto.randomBytes(32).toString("hex");
  // const rand_buf = Buffer.from("!", 'hex');
  console.log("rand_buf: " + rand_buf);
  // socket.send(rand_buf);

  socket.emit("request_sig", rand_buf);

  socket.on("response_sig", (data) => {
    console.log("sig: ", data);
    const verify = crypto.verify(
      "SHA256",
      Buffer.from(socket.id+rand_buf),
      data["pubKey_c"],
      data["sig"]
    );

    console.log("verify: ", verify);
    
    if (verify == true) {
      console.log("Authentication success!");
      socket.emit("authentication_success");
    } else {
      console.log("Authentication error: signature does not match!");
      socket.emit("authentication_error");
    }
  });

  // socket.on("login", (data) => {
  //   console.log("login: ", data);
  // });

  // socket.emit("message", "Hello from server");

  // socket.on("message", (data) => {
  //   console.log('received: %b', data);
  // });

  socket.on("disconnect", () => {
    console.log("Client disconnected");
  });
});

httpServer.listen(8080);
