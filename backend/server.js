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

let A_id;
let B_id;

// Define authentication middleware
io.use(async (socket, next) => {
  // Get username and pubKey_C
  const username = socket.handshake.auth.username;
  const pubKey_pem = socket.handshake.auth.pubKey_pem;

  console.log(
    `\n[${socket.id} ${username}] Starting client-server authentication...`
  );

  // Get user from database
  console.log(
    `[${socket.id} ${username}] Getting user ${username} from database...`
  );

  const user = await prisma.user.findUnique({
    where: {
      username: username,
    },
  });

  // If user does not exist
  if (user == null) {
    // Create new user
    console.log(`[${socket.id} ${username}] Creating new user ${username}...`);
    await prisma.user.create({
      data: {
        username: username,
        pubKey_pem: pubKey_pem,
      },
    });
    console.log(`[${socket.id} ${username}] Successfully created new user!`);
    socket.send("New user created!");
    next();
  // User exists in database
  } else {
    console.log(
      `[${socket.id} ${username}] Successfully retrieved user ${username}:`
    );
    console.log(`[${socket.id} ${username}] createdAt: ${user.createdAt}`);
    console.log(`[${socket.id} ${username}] pubKey_pem:\n ${pubKey_pem}`);
    
    // Verify user provided pubKey_c matches database
    if (user.pubKey_pem != pubKey_pem) {
      console.log(
        `[${socket.id} ${username}] Authentication error: user pubKey does not match db!`
      );
      console.log(`[${socket.id} ${username}] pubKey_pem:\n ${user.pubKey_pem}`);
      const err = new Error(
        "Authentication error: public key does not match user!"
      );
      err.data = { content: "Please try another username." };
      socket.disconnect();
      next(err);
    } else {
      console.log(`[${socket.id} ${username}] User pubKey matches db!`);
      console.log(`[${socket.id} ${username}] pubKey_pem:\n ${user.pubKey_pem}`);
      next();
    }
  }
});

io.on("connection", (socket) => {
  const username = socket.handshake.auth.username;
  // console.log(`[${socket.id} ${username}]`);

  console.log(`[${socket.id} ${username}] Websocket connection established!`);
  console.log(`[${socket.id} ${username}] Continuing client-server authentication...`);

  // Generate random token for client authentication with server
  console.log(`[${socket.id} ${username}] Generating random token...`);
  const rand_token = crypto.randomBytes(32).toString("hex");
  console.log(`[${socket.id} ${username}] ${rand_token}`);

  // Send random token to client and request signature
  console.log(`[${socket.id} ${username}] Requesting signature from client...`);
  socket.emit("request_sig", rand_token);

  // Receive signature from client
  socket.on("response_sig", async (data) => {
    console.log(`[${socket.id} ${username}] Received signature from client:`);
    console.log(`[${socket.id} ${username}] auth_sig: ${data["auth_sig"].toString("hex")}`);

    console.log(`[${socket.id} ${username}] Verifying signature...`);

    // Get user from database
    const user = await prisma.user.findUnique({
      where: {
        username: username,
      },
    });

    // Verify signature is valid
    if (
      crypto.verify(
        "SHA256",
        Buffer.from(socket.id + rand_token),
        user.pubKey_pem,
        data["auth_sig"]
      )
    ) {
      console.log(`[${socket.id} ${username}] Signature verification successful!`);
      socket.emit("authentication_success");
    } else {
      console.log(`[${socket.id} ${username}] Signature verification failed!`);
      socket.emit("authentication_error");
      socket.disconnect();
    }
  });

  console.log(
    `[${socket.id} ${username}] Client-server authentication successful!`
  );
  console.log(
    `[${socket.id} ${username}] Clients connected: ${io.engine.clientsCount}`
  );
  // console.log("Clients connected: ", io.of("/").sockets.keys());

  if (io.engine.clientsCount == 2) {
    console.log(`[${socket.id} ${username}] Second client connected!`);
    A_id = socket.id;
  } else {
    console.log(`[${socket.id} ${username}] Waiting for second client...`);
    B_id = socket.id;
  }

  // Begin ECDH key exchange
  if (socket.id == A_id) {
    console.log(`[${socket.id} ${username}] Start A-B ECDH handshake...`);
    console.log(`[${socket.id} ${username}] Sending A_handshake to B...`);
    console.log(`[${socket.id} ${username}] id_A: ${socket.id}`);
    console.log(`[${socket.id} ${username}] pubKey_A: ${socket.handshake.auth.pubKey_c}`);
    socket
      .to(B_id)
      .emit("A_handshake", {
        id_A: socket.id,
        pubKey_A: socket.handshake.auth.pubKey_c,
      });
  }

  socket.on("B_handshake", (data) => {
    console.log(`[${socket.id} ${username}] Received B_handshake!`);
    console.log(`[${socket.id} ${username}] B_id: ${data.id_B}`);
    console.log(`[${socket.id} ${username}] pubKey_B: ${data["pubKey_B"]}`);
    console.log(`[${socket.id} ${username}] sig: ${data["sig"]}`);
    socket
      .to(A_id)
      .emit("B_handshake", {
        id_B: data["B_id"],
        pubKey_B: data["pubKey_B"],
        sig: data["sig"],
      });
  });

  socket.on("responseA_ECDH", (data) => {
    console.log("Received ECDH from A...");
    console.log("data:", data);
    socket
      .to(B_id)
      .emit("finalA_handshake", { id_A: data["A_id"], sig: data["sig"] });
  });

  socket.on("send_message", (data) => {
    if (socket.id == A_id) {
      socket.to(B_id).emit("recv_message", data);
    }
    if (socket.id == B_id) {
      socket.to(A_id).emit("recv_message", data);
    }
  });

  socket.on("disconnect", () => {
    console.log("Client disconnected");
  });
});

httpServer.listen(8080);
