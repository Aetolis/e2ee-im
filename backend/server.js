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

// Define authentication middleware
io.use(async (socket, next) => {
  // Get username and pubKey_C
  const username = socket.handshake.auth.username;
  const pubKey_c = socket.handshake.auth.pubKey_c;

  // Get user from database
  console.log("Get username and pubKey_C", username, pubKey_c);

  const user = await prisma.user.findUnique({
    where: {
      username: username,
    },
  });

  // Check if user exists
  if (user == null) {
    // Create new user
    console.log("Adding new user:", username);
    await prisma.user.create({
      data: {
        username: username,
        pubKey_c: pubKey_c,
      },
    });
    socket.send("New user:" + username);
    next();
  } else {
    console.log("User already exists:", user.username);
    // Verify user provided pubKey_c matches database
    if (user.pubKey_c != pubKey_c) {
      // console.log("User pubKey_c does not match:", username, pubKey_c);
      console.log("Authentication error: public key does not match user!");
      const err = new Error(
        "Authentication error: public key does not match user!"
      );
      err.data = { content: "Please try another username." };
      socket.disconnect(true);
      next(err);
    } else {
      next();
    }
  }
});

io.on("connection", (socket) => {
  console.log("New client connected: ", socket.id);
  console.log("Clients connected: ", io.of("/").sockets.keys());

  // Generate random token for client authentication with server
  console.log("Generate random token...");
  const rand_token = crypto.randomBytes(32).toString("hex");
  // console.log("rand_token:", rand_token);

  // Send random token to client and request signature
  socket.emit("request_sig", rand_token);

  // Receive signature from client
  socket.on("response_sig", async (data) => {
    console.log("Received signature from client...");
    // console.log("data:", data);

    // Get user from database
    const user = await prisma.user.findUnique({
      where: {
        username: socket.handshake.auth.username,
      },
    });

    // Verify user provided pubKey_c matches database
    if (user.pubKey_c != data["pubKey_c"]) {
      console.log(
        "User pubKey_c does not match:",
        socket.handshake.auth.username,
        data["pubKey_c"]
      );
      console.log("Signature verification failed!");
      socket.emit("authentication_error");
      socket.disconnect();
    }

    // Verify signature is valid
    if (
      crypto.verify(
        "SHA256",
        Buffer.from(socket.id + rand_token),
        data["pubKey_c"],
        data["sig"]
      )
    ) {
      console.log("Signature verification successful!");
      socket.emit("authentication_success");
    } else {
      console.log("Signature verification failed!");
      socket.emit("authentication_error");
      socket.disconnect();
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
