-- CreateTable
CREATE TABLE "User" (
    "username" TEXT NOT NULL,
    "pubKey_pem" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateIndex
CREATE UNIQUE INDEX "User_username_key" ON "User"("username");
