/*
  Warnings:

  - The primary key for the `User` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `IK_B` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `SPK_B` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `Sig` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `id` on the `User` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[username]` on the table `User` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `pubKey_c` to the `User` table without a default value. This is not possible if the table is not empty.
  - Added the required column `username` to the `User` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "User" DROP CONSTRAINT "User_pkey",
DROP COLUMN "IK_B",
DROP COLUMN "SPK_B",
DROP COLUMN "Sig",
DROP COLUMN "id",
ADD COLUMN     "pubKey_c" TEXT NOT NULL,
ADD COLUMN     "username" TEXT NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "User_username_key" ON "User"("username");
