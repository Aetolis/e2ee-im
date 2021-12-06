/*
  Warnings:

  - You are about to drop the column `IK_B` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `SPK_B` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `Sig` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `createdAt` on the `User` table. All the data in the column will be lost.
  - Added the required column `name` to the `User` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "IK_B",
DROP COLUMN "SPK_B",
DROP COLUMN "Sig",
DROP COLUMN "createdAt",
ADD COLUMN     "name" TEXT NOT NULL;
