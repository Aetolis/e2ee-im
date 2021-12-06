/*
  Warnings:

  - Added the required column `IK_B` to the `User` table without a default value. This is not possible if the table is not empty.
  - Added the required column `SPK_B` to the `User` table without a default value. This is not possible if the table is not empty.
  - Added the required column `Sig` to the `User` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "User" ADD COLUMN     "IK_B" BYTEA NOT NULL,
ADD COLUMN     "SPK_B" BYTEA NOT NULL,
ADD COLUMN     "Sig" BYTEA NOT NULL,
ADD COLUMN     "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;
