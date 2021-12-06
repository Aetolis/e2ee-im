/*
  Warnings:

  - Changed the type of `IK_B` on the `User` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.
  - Changed the type of `SPK_B` on the `User` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.
  - Changed the type of `Sig` on the `User` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "IK_B",
ADD COLUMN     "IK_B" BIT(256) NOT NULL,
DROP COLUMN "SPK_B",
ADD COLUMN     "SPK_B" BIT(256) NOT NULL,
DROP COLUMN "Sig",
ADD COLUMN     "Sig" BIT(256) NOT NULL;
