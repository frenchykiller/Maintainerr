import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateUserTable1790500000000 implements MigrationInterface {
  name = 'CreateUserTable1790500000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "user" (
        "id" integer PRIMARY KEY AUTOINCREMENT NOT NULL,
        "email" varchar NOT NULL UNIQUE,
        "username" varchar NOT NULL,
        "passwordHash" varchar,
        "oidcSub" varchar,
        "role" varchar NOT NULL DEFAULT ('user'),
        "createdAt" datetime NOT NULL DEFAULT (datetime('now')),
        "updatedAt" datetime NOT NULL DEFAULT (datetime('now'))
      )
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "user"`);
  }
}
