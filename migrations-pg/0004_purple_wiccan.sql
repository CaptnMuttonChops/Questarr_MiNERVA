CREATE TABLE "game_journal_entries" (
	"id" text PRIMARY KEY NOT NULL,
	"game_id" text NOT NULL,
	"user_id" text NOT NULL,
	"note" text NOT NULL,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM now()) * 1000)::bigint
);
--> statement-breakpoint
CREATE TABLE "game_milestones" (
	"id" text PRIMARY KEY NOT NULL,
	"game_id" text NOT NULL,
	"user_id" text NOT NULL,
	"label" text NOT NULL,
	"completed_at" bigint,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM now()) * 1000)::bigint
);
--> statement-breakpoint
CREATE TABLE "game_screenshots" (
	"id" text PRIMARY KEY NOT NULL,
	"game_id" text NOT NULL,
	"user_id" text NOT NULL,
	"file_path" text NOT NULL,
	"caption" text,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM now()) * 1000)::bigint
);
--> statement-breakpoint
ALTER TABLE "game_journal_entries" ADD CONSTRAINT "game_journal_entries_game_id_games_id_fk" FOREIGN KEY ("game_id") REFERENCES "public"."games"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "game_journal_entries" ADD CONSTRAINT "game_journal_entries_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "game_milestones" ADD CONSTRAINT "game_milestones_game_id_games_id_fk" FOREIGN KEY ("game_id") REFERENCES "public"."games"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "game_milestones" ADD CONSTRAINT "game_milestones_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "game_screenshots" ADD CONSTRAINT "game_screenshots_game_id_games_id_fk" FOREIGN KEY ("game_id") REFERENCES "public"."games"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "game_screenshots" ADD CONSTRAINT "game_screenshots_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "game_journal_entries_game_user_idx" ON "game_journal_entries" USING btree ("game_id","user_id");--> statement-breakpoint
CREATE INDEX "game_milestones_game_user_idx" ON "game_milestones" USING btree ("game_id","user_id");--> statement-breakpoint
CREATE INDEX "game_screenshots_game_user_idx" ON "game_screenshots" USING btree ("game_id","user_id");--> statement-breakpoint
INSERT INTO "game_journal_entries" ("id", "game_id", "user_id", "note", "created_at")
SELECT
	gen_random_uuid()::text,
	"id",
	COALESCE("user_id", (SELECT "id" FROM "users" LIMIT 1)),
	"notes",
	(EXTRACT(EPOCH FROM now()) * 1000)::bigint
FROM "games"
WHERE "notes" IS NOT NULL AND trim("notes") != ''
	AND COALESCE("user_id", (SELECT "id" FROM "users" LIMIT 1)) IS NOT NULL;
--> statement-breakpoint
ALTER TABLE "games" DROP COLUMN "notes";