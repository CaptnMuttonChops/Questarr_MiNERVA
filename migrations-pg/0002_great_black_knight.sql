CREATE TABLE "ai_auto_download_holds" (
	"id" text PRIMARY KEY NOT NULL,
	"game_id" text NOT NULL,
	"release_title" text NOT NULL,
	"reason" text NOT NULL,
	"created_at" bigint DEFAULT (EXTRACT(EPOCH FROM now()) * 1000)::bigint
);
--> statement-breakpoint
ALTER TABLE "ai_auto_download_holds" ADD CONSTRAINT "ai_auto_download_holds_game_id_games_id_fk" FOREIGN KEY ("game_id") REFERENCES "public"."games"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "ai_auto_download_holds_game_title_idx" ON "ai_auto_download_holds" USING btree ("game_id","release_title");