import type { UseMutationResult } from "@tanstack/react-query";
import GameGrid from "./GameGrid";
import { type Game, type DownloadSummary } from "@shared/schema";
import { type GameStatus } from "./StatusBadge";

interface GameStatusGridProps {
  readonly games: Game[];
  readonly statusMutation: UseMutationResult<
    unknown,
    Error,
    { gameId: string; status: GameStatus }
  >;
  readonly hiddenMutation: UseMutationResult<unknown, Error, { gameId: string; hidden: boolean }>;
  readonly isLoading: boolean;
  readonly viewMode: "grid" | "list";
  readonly density: "comfortable" | "compact";
  readonly downloadSummaries: Record<string, DownloadSummary>;
  readonly columns: number;
}

/** Wires a GameGrid's status/hidden toggle callbacks to the given mutations; shared by the Wishlist and Playing pages. */
export default function GameStatusGrid({
  games,
  statusMutation,
  hiddenMutation,
  isLoading,
  viewMode,
  density,
  downloadSummaries,
  columns,
}: GameStatusGridProps) {
  return (
    <GameGrid
      games={games}
      onStatusChange={(id, status) => statusMutation.mutate({ gameId: id, status })}
      onToggleHidden={(id, hidden) => hiddenMutation.mutate({ gameId: id, hidden })}
      isLoading={isLoading}
      viewMode={viewMode}
      density={density}
      downloadSummaries={downloadSummaries}
      columns={columns}
    />
  );
}
