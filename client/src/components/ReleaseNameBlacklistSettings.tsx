import React, { useState, useEffect, useCallback } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Ban, X, Plus, RotateCcw, Save } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

interface ReleaseNameBlacklistSettingsProps {
  blacklistTerms: string[];
  onTermsChange: (terms: string[]) => void;
}

export default function ReleaseNameBlacklistSettings({
  blacklistTerms,
  onTermsChange,
}: ReleaseNameBlacklistSettingsProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [terms, setTerms] = useState<string[]>(blacklistTerms);
  const [inputValue, setInputValue] = useState("");

  useEffect(() => {
    setTerms(blacklistTerms);
  }, [blacklistTerms]);

  useEffect(() => {
    onTermsChange(terms);
  }, [terms, onTermsChange]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("PATCH", "/api/settings", {
        releaseNameBlacklist: JSON.stringify(terms),
      });
      return res.json();
    },
    onSuccess: () => {
      toast({
        title: "Release Name Blacklist Saved",
        description: "Your blacklisted release name terms have been saved.",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/settings"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Save Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleAddTerm = useCallback(() => {
    const trimmed = inputValue.trim();
    if (!trimmed) return;
    if (terms.some((t) => t.toLowerCase() === trimmed.toLowerCase())) {
      setInputValue("");
      return;
    }
    setTerms((prev) => [...prev, trimmed]);
    setInputValue("");
  }, [inputValue, terms]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleAddTerm();
    }
  };

  const handleRemoveTerm = (term: string) => {
    setTerms((prev) => prev.filter((t) => t !== term));
  };

  const handleReset = () => {
    setTerms([]);
    setInputValue("");
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center space-x-3">
          <Ban className="h-5 w-5 text-muted-foreground" />
          <CardTitle className="text-lg">Release Name Blacklist</CardTitle>
        </div>
        <CardDescription>
          Hide releases whose name contains any of these terms, across manual search, auto-search
          and AI-assisted results. Matching is case-insensitive and checks for the term anywhere in
          the release name.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="blacklist-term-input" className="text-sm font-medium">
              Blacklisted Terms
            </Label>
            <div className="flex gap-2">
              <Input
                id="blacklist-term-input"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="e.g. HYPERVISOR, CAM, SAMPLE..."
                className="flex-1"
              />
              <Button
                type="button"
                variant="outline"
                size="icon"
                onClick={handleAddTerm}
                disabled={!inputValue.trim()}
                aria-label="Add blacklisted term"
              >
                <Plus className="h-4 w-4" aria-hidden="true" />
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Press Enter or click + to add a term. Comparison is case-insensitive.
            </p>
          </div>

          {terms.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {terms.map((term) => (
                <Badge key={term} variant="secondary" className="gap-1 pr-1">
                  {term}
                  <button
                    type="button"
                    onClick={() => handleRemoveTerm(term)}
                    className="ml-1 rounded-full hover:bg-muted-foreground/20 p-0.5"
                    aria-label={`Remove ${term}`}
                  >
                    <X className="h-3 w-3" />
                  </button>
                </Badge>
              ))}
            </div>
          )}

          {terms.length === 0 && (
            <p className="text-xs text-muted-foreground italic">
              No blacklisted terms configured. All release names will be considered.
            </p>
          )}
        </div>

        <div className="flex justify-end gap-2 pt-4 border-t">
          <Button
            variant="outline"
            size="sm"
            onClick={handleReset}
            disabled={saveMutation.isPending}
            className="gap-2"
          >
            <RotateCcw className="h-4 w-4" />
            Reset
          </Button>
          <Button
            size="sm"
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending}
            className="gap-2"
          >
            {saveMutation.isPending ? (
              <>
                <Save className="h-4 w-4 animate-pulse" />
                Saving...
              </>
            ) : (
              <>
                <Save className="h-4 w-4" />
                Save Blacklist
              </>
            )}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
