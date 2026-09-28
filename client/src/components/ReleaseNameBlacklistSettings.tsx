import React, { useState, useEffect } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Ban, RotateCcw, Save } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import TagListEditor from "@/components/TagListEditor";

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

  const handleReset = () => {
    setTerms([]);
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
        <TagListEditor
          tags={terms}
          onChange={setTerms}
          inputId="blacklist-term-input"
          label="Blacklisted Terms"
          placeholder="e.g. HYPERVISOR, CAM, SAMPLE..."
          helperText="Press Enter or click + to add a term. Comparison is case-insensitive."
          emptyText="No blacklisted terms configured. All release names will be considered."
          addAriaLabel="Add blacklisted term"
          removeAriaLabel={(term) => `Remove ${term}`}
        />

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
