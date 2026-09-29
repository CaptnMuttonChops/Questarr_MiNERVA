/**
 * @vitest-environment jsdom
 */
import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import { vi, describe, it, expect } from "vitest";
import TagListEditor from "../src/components/TagListEditor";

function renderEditor(overrides: Partial<React.ComponentProps<typeof TagListEditor>> = {}) {
  const onChange = vi.fn();
  const props: React.ComponentProps<typeof TagListEditor> = {
    tags: [],
    onChange,
    inputId: "test-tag-input",
    label: "Terms",
    placeholder: "e.g. HYPERVISOR",
    helperText: "Press Enter or click + to add a term.",
    emptyText: "No terms configured.",
    addAriaLabel: "Add term",
    removeAriaLabel: (tag) => `Remove ${tag}`,
    ...overrides,
  };
  render(<TagListEditor {...props} />);
  return { onChange, props };
}

describe("TagListEditor", () => {
  it("renders the empty state when there are no tags", () => {
    renderEditor();
    expect(screen.getByText("No terms configured.")).toBeInTheDocument();
  });

  it("renders existing tags as badges", () => {
    renderEditor({ tags: ["HYPERVISOR", "CAM"] });
    expect(screen.getByText("HYPERVISOR")).toBeInTheDocument();
    expect(screen.getByText("CAM")).toBeInTheDocument();
    expect(screen.queryByText("No terms configured.")).not.toBeInTheDocument();
  });

  it("adds a trimmed tag when pressing Enter in the input", () => {
    const { onChange } = renderEditor();
    const input = screen.getByLabelText("Terms");
    fireEvent.change(input, { target: { value: "  HYPERVISOR  " } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(onChange).toHaveBeenCalledWith(["HYPERVISOR"]);
  });

  it("adds a tag when clicking the add button", () => {
    const { onChange } = renderEditor();
    const input = screen.getByLabelText("Terms");
    fireEvent.change(input, { target: { value: "CODEX" } });
    fireEvent.click(screen.getByLabelText("Add term"));
    expect(onChange).toHaveBeenCalledWith(["CODEX"]);
  });

  it("does not add an empty or whitespace-only tag", () => {
    const { onChange } = renderEditor();
    const input = screen.getByLabelText("Terms");
    fireEvent.change(input, { target: { value: "   " } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(onChange).not.toHaveBeenCalled();
  });

  it("does not add a duplicate tag, case-insensitively", () => {
    const { onChange } = renderEditor({ tags: ["HYPERVISOR"] });
    const input = screen.getByLabelText("Terms");
    fireEvent.change(input, { target: { value: "hypervisor" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(onChange).not.toHaveBeenCalled();
  });

  it("clears the input after adding a tag", () => {
    renderEditor();
    const input = screen.getByLabelText("Terms") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "CODEX" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(input.value).toBe("");
  });

  it("removes a tag when its remove button is clicked", () => {
    const { onChange } = renderEditor({ tags: ["HYPERVISOR", "CAM"] });
    fireEvent.click(screen.getByLabelText("Remove HYPERVISOR"));
    expect(onChange).toHaveBeenCalledWith(["CAM"]);
  });

  it("disables the add button while the input is empty", () => {
    renderEditor();
    expect(screen.getByLabelText("Add term")).toBeDisabled();
  });

  it("enables the add button once the input has text", () => {
    renderEditor();
    const input = screen.getByLabelText("Terms");
    fireEvent.change(input, { target: { value: "CODEX" } });
    expect(screen.getByLabelText("Add term")).not.toBeDisabled();
  });
});
