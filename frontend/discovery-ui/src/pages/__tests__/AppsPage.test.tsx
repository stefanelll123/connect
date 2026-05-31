import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AppsPage } from "../AppsPage";

// ── Module mocks ──────────────────────────────────────────────────────────────

vi.mock("../../api/apps", () => ({
  listApps: vi.fn().mockResolvedValue({ items: [], total_count: 0, next_cursor: null }),
  createApp: vi.fn().mockResolvedValue({ id: "abc", name: "test-app", owner: null, is_active: true, created_at: null, updated_at: null }),
  updateApp: vi.fn().mockResolvedValue({ id: "abc", name: "test-app-2", owner: null, is_active: true, created_at: null, updated_at: null }),
  deleteApp: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../api/client", () => ({
  apiClient: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), delete: vi.fn() },
  registerAuthHandlers: vi.fn(),
}));

import { listApps, createApp } from "../../api/apps";
const mockList = vi.mocked(listApps);
const mockCreate = vi.mocked(createApp);

function renderPage() {
  return render(
    <MemoryRouter>
      <AppsPage />
    </MemoryRouter>,
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("AppsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockList.mockResolvedValue({ items: [], total_count: 0, next_cursor: null });
    mockCreate.mockResolvedValue({ id: "abc", name: "test-app", owner: null, is_active: true, created_at: null, updated_at: null });
  });

  it("shows 'No apps found' empty state on load", async () => {
    renderPage();
    await waitFor(() =>
      expect(screen.getByText("No apps found.")).toBeDefined(),
    );
  });

  it("renders the Apps title and New App button", async () => {
    renderPage();
    await waitFor(() => screen.getByText("No apps found."));
    expect(screen.getByRole("heading", { name: /apps/i })).toBeDefined();
    expect(screen.getByRole("button", { name: /new app/i })).toBeDefined();
  });

  it("opens New App dialog on button click", async () => {
    renderPage();
    await waitFor(() => screen.getByText("No apps found."));
    fireEvent.click(screen.getByRole("button", { name: /new app/i }));
    await waitFor(() =>
      expect(screen.getByRole("dialog")).toBeDefined(),
    );
    expect(screen.getByLabelText(/name/i)).toBeDefined();
  });

  it("Create button is disabled when Name is empty", async () => {
    renderPage();
    await waitFor(() => screen.getByText("No apps found."));
    fireEvent.click(screen.getByRole("button", { name: /new app/i }));
    await waitFor(() => screen.getByRole("dialog"));
    const createBtn = screen.getByRole("button", { name: /^create$/i });
    expect((createBtn as HTMLButtonElement).disabled).toBe(true);
  });

  it("renders rows when listApps returns data", async () => {
    mockList.mockResolvedValue({
      items: [
        { id: "1", name: "my-api", owner: "team@example.com", is_active: true, created_at: new Date().toISOString(), updated_at: null },
      ],
      total_count: 1,
      next_cursor: null,
    });
    renderPage();
    await waitFor(() => screen.getByText("my-api"));
    expect(screen.getByText("team@example.com")).toBeDefined();
  });
});
