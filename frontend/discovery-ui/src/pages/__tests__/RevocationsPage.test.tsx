import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { RevocationsPage } from "../RevocationsPage";

// ── Module mocks ──────────────────────────────────────────────────────────────

vi.mock("../../api/credentials", () => ({
  revokeCredential: vi.fn(),
  listCredentials: vi.fn().mockResolvedValue({ items: [], total: 0 }),
}));

vi.mock("../../api/statusLists", () => ({
  listStatusLists: vi.fn().mockResolvedValue({ items: [], total: 0 }),
}));

vi.mock("../../api/client", () => ({
  apiClient: { get: vi.fn(), post: vi.fn() },
  registerAuthHandlers: vi.fn(),
}));

function renderPage() {
  return render(
    <MemoryRouter>
      <RevocationsPage />
    </MemoryRouter>,
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("RevocationsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders Revoked Credentials tab by default", async () => {
    renderPage();
    await waitFor(() =>
      expect(screen.getByRole("tab", { name: /revoked credentials/i })).toBeDefined(),
    );
  });

  it("shows 'No revoked credentials found' in first tab", async () => {
    renderPage();
    await waitFor(() =>
      expect(screen.getByText("No revoked credentials found.")).toBeDefined(),
    );
  });

  it("switches to Status Lists tab and shows empty state", async () => {
    renderPage();
    const tab = screen.getByRole("tab", { name: /status lists/i });
    fireEvent.click(tab);
    await waitFor(() =>
      expect(screen.getByText("No status lists found.")).toBeDefined(),
    );
  });
});
