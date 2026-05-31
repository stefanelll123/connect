import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { CredentialsPage } from "../CredentialsPage";

// ── Module mocks ──────────────────────────────────────────────────────────────

vi.mock("../../api/credentials", () => ({
  revokeCredential: vi.fn(),
  issueSentinelIdentity: vi.fn(),
  issueAccessGrant: vi.fn(),
  issueServiceBinding: vi.fn(),
  listCredentials: vi.fn().mockResolvedValue({ items: [], total: 0 }),
}));

vi.mock("../../api/client", () => ({
  apiClient: { get: vi.fn(), post: vi.fn() },
  registerAuthHandlers: vi.fn(),
}));

import { revokeCredential } from "../../api/credentials";

const mockRevoke = vi.mocked(revokeCredential);

function renderPage() {
  return render(
    <MemoryRouter>
      <CredentialsPage />
    </MemoryRouter>,
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("CredentialsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRevoke.mockResolvedValue(undefined);
  });

  it("shows 'No credentials found' when there is no list endpoint", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("No credentials found.")).toBeDefined());
  });

  it("renders filter dropdowns and Issue button", async () => {
    renderPage();
    await waitFor(() => screen.getByText("No credentials found."));
    const combos = screen.getAllByRole("combobox");
    expect(combos.length).toBeGreaterThanOrEqual(3);
    expect(screen.getByRole("button", { name: /issue/i })).toBeDefined();
  });

  it("opens issue wizard dialog on Issue button click", async () => {
    renderPage();
    await waitFor(() => screen.getByText("No credentials found."));
    fireEvent.click(screen.getByRole("button", { name: /issue/i }));
    await waitFor(() => expect(screen.getByRole("dialog")).toBeDefined());
    expect(screen.getByText(/issue credential/i)).toBeDefined();
  });
});
