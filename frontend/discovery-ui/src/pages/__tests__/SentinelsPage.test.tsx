import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { SentinelsPage } from "../SentinelsPage";

// ── Module mocks ──────────────────────────────────────────────────────────────

vi.mock("../../api/sentinels", () => ({
  listSentinels: vi.fn(),
  createEnrollment: vi.fn(),
  approveEnrollment: vi.fn(),
  cancelEnrollment: vi.fn(),
  listPendingEnrollments: vi.fn(),
}));

vi.mock("../../api/audit", () => ({
  listAuditEvents: vi.fn().mockResolvedValue({ items: [], count: 0 }),
}));

vi.mock("../../api/client", () => ({
  apiClient: { get: vi.fn(), post: vi.fn() },
  registerAuthHandlers: vi.fn(),
}));

import { listSentinels } from "../../api/sentinels";
const mockListSentinels = vi.mocked(listSentinels);

// ── Fixtures ──────────────────────────────────────────────────────────────────

const DID_1 = "did:web:sentinel-alpha.example.com";
const DID_2 = "did:web:sentinel-beta.example.com";
// DID displayed in table = last segment sliced to 16 chars
const DID_1_SHORT = "sentinel-alpha.e"; // "sentinel-alpha.example.com".slice(0,16)
const DID_2_SHORT = "sentinel-beta.ex"; // "sentinel-beta.example.com".slice(0,16)

const SENTINELS = [
  {
    id: "s1",
    did: DID_1,
    role: "producer" as const,
    env: "prod" as const,
    is_active: true,
    computed_status: "active" as const,
    last_seen: new Date(Date.now() - 60_000).toISOString(),
  },
  {
    id: "s2",
    did: DID_2,
    role: "consumer" as const,
    env: "dev" as const,
    is_active: false,
    computed_status: "offline" as const,
    last_seen: new Date(Date.now() - 3_600_000).toISOString(),
  },
];

function makeResponse(items = SENTINELS) {
  return { items, count: items.length };
}

function renderPage() {
  return render(
    <MemoryRouter>
      <SentinelsPage />
    </MemoryRouter>,
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("SentinelsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockListSentinels.mockResolvedValue(makeResponse());
  });

  it("renders sentinel rows after data loads", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText(DID_1_SHORT)).toBeDefined());
    expect(screen.getByText(DID_2_SHORT)).toBeDefined();
  });

  it("shows 'No sentinels found' when list is empty", async () => {
    mockListSentinels.mockResolvedValue(makeResponse([]));
    renderPage();
    await waitFor(() => expect(screen.getByText("No sentinels found.")).toBeDefined());
  });

  it("opens detail drawer on row click", async () => {
    renderPage();
    const row = await waitFor(() => screen.getByText(DID_1_SHORT));
    fireEvent.click(row.closest("tr")!);
    // Drawer opens showing full DID
    await waitFor(() => expect(screen.getByText(DID_1)).toBeDefined());
  });

  it("renders role chip for each sentinel", async () => {
    renderPage();
    await waitFor(() => screen.getByText(DID_1_SHORT));
    expect(screen.getByText("producer")).toBeDefined();
    expect(screen.getByText("consumer")).toBeDefined();
  });

  it("env filter renders a combobox element", async () => {
    renderPage();
    await waitFor(() => screen.getByText(DID_1_SHORT));
    const combos = screen.getAllByRole("combobox");
    expect(combos.length).toBeGreaterThanOrEqual(3);
  });

  it("opens enroll form when Enroll Sentinel button clicked", async () => {
    renderPage();
    await waitFor(() => screen.getByText(DID_1_SHORT));
    fireEvent.click(screen.getByRole("button", { name: /enroll sentinel/i }));
    expect(screen.getByRole("dialog")).toBeDefined();
  });

  it("pagination controls are rendered", async () => {
    renderPage();
    await waitFor(() => screen.getByText(DID_1_SHORT));
    const pagination = document.querySelector(".MuiTablePagination-displayedRows");
    expect(pagination).not.toBeNull();
  });
});
