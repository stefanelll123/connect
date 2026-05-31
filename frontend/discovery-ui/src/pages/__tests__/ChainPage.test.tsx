import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ChainPage } from "../ChainPage";

// ── Module mocks ──────────────────────────────────────────────────────────────

vi.mock("../../api/chain", () => ({
  getChainStatus: vi.fn(),
  listChainEvents: vi.fn(),
}));

vi.mock("../../api/client", () => ({
  apiClient: { get: vi.fn(), post: vi.fn() },
  registerAuthHandlers: vi.fn(),
}));

import {
  getChainStatus,
  listChainEvents,
} from "../../api/chain";

const mockGetStatus = vi.mocked(getChainStatus);
const mockListEvents = vi.mocked(listChainEvents);

// ── Fixtures ──────────────────────────────────────────────────────────────────

const STATUS_OK = {
  network: "Sepolia",
  chain_id: 11155111,
  rpc_url: "https://rpc.sepolia.example.com",
  is_available: true,
  indexer_last_block: 1_000_000,
  blockchain_integration_enabled: true,
  policy_cache: { is_stale: false, cache_age_seconds: 30 },
};

const STATUS_DEGRADED = {
  ...STATUS_OK,
  is_available: false,
  policy_cache: { is_stale: true, cache_age_seconds: 600 },
};

const EVENTS_RESPONSE = {
  items: [
    {
      id: "evt-1",
      block_number: 999_999,
      event_name: "IssuerRegistered",
      tx_hash: "0xdeadbeefcafe1234567890abcdef1234567890abcdef1234567890abcdef12345678",
      contract: "0x1234567890abcdef1234567890abcdef12345678",
      args: { issuer: "did:web:example.com" },
      indexed_at: new Date().toISOString(),
    },
  ],
  count: 1,
};

function renderPage() {
  return render(
    <MemoryRouter>
      <ChainPage />
    </MemoryRouter>,
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("ChainPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetStatus.mockResolvedValue(STATUS_OK);
    mockListEvents.mockResolvedValue(EVENTS_RESPONSE);
  });

  it("renders chain status cards with network info", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("Sepolia")).toBeDefined());
    expect(screen.getByText("11155111")).toBeDefined();
  });

  it("shows ONLINE chip when is_available is true", async () => {
    renderPage();
    await waitFor(() => screen.getByText("ONLINE"));
    const chip = screen.getByText("ONLINE");
    expect(chip.closest(".MuiChip-root")?.className).toMatch(/colorSuccess/);
  });

  it("shows OFFLINE chip when is_available is false", async () => {
    mockGetStatus.mockResolvedValue(STATUS_DEGRADED);
    renderPage();
    await waitFor(() => screen.getByText("OFFLINE"));
    const chip = screen.getByText("OFFLINE");
    expect(chip.closest(".MuiChip-root")?.className).toMatch(/colorError/);
  });

  it("shows STALE policy cache chip when stale", async () => {
    mockGetStatus.mockResolvedValue(STATUS_DEGRADED);
    renderPage();
    await waitFor(() => expect(screen.getByText("STALE")).toBeDefined());
  });

  it("shows FRESH policy cache chip when not stale", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("FRESH")).toBeDefined());
  });

  it("sets up auto-refresh interval (calls getChainStatus multiple times)", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderPage();
    await waitFor(() => expect(mockGetStatus).toHaveBeenCalledTimes(1));
    vi.advanceTimersByTime(31_000);
    await waitFor(() => expect(mockGetStatus).toHaveBeenCalledTimes(2), { timeout: 2000 });
    vi.useRealTimers();
  });
});
