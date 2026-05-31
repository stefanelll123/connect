import React, { useCallback, useEffect, useRef, useState } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Chip from "@mui/material/Chip";
import CircularProgress from "@mui/material/CircularProgress";
import Paper from "@mui/material/Paper";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Typography from "@mui/material/Typography";
import DownloadIcon from "@mui/icons-material/Download";
import { AuditFiltersBar, type AuditFilters } from "../components/audit/AuditFiltersBar";
import { TamperDetectionStatus } from "../components/audit/TamperDetectionStatus";
import {
  exportAuditEventsJSONL,
  listAuditEvents,
  type AuditEvent,
} from "../api/audit";

const EXPORT_LIMIT = 100_000;

function actionColor(action: string): "primary" | "warning" | "error" | "default" {
  if (action.startsWith("credential")) return "primary";
  if (action.startsWith("chain")) return "warning";
  if (action.startsWith("auth")) return "error";
  return "default";
}

const DEFAULT_FILTERS: AuditFilters = {
  actor_did: "",
  actions: [],
  target_id: "",
  from_ts: "",
  to_ts: "",
};

export const AuditPage: React.FC = () => {
  const [filters, setFilters] = useState<AuditFilters>(DEFAULT_FILTERS);
  const [cursor, setCursor] = useState<string | undefined>();
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [allEvents, setAllEvents] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [isLoading, setIsLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [exportProgress, setExportProgress] = useState(0);
  const [showExportWarning, setShowExportWarning] = useState(false);

  const fetchIdRef = useRef(0);

  useEffect(() => {
    const id = ++fetchIdRef.current;
    setIsLoading(true);
    listAuditEvents({
      actor_id: filters.actor_did || undefined,
      action: filters.actions.length === 1 ? filters.actions[0] : undefined,
      from: filters.from_ts || undefined,
      to: filters.to_ts || undefined,
      limit: 50,
      cursor,
    })
      .then((resp) => {
        if (fetchIdRef.current !== id) return;
        if (!cursor) {
          setAllEvents(resp.items);
          setTotal(resp.count);
        } else {
          setAllEvents((prev) => [...prev, ...resp.items]);
        }
        setNextCursor(resp.next_cursor);
      })
      .catch(console.error)
      .finally(() => {
        if (fetchIdRef.current === id) setIsLoading(false);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    filters.actor_did,
    filters.actions.join(","),
    filters.target_id,
    filters.from_ts,
    filters.to_ts,
    cursor,
  ]);

  const handleFiltersChange = useCallback((updated: AuditFilters) => {
    setFilters(updated);
    setCursor(undefined);
    setAllEvents([]);
  }, []);

  const handleLoadMore = () => {
    if (nextCursor) setCursor(nextCursor);
  };

  const handleExport = async () => {
    if (total > EXPORT_LIMIT) setShowExportWarning(true);
    setExporting(true);
    setExportProgress(0);
    try {
      await exportAuditEventsJSONL(
        {
          actor_did: filters.actor_did || undefined,
          action: filters.actions.length === 1 ? filters.actions[0] : undefined,
          target_id: filters.target_id || undefined,
          from_ts: filters.from_ts || undefined,
          to_ts: filters.to_ts || undefined,
        },
        setExportProgress,
      );
    } finally {
      setExporting(false);
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Box
        sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}
      >
        <Typography variant="h5">Audit Log</Typography>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
          <TamperDetectionStatus />
          <Button
            variant="outlined"
            size="small"
            startIcon={exporting ? <CircularProgress size={14} /> : <DownloadIcon />}
            onClick={handleExport}
            disabled={exporting}
          >
            {exporting ? `Downloading\u2026 ${exportProgress} events` : "Export JSONL"}
          </Button>
        </Box>
      </Box>

      {showExportWarning && (
        <Alert severity="warning" onClose={() => setShowExportWarning(false)} sx={{ mb: 2 }}>
          Export is limited to {EXPORT_LIMIT.toLocaleString()} events. Refine your filters to
          reduce the result set.
        </Alert>
      )}

      <Box sx={{ mb: 2 }}>
        <AuditFiltersBar filters={filters} onChange={handleFiltersChange} />
      </Box>

      {total > 0 && (
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          Showing 1\u2013{allEvents.length} of {total.toLocaleString()} events
        </Typography>
      )}

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Timestamp</TableCell>
              <TableCell>Action</TableCell>
              <TableCell>Actor</TableCell>
              <TableCell>Target ID</TableCell>
              <TableCell>Env</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {isLoading && allEvents.length === 0 && (
              <TableRow>
                <TableCell colSpan={4} align="center">
                  <CircularProgress size={20} />
                </TableCell>
              </TableRow>
            )}
            {!isLoading && allEvents.length === 0 && (
              <TableRow>
                <TableCell colSpan={4} align="center">
                  No audit events found.
                </TableCell>
              </TableRow>
            )}
            {allEvents.map((evt) => (
              <TableRow key={evt.event_id} hover>
                <TableCell sx={{ whiteSpace: "nowrap" }}>
                  {new Date(evt.ts).toLocaleString()}
                </TableCell>
                <TableCell>
                  <Chip label={evt.action} size="small" color={actionColor(evt.action)} />
                </TableCell>
                <TableCell>
                  <code>{(evt.actor_id ?? "unknown").slice(0, 8)}</code>
                </TableCell>
                <TableCell>{evt.target_id}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {nextCursor && (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 2 }}>
          <Button variant="outlined" onClick={handleLoadMore} disabled={isLoading}>
            Load more
          </Button>
        </Box>
      )}
    </Box>
  );
};
