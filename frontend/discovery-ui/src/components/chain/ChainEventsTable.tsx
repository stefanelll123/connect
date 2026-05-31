import React, { useState } from "react";
import Box from "@mui/material/Box";
import Checkbox from "@mui/material/Checkbox";
import Chip from "@mui/material/Chip";
import Collapse from "@mui/material/Collapse";
import FormControlLabel from "@mui/material/FormControlLabel";
import FormGroup from "@mui/material/FormGroup";
import IconButton from "@mui/material/IconButton";
import Link from "@mui/material/Link";
import Paper from "@mui/material/Paper";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TablePagination from "@mui/material/TablePagination";
import TableRow from "@mui/material/TableRow";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";
import { useQuery } from "../hooks/useQuery";
import { listChainEvents, type ChainEvent } from "../../api/chain";

const EVENT_TYPES = [
  "IssuerRegistered",
  "IssuerRevoked",
  "PolicyUpdated",
  "StatusAnchorPublished",
  "ServiceRegistered",
] as const;

const EVENT_COLORS: Record<string, "primary" | "error" | "warning" | "success" | "info"> = {
  IssuerRegistered: "primary",
  IssuerRevoked: "error",
  PolicyUpdated: "warning",
  StatusAnchorPublished: "success",
  ServiceRegistered: "info",
};

const ETHERSCAN_BASE = "https://sepolia.etherscan.io/tx/";

interface ExpandedRowProps {
  event: ChainEvent;
}
const ExpandedRow: React.FC<ExpandedRowProps> = ({ event }) => (
  <Box
    component="pre"
    sx={{
      p: 2,
      m: 0,
      bgcolor: "action.hover",
      fontSize: "0.75rem",
      overflowX: "auto",
      whiteSpace: "pre-wrap",
      wordBreak: "break-all",
    }}
  >
    {JSON.stringify(event.args ?? {}, null, 2)}
  </Box>
);

export const ChainEventsTable: React.FC = () => {
  const [selectedTypes, setSelectedTypes] = useState<Set<string>>(new Set());
  const [page, setPage] = useState(0);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const activeType = selectedTypes.size === 1 ? [...selectedTypes][0] : undefined;

  const { data, isLoading } = useQuery(
    ["chain-events", activeType, page],
    () => listChainEvents({ event_name: activeType, limit: 100 }),
  );

  const events: ChainEvent[] = data?.items ?? [];

  const toggleType = (type: string) =>
    setSelectedTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });

  return (
    <Box>
      <FormGroup row sx={{ mb: 1 }}>
        {EVENT_TYPES.map((t) => (
          <FormControlLabel
            key={t}
            control={
              <Checkbox
                size="small"
                checked={selectedTypes.has(t)}
                onChange={() => toggleType(t)}
              />
            }
            label={<Chip label={t} size="small" color={EVENT_COLORS[t]} />}
          />
        ))}
      </FormGroup>

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell width={40} />
              <TableCell align="right">Block</TableCell>
              <TableCell>Event Type</TableCell>
              <TableCell>Tx Hash</TableCell>
              <TableCell>Actor</TableCell>
              <TableCell>Payload</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {isLoading && (
              <TableRow>
                <TableCell colSpan={6} align="center">Loading…</TableCell>
              </TableRow>
            )}
            {!isLoading && events.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} align="center">No events found.</TableCell>
              </TableRow>
            )}
            {events.map((evt) => (
              <React.Fragment key={evt.id}>
                <TableRow
                  hover
                  sx={{ cursor: "pointer" }}
                  onClick={() => setExpandedId(expandedId === evt.id ? null : evt.id)}
                >
                  <TableCell>
                    <IconButton
                      size="small"
                      aria-label="expand event"
                    >
                      {expandedId === evt.id ? (
                        <KeyboardArrowUpIcon fontSize="small" />
                      ) : (
                        <KeyboardArrowDownIcon fontSize="small" />
                      )}
                    </IconButton>
                  </TableCell>
                  <TableCell align="right">{evt.block_number.toLocaleString()}</TableCell>
                  <TableCell>
                    <Chip
                      label={evt.event_name}
                      size="small"
                      color={EVENT_COLORS[evt.event_name] ?? "default"}
                    />
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                      <code>{evt.tx_hash.slice(0, 10)}</code>
                      <Link
                        href={`${ETHERSCAN_BASE}${evt.tx_hash}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <OpenInNewIcon fontSize="inherit" />
                      </Link>
                    </Box>
                  </TableCell>
                  <TableCell>
                    <code>{evt.contract}</code>
                  </TableCell>
                </TableRow>
                <TableRow>
                  <TableCell colSpan={6} sx={{ p: 0, border: 0 }}>
                    <Collapse in={expandedId === evt.id} unmountOnExit>
                      <ExpandedRow event={evt} />
                    </Collapse>
                  </TableCell>
                </TableRow>
              </React.Fragment>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      <TablePagination
        component="div"
        count={-1}
        page={page}
        rowsPerPage={20}
        rowsPerPageOptions={[20]}
        onPageChange={(_, p) => setPage(p)}
      />
    </Box>
  );
};
