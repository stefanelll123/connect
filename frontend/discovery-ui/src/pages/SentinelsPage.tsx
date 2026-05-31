import React, { useState } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import CircularProgress from "@mui/material/CircularProgress";
import Chip from "@mui/material/Chip";
import Drawer from "@mui/material/Drawer";
import Divider from "@mui/material/Divider";
import FormControl from "@mui/material/FormControl";
import InputLabel from "@mui/material/InputLabel";
import MenuItem from "@mui/material/MenuItem";
import Select from "@mui/material/Select";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import TablePagination from "@mui/material/TablePagination";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";
import AddIcon from "@mui/icons-material/Add";
import { StatusChip } from "../components/common/StatusChip";
import { AuditSnippet } from "../components/audit/AuditSnippet";
import { CreateEnrollmentForm } from "../components/enrollment/CreateEnrollmentForm";
import { listSentinels, Sentinel } from "../api/sentinels";
import { useQuery } from "../components/hooks/useQuery";

function relativeTime(isoString: string): string {
  const diffMs = Date.now() - new Date(isoString).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export const SentinelsPage: React.FC = () => {
  const [page, setPage] = useState(0);
  const [filterEnv, setFilterEnv] = useState("");
  const [filterRole, setFilterRole] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [selected, setSelected] = useState<Sentinel | null>(null);
  const [enrollOpen, setEnrollOpen] = useState(false);

  const { data, isLoading, error, refetch } = useQuery(
    ["sentinels", page, filterEnv, filterRole, filterStatus],
    () =>
      listSentinels({
        env: filterEnv || undefined,
        role: filterRole || undefined,
        status: filterStatus || undefined,
        limit: 25,
      }),
  );

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Typography variant="h5">Sentinels</Typography>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setEnrollOpen(true)}>
          Enroll Sentinel
        </Button>
      </Box>

      <Box sx={{ display: "flex", gap: 2, mb: 2 }}>
        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel>Env</InputLabel>
          <Select value={filterEnv} label="Env" onChange={(e) => setFilterEnv(e.target.value)}>
            <MenuItem value="">All</MenuItem>
            <MenuItem value="dev">dev</MenuItem>
            <MenuItem value="test">test</MenuItem>
            <MenuItem value="prod">prod</MenuItem>
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel>Role</InputLabel>
          <Select value={filterRole} label="Role" onChange={(e) => setFilterRole(e.target.value)}>
            <MenuItem value="">All</MenuItem>
            <MenuItem value="producer">producer</MenuItem>
            <MenuItem value="consumer">consumer</MenuItem>
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel>Status</InputLabel>
          <Select value={filterStatus} label="Status" onChange={(e) => setFilterStatus(e.target.value)}>
            <MenuItem value="">All</MenuItem>
            <MenuItem value="active">active</MenuItem>
            <MenuItem value="degraded">degraded</MenuItem>
            <MenuItem value="offline">offline</MenuItem>
            <MenuItem value="pending">pending</MenuItem>
          </Select>
        </FormControl>
      </Box>

      {isLoading && <CircularProgress />}
      {!!error && <Alert severity="error">Failed to load sentinels.</Alert>}

      {!isLoading && !error && (
        <>
          <Table size="small" aria-label="sentinels table">
            <TableHead>
              <TableRow>
                <TableCell>DID</TableCell>
                <TableCell>Role</TableCell>
                <TableCell>Env</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Last Seen</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {(data?.items ?? []).map((s: Sentinel) => (
                <TableRow
                  key={s.id}
                  hover
                  sx={{ cursor: "pointer" }}
                  onClick={() => setSelected(s)}
                >
                  <TableCell>
                    <Tooltip title={s.did ?? ""}>
                      <code>{s.did?.split(":").pop()?.slice(0, 16) ?? s.id?.slice(0, 8) ?? "—"}</code>
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    <Chip label={s.role} size="small" color={s.role === "producer" ? "primary" : "secondary"} />
                  </TableCell>
                  <TableCell>{s.env}</TableCell>
                  <TableCell><StatusChip status={s.computed_status ?? "unknown"} /></TableCell>
                  <TableCell>
                    {s.last_seen ? (
                      <Tooltip title={s.last_seen}>
                        <span>{relativeTime(s.last_seen)}</span>
                      </Tooltip>
                    ) : "—"}
                  </TableCell>
                </TableRow>
              ))}
              {(data?.items ?? []).length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} align="center">No sentinels found.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
          <TablePagination
            component="div"
            count={-1}
            page={page}
            rowsPerPage={25}
            rowsPerPageOptions={[25]}
            onPageChange={(_, p) => setPage(p)}
          />
        </>
      )}

      {/* Detail drawer */}
      <Drawer anchor="right" open={Boolean(selected)} onClose={() => setSelected(null)}>
        {selected && (
          <Box sx={{ width: 420, p: 3 }}>
            <Typography variant="h6" gutterBottom>Sentinel Detail</Typography>
            <Typography variant="body2" sx={{ fontFamily: "monospace", wordBreak: "break-all", mb: 1 }}>
              {selected.did}
            </Typography>
            <Box sx={{ display: "flex", gap: 1, mb: 1 }}>
              <Chip label={selected.role} size="small" color={selected.role === "producer" ? "primary" : "secondary"} />
              <Chip label={selected.env} size="small" />
              <StatusChip status={selected.computed_status ?? "unknown"} />
            </Box>
            <Divider sx={{ my: 2 }} />
            <Typography variant="subtitle2" gutterBottom>Recent Audit Events</Typography>
            <AuditSnippet entityType="sentinel" entityId={selected.id} />
          </Box>
        )}
      </Drawer>

      <CreateEnrollmentForm open={enrollOpen} onClose={() => { setEnrollOpen(false); refetch(); }} />
    </Box>
  );
};
