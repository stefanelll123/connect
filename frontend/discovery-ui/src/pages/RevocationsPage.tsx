import React, { useEffect, useState } from "react";
import Box from "@mui/material/Box";
import Chip from "@mui/material/Chip";
import FormControl from "@mui/material/FormControl";
import InputLabel from "@mui/material/InputLabel";
import LinearProgress from "@mui/material/LinearProgress";
import MenuItem from "@mui/material/MenuItem";
import Paper from "@mui/material/Paper";
import Select from "@mui/material/Select";
import Tab from "@mui/material/Tab";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TablePagination from "@mui/material/TablePagination";
import TableRow from "@mui/material/TableRow";
import Tabs from "@mui/material/Tabs";
import Toolbar from "@mui/material/Toolbar";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";
import { StatusChip } from "../components/common/StatusChip";
import { type Credential, listCredentials } from "../api/credentials";
import { type StatusList, listStatusLists } from "../api/statusLists";

const ENVS = ["prod", "staging", "dev"];
const TYPES = ["access_grant", "service_binding", "identity"];

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

// ── Revoked Credentials Tab ──────────────────────────────────────────────────
const RevokedCredentialsTab: React.FC = () => {
  const [envFilter, setEnvFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [page, setPage] = useState(0);
  const [rowsPerPage] = useState(20);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    listCredentials({
      status: "revoked",
      env: envFilter || undefined,
      credential_type: typeFilter || undefined,
      skip: page * rowsPerPage,
      limit: rowsPerPage,
    })
      .then((res) => {
        setCredentials(res.items);
        setTotal(res.total);
      })
      .catch(() => {
        setCredentials([]);
        setTotal(0);
      })
      .finally(() => setLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [envFilter, typeFilter, page]);

  return (
    <Box>
      <Toolbar disableGutters sx={{ gap: 2, mb: 2, flexWrap: "wrap" }}>
        {[
          { label: "Environment", value: envFilter, setter: setEnvFilter, options: ENVS },
          { label: "Type", value: typeFilter, setter: setTypeFilter, options: TYPES },
        ].map(({ label, value, setter, options }) => (
          <FormControl key={label} size="small" sx={{ minWidth: 110 }}>
            <InputLabel>{label}</InputLabel>
            <Select value={value} label={label} onChange={(e) => setter(e.target.value)}>
              <MenuItem value="">All</MenuItem>
              {options.map((o) => <MenuItem key={o} value={o}>{o}</MenuItem>)}
            </Select>
          </FormControl>
        ))}
      </Toolbar>
      <Paper>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Credential ID</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Subject</TableCell>
                <TableCell>Env</TableCell>
                <TableCell>Revoked At</TableCell>
                <TableCell>Status</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading && (
                <TableRow>
                  <TableCell colSpan={6} align="center">Loading…</TableCell>
                </TableRow>
              )}
              {!loading && credentials.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} align="center">No revoked credentials found.</TableCell>
                </TableRow>
              )}
              {credentials.map((cred) => (
                <TableRow key={cred.credential_id} hover>
                  <TableCell>
                    <Tooltip title={cred.credential_id}>
                      <code>{cred.credential_id.slice(0, 12)}</code>
                    </Tooltip>
                  </TableCell>
                  <TableCell><Chip label={cred.credential_type} size="small" /></TableCell>
                  <TableCell>
                    <Tooltip title={cred.subject_did}>
                      <code>{cred.subject_did.slice(-8)}</code>
                    </Tooltip>
                  </TableCell>
                  <TableCell>{cred.env}</TableCell>
                  <TableCell>{cred.revoked_at ? formatDate(cred.revoked_at) : "—"}</TableCell>
                  <TableCell><StatusChip status={cred.status} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        <TablePagination
          component="div"
          count={total}
          page={page}
          onPageChange={(_, p) => setPage(p)}
          rowsPerPage={rowsPerPage}
          rowsPerPageOptions={[rowsPerPage]}
        />
      </Paper>
    </Box>
  );
};

// ── Status Lists Tab ─────────────────────────────────────────────────────────
const StatusListsTab: React.FC = () => {
  const [envFilter, setEnvFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [page, setPage] = useState(0);
  const [rowsPerPage] = useState(20);
  const [statusLists, setStatusLists] = useState<StatusList[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    listStatusLists({
      env: envFilter || undefined,
      credential_type: typeFilter || undefined,
      skip: page * rowsPerPage,
      limit: rowsPerPage,
    })
      .then((res) => {
        setStatusLists(res.items);
        setTotal(res.total);
      })
      .catch(() => {
        setStatusLists([]);
        setTotal(0);
      })
      .finally(() => setLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [envFilter, typeFilter, page]);

  return (
    <Box>
      <Toolbar disableGutters sx={{ gap: 2, mb: 2, flexWrap: "wrap" }}>
        {[
          { label: "Environment", value: envFilter, setter: setEnvFilter, options: ENVS },
          { label: "Type", value: typeFilter, setter: setTypeFilter, options: TYPES },
        ].map(({ label, value, setter, options }) => (
          <FormControl key={label} size="small" sx={{ minWidth: 110 }}>
            <InputLabel>{label}</InputLabel>
            <Select value={value} label={label} onChange={(e) => setter(e.target.value)}>
              <MenuItem value="">All</MenuItem>
              {options.map((o) => <MenuItem key={o} value={o}>{o}</MenuItem>)}
            </Select>
          </FormControl>
        ))}
      </Toolbar>
      <Paper>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Status List ID</TableCell>
                <TableCell>Env</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Used / Max</TableCell>
                <TableCell>Frozen</TableCell>
                <TableCell>Published At</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading && (
                <TableRow>
                  <TableCell colSpan={6} align="center">Loading…</TableCell>
                </TableRow>
              )}
              {!loading && statusLists.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} align="center">No status lists found.</TableCell>
                </TableRow>
              )}
              {statusLists.map((sl) => (
                <TableRow key={sl.status_list_id} hover>
                  <TableCell><code>{sl.status_list_id}</code></TableCell>
                  <TableCell>{sl.env}</TableCell>
                  <TableCell>
                    <Chip label={sl.credential_type ?? "—"} size="small" />
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <LinearProgress
                        variant="determinate"
                        value={sl.max_size > 0 ? (sl.top_index / sl.max_size) * 100 : 0}
                        sx={{ flexGrow: 1, minWidth: 60 }}
                      />
                      <Typography variant="caption">
                        {sl.top_index}/{sl.max_size}
                      </Typography>
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={sl.is_frozen ? "frozen" : "active"}
                      color={sl.is_frozen ? "default" : "success"}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    {sl.published_at ? formatDate(sl.published_at) : "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        <TablePagination
          component="div"
          count={total}
          page={page}
          onPageChange={(_, p) => setPage(p)}
          rowsPerPage={rowsPerPage}
          rowsPerPageOptions={[rowsPerPage]}
        />
      </Paper>
    </Box>
  );
};

// ── Page ─────────────────────────────────────────────────────────────────────
export const RevocationsPage: React.FC = () => {
  const [tab, setTab] = useState(0);

  return (
    <Box>
      <Typography variant="h6" sx={{ mb: 2 }}>Revocations</Typography>
      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
        <Tab label="Revoked Credentials" />
        <Tab label="Status Lists" />
      </Tabs>
      {tab === 0 && <RevokedCredentialsTab />}
      {tab === 1 && <StatusListsTab />}
    </Box>
  );
};
