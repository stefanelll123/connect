import React, { useEffect, useState } from "react";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Chip from "@mui/material/Chip";
import Collapse from "@mui/material/Collapse";
import FormControl from "@mui/material/FormControl";
import IconButton from "@mui/material/IconButton";
import InputLabel from "@mui/material/InputLabel";
import MenuItem from "@mui/material/MenuItem";
import Paper from "@mui/material/Paper";
import Select from "@mui/material/Select";
import Snackbar from "@mui/material/Snackbar";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TablePagination from "@mui/material/TablePagination";
import TableRow from "@mui/material/TableRow";
import Toolbar from "@mui/material/Toolbar";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import BlockIcon from "@mui/icons-material/Block";
import AddIcon from "@mui/icons-material/Add";
import { StatusChip } from "../components/common/StatusChip";
import { IssueCredentialWizard } from "../components/credentials/IssueCredentialWizard";
import { RevokeCredentialDialog } from "../components/credentials/RevokeCredentialDialog";
import { type Credential, listCredentials } from "../api/credentials";

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function relativeDate(iso: string) {
  const diff = new Date(iso).getTime() - Date.now();
  const days = Math.round(diff / 86_400_000);
  if (days < 0) return `${Math.abs(days)}d ago`;
  return `in ${days}d`;
}

const ENVS = ["prod", "staging", "dev"];
const STATUSES = ["active", "revoked", "expired"];
const TYPES = ["access_grant", "service_binding", "identity"];

interface ExpandedRowProps {
  credential: Credential;
  onRevoke: (cred: Credential) => void;
}

const ExpandedRow: React.FC<ExpandedRowProps> = ({ credential, onRevoke }) => {
  const canRevoke = credential.status !== "revoked" && credential.status !== "expired";
  return (
    <Box sx={{ p: 2, bgcolor: "action.hover" }}>
      <Table size="small">
        <TableBody>
          <TableRow>
            <TableCell>Issuer DID</TableCell>
            <TableCell>
              <Tooltip title={credential.issuer_did}>
                <code>{credential.issuer_did.slice(-12)}</code>
              </Tooltip>
            </TableCell>
          </TableRow>
          <TableRow>
            <TableCell>JTI</TableCell>
            <TableCell><code>{credential.jti}</code></TableCell>
          </TableRow>
          <TableRow>
            <TableCell>Status List</TableCell>
            <TableCell>
              {credential.status_list_id ?? "—"} / index {credential.status_list_index ?? "—"}
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
      {canRevoke && (
        <Button
          startIcon={<BlockIcon />}
          color="error"
          size="small"
          sx={{ mt: 1 }}
          onClick={() => onRevoke(credential)}
        >
          Revoke
        </Button>
      )}
    </Box>
  );
};

export const CredentialsPage: React.FC = () => {
  const [envFilter, setEnvFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [page, setPage] = useState(0);
  const [rowsPerPage] = useState(20);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [issueOpen, setIssueOpen] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<Credential | null>(null);
  const [snack, setSnack] = useState("");
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);

  const params = {
    env: envFilter || undefined,
    status: statusFilter || undefined,
    credential_type: typeFilter || undefined,
    skip: page * rowsPerPage,
    limit: rowsPerPage,
  };

  useEffect(() => {
    setLoading(true);
    listCredentials(params)
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
  }, [envFilter, statusFilter, typeFilter, page]);

  return (
    <Box>
      <Toolbar disableGutters sx={{ gap: 2, mb: 2, flexWrap: "wrap" }}>
        <Typography variant="h6" sx={{ flexGrow: 1 }}>
          Credentials
        </Typography>

        {[
          { label: "Environment", value: envFilter, setter: setEnvFilter, options: ENVS },
          { label: "Status", value: statusFilter, setter: setStatusFilter, options: STATUSES },
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

        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setIssueOpen(true)}
        >
          Issue
        </Button>
      </Toolbar>

      <Paper>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell width={40} />
                <TableCell>Credential ID</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Subject</TableCell>
                <TableCell>Env</TableCell>
                <TableCell>Expires</TableCell>
                <TableCell>Status</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading && (
                <TableRow>
                  <TableCell colSpan={7} align="center">Loading…</TableCell>
                </TableRow>
              )}
              {!loading && credentials.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} align="center">No credentials found.</TableCell>
                </TableRow>
              )}
              {credentials.map((cred) => (
                <React.Fragment key={cred.credential_id}>
                  <TableRow hover>
                    <TableCell>
                      <IconButton
                        size="small"
                        onClick={() => setExpanded(expanded === cred.credential_id ? null : cred.credential_id)}
                        aria-label="expand row"
                      >
                        {expanded === cred.credential_id ? <KeyboardArrowUpIcon /> : <KeyboardArrowDownIcon />}
                      </IconButton>
                    </TableCell>
                    <TableCell>
                      <Tooltip title={cred.credential_id}>
                        <code>{cred.credential_id.slice(0, 12)}</code>
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <Chip label={cred.credential_type} size="small" />
                    </TableCell>
                    <TableCell>
                      <Tooltip title={cred.subject_did}>
                        <code>{cred.subject_did.slice(-8)}</code>
                      </Tooltip>
                    </TableCell>
                    <TableCell>{cred.env}</TableCell>
                    <TableCell>
                      <Tooltip title={formatDate(cred.expires_at)}>
                        <span>{relativeDate(cred.expires_at)}</span>
                      </Tooltip>
                    </TableCell>
                    <TableCell><StatusChip status={cred.status} /></TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell colSpan={7} sx={{ p: 0, border: 0 }}>
                      <Collapse in={expanded === cred.credential_id} unmountOnExit>
                        <ExpandedRow credential={cred} onRevoke={setRevokeTarget} />
                      </Collapse>
                    </TableCell>
                  </TableRow>
                </React.Fragment>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        <TablePagination
          rowsPerPageOptions={[20]}
          component="div"
          count={total}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={(_, p) => setPage(p)}
        />
      </Paper>

      <IssueCredentialWizard
        open={issueOpen}
        onClose={(issued) => {
          setIssueOpen(false);
          if (issued) {
            setSnack("Credential issued successfully.");
            setPage(0);
          }
        }}
      />

      {revokeTarget && (
        <RevokeCredentialDialog
          credentialId={revokeTarget.credential_id}
          credentialIdPrefix={revokeTarget.credential_id.slice(0, 12)}
          isProd={revokeTarget.env === "prod"}
          open={!!revokeTarget}
          onClose={(revoked) => {
            setRevokeTarget(null);
            if (revoked) {
              setSnack("Credential revoked.");
              setPage(0);
            }
          }}
        />
      )}

      <Snackbar
        open={!!snack}
        autoHideDuration={4000}
        onClose={() => setSnack("")}
        message={snack}
      />
    </Box>
  );
};
