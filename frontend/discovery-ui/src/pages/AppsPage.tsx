import React, { useEffect, useRef, useState } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Chip from "@mui/material/Chip";
import CircularProgress from "@mui/material/CircularProgress";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogTitle from "@mui/material/DialogTitle";
import IconButton from "@mui/material/IconButton";
import ListItemIcon from "@mui/material/ListItemIcon";
import ListItemText from "@mui/material/ListItemText";
import Menu from "@mui/material/Menu";
import MenuItem from "@mui/material/MenuItem";
import Snackbar from "@mui/material/Snackbar";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import TextField from "@mui/material/TextField";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";
import Paper from "@mui/material/Paper";
import AddIcon from "@mui/icons-material/Add";
import MoreVertIcon from "@mui/icons-material/MoreVert";
import EditIcon from "@mui/icons-material/Edit";
import BlockIcon from "@mui/icons-material/Block";
import { type App, listApps, createApp, updateApp, deleteApp } from "../api/apps";

function relativeTime(isoString: string): string {
  const diffMs = Date.now() - new Date(isoString).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// ── App Form Dialog ──────────────────────────────────────────────────────────

interface AppFormDialogProps {
  open: boolean;
  initial?: App;
  onClose: (saved: boolean) => void;
}

const AppFormDialog: React.FC<AppFormDialogProps> = ({ open, initial, onClose }) => {
  const isEdit = Boolean(initial);
  const [name, setName] = useState("");
  const [owner, setOwner] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (open) {
      setName(initial?.name ?? "");
      setOwner(initial?.owner ?? "");
      setError("");
      setSaving(false);
    }
  }, [open, initial]);

  const nameError = name.length > 128 ? "Max 128 characters" : "";
  const ownerError = owner.length > 256 ? "Max 256 characters" : "";
  const canSubmit = name.trim().length > 0 && !nameError && !ownerError && !saving;

  const handleSubmit = async () => {
    setSaving(true);
    setError("");
    try {
      if (isEdit && initial) {
        await updateApp(initial.id, { name: name.trim(), owner: owner.trim() || undefined });
      } else {
        await createApp({ name: name.trim(), owner: owner.trim() || undefined });
      }
      onClose(true);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      setError(typeof msg === "string" ? msg : (isEdit ? "Failed to update app." : "Failed to create app."));
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onClose={() => onClose(false)} maxWidth="xs" fullWidth>
      <DialogTitle>{isEdit ? "Edit App" : "New App"}</DialogTitle>
      <DialogContent>
        <Box sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField
            label="Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            error={Boolean(nameError)}
            helperText={nameError || "Unique application name (e.g. my-api)"}
            inputProps={{ maxLength: 128 }}
            required
            autoFocus
          />
          <TextField
            label="Owner"
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
            error={Boolean(ownerError)}
            helperText={ownerError || "Email, DID, or team identifier (optional)"}
            inputProps={{ maxLength: 256 }}
          />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => onClose(false)}>Cancel</Button>
        <Button onClick={handleSubmit} variant="contained" disabled={!canSubmit}>
          {isEdit ? "Save" : "Create"}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

// ── Deactivate Confirmation Dialog ───────────────────────────────────────────

interface DeactivateDialogProps {
  app: App | null;
  onClose: (confirmed: boolean) => void;
}

const DeactivateDialog: React.FC<DeactivateDialogProps> = ({ app, onClose }) => (
  <Dialog open={Boolean(app)} onClose={() => onClose(false)} maxWidth="xs" fullWidth>
    <DialogTitle>Deactivate App</DialogTitle>
    <DialogContent>
      <Typography>
        Deactivate <strong>{app?.name}</strong>? It will no longer appear in service creation dropdowns. This can be undone via the API.
      </Typography>
    </DialogContent>
    <DialogActions>
      <Button onClick={() => onClose(false)}>Cancel</Button>
      <Button onClick={() => onClose(true)} variant="contained" color="error">
        Deactivate
      </Button>
    </DialogActions>
  </Dialog>
);

// ── Row action menu ───────────────────────────────────────────────────────────

interface RowMenuProps {
  app: App;
  onEdit: (app: App) => void;
  onDeactivate: (app: App) => void;
}

const RowMenu: React.FC<RowMenuProps> = ({ app, onEdit, onDeactivate }) => {
  const [anchor, setAnchor] = useState<null | HTMLElement>(null);
  const btnRef = useRef<HTMLButtonElement>(null);

  return (
    <>
      <IconButton
        ref={btnRef}
        size="small"
        onClick={(e) => { e.stopPropagation(); setAnchor(e.currentTarget); }}
        aria-label="row actions"
      >
        <MoreVertIcon fontSize="small" />
      </IconButton>
      <Menu
        anchorEl={anchor}
        open={Boolean(anchor)}
        onClose={() => setAnchor(null)}
        onClick={() => setAnchor(null)}
      >
        <MenuItem onClick={() => onEdit(app)}>
          <ListItemIcon><EditIcon fontSize="small" /></ListItemIcon>
          <ListItemText>Edit</ListItemText>
        </MenuItem>
        {app.is_active && (
          <MenuItem onClick={() => onDeactivate(app)}>
            <ListItemIcon><BlockIcon fontSize="small" color="error" /></ListItemIcon>
            <ListItemText sx={{ color: "error.main" }}>Deactivate</ListItemText>
          </MenuItem>
        )}
      </Menu>
    </>
  );
};

// ── Page ─────────────────────────────────────────────────────────────────────

export const AppsPage: React.FC = () => {
  const [apps, setApps] = useState<App[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [formOpen, setFormOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<App | undefined>(undefined);
  const [deactivateTarget, setDeactivateTarget] = useState<App | null>(null);
  const [snack, setSnack] = useState("");

  const load = () => {
    setLoading(true);
    setLoadError("");
    listApps({ limit: 100 })
      .then((res) => setApps(res.items))
      .catch(() => setLoadError("Failed to load apps."))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleFormClose = (saved: boolean) => {
    setFormOpen(false);
    setEditTarget(undefined);
    if (saved) {
      load();
      setSnack(editTarget ? "App updated." : "App created.");
    }
  };

  const handleDeactivateClose = async (confirmed: boolean) => {
    if (!confirmed || !deactivateTarget) { setDeactivateTarget(null); return; }
    try {
      await deleteApp(deactivateTarget.id);
      setDeactivateTarget(null);
      load();
      setSnack("App deactivated.");
    } catch {
      setDeactivateTarget(null);
      setSnack("Failed to deactivate app.");
    }
  };

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Typography variant="h5">Apps</Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => { setEditTarget(undefined); setFormOpen(true); }}
        >
          New App
        </Button>
      </Box>

      {loading && <CircularProgress />}
      {!loading && loadError && <Alert severity="error">{loadError}</Alert>}

      {!loading && !loadError && (
        <Paper>
          <TableContainer>
            <Table size="small" aria-label="apps table">
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Owner</TableCell>
                  <TableCell>Active</TableCell>
                  <TableCell>Created</TableCell>
                  <TableCell width={48} />
                </TableRow>
              </TableHead>
              <TableBody>
                {apps.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} align="center">No apps found.</TableCell>
                  </TableRow>
                )}
                {apps.map((app) => (
                  <TableRow key={app.id} hover>
                    <TableCell>
                      <Tooltip title={app.id}>
                        <strong style={{ fontFamily: "monospace" }}>{app.name}</strong>
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      {app.owner
                        ? <Tooltip title={app.owner}><span>{app.owner.length > 32 ? app.owner.slice(0, 32) + "…" : app.owner}</span></Tooltip>
                        : "—"}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={app.is_active ? "active" : "inactive"}
                        color={app.is_active ? "success" : "default"}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      {app.created_at ? relativeTime(app.created_at) : "—"}
                    </TableCell>
                    <TableCell>
                      <RowMenu
                        app={app}
                        onEdit={(a) => { setEditTarget(a); setFormOpen(true); }}
                        onDeactivate={(a) => setDeactivateTarget(a)}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}

      <AppFormDialog open={formOpen} initial={editTarget} onClose={handleFormClose} />
      <DeactivateDialog app={deactivateTarget} onClose={handleDeactivateClose} />

      <Snackbar
        open={Boolean(snack)}
        autoHideDuration={3000}
        onClose={() => setSnack("")}
        message={snack}
      />
    </Box>
  );
};
