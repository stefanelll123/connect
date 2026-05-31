import React, { useState } from "react";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogTitle from "@mui/material/DialogTitle";
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
import TextField from "@mui/material/TextField";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";
import Alert from "@mui/material/Alert";
import Chip from "@mui/material/Chip";
import CircularProgress from "@mui/material/CircularProgress";
import AddIcon from "@mui/icons-material/Add";
import { listServices, createService, Service } from "../api/services";
import { listApps, App } from "../api/apps";
import { useQuery } from "../components/hooks/useQuery";
import { ServiceDescriptorDrawer } from "../components/services/ServiceDescriptorDrawer";

const SERVICE_ID_RE = /^[a-z0-9-]+$/;

const CHAIN_MAX_ATTEMPTS = 5;

function chainStatusChip(svc: Service): React.ReactNode {
  if (svc.chain_sync_pending) {
    return <Chip label="Pending deploy" color="warning" size="small" />;
  }
  if (svc.chain_tx_hash) {
    const hash = "0x" + svc.chain_tx_hash;
    return (
      <Tooltip title={hash}>
        <Chip
          label={hash.slice(0, 10) + "…"}
          color="success"
          size="small"
          sx={{ fontFamily: "monospace" }}
        />
      </Tooltip>
    );
  }
  if (!svc.chain_sync_pending && !svc.chain_tx_hash && (svc.chain_sync_attempts ?? 0) >= CHAIN_MAX_ATTEMPTS) {
    return <Chip label="Error at deploy" color="error" size="small" />;
  }
  return null;
}

function relativeTime(isoString: string): string {
  const diffMs = Date.now() - new Date(isoString).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

const CreateServiceModal: React.FC<{ open: boolean; onClose: (created: boolean) => void }> = ({
  open,
  onClose,
}) => {
  const [appId, setAppId] = useState("");
  const [serviceId, setServiceId] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [env, setEnv] = useState("dev");
  const [ownerDid, setOwnerDid] = useState("");
  const [description, setDescription] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [error, setError] = useState("");
  const [apps, setApps] = useState<App[]>([]);

  React.useEffect(() => {
    if (open) listApps().then((res) => setApps(res.items)).catch(() => setApps([]));
  }, [open]);

  const idError = serviceId && !SERVICE_ID_RE.test(serviceId)
    ? "Only lowercase alphanumeric and hyphens allowed"
    : "";
  const didError = ownerDid && !ownerDid.startsWith("did:")
    ? "Must start with did:"
    : "";

  const handleSubmit = async () => {
    setError("");
    try {
      await createService({ app_id: appId, service_id: serviceId, env, display_name: displayName, owner_did: ownerDid || undefined, description: description || undefined, base_url: baseUrl });
      onClose(true);
      setAppId(""); setServiceId(""); setDisplayName(""); setOwnerDid(""); setDescription(""); setBaseUrl("");
    } catch {
      setError("Failed to create service.");
    }
  };

  return (
    <Dialog open={open} onClose={() => onClose(false)} maxWidth="sm" fullWidth>
      <DialogTitle>Create Service</DialogTitle>
      <DialogContent>
        <Box sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
          {error && <Alert severity="error">{String(error)}</Alert>}
          <FormControl required>
            <InputLabel>Application</InputLabel>
            <Select value={appId} label="Application" onChange={(e) => setAppId(e.target.value)}>
              {apps.filter(a => a.is_active).map(a => (
                <MenuItem key={a.id} value={a.id}>{a.name}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <TextField
            label="Service ID"
            value={serviceId}
            onChange={(e) => setServiceId(e.target.value)}
            error={Boolean(idError)}
            helperText={idError || "e.g. my-api-service"}
            inputProps={{ maxLength: 64 }}
            required
          />
          <TextField
            label="Display Name"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            inputProps={{ maxLength: 256 }}
            required
          />
          <FormControl required>
            <InputLabel>Environment</InputLabel>
            <Select value={env} label="Environment" onChange={(e) => setEnv(e.target.value)}>
              <MenuItem value="dev">dev</MenuItem>
              <MenuItem value="test">test</MenuItem>
              <MenuItem value="prod">prod</MenuItem>
            </Select>
          </FormControl>
          <TextField
            label="Owner DID"
            value={ownerDid}
            onChange={(e) => setOwnerDid(e.target.value)}
            error={Boolean(didError)}
            helperText={didError}
          />
          <TextField
            label="Base URL"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            error={Boolean(baseUrl && !baseUrl.startsWith("http"))}
            helperText={baseUrl && !baseUrl.startsWith("http") ? "Must start with http:// or https://" : "e.g. https://my-service.example.com"}
            inputProps={{ maxLength: 2048 }}
            required
          />
          <TextField
            label="Description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            multiline
            rows={2}
          />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => onClose(false)}>Cancel</Button>
        <Button
          onClick={handleSubmit}
          variant="contained"
          disabled={!appId || !serviceId || !displayName || !baseUrl || Boolean(idError) || Boolean(didError) || Boolean(baseUrl && !baseUrl.startsWith("http"))}
        >
          Create
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export const ServicesPage: React.FC = () => {
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [selectedService, setSelectedService] = useState<Service | null>(null);
  const { data, isLoading, error, refetch } = useQuery(
    ["services", page, search],
    () => listServices({ page: page + 1, page_size: 25 }),
  );

  const filtered = (data?.items ?? []).filter(
    (s) =>
      !search ||
      s.service_id.includes(search) ||
      s.display_name.toLowerCase().includes(search.toLowerCase()) ||
      (s.owner_did ?? "").toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Typography variant="h5">Services</Typography>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreateOpen(true)}>
          New Service
        </Button>
      </Box>

      <TextField
        placeholder="Search by service_id or owner DID"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        size="small"
        sx={{ mb: 2, width: 360 }}
      />

      {isLoading && <CircularProgress />}
      {!!error && <Alert severity="error">Failed to load services.</Alert>}

      {!isLoading && !error && (
        <>
          <Table size="small" aria-label="services table">
            <TableHead>
              <TableRow>
                <TableCell>Service ID</TableCell>
                <TableCell>Display Name</TableCell>
                <TableCell>Env</TableCell>
                <TableCell>Base URL</TableCell>
                <TableCell>Owner DID</TableCell>
                <TableCell>Chain</TableCell>
                <TableCell>Active</TableCell>
                <TableCell>Created</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filtered.map((svc: Service) => (
                <TableRow
                  key={svc.id}
                  hover
                  sx={{ cursor: "pointer" }}
                  onClick={() => setSelectedService(svc)}
                >
                  <TableCell>{svc.service_id}</TableCell>
                  <TableCell>{svc.display_name}</TableCell>
                  <TableCell>{svc.env}</TableCell>
                  <TableCell sx={{ maxWidth: 160 }}>
                    {svc.base_url ? (
                      <Tooltip title={svc.base_url}>
                        <span style={{ fontFamily: "monospace", fontSize: "0.75rem" }}>
                          {svc.base_url.length > 30 ? svc.base_url.slice(0, 30) + "…" : svc.base_url}
                        </span>
                      </Tooltip>
                    ) : "—"}
                  </TableCell>
                  <TableCell>
                    <Tooltip title={svc.owner_did ?? ""}>
                      <span>{(svc.owner_did ?? "—").slice(0, 20)}{(svc.owner_did ?? "").length > 20 ? "…" : ""}</span>
                    </Tooltip>
                  </TableCell>
                  <TableCell>{chainStatusChip(svc)}</TableCell>
                  <TableCell>{svc.is_active ? "✓" : "✗"}</TableCell>
                  <TableCell>{svc.created_at ? relativeTime(svc.created_at) : "—"}</TableCell>
                </TableRow>
              ))}
              {filtered.length === 0 && (
                <TableRow>
                  <TableCell colSpan={8} align="center">No services found.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
          <TablePagination
            component="div"
            count={data?.total_count ?? 0}
            page={page}
            rowsPerPage={25}
            rowsPerPageOptions={[25]}
            onPageChange={(_, p) => setPage(p)}
          />
        </>
      )}

      <CreateServiceModal
        open={createOpen}
        onClose={(created) => {
          setCreateOpen(false);
          if (created) refetch();
        }}
      />

      <ServiceDescriptorDrawer
        service={selectedService}
        onClose={() => setSelectedService(null)}
      />
    </Box>
  );
};
