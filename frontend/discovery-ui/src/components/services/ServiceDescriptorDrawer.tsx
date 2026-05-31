import React from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Chip from "@mui/material/Chip";
import CircularProgress from "@mui/material/CircularProgress";
import Divider from "@mui/material/Divider";
import Drawer from "@mui/material/Drawer";
import IconButton from "@mui/material/IconButton";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";
import CloseIcon from "@mui/icons-material/Close";
import { Service, getServiceDescriptor, ServiceDescriptor } from "../../api/services";
import { useQuery } from "../hooks/useQuery";

interface Props {
  service: Service | null;
  onClose: () => void;
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

function isExpired(iso: string | null): boolean {
  if (!iso) return false;
  return new Date(iso) < new Date();
}

const PROTOCOL_COLOR: Record<string, "default" | "primary" | "secondary" | "warning"> = {
  https: "primary",
  http: "warning",
  grpc: "secondary",
  mqtt: "default",
};

export const ServiceDescriptorDrawer: React.FC<Props> = ({ service, onClose }) => {
  const open = Boolean(service);

  const { data, isLoading, error } = useQuery(
    ["descriptor", service?.service_id, service?.env],
    () => getServiceDescriptor(service!.service_id, service!.env),
    { enabled: open && Boolean(service) },
  );

  return (
    <Drawer anchor="right" open={open} onClose={onClose} PaperProps={{ sx: { width: 520, p: 3 } }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Box>
          <Typography variant="h6">{service?.service_id}</Typography>
          <Typography variant="body2" color="text.secondary">
            {service?.env} · Service Descriptor
          </Typography>
        </Box>
        <IconButton onClick={onClose} size="small">
          <CloseIcon />
        </IconButton>
      </Box>

      <Divider sx={{ mb: 2 }} />

      {isLoading && <CircularProgress size={24} />}

      {Boolean(error) && (
        <Alert severity="warning">
          No active descriptor found for this service. The producer sentinel may not have published
          one yet, or the descriptor has expired.
        </Alert>
      )}

      {data && <DescriptorDetail descriptor={data} />}
    </Drawer>
  );
};

const DescriptorDetail: React.FC<{ descriptor: ServiceDescriptor }> = ({ descriptor }) => {
  const expired = isExpired(descriptor.valid_until);

  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
      {/* Status */}
      <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
        <Chip
          label={descriptor.is_active ? "Active" : "Inactive"}
          color={descriptor.is_active ? "success" : "default"}
          size="small"
        />
        {expired && <Chip label="Expired" color="error" size="small" />}
      </Box>

      {/* Identity */}
      <Box>
        <Typography variant="subtitle2" gutterBottom>
          Producer
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ wordBreak: "break-all" }}>
          Sentinel DID: {descriptor.producer_sentinel_did ?? "—"}
        </Typography>
        {descriptor.producer_service_did && (
          <Typography variant="body2" color="text.secondary" sx={{ wordBreak: "break-all" }}>
            Service DID: {descriptor.producer_service_did}
          </Typography>
        )}
      </Box>

      <Divider />

      {/* Timing */}
      <Box>
        <Typography variant="subtitle2" gutterBottom>
          Validity
        </Typography>
        <Box sx={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 0.5 }}>
          <Typography variant="body2" color="text.secondary">Valid from</Typography>
          <Typography variant="body2">{formatDate(descriptor.valid_from)}</Typography>
          <Typography variant="body2" color="text.secondary">Valid until</Typography>
          <Typography variant="body2" color={expired ? "error" : "text.primary"}>
            {formatDate(descriptor.valid_until)}
          </Typography>
          <Typography variant="body2" color="text.secondary">Published</Typography>
          <Typography variant="body2">{formatDate(descriptor.published_at)}</Typography>
          <Typography variant="body2" color="text.secondary">Issued at</Typography>
          <Typography variant="body2">{formatDate(descriptor.issued_at)}</Typography>
        </Box>
      </Box>

      {descriptor.descriptor_hash && (
        <>
          <Divider />
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              Integrity
            </Typography>
            <Tooltip title={descriptor.descriptor_hash}>
              <Typography
                variant="body2"
                fontFamily="monospace"
                color="text.secondary"
                sx={{ wordBreak: "break-all" }}
              >
                SHA-256: {descriptor.descriptor_hash.slice(0, 32)}…
              </Typography>
            </Tooltip>
          </Box>
        </>
      )}

      <Divider />

      {/* Endpoints */}
      <Box>
        <Typography variant="subtitle2" gutterBottom>
          Endpoints ({descriptor.endpoints.length})
        </Typography>
        {descriptor.endpoints.length === 0 ? (
          <Typography variant="body2" color="text.secondary">
            No endpoints in descriptor.
          </Typography>
        ) : (
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>URL</TableCell>
                <TableCell>Protocol</TableCell>
                <TableCell>Weight</TableCell>
                <TableCell>Instance</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {descriptor.endpoints.map((ep, i) => (
                <TableRow key={i}>
                  <TableCell sx={{ wordBreak: "break-all", maxWidth: 200 }}>
                    <Tooltip title={ep.url}>
                      <span>{ep.url.length > 40 ? ep.url.slice(0, 40) + "…" : ep.url}</span>
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={ep.protocol}
                      size="small"
                      color={PROTOCOL_COLOR[ep.protocol] ?? "default"}
                    />
                  </TableCell>
                  <TableCell>{ep.weight}</TableCell>
                  <TableCell>
                    <Typography variant="body2" fontFamily="monospace" fontSize="0.75rem">
                      {ep.instance_id ? ep.instance_id.slice(0, 12) : "—"}
                    </Typography>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Box>
    </Box>
  );
};
