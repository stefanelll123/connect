import React from "react";
import Box from "@mui/material/Box";
import Chip from "@mui/material/Chip";
import FormControl from "@mui/material/FormControl";
import InputLabel from "@mui/material/InputLabel";
import ListItemText from "@mui/material/ListItemText";
import MenuItem from "@mui/material/MenuItem";
import OutlinedInput from "@mui/material/OutlinedInput";
import Select, { type SelectChangeEvent } from "@mui/material/Select";
import TextField from "@mui/material/TextField";

const ACTION_OPTIONS = [
  { value: "credential.issue", label: "Issue", category: "credential" },
  { value: "credential.revoke", label: "Revoke", category: "credential" },
  { value: "credential.verify", label: "Verify", category: "credential" },
  { value: "chain.index", label: "Index", category: "chain" },
  { value: "chain.anchor", label: "Anchor", category: "chain" },
  { value: "auth.login", label: "Login", category: "auth" },
  { value: "auth.logout", label: "Logout", category: "auth" },
  { value: "config.update", label: "Config Update", category: "config" },
] as const;

const CATEGORY_COLOR: Record<string, "primary" | "warning" | "error" | "default"> = {
  credential: "primary",
  chain: "warning",
  auth: "error",
  config: "default",
};

export interface AuditFilters {
  actor_did: string;
  actions: string[];
  target_id: string;
  from_ts: string;
  to_ts: string;
}

interface Props {
  filters: AuditFilters;
  onChange: (updated: AuditFilters) => void;
}

export const AuditFiltersBar: React.FC<Props> = ({ filters, onChange }) => {
  const set = (patch: Partial<AuditFilters>) => onChange({ ...filters, ...patch });

  const handleActionsChange = (e: SelectChangeEvent<string[]>) => {
    const value = e.target.value;
    set({ actions: typeof value === "string" ? value.split(",") : value });
  };

  return (
    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 2, alignItems: "center" }}>
      <TextField
        label="Actor DID"
        size="small"
        value={filters.actor_did}
        onChange={(e) => set({ actor_did: e.target.value })}
        sx={{ minWidth: 200 }}
        inputProps={{ "aria-label": "actor did" }}
      />

      <FormControl size="small" sx={{ minWidth: 200 }}>
        <InputLabel>Actions</InputLabel>
        <Select
          multiple
          value={filters.actions}
          onChange={handleActionsChange}
          input={<OutlinedInput label="Actions" />}
          renderValue={(selected) => (
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
              {selected.map((v) => {
                const opt = ACTION_OPTIONS.find((o) => o.value === v);
                return (
                  <Chip
                    key={v}
                    label={opt?.label ?? v}
                    size="small"
                    color={CATEGORY_COLOR[opt?.category ?? "config"]}
                  />
                );
              })}
            </Box>
          )}
        >
          {ACTION_OPTIONS.map((opt) => (
            <MenuItem key={opt.value} value={opt.value}>
              <Chip
                label={opt.category}
                size="small"
                color={CATEGORY_COLOR[opt.category]}
                sx={{ mr: 1, width: 80 }}
              />
              <ListItemText primary={opt.label} secondary={opt.value} />
            </MenuItem>
          ))}
        </Select>
      </FormControl>

      <TextField
        label="Target ID"
        size="small"
        value={filters.target_id}
        onChange={(e) => set({ target_id: e.target.value })}
        sx={{ minWidth: 200 }}
        inputProps={{ "aria-label": "target id" }}
      />

      <TextField
        label="From"
        size="small"
        type="datetime-local"
        value={filters.from_ts}
        onChange={(e) => set({ from_ts: e.target.value })}
        InputLabelProps={{ shrink: true }}
        inputProps={{ "aria-label": "from date" }}
      />

      <TextField
        label="To"
        size="small"
        type="datetime-local"
        value={filters.to_ts}
        onChange={(e) => set({ to_ts: e.target.value })}
        InputLabelProps={{ shrink: true }}
        inputProps={{ "aria-label": "to date" }}
      />
    </Box>
  );
};
