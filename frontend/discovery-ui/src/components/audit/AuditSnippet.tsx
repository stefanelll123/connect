import React from "react";
import { useNavigate } from "react-router-dom";
import Box from "@mui/material/Box";
import CircularProgress from "@mui/material/CircularProgress";
import List from "@mui/material/List";
import ListItem from "@mui/material/ListItem";
import ListItemText from "@mui/material/ListItemText";
import Link from "@mui/material/Link";
import { useQuery } from "../hooks/useQuery";
import { listAuditEvents } from "../../api/audit";

interface AuditSnippetProps {
  entityType: "sentinel" | "service";
  entityId: string;
}

function relativeTime(isoString: string): string {
  const diffMs = Date.now() - new Date(isoString).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export const AuditSnippet: React.FC<AuditSnippetProps> = ({ entityId }) => {
  const navigate = useNavigate();
  const { data, isLoading } = useQuery(
    ["audit", entityId],
    () => listAuditEvents({ limit: 5 }),
  );

  if (isLoading) return <CircularProgress size={20} />;

  return (
    <Box>
      <List dense disablePadding>
        {(data?.items ?? []).map((ev) => (
          <ListItem key={ev.event_id} disablePadding>
            <ListItemText
              primary={`${ev.action} — ${(ev.actor_id ?? "unknown").slice(0, 8)}`}
              secondary={relativeTime(ev.ts)}
            />
          </ListItem>
        ))}
      </List>
      <Link
        component="button"
        variant="body2"
        onClick={() => navigate(`/audit?target_id=${entityId}`)}
      >
        View Full Audit →
      </Link>
    </Box>
  );
};
