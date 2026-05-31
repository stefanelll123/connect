import React, { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "react-oidc-context";
import AppBar from "@mui/material/AppBar";
import Box from "@mui/material/Box";
import Drawer from "@mui/material/Drawer";
import IconButton from "@mui/material/IconButton";
import List from "@mui/material/List";
import ListItemButton from "@mui/material/ListItemButton";
import ListItemIcon from "@mui/material/ListItemIcon";
import ListItemText from "@mui/material/ListItemText";
import Menu from "@mui/material/Menu";
import MenuItem from "@mui/material/MenuItem";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";
import Avatar from "@mui/material/Avatar";
import MenuIcon from "@mui/icons-material/Menu";
import AppsIcon from "@mui/icons-material/Apps";
import StorageIcon from "@mui/icons-material/Storage";
import SecurityIcon from "@mui/icons-material/Security";
import BadgeIcon from "@mui/icons-material/Badge";
import BlockIcon from "@mui/icons-material/Block";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import HistoryIcon from "@mui/icons-material/History";

const DRAWER_WIDTH = 240;

const NAV_ITEMS = [
  { label: "Apps", path: "/apps", icon: <AppsIcon /> },
  { label: "Services", path: "/services", icon: <StorageIcon /> },
  { label: "Sentinels", path: "/sentinels", icon: <SecurityIcon /> },
  { label: "Credentials", path: "/credentials", icon: <BadgeIcon /> },
  { label: "Revocations", path: "/revocations", icon: <BlockIcon /> },
  { label: "Chain", path: "/chain", icon: <AccountTreeIcon /> },
  { label: "Audit", path: "/audit", icon: <HistoryIcon /> },
];

interface AppShellProps {
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({ children }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, signoutRedirect } = useAuth();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  const currentPage =
    NAV_ITEMS.find((item) => location.pathname.startsWith(item.path))?.label ?? "Discovery";

  const drawerContent = (
    <Box>
      <Toolbar>
        <Typography variant="h6" fontWeight={700} color="primary">
          Discovery
        </Typography>
      </Toolbar>
      <List>
        {NAV_ITEMS.map((item) => (
          <ListItemButton
            key={item.path}
            selected={location.pathname.startsWith(item.path)}
            onClick={() => {
              navigate(item.path);
              setMobileOpen(false);
            }}
          >
            <ListItemIcon>{item.icon}</ListItemIcon>
            <ListItemText primary={item.label} />
          </ListItemButton>
        ))}
      </List>
    </Box>
  );

  return (
    <Box sx={{ display: "flex" }}>
      <AppBar
        position="fixed"
        color="default"
        elevation={1}
      >
        <Toolbar>
          <IconButton
            edge="start"
            sx={{ mr: 2, display: { sm: "none" } }}
            onClick={() => setMobileOpen(!mobileOpen)}
            aria-label="open drawer"
          >
            <MenuIcon />
          </IconButton>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            {currentPage}
          </Typography>
          <IconButton onClick={(e) => setAnchorEl(e.currentTarget)}>
            <Avatar sx={{ width: 32, height: 32, bgcolor: "primary.main" }}>
              {user?.profile?.email?.[0]?.toUpperCase() ?? "U"}
            </Avatar>
          </IconButton>
          <Menu
            anchorEl={anchorEl}
            open={Boolean(anchorEl)}
            onClose={() => setAnchorEl(null)}
          >
            <MenuItem disabled>
              <Typography variant="body2">{user?.profile?.email ?? "User"}</Typography>
            </MenuItem>
            <MenuItem
              onClick={() => {
                setAnchorEl(null);
                signoutRedirect();
              }}
            >
              Logout
            </MenuItem>
          </Menu>
        </Toolbar>
      </AppBar>

      {/* Mobile drawer */}
      <Drawer
        variant="temporary"
        open={mobileOpen}
        onClose={() => setMobileOpen(false)}
        sx={{
          display: { xs: "block", sm: "none" },
          "& .MuiDrawer-paper": { width: DRAWER_WIDTH },
        }}
        ModalProps={{ keepMounted: true }}
      >
        {drawerContent}
      </Drawer>

      {/* Permanent drawer */}
      <Drawer
        variant="permanent"
        sx={{
          display: { xs: "none", sm: "block" },
          width: DRAWER_WIDTH,
          flexShrink: 0,
          "& .MuiDrawer-paper": { width: DRAWER_WIDTH, boxSizing: "border-box" },
        }}
        open
      >
        {drawerContent}
      </Drawer>

      <Box
        component="main"
        sx={{ flexGrow: 1, p: 3, mt: 8, minHeight: "100vh" }}
      >
        {children}
      </Box>
    </Box>
  );
};
