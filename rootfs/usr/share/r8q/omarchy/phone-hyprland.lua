-- SM-G7810 selective Omarchy/Quattro session.
--
-- This deliberately stays independent of Omarchy's full default/hypr tree.
-- It preserves the already validated phone output, touch mapping and
-- compositor suspend policy while starting Quickshell, the on-screen keyboard
-- and native locking before display blanking.

local omarchy_path = os.getenv("OMARCHY_PATH") or "/usr/share/omarchy"
local inherited_path = os.getenv("PATH") or "/usr/local/bin:/usr/bin"

hl.env("OMARCHY_PATH", omarchy_path)
hl.env("PATH", omarchy_path .. "/bin:" .. inherited_path)
hl.env("XDG_CURRENT_DESKTOP", "Hyprland")
hl.env("XDG_SESSION_DESKTOP", "Hyprland")
hl.env("XDG_SESSION_TYPE", "wayland")
hl.env("AQ_DRM_DEVICES", "/dev/dri/by-path/platform-9c000000.framebuffer-card")
hl.env("LIBSEAT_BACKEND", "seatd")

hl.monitor({
  output = "DSI-1",
  mode = "preferred",
  position = "auto",
  scale = 2,
})

hl.config({
  debug = {
    disable_logs = true,
    enable_stdout_logs = false,
  },
  xwayland = {
    enabled = false,
  },
  input = {
    touchdevice = {
      output = "DSI-1",
      transform = 0,
    },
  },
  general = {
    gaps_in = 0,
    gaps_out = 0,
    border_size = 1,
  },
  misc = {
    -- Let the supervised shell replace a crashed lock client while the
    -- compositor continues to protect the session with its failsafe.
    allow_session_lock_restore = true,
    -- Omarchy renders the selected image; use Tokyo Night's solid color
    -- while the wallpaper is loading, with no compositor default image.
    disable_hyprland_logo = true,
    disable_splash_rendering = true,
    force_default_wallpaper = 0,
    background_color = 0xff1a1b26,
    -- The side button owns waking. Automatic wake would race its toggle and
    -- could immediately turn the display back off after an idle timeout.
    key_press_enables_dpms = false,
    mouse_move_enables_dpms = false,
  },
  decoration = {
    rounding = 0,
    shadow = { enabled = false },
    blur = { enabled = false },
  },
  animations = {
    enabled = false,
  },
})

-- Generated from the pinned Tokyo Night palette and Omarchy's border template.
-- Install this theme file before deploying or verifying the phone profile.
dofile((os.getenv("HOME") or "/home/alarm") .. "/.local/state/omarchy/current/theme/hyprland.lua")

-- Dispatch DPMS after the key event completes, as required by Hyprland.
-- Release-only, non-repeating handling gives one toggle per short press.
hl.bind("XF86PowerOff", function()
  hl.timer(function()
    hl.exec_cmd("/usr/local/bin/r8q-screen-lock power")
  end, { timeout = 200, type = "oneshot" })
end, {
  release = true,
  locked = true,
  ignore_mods = true,
  dont_inhibit = true,
  submap_universal = true,
})

hl.on("hyprland.start", function()
  -- Update this session's private bus for portal activation. This system
  -- service has no user-manager bus in its private XDG_RUNTIME_DIR.
  hl.exec_cmd("dbus-update-activation-environment --all")

  -- Keep startup blank until the native lock covers the display. The helper
  -- then starts the keyboard and the idle policy in this private session.
  hl.dispatch(hl.dsp.dpms({ monitor = "DSI-1", action = "disable" }))
  hl.exec_cmd("/usr/local/bin/r8q-screen-lock startup")
end)

-- The private desktop PipeWire session owns the speaker volume.
for key, change in pairs({ XF86AudioRaiseVolume = "5%+", XF86AudioLowerVolume = "5%-" }) do
  hl.bind(key, function()
    hl.exec_cmd("wpctl set-volume --limit 1 @DEFAULT_AUDIO_SINK@ " .. change)
  end, { locked = true, ignore_mods = true, dont_inhibit = true, submap_universal = true })
end
