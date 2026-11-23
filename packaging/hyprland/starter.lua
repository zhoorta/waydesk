-- Waydesk's starter Hyprland configuration, for an account that has none of its own (~/.config/hypr/hyprland.lua missing).
--
-- Without it Hyprland writes its example configuration into the account: a warning banner on the screen, the Welcome app, a terminal (kitty) and a
-- file manager (dolphin) that are not installed, and animations, blur and shadows, which only cost bandwidth in a remote session. This one is small,
-- uses what Waydesk installs (foot), draws as little as it can and says what its keys are. An account that wants its own copies this file to
-- ~/.config/hypr/hyprland.lua (the wrapper then loads that instead) and edits it; /usr/lib/waydesk/hyprland.lua still runs around it.
local terminal = "foot"
local mod = "SUPER"

-- The session's output is made and sized by Waydesk (the wrapper loads its rule after this file); this one is for anything else.
hl.monitor({ output = "", mode = "preferred", position = "auto", scale = "auto" })

hl.env("XCURSOR_SIZE", "24")

hl.config({
  general = { gaps_in = 4, gaps_out = 8, border_size = 2, layout = "dwindle", resize_on_border = true,
    col = { active_border = "rgba(33ccffee)", inactive_border = "rgba(595959aa)" } },
  decoration = { rounding = 6, blur = { enabled = false }, shadow = { enabled = false } },
  animations = { enabled = false },
  dwindle = { preserve_split = true },
  misc = {
    force_default_wallpaper = 0,
    disable_hyprland_logo = true,
    disable_splash_rendering = true,
    background_color = 0x10222b,
  },
  input = { kb_layout = "us", follow_mouse = 1 },
})

-- Keys: SUPER+Return or SUPER+Q a terminal, SUPER+C closes the window, SUPER+V floats it, SUPER+1..4 workspaces (SHIFT moves the window there),
-- SUPER+arrows move the focus, SUPER+left or right mouse button moves or resizes, SUPER+M logs out (ends the session).
hl.bind(mod .. " + Return", hl.dsp.exec_cmd(terminal))
hl.bind(mod .. " + Q", hl.dsp.exec_cmd(terminal))
hl.bind(mod .. " + C", hl.dsp.window.close())
hl.bind(mod .. " + V", hl.dsp.window.float({ action = "toggle" }))
hl.bind(mod .. " + J", hl.dsp.layout("togglesplit"))
hl.bind(mod .. " + M", hl.dsp.exec_cmd("command -v hyprshutdown >/dev/null 2>&1 && hyprshutdown || hyprctl dispatch 'hl.dsp.exit()'"))
hl.bind(mod .. " + left", hl.dsp.focus({ direction = "left" }))
hl.bind(mod .. " + right", hl.dsp.focus({ direction = "right" }))
hl.bind(mod .. " + up", hl.dsp.focus({ direction = "up" }))
hl.bind(mod .. " + down", hl.dsp.focus({ direction = "down" }))
for i = 1, 4 do
  hl.bind(mod .. " + " .. i, hl.dsp.focus({ workspace = i }))
  hl.bind(mod .. " + SHIFT + " .. i, hl.dsp.window.move({ workspace = i }))
end
hl.bind(mod .. " + mouse:272", hl.dsp.window.drag(), { mouse = true })
hl.bind(mod .. " + mouse:273", hl.dsp.window.resize(), { mouse = true })

hl.window_rule({ name = "suppress-maximize-events", match = { class = ".*" }, suppress_event = "maximize" })
