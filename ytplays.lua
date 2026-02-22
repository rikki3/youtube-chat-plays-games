-- ytplays_file.lua (mGBA)
-- Reads appended lines from /media/sf_ytplays/commands.txt
-- Commands: !UP !DOWN !LEFT !RIGHT !A !B !L !R !START !SELECT

local PATH = "/media/sf_ytplays/commands.txt"

local lastSize = 0
local TAP_FRAMES = 8
local GAP_FRAMES = 2
local FPS = 60

local queue = {}
local current = nil
local gap = 0

-- mGBA constants are under C.GBA_KEY (not "keys")
local KEYMAP = {
  UP = C.GBA_KEY.UP,
  DOWN = C.GBA_KEY.DOWN,
  LEFT = C.GBA_KEY.LEFT,
  RIGHT = C.GBA_KEY.RIGHT,
  A = C.GBA_KEY.A,
  B = C.GBA_KEY.B,
  L = C.GBA_KEY.L,
  R = C.GBA_KEY.R,
  START = C.GBA_KEY.START,
  SELECT = C.GBA_KEY.SELECT,
}

local function msToFrames(ms)
  if not ms then return TAP_FRAMES end
  if ms <= 0 then return TAP_FRAMES end
  return math.max(1, math.ceil((ms * FPS) / 1000))
end

local function enqueue(cmd, holdMs)
  local k = KEYMAP[cmd]
  if not k then return end
  table.insert(queue, {
    key = k,
    frames = msToFrames(holdMs),
  })
end

local function parseLine(line)
  local upper = line:upper()
  local cmd, msToken = upper:match("^%s*!?([A-Z]+)%s*(%S*)%s*$")
  if not cmd then return nil, nil end
  if msToken == nil or msToken == "" then return cmd, nil end

  local ms = tonumber(msToken:match("(%d+)"))
  if not ms then return cmd, nil end
  return cmd, ms
end

local function checkFile()
  local f = io.open(PATH, "r")
  if not f then return end

  local content = f:read("*a") or ""
  f:close()

  if #content <= lastSize then return end

  local newData = content:sub(lastSize + 1)
  lastSize = #content

  for line in newData:gmatch("[^\r\n]+") do
    local cmd, holdMs = parseLine(line)
    if cmd then enqueue(cmd, holdMs) end
  end
end

callbacks:add("frame", function()
  checkFile()

  if gap > 0 then
    gap = gap - 1
    return
  end

  if not current and #queue > 0 then
    current = table.remove(queue, 1)
    emu:addKey(current.key)   -- core methods via emu
    return
  end

  if current then
    current.frames = current.frames - 1
    if current.frames <= 0 then
      emu:clearKey(current.key)
      current = nil
      gap = GAP_FRAMES
    end
  end
end)

console:log("ytplays_file.lua loaded OK")
