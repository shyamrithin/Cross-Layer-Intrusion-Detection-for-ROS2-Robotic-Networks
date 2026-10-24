--[[
================================================================================
 File        : ros2_ids.lua
 Project     : Cross-Layer Intrusion Detection for ROS 2 Robotic Networks
 Course      : 21ECC402P - Computer Communication and Network Security
 Author      : Shyam Rithin S (RA2311004010308)
 Version     : 2.0  (replaces ros2_twist.lua)
================================================================================
 Description

 Wireshark post-dissector that turns raw RTPS (DDS) packets from a ROS 2
 system into readable rows. Wireshark's RTPS dissector does the parsing;
 this script adds a ROS 2 layer on top and rewrites the Info column.

 Every RTPS packet gets
   ros2ids.kind      what it is, in plain words:
                       CMD wire      /cmd_vel_raw  (controller + any attacker)
                       CMD auth      /cmd_vel_auth (authorized reference)
                       CMD motors    /cmd_vel      (after the safety filter)
                       IDS           /physguard/*  (detector output)
                       SENSOR        /odom /scan /joint_states /ground_truth
                       SIM           /clock        (simulator only)
                       VIZ           /track/* /tf* markers
                       ROS           /rosout /parameter_events ...
                       DISCOVERY     a process or endpoint announcing itself
                       RELIABILITY   HEARTBEAT / ACKNACK bookkeeping only
   ros2ids.topic     the ROS topic name, e.g. /cmd_vel_raw (no rt/ prefix)
   ros2ids.writer    W1, W2, ... : the n-th distinct writer seen on that topic
                     in this capture. On /cmd_vel_raw the controller starts
                     first, so W1 is normally the controller and W2+ are extra
                     publishers. Numbering is by order of appearance only.
   ros2ids.writer_n  the same number, for filters (ros2ids.writer_n > 1)
   ros2ids.event     the readable summary that also replaces the Info column

 Velocity commands (geometry_msgs/msg/Twist, 52-byte CDR payload) on the
 cmd_vel topics are decoded:
   ros2ids.v, ros2ids.w      linear.x (m/s) and angular.z (rad/s)
   ros2ids.infeasible        1 when |v| > 1.20 m/s or |w| > 2.50 rad/s or
                             the value is NaN/inf (the detector's limits)

 Discovery
   ros2ids.new_participant   1 the first time a process (DDS participant)
                             announces itself in this capture
   Endpoint announcements say "new publisher on /topic (type)".

 Filters
   ros2ids && ros2ids.kind != "SIM"         demo view (no clock noise)
   ros2ids.kind contains "CMD"               all command traffic
   ros2ids.topic == "/cmd_vel_raw" && ros2ids.writer_n > 1   extra writers
   ros2ids.infeasible == 1                   commands the IDS would reject
   ros2ids.kind == "DISCOVERY"               who joined / announced what

 Install: copy to ~/.local/lib/wireshark/plugins/ and restart Wireshark
 (install.sh does this and removes the older ros2_twist.lua).
================================================================================
--]]

local V_MAX, W_MAX = 1.20, 2.50          -- detector_core.DetectorConfig
local TWIST_LEN = 52                     -- 4-byte CDR header + 6 x float64

local ENT_SPDP     = 0x000100c2          -- participant announcements
local ENT_SEDP_PUB = 0x000003c2          -- publication (writer) announcements
local ENT_SEDP_SUB = 0x000004c2          -- subscription (reader) announcements
local SM_DATA, SM_DATA_FRAG = 0x15, 0x16
local SM_HEARTBEAT, SM_ACKNACK, SM_GAP = 0x07, 0x06, 0x08

local p = Proto("ros2ids", "ROS 2 (IDS view)")
local pf = {
    kind     = ProtoField.string("ros2ids.kind", "Kind"),
    topic    = ProtoField.string("ros2ids.topic", "Topic"),
    rtype    = ProtoField.string("ros2ids.type", "Type"),
    writer   = ProtoField.string("ros2ids.writer", "Writer"),
    writer_n = ProtoField.uint16("ros2ids.writer_n", "Writer number", base.DEC),
    event    = ProtoField.string("ros2ids.event", "Summary"),
    v        = ProtoField.double("ros2ids.v", "linear.x (m/s)"),
    w        = ProtoField.double("ros2ids.w", "angular.z (rad/s)"),
    ly       = ProtoField.double("ros2ids.linear_y", "linear.y (m/s)"),
    lz       = ProtoField.double("ros2ids.linear_z", "linear.z (m/s)"),
    ax       = ProtoField.double("ros2ids.angular_x", "angular.x (rad/s)"),
    ay       = ProtoField.double("ros2ids.angular_y", "angular.y (rad/s)"),
    infeas   = ProtoField.uint8("ros2ids.infeasible", "Infeasible command", base.DEC),
    newpart  = ProtoField.uint8("ros2ids.new_participant", "New participant", base.DEC),
}
p.fields = { pf.kind, pf.topic, pf.rtype, pf.writer, pf.writer_n, pf.event, pf.v, pf.w,
             pf.ly, pf.lz, pf.ax, pf.ay, pf.infeas, pf.newpart }

local function try_field(name)
    local ok, f = pcall(Field.new, name)
    if ok then return f end
    return nil
end
local f_rtps   = Field.new("rtps")
local f_smid   = Field.new("rtps.sm.id")
local f_wr     = Field.new("rtps.sm.wrEntityId")
local f_topic  = Field.new("rtps.param.topicName")
local f_type   = try_field("rtps.param.typeName")
local f_data   = Field.new("rtps.issueData")
local f_prefix = try_field("rtps.guidPrefix.src") or try_field("rtps.guidPrefix")

-- per-capture state, reset whenever Wireshark re-reads the capture
local writers, nwriters, participants, nparts

local function reset_state()
    writers, nwriters = {}, {}
    participants, nparts = {}, 0
end
p.init = reset_state    -- Wireshark calls this on every (re)load of a capture
reset_state()

local function all(f)
    if f == nil then return {} end
    return { f() }
end

local function ros_topic(dds)
    if dds == nil then return nil end
    local t = dds:gsub("^rt/", "/"):gsub("^rq/", "/srv-req/"):gsub("^rr/", "/srv-rep/")
    return t
end

local function ros_type(dds)
    if dds == nil then return nil end
    -- geometry_msgs::msg::dds_::Twist_  ->  geometry_msgs/msg/Twist
    return (dds:gsub("::dds_::", "::"):gsub("_$", ""):gsub("::", "/"))
end

local function kind_of(topic)
    if topic == nil then return "ROS" end
    if topic == "/cmd_vel_raw" then return "CMD wire" end
    if topic == "/cmd_vel_auth" then return "CMD auth" end
    if topic == "/cmd_vel" then return "CMD motors" end
    if topic:find("physguard", 1, true) then return "IDS" end
    if topic == "/clock" then return "SIM" end
    if topic == "/odom" or topic == "/scan" or topic == "/joint_states"
       or topic == "/ground_truth" or topic:find("odom_error", 1, true) then return "SENSOR" end
    if topic:find("^/track") or topic:find("^/tf") or topic:find("marker")
       or topic == "/robot_description" then return "VIZ" end
    if topic:find("attack", 1, true) then return "ATTACK-GT" end
    return "ROS"
end

local function finite(x) return x == x and x ~= math.huge and x ~= -math.huge end

local function short(prefix_hex)
    -- last 4 bytes of the participant GUID prefix: compact, unique per process here
    local s = tostring(prefix_hex or ""):gsub("[:%s]", "")
    return s:sub(-8)
end

local function decode_twist(r)
    if r == nil or r:len() ~= TWIST_LEN then return nil end
    local enc = r(0, 2):uint()
    local le
    if enc == 0x0001 then le = true elseif enc == 0x0000 then le = false else return nil end
    local function d(off) if le then return r(off, 8):le_float() else return r(off, 8):float() end end
    return { d(4), d(12), d(20), d(28), d(36), d(44) }
end

function p.dissector(tvb, pinfo, tree)
    if not f_rtps() then return end

    local smids  = all(f_smid)
    local wrs    = all(f_wr)
    local topics = all(f_topic)
    local types  = all(f_type)
    local datas  = all(f_data)
    local pfx    = f_prefix and f_prefix() or nil
    local pkey   = pfx and tostring(pfx.value) or "?"

    local has_data, has_hb = false, false
    for _, s in ipairs(smids) do
        local v = s.value
        if v == SM_DATA or v == SM_DATA_FRAG then has_data = true end
        if v == SM_HEARTBEAT or v == SM_ACKNACK or v == SM_GAP then has_hb = true end
    end
    local wr_spdp, wr_pub, wr_sub, wr_user = false, false, false, nil
    for _, w in ipairs(wrs) do
        local v = w.value
        if v == ENT_SPDP then wr_spdp = true
        elseif v == ENT_SEDP_PUB then wr_pub = true
        elseif v == ENT_SEDP_SUB then wr_sub = true
        elseif wr_user == nil and v ~= 0 and (v % 256) < 0xc0 then wr_user = v end
    end

    local topic = topics[1] and ros_topic(tostring(topics[1].value)) or nil
    local rtype = types[1] and ros_type(tostring(types[1].value)) or nil
    local orig  = tostring(pinfo.cols.info)
    local kind, event, wlabel, wnum, twist, bad, newp

    if wr_spdp and has_data then
        kind = "DISCOVERY"
        if orig:find("p%[UD%]") then
            event = "participant LEFT  (process " .. short(pkey) .. " shut down)"
        elseif not participants[pkey] then
            nparts = nparts + 1
            participants[pkey] = nparts
            newp = 1
            event = "NEW participant #" .. nparts .. "  (process " .. short(pkey) .. " joined the domain)"
        else
            event = "participant alive  (process " .. short(pkey) .. ", #" .. participants[pkey] .. ")"
        end
    elseif (wr_pub or wr_sub) and has_data then
        kind = "DISCOVERY"
        local what = wr_pub and "publisher" or "subscriber"
        if orig:find("%[UD%]") then
            event = what .. " REMOVED" .. (topic and (" from " .. topic) or "")
        else
            event = "new " .. what .. " on " .. (topic or "?") .. (rtype and ("  [" .. rtype .. "]") or "")
                    .. "  (process " .. short(pkey) .. ")"
        end
    elseif has_data and topic ~= nil then
        kind = kind_of(topic)
        local key = pkey .. ":" .. tostring(wr_user or 0)
        writers[topic] = writers[topic] or {}
        if writers[topic][key] == nil then
            nwriters[topic] = (nwriters[topic] or 0) + 1
            writers[topic][key] = nwriters[topic]
        end
        wnum = writers[topic][key]
        wlabel = "W" .. wnum
        if kind:find("^CMD") then
            for _, fi in ipairs(datas) do
                twist = decode_twist(fi.range)
                if twist then break end
            end
        end
        if twist then
            local v, w = twist[1], twist[6]
            bad = (not finite(v) or not finite(w) or math.abs(v) > V_MAX or math.abs(w) > W_MAX) and 1 or 0
            event = string.format("%-13s %s   v=%+7.3f m/s   w=%+7.3f rad/s%s",
                topic, wlabel, v, w, bad == 1 and "   !! INFEASIBLE" or "")
        else
            local n = 0
            for _, fi in ipairs(datas) do if fi.range then n = n + fi.range:len() end end
            event = string.format("%-13s %s   data %d B", topic, wlabel, n)
        end
    elseif has_hb and not has_data then
        kind = "RELIABILITY"
        event = "reliability bookkeeping (heartbeat / ack)"
    elseif has_data then
        kind = "ROS"
        event = "data (topic not yet learned - start capture before the nodes)"
    else
        kind = "ROS"
        event = orig
    end

    -- tree
    local st = tree:add(p, tvb(), "ROS 2: " .. (event or kind))
    st:add(pf.kind, kind):set_generated()
    if topic then st:add(pf.topic, topic):set_generated() end
    if rtype then st:add(pf.rtype, rtype):set_generated() end
    if wlabel then
        st:add(pf.writer, wlabel):set_generated()
        st:add(pf.writer_n, wnum):set_generated()
    end
    if newp then st:add(pf.newpart, 1):set_generated() end
    if twist then
        local r
        for _, fi in ipairs(datas) do if fi.range and fi.range:len() == TWIST_LEN then r = fi.range break end end
        local t = st:add(p, r, "Twist  (geometry_msgs/msg/Twist)")
        t:add(pf.v,  r(4, 8),  twist[1])
        t:add(pf.ly, r(12, 8), twist[2])
        t:add(pf.lz, r(20, 8), twist[3])
        t:add(pf.ax, r(28, 8), twist[4])
        t:add(pf.ay, r(36, 8), twist[5])
        t:add(pf.w,  r(44, 8), twist[6])
        local it = t:add(pf.infeas, bad)
        it:set_generated()
        if bad == 1 then
            it:add_expert_info(PI_PROTOCOL, PI_WARN,
                string.format("Command outside feasibility limits (|v| <= %.2f m/s, |w| <= %.2f rad/s)", V_MAX, W_MAX))
        end
    end
    st:add(pf.event, event or ""):set_generated()

    -- columns
    pinfo.cols.protocol:set("ROS2")
    if event then pinfo.cols.info:set(event) end
end

register_postdissector(p)
