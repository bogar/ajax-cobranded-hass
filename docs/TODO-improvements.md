# Improvement Plan — Ajax Security HA Integration

Prioritized list of improvements based on analysis of foXaCe/ajax-security-hass, prismagroupsa/Ajax_alarm_ha_integration, HA platinum integration patterns, and real-world testing.

## Priority 1 — High impact, moderate effort

### 1.1 ~~Event Platform (`event.py`)~~ ✅ DONE (v0.5.0 + v0.9.0)
Implemented with 16 event types and enriched device source info (device_name, device_id, device_type, room_name).

### 1.2 ~~Force Arm Services~~ ✅ DONE (v0.5.0)
`aegis_ajax.force_arm` and `aegis_ajax.force_arm_night` services available.

### 1.3 ~~Logbook Integration (`logbook.py`)~~ ✅ DONE (v0.5.0)
Human-readable event descriptions with icons in the HA logbook.

### 1.4 Missing Binary Sensors (partially done)
**Done:** glass_break, vibration, external_contact
**Remaining:**
- `tilt` — DoorProtect Plus (accelerometer tilt detection)
- `steam` — FireProtect 2 (steam detection)

**Effort:** Low (1 hour).

---

## Priority 2 — Medium impact, moderate effort

### 2.1 Lock Platform (`lock.py`)
**Why:** Users with LockBridge (Yale smart lock) expect a lock entity.

**Implementation:**
1. Create `lock.py` with `AjaxLock` entity
2. Parse `smart_lock` status from `LightDeviceStatus` (field 66)
3. Commands via `SwitchSmartLockService` gRPC (proto exists: `switch_smart_lock/`)
4. States: locked, unlocked, locking, unlocking, jammed

**Effort:** Medium (3-4 hours). Need to compile switch_smart_lock protos.

### 2.2 Valve Platform (`valve.py`)
**Why:** WaterStop devices should be controlled as native HA valves, not switches.

**Implementation:**
1. Create `valve.py` with `AjaxWaterStopValve` entity
2. Parse `water_stop_valve_stuck` status
3. Commands need investigation — may be via device command service

**Effort:** Medium (2-3 hours).

### 2.3 Update Platform (`update.py`)
**Why:** Users want to see firmware status and update availability.

**Data source:** `streamHubObject` v2 field 200 (`DeviceFirmwareUpdates`) and field 201 (`SystemFirmwareUpdate`).

**Implementation:**
1. Create `update.py` with `AjaxFirmwareUpdate` entity
2. Parse firmware info from `streamHubObject` response
3. Show current version, latest available, update progress

**Effort:** Medium (3 hours). Need to parse firmware proto fields.

### 2.4 ~~icons.json~~ ✅ DONE (v0.5.0)
MDI icons for all entity types.

### 2.5 DHCP Discovery
**Why:** Automatic hub detection on the local network without manual setup.

**Implementation:**
1. Add `dhcp` entries to `manifest.json` with Ajax hub MAC prefixes (`9C:75:6E`, `38:B8:EB`)
2. Implement `async_step_dhcp` in config_flow

**Note:** This only helps if the hub is on the same network as HA. The gRPC connection is still to the cloud.

**Effort:** Low (1 hour).

---

## Priority 3 — Nice to have, higher effort

### 3.1 Number Platform (`number.py`)
**Why:** Expose configurable device settings (shock sensitivity, LED brightness, etc.)

**Entities:**
- DoorProtect Plus: tilt angle threshold (5-25°)
- Socket: current protection limit (1-16A)
- Dimmer: min/max brightness, touch sensitivity

**Data source:** These are device settings, not statuses. Require `UpdateHubDeviceService` gRPC to write.

**Effort:** High (4-5 hours). Need to understand the update device settings flow.

### 3.2 Select Platform (`select.py`)
**Why:** Configuration options that are enum-based (shock sensitivity: low/normal/high, etc.)

**Implementation:** Similar to number platform but with enum options.

**Effort:** High (4-5 hours). Same dependency on UpdateHubDeviceService.

### 3.3 Device Tracker (`device_tracker.py`)
**Why:** Show hub location on HA map.

**Data source:** Hub geoFence coordinates. May be available in the space/facility data.

**Effort:** Low (1-2 hours) if data is available.

### 3.4 Persistent Notification Service
**Why:** Show alarm events as HA persistent notifications with configurable filters.

**Implementation:**
1. Add options flow setting: notification filter (none, alarms only, security, all)
2. From FCM push handler, create `persistent_notification.create` based on filter

**Effort:** Medium (2 hours).

### 3.5 Device Handler Architecture Refactor
**Why:** Current monolithic `_DEVICE_TYPE_SENSORS` dict becomes unwieldy as device types grow. A per-device-type handler pattern (like foXaCe's `devices/` directory) would be cleaner.

**Implementation:**
1. Create `devices/` directory with a base class and per-device-type modules
2. Each handler defines which binary sensors, sensors, switches, events it supports
3. Entity platforms query handlers instead of static dicts

**Effort:** High (6-8 hours). Significant refactor, should be done when adding new entity types.

---

## Known Limitations (Cannot Fix)

These are protocol-level limitations that cannot be resolved by emulating the mobile app:

- **Hub tamper (lid) real state** — the `lid_opened` status exists in the proto but the server doesn't send it in `StreamLightDevices` for the hub
- **Photo on-demand URL retrieval** — v2 capture works but the photo URL only arrives via the v3 detection area stream, which returns `permission_denied` for our sessions
- **SpaceControl keyfob listing** — keyfobs don't appear in `StreamLightDevices` (they may appear in a different device list API)
- **Motion detection when disarmed** — Ajax firmware disables motion reporting when the system is disarmed (battery conservation)
- **Shock/vibration as persistent sensor** — these are alarm events, not persistent statuses

## Dependencies and Prerequisites

| Improvement | Depends on |
|---|---|
| Event platform | FCM push notification parsing (notification.py) |
| Force Arm services | Nothing (API already supports it) |
| Logbook | FCM push parsing + event platform |
| Lock platform | switch_smart_lock proto compilation |
| Valve platform | Device command investigation |
| Update platform | streamHubObject firmware field parsing |
| Number/Select | UpdateHubDeviceService proto understanding |
| Device tracker | Space/facility geo data source |

## Estimated Total Effort

| Priority | Items | Effort |
|---|---|---|
| P1 | 4 items | ~8-10 hours |
| P2 | 5 items | ~10-12 hours |
| P3 | 5 items | ~16-20 hours |
| **Total** | **14 items** | **~34-42 hours** |
