# Apple Home (HomeKit)

In AirPlay 2 mode the speaker can be added to the Apple **Home** app, like a
HomePod or any other AirPlay 2 speaker. Once added, it appears in a room, can be
used in scenes and automations, and joins in when a home hub (an Apple TV or
HomePod) plays to a group of speakers.

This is HomeKit *pairing* for an AirPlay speaker. The speaker does not appear as
a general HomeKit accessory, and there is no Matter support.

## Adding the speaker

1. In the Home app, open **Home Settings → Speakers & TV** and set **Allow
   Speaker & TV Access** to **Everyone** or **Anyone on the Same Network**.
   Leave **Require Password** off: this firmware has no speaker password.
2. Tap **+ → Add Accessory → More options…**.
3. Pick the speaker from the list of nearby devices, then choose a room and a name.

No setup code is asked for. An AirPlay speaker has no label or screen to show
one, so the pairing uses the fixed code that AirPlay devices share.

The speaker must be in AirPlay 2 mode, which is the default. In legacy (v1) mode
it does not advertise HomeKit support and cannot be added.

## What the speaker stores

When you add the speaker, the Home app connects with the shared AirPlay code
and hands it the home's controllers: your devices and home hubs. Home hubs keep
that list up to date afterwards. Up to 16 controllers are kept in flash, so the
speaker stays in the home across restarts and firmware updates.

When a stored controller connects again, the speaker checks its signature
against the key it stored. A device claiming a stored controller's identity
without its key is refused.

Removing the speaker from the Home app removes its last admin, and the speaker
then forgets every pairing.

## Starting over

If the speaker was removed from the Home app while it was offline, it still
holds that home's pairings. You don't need to do anything: adding it again works
regardless, and the new home's controllers replace the old ones, so the old home
keeps no rights over it.

To clear the stored pairings by hand, call the web API:

```bash
curl http://<speaker>.local/api/homekit                 # what is stored
curl -X POST http://<speaker>.local/api/homekit/reset   # forget it all
```

Remove the speaker in the Home app as well, otherwise the app keeps a stale entry.

## Limits

- **Access control is advertised, not enforced.** The Home app's **Allow Speaker
  & TV Access** level is stored and reported back, but anyone on the network can
  still stream to the speaker. The same is true of
  [shairport-sync](https://github.com/mikebrady/shairport-sync).
- **No speaker password.** If **Require Password** is set in the Home app, the
  password is ignored and a warning is logged.
- **Pairing uses the shared AirPlay code.** Anyone on your network who connects
  with it can change the speaker's list of controllers, as with other AirPlay
  speakers. That gives them no access to anything else in your home.
- **No now-playing in the Home app.** The speaker's tile shows no track, artwork
  or transport controls, whatever is playing. That information comes from
  Apple's MediaRemote protocol. Third-party AirPlay speakers don't provide it
  either: a JBL soundbar looks the same, and shairport-sync doesn't implement it.
- **Renaming in the Home app** changes the name the Home app shows, not the
  AirPlay name the speaker advertises. Rename the speaker in its web interface
  instead.
