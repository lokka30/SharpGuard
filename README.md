# SharpGuard

## Purpose

SharpGuard is a basic CLI program which is an extremely basic intrusion detection platform.

I wrote this purely to learn C# and experiment with .NET Framework to interact with Windows.

It certainly isn't a program you should use in a production environment (in it's current state).

## Features

### Seatbelt Detections

It includes a detection for Seatbelt's FileInfo and LOLBAS commands, when ran with the 'full' parameter. The detection is very primitive, simply tracking activity on files of interest over time, and writing to the Windows Event Log when it finds a suspicious amount of activity.

## Testing

- [x] Seatbelt FileInfo command with 'full' parameter is detected.
    - Caveats: May require 'Last Accessed' NTFS attribute to be enabled.
      May also require a time delay between running the commands to trigger an alert. 30 minutes has been consistently sufficient on my environment.
- [ ] Seatbelt LOLBAS command has not been tested for successful alerts yet.

## Branches

- The `master` branch contains the latest stable version of the program (usually the same source that was used to publish the latest stable binary).
- The `dev/v???` branches indicate a branch used for developing a specific version of the program. These (usually) eventually get merged into `master`.
- The `task/???` branches indicate a particular task being worked on, which is usually merged into a `dev` branch.

## Maintenance Status

This project is not actively maintained or supported.

## Copyright Notice

Copyright (c) 2024 Lachlan Adamson and contributors.

<blockquote>
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
<br>
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
<br>
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>
</blockquote>

