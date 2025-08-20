## Background
This is a tool I wrote to apply various fixes to the Asus ProArt PX13 laptop under linux.  It should work with other PX laptops and some other Asus laptops as well.

This tool does 3 tasks:
1. Adds support for missing keys on the keyboard allowing other utilities to use them.
    * Fn + Esc (Fn lock)
    * Fn + F7 (Emoji button)
    * Fn + F12 (ProArt button)
2. Listens for the Fn+Esc key combo and toggles the Fn lock.
3. Saves the fn-lock state across reboots.

Note: this was developed and tested on Arch 6.16 on the PX13 ProArt laptop, but should work on other distros and Asus laptops as well.

Looking for others to test this on other distros and Asus laptops!
## Install
1. try running the binary as-is and see if it works on your system
   * if it doesn't work, continue with the build instructions below
2. if it works use `sudo cp px13-fnlock /usr/local/bin/` to copy the binary to a location in your PATH
3. if you want to run this on boot, copy the service files to `/etc/systemd/system`
4. `sudo systemctl enable --now pxfnlock.service` to enable the service

## Building
1. make sure your distros `linux-headers`, general development packages are installed (ie: "build-essential"), and libbpf-dev.
2. run `make` in the root directory of this repository to build the tool
3. lastly run `sudo make install` to install it

## Usage
1. enabling the systemd service should be all that's necessary
2. fn-esc will toggle the Fn lock state.  but there is NO visual indicator of the state change.
   * You can try making your own by listening for the `KEY_PROG3` keycode
3. feel free to use your tool of choice to bind the emoji and proart keys to something useful.

## Tech Details
This was discovered by reading the hid feature status from windows after using the OEM driver to enable/disable fn lock.

The hid-asus driver in linux doesn't recognize the emitted scancode and
drops it (along with a few other ones). This tool packages a bpf program to modify the scancodes sent by the keyboard to something the driver does recognize. 

| Hardware Key | Description | Userspace Keycode |
|--------------|-------------|-------------------|
| Fn+Esc       | Fn-Lock     | KEY_PROG3         |
| Fn+F7        | Emoji Key   | KEY_PROG2         |
| Fn+F12       | ProArt Key  | KEY_PROG1         |
