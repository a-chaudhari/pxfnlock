#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bpf/hid_modify.skel.h"
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/input.h>
#include <linux/hidraw.h>
#include "bpf/loader.h"
#include <pthread.h>
#include "file_state.h"
#include "bpf/common.h"

#define VID_PID "0B05:19B6" // Asus ProArt Keyboard VID:PID

/**
 * Find the first input device and hidraw device associated with a HID device
 * @param hid_path: The HID sysfs path (e.g., "/sys/bus/hid/devices/0003:0B05:19B6.0002")
 * @param devices: Structure to store found device paths
 * @return 0 on success, -1 on error
 */
int find_hid_devices_paths(const char *hid_path, hid_sub_paths_t *devices) {
    DIR *dir;
    struct dirent *entry;
    char path[MAX_PATH];
    struct stat st;

    // Initialize the structure
    memset(devices, 0, sizeof(hid_sub_paths_t));

    // Check if the HID path exists
    if (stat(hid_path, &st) != 0) {
        fprintf(stderr, "HID path does not exist: %s\n", hid_path);
        return -1;
    }

    // Find hidraw device
    snprintf(path, sizeof(path), "%s/hidraw", hid_path);
    dir = opendir(path);
    if (dir) {
        while ((entry = readdir(dir)) != NULL) {
            if (strncmp(entry->d_name, "hidraw", 6) == 0) {
                snprintf(devices->hidraw_device, MAX_PATH,
                        "/dev/%s", entry->d_name);
                break;
            }
        }
        closedir(dir);
    }

    // Find first input device
    snprintf(path, sizeof(path), "%s/input", hid_path);
    dir = opendir(path);
    if (dir) {
        int found_input = 0;
        while ((entry = readdir(dir)) != NULL && !found_input) {
            // Look for input event devices (e.g., input5)
            if (strncmp(entry->d_name, "input", 5) == 0 &&
                strcmp(entry->d_name, "input") != 0) {

                // Look for event devices within this input device
                char event_path[MAX_PATH];
                snprintf(event_path, sizeof(event_path),
                        "%s/%s", path, entry->d_name);

                DIR *event_dir = opendir(event_path);
                if (event_dir) {
                    struct dirent *event_entry;
                    while ((event_entry = readdir(event_dir)) != NULL) {
                        if (strncmp(event_entry->d_name, "event", 5) == 0) {
                            snprintf(devices->input_device, MAX_PATH,
                                    "/dev/input/%s", event_entry->d_name);
                            found_input = 1;  // Stop after finding first
                            break;
                        }
                    }
                    closedir(event_dir);
                }
            }
        }
        closedir(dir);
    }

    return 0;
}

/**
 * Find a HID device by its VID:PID and verify its report descriptor matches the one we want
 * @param search_id "VID:PID" to search for, e.g. "0B05:19B6"
 * @param info the structure to fill with the found HID device information
 * @return 0 on success, -1 on failure
 */
int find_hid_id(const char *search_id, hid_device_info_t *info) {
    const char *hid_path = "/sys/bus/hid/devices";
    DIR *dir;
    struct dirent *entry;

    dir = opendir(hid_path);
    if (dir == NULL) {
        perror("Failed to open /sys/bus/hid/devices");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        // Skip . and .. directories
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
            }

        // Check if device name contains the search ID
        if (strstr(entry->d_name, search_id) != NULL) {
            // we found a matching device, need to check the report descriptor
            // get the full path and add /report_descriptor
            char full_path[MAX_PATH];
            sprintf(full_path, "%s/%s/report_descriptor", hid_path, entry->d_name);
            FILE *fp = fopen(full_path, "rb");
            if (fp == NULL)
            {
                printf("cannot open device %s\n", full_path);
                continue;
            }

            // read first 4kb of the report descriptor
            unsigned char report_descriptor[4096];
            size_t bytes_read = fread(report_descriptor, 1, sizeof(report_descriptor), fp);
            fclose(fp);
            if (bytes_read <= 0) {
                printf("Failed to read report descriptor for device %s\n", entry->d_name);
                continue;
            }

            // check against the expected report descriptor
            unsigned char expected_descriptor[] = {0x06, 0x31, 0xff, 0x09, 0x76, 0xa1, 0x01, 0x85, 0x5a};
            void *status = memmem(report_descriptor, bytes_read, expected_descriptor, sizeof(expected_descriptor));
            if (status != NULL)
            {
                // extract the id (the number after the last period in the directory name)
                char *colon_pos = strrchr(entry->d_name, '.');
                if (colon_pos != NULL)
                {
                    info->hid_id = atoi(colon_pos + 1);
                    sprintf(info->hid_path, "%s/%s", hid_path, entry->d_name);
                    return 0;
                }
                return -1;
            }
        }
    }
    printf("No suitable HID device found with VID:PID %s\n", search_id);
    closedir(dir);
    return -1;
}

/**
 * Toggle the fn lock state by sending a HID feature report
 * @param hidraw_path path to specific hidraw device, e.g. /dev/hidraw1
 * @param fn_lock 0 = fn lock on (f1-12 buttons act as hotkeys), 1 = fn lock off (f1-12 buttons act as normal)
 * @return 0 on success, -1 on failure
 */
int toggle_fnlock(const char *hidraw_path, int fn_lock)
{
    unsigned char hid_buffer[63] = {
        0x5a, 0xd0, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    // Open the hidraw device for writing
    int hidraw_fd = open(hidraw_path, O_RDWR);
    if (hidraw_fd < 0) {
        perror("Failed to open hidraw device");
        // close(evdev_fd);
        return -1;
    }

    hid_buffer[3] = fn_lock; // Set fn lock byte

    int res = ioctl(hidraw_fd, HIDIOCSFEATURE(sizeof(hid_buffer)), hid_buffer);
    if (res < 0) {
        perror("Error sending feature report");
        return -1;
    } else {
        printf("Sent feature report (%d bytes)\n", res);
    }
    return 0;
}


int restore(int state)
{
    // restore the default state
    printf("restoring state oneshot\n");

    int err;
    hid_device_info_t device_info;
    hid_sub_paths_t devices;

    err = find_hid_id(VID_PID, &device_info);
    if (err)
    {
        printf("Failed to find hid\n");
        return -1;
    }

    err = find_hid_devices_paths(device_info.hid_path, &devices);
    if (err) {
        fprintf(stderr, "Failed to find HID devices\n");
        return -1;
    }

    toggle_fnlock(devices.hidraw_device, state);
    printf("restored state: %d\n", state);

    return 0;
}

int main(int argc, char **argv)
{
    int fn_state = read_state();
    if (fn_state < 0)
    {
        printf("Failed to read state file\n");
        return -1;
    }

    if (argc > 1 && strcmp(argv[1], "restore") == 0) {
        return restore(fn_state);
    }

    hid_device_info_t device_info;
    hid_sub_paths_t devices;
    int err, evdev_fd;
    struct hid_modify_bpf *skel = nullptr;
    struct input_event ev;

    err = find_hid_id(VID_PID, &device_info);
    if (err)
    {
        printf("Failed to find hid\n");
        return -1;
    }

    err = find_hid_devices_paths(device_info.hid_path, &devices);
    if (err) {
        fprintf(stderr, "Failed to find HID devices\n");
        return -1;
    }

    printf("HID Device ID: %d\n", device_info.hid_id);
    printf("HID Device Path: %s\n", device_info.hid_path);
    printf("Input path: %s\n", devices.input_device);
    printf("Hidraw path: %s\n", devices.hidraw_device);

    /*
     * this is a simple 1d array, add maps as pairs of: original scancode, new scancode
     * 1. use hid-recorder to find the original scancode from the keyboard
     * 2. read the hid-asus.c file to see what scancodes are recognized by the driver
     * 3. remap the original scancode to one that is detected by the driver but isn't used for anything on yours
     * 4. you can now use that keycode and bind functions using keyd or any other tool
     */
    const int remaps[] = {
        0x4e, 0x5c, // fn-lock (fn + esc) -> key_prog3
        0x7e, 0xba, // emoji picker key -> key_prog2
        0x8b, 0x38, // proart hub key -> key_prog1
    };
    err = run_bpf(skel, device_info.hid_id, &remaps[0], 3);
    if (err)
    {
        printf("Failed to load BPF\n");
        return -1;
    }

    evdev_fd = open(devices.input_device, O_RDONLY);
    if (evdev_fd < 0) {
        perror("Failed to open evdev device");
        printf("Try running as root or check device path\n");
        return -1;
    }

    // set the default state before entering the loop
    toggle_fnlock(devices.hidraw_device, fn_state);

    while (1) {
        // Read input event
        ssize_t bytes = read(evdev_fd, &ev, sizeof(ev));

        if (bytes < (ssize_t)sizeof(ev)) {
            perror("Error reading event");
            return -1;
        }

        // Check if it's a key event for our target keycode
        if (ev.type == EV_KEY && (ev.code == KEY_PROG3 || ev.code == KEY_FN_ESC)) {
            if (ev.value == 1) {  // Key press (not release)
                printf("Fn+Esc Key pressed! Sending HID report...\n");

                // toggle the state
                fn_state = !fn_state;

                err = toggle_fnlock(devices.hidraw_device, fn_state);
                if (err) {
                    printf("Failed to toggle fn lock\n");
                } else {
                    printf("Fn lock toggled to %s\n", fn_state ? "off" : "on");
                }

                err = write_state(fn_state);
                if (err)
                {
                    printf("failed to write state file\n");
                }
            }
        }
    }
}
