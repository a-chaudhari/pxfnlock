//
// Created by amitchaudhari on 8/21/25.
//

#include "loader.h"
#include <pthread.h>
#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "common.h"

pthread_t ringbuf_polling_thread;

int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event_log_entry *e = data;
    if (e->remapped)
        printf("Remapped: %x -> %x\n", e->original, e->new);
    else
        printf("Detected unmapped scancode: %x\n", e->original);

    return 0;
}

void *poll_ringbuf( void *ptr )
{
    int err;
    struct ring_buffer *rb = ptr;
    printf("Starting ringbuff pollign thread\n");
    while (1)
    {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }
    printf("Exiting polling thread\n");
    return nullptr;
}

/** * This function loads the BPF program, attaches it to the HID device,
 * and sets up a map for remapping scancodes.
 * @param skel: Pointer to the BPF skeleton structure
 * @param hid_id: The HID device ID to attach the BPF program to
 * @return 0 on success, -1 on error
 */
int run_bpf(struct hid_modify_bpf *skel, int hid_id)
{
    int err, map_fd;
    struct ring_buffer *rb = nullptr;

    // Open and load the BPF program
    skel = hid_modify_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return -1;
    }

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

    skel->struct_ops.hid_modify_ops->hid_id = hid_id;

    err = hid_modify_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return -1;
   }

    // Attach to HID device
    err = hid_modify_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program\n");
        hid_modify_bpf__destroy(skel);
        return -1;
    }

    map_fd = bpf_map__fd(skel->maps.remap_map);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map fd\n");
        hid_modify_bpf__destroy(skel);
        return -1;
    }

    for (int i = 0; i < sizeof(remaps)/sizeof(int)/2; i ++)
    {
        bpf_map_update_elem(map_fd,
            &remaps[i * 2],
            &remaps [i * 2 + 1],
            BPF_ANY);
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.event_rb), handle_event, NULL, nullptr);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return -1;
    }

    // need to poll to see output
    pthread_create( &ringbuf_polling_thread, nullptr, poll_ringbuf, rb);

    return 0;
}