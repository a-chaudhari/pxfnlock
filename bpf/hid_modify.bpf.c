#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 32);
} remap_map SEC(".maps");

SEC("struct_ops/hid_bpf_device_event")
int BPF_PROG(modify_hid_event, struct hid_bpf_ctx *hid_ctx)
{
    __u8* data = hid_bpf_get_data(hid_ctx, 0, 6);
    int *value;

    if (!data)
        return 0;

    // we're only interested in report id 90, which are the hotkey buttons
    if (data[0] != 0x5a)
        return 0; // Keep original data for other report ids

    if (data[1] == 0)
        return 0; // ignore key releases

    // bpf_printk("Event: %x, %x, %x, %x, %x, %x", data[0],
    //   data[1], data[2], data[3], data[4], data[5]);

    value = bpf_map_lookup_elem(&remap_map, &data[1]);
    if (value)
    {
        bpf_printk("Remapping scancode: %x -> %x", data[1], *value);
        data[1] = *value; // remap the scancode if it exists in the map
    } else {
        bpf_printk("No remap found for scancode: %x", data[1]);
    }

    return 0;
}

SEC(".struct_ops.link")
struct hid_bpf_ops hid_modify_ops = {
    .hid_device_event = (void*)modify_hid_event,
};

char _license[] SEC("license") = "GPL";
