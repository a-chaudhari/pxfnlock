//
// Created by amitchaudhari on 8/21/25.
//

#ifndef HIDTEST3_LOADER_H
#define HIDTEST3_LOADER_H

#include "hid_modify.skel.h"

int run_bpf(struct hid_modify_bpf *skel, int hid_id);

#endif //HIDTEST3_LOADER_H