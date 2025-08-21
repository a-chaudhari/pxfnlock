//
// Created by amitchaudhari on 8/21/25.
//

#include "file_state.h"
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <bits/fcntl-linux.h>
#include <sys/stat.h>

#define FN_LOCK_DEFAULT_VALUE 0 // 0 = fn lock on, 1 = fn lock off

/**
 * Reads the state file to determine the current fn lock state
 * The state file is expected to contain a single integer
 * @return -1 on failure, otherwise 0 for fn_lock on, 1 for fn-lock off
 */
int read_state()
{
    const char* state_file_path = "/var/lib/pxFnLock/state";
    // need to create the directory if it doesn't exist
    struct stat st;
    if (stat("/var/lib/pxFnLock", &st) != 0)
    {
        // Directory does not exist, create it
        if (mkdir("/var/lib/pxFnLock", 0755) != 0)
        {
            perror("Failed to create state directory");
            return -1;
        }
    }

    int fd = open(state_file_path, O_RDWR | O_CREAT, 0644);
    if (fd < 0)
    {
        perror("Failed to open state file");
        return -1;
    }

    // read contents
    int buffer;
    ssize_t bytes_read = read(fd, &buffer, sizeof(buffer));
    int state = FN_LOCK_DEFAULT_VALUE;
    if (bytes_read > 0)
    {
        // reading worked. convert the int
        printf("Read state from file: %x\n", buffer);
        if (buffer == 0 || buffer == 1)
        {
            printf("found state in file: %d\n", buffer);
            close(fd);
            return buffer;
        }
    }

    printf("Invalid state in file, using default value\n");
    // save the state to the file
    lseek(fd, 0, SEEK_SET); // reset file pointer to the beginning
    if (write(fd, &state, sizeof(state)) < 0)
    {
        perror("Failed to write default state to file");
        close(fd);
        return -1;
    }
    close(fd);
    return state;
}

/**
 * Write the current fn lock state to the state file
 * @param new_state 0 for fn lock on, 1 for fn lock off
 * @return 0 on success, -1 on failure
 */
int write_state(int new_state)
{
    // open state file
    const char* state_file_path = "/var/lib/pxFnLock/state";
    int fd = open(state_file_path, O_RDWR);
    if (fd < 0)
    {
        perror("Failed to open state file");
        return -1;
    }

    size_t bytesWritten = write(fd, &new_state, sizeof(new_state));
    if (bytesWritten == 0)
    {
        perror("Failed to write default state to file");
        close(fd);
        return -1;
    }

    printf("Write state to file: %d\n", new_state);
    close(fd);
    return 0;
}