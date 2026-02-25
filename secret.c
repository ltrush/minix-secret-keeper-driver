/**
 * QUESTIONS:
 * check the return value of the ds_publish_xxx, ds_retrieve_xxx functions?
 * can i just use ds_publish_u32 for all my ints instead of ds_publish_mem
 * can i have one line if statements
 * what to do about geometery and prepare
 * TO DO:
 * check return values of system calls
 */

#include <minix/drivers.h>
#include <minix/driver.h>
#include <minix/const.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>
#include <sys/ucred.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include "secret.h"

#ifndef SECRET_SIZE /* only define it if not already defined */
#define SECRET_SIZE 8192
#endif

#define FALSE 0
#define TRUE 1

/*
 * Function prototypes for the secret driver.
 */
FORWARD _PROTOTYPE( char * secret_name,   (void) );
FORWARD _PROTOTYPE( int secret_open,      (struct driver *d, message *m) );
FORWARD _PROTOTYPE( int secret_close,     (struct driver *d, message *m) );
FORWARD _PROTOTYPE( int secret_ioctl,     (struct driver *d, message *m) );
FORWARD _PROTOTYPE( struct device * secret_prepare, (int device) );
FORWARD _PROTOTYPE( int secret_transfer,  (int procnr, int opcode,
                                          u64_t position, iovec_t *iov,
                                          unsigned nr_req) );
FORWARD _PROTOTYPE( void secret_geometry, (struct partition *entry) );
FORWARD _PROTOTYPE( void ret_and_del_u32_ds, 
                                    (const char *ds_name, uint32_t *value));

/* SEF functions and variables. */
FORWARD _PROTOTYPE( void sef_local_startup, (void) );
FORWARD _PROTOTYPE( int sef_cb_init, (int type, sef_init_info_t *info) );
FORWARD _PROTOTYPE( int sef_cb_lu_state_save, (int) );
FORWARD _PROTOTYPE( int lu_state_restore, (void) );

/* Entry points to the secret driver. */
PRIVATE struct driver secret_tab =
{
    secret_name,
    secret_open,
    secret_close,
    secret_ioctl, // this is the real nop_ioctl
    secret_prepare,
    secret_transfer,
    nop_cleanup,
    secret_geometry,
    nop_alarm,
    nop_cancel,
    nop_select,
    nop_ioctl,  // this one is a mistake??
    do_nop,
};

/** Represents the /dev/secret device. */
PRIVATE struct device secret_device;

/** State variable to count the number of times the device has been opened. */
PRIVATE int open_counter;
PRIVATE uid_t owner;
PRIVATE int owned = FALSE;
PRIVATE int opened_for_read = FALSE;

PRIVATE uint8_t secret[SECRET_SIZE];
PRIVATE uint8_t *read_end = secret;
PRIVATE uint8_t *write_end = secret;

// do we need this function and if not then do i get 
// rid of it in the table or replace it with a nop
PRIVATE char * secret_name(void) {
    printf("secret_name()\n");
    return "secret";
}

// is it okay to change the function to look like this? thats just C right
PRIVATE int secret_open(struct driver *d, message *m) {
    int read, write; 
    struct ucred caller;

    if (getnucred(m->IO_ENDPT, &caller) == -1) {
        perror("getnucred");
        return errno; // is this the correct behavior for if getnucred fails?
    }
    
    read = m->COUNT & R_BIT;
    write = m->COUNT & W_BIT;

    if (read && write) {
        return EACCES; /* can't open for read and write access */
    } else if (write) {
        printf("owned is %d\n", owned);
        if (owned) return ENOSPC; /* can't open for write if secret is full */
    } else if (read) {
        /* can read if not owned or if user is owner */
        if (owned && caller.uid != owner) return EACCES;
        opened_for_read = TRUE;
    } else {
        /* open() should require one of O_RDONLY, O_WRONLY, or O_RDWR
         * but I'd rather be safe then sorry
         */
        printf("open() not given an access mode\n");
        return EACCES;
    }

    /* opening for read or write was successful */
    owner = caller.uid;
    owned = TRUE;
    open_counter++;

    printf("secret_open(). Called %d time(s).\n", open_counter);
    return OK;
}

PRIVATE int secret_close(struct driver * d, message *m) {
    printf("secret_close()\n");
    open_counter--;
    printf("open_counter %d\n", open_counter);
    if (open_counter == 0 && opened_for_read) {
        printf("secreet is no longer owned\n");
        owned = FALSE;
        opened_for_read = FALSE;
        read_end = secret;
        write_end = secret;
    }
    return OK;
}

PRIVATE int secret_ioctl(struct driver * d, message *m) {
    int res;
    uid_t grantee; /* the uid of the new owner of the secret */

    if (m->REQUEST != SSGRANT) return ENOTTY;
    res = sys_safecopyfrom(m->IO_ENDPT, (vir_bytes)m->IO_GRANT,
                    0, (vir_bytes)&grantee, sizeof(grantee), D);

    // is this apporaite for checking sys_safecopyfrom
    // in secret_transfer we just return res, should we do that instead?
    if (res != OK) {
        perror("sys_safecopyfrom");
        return errno;
    }

    owner = grantee;
    return OK;
}

// not sure what we're supposed to do with this
PRIVATE struct device * secret_prepare(int dev) {
    secret_device.dv_base.lo = 0;
    secret_device.dv_base.hi = 0;
    secret_device.dv_size.lo = 0;
    secret_device.dv_size.hi = 0;
    return &secret_device;
}

PRIVATE int secret_transfer(int proc_nr, int opcode, u64_t position, 
                                        iovec_t *iov, unsigned nr_req) {
    int ret, bytes_avaliable, bytes_requested, bytes_to_transfer;

    printf("secret_transfer()\n");
                        
    bytes_requested = iov->iov_size;

    // I BELIEVE IF usr TRY WRITE ZERO BYTES IT SHOULDNT FAIL Jus RET
    if (bytes_requested == 0) return OK;
                
    /* if reading, get bytes avaliable to read
     * otherwise get bytes left for write
     */
    if (opcode == DEV_GATHER_S) bytes_avaliable = write_end - read_end;
    else bytes_avaliable = (secret + SECRET_SIZE) - write_end;

    /* will transfer min(bytes_avaliable, bytes_requested) */
    bytes_to_transfer = bytes_avaliable <= bytes_requested 
                            ? bytes_avaliable : bytes_requested;
    
    printf("bytes_to_transfer: %d\n", bytes_to_transfer);

    switch (opcode) {
        case DEV_GATHER_S:
            // is this the correct behavior??
            if (bytes_to_transfer <= 0) return OK; 
            ret = sys_safecopyto(proc_nr, iov->iov_addr, 0,
                                (vir_bytes) read_end,
                                 bytes_to_transfer, D);
            iov->iov_size -= bytes_to_transfer;
            read_end += bytes_to_transfer;
            break;
        
        case DEV_SCATTER_S:
            if (bytes_to_transfer <= 0) return ENOSPC;
            ret = sys_safecopyfrom(proc_nr, iov->iov_addr, 0,
                                (vir_bytes) write_end,
                                 bytes_to_transfer, D);
            printf("iov->iov_size: %d\n", iov->iov_size);
            iov->iov_size -= bytes_to_transfer;
            write_end += bytes_to_transfer;
            break;
        default:
            return EINVAL;
    }
    
    return ret;
}

// what to do with this?
PRIVATE void secret_geometry(entry)
    struct partition *entry;
{
    printf("secret_geometry()\n");
    entry->cylinders = 0;
    entry->heads     = 0;
    entry->sectors   = 0;
}

PRIVATE int sef_cb_lu_state_save(int state) {
/* Save the state. */
    ds_publish_u32("open_counter", open_counter, DSF_OVERWRITE);
    ds_publish_u32("owner", owner, DSF_OVERWRITE);
    ds_publish_u32("owned", owned, DSF_OVERWRITE);
    ds_publish_u32("opened_for_read", opened_for_read, DSF_OVERWRITE);
    ds_publish_mem("secret", (void *)secret, SECRET_SIZE, DSF_OVERWRITE);
    ds_publish_u32("read_end", (uint32_t) read_end, DSF_OVERWRITE);
    ds_publish_u32("write_end", (uint32_t) write_end, DSF_OVERWRITE);

    return OK;
}

PRIVATE int lu_state_restore() {
/* Restore the state. */
    uint32_t value;
    uint32_t secret_size = SECRET_SIZE; // ds_retreive_mem 
    // changes value of secret_size to be what it actually retrieved.... 
    // is this needed for something?

    ret_and_del_u32_ds("open_counter", &value);
    open_counter = (int) value;

    ret_and_del_u32_ds("owner", &value);
    owner = (uid_t) value;

    ret_and_del_u32_ds("owned", &value);
    owned = (int) value;

    ret_and_del_u32_ds("opened_for_read", &value);
    opened_for_read = (int) value;

    ret_and_del_u32_ds("read_end", &value);
    read_end = (uint8_t*) value;

    ret_and_del_u32_ds("write_end", &value);
    write_end = (uint8_t*) value;

    ds_retrieve_mem("secret", (char *)secret, &secret_size);
    ds_delete_mem("secret");

    return OK;
}

PRIVATE void ret_and_del_u32_ds(const char *ds_name, uint32_t *value) {
    ds_retrieve_u32(ds_name, value);
    ds_delete_u32(ds_name);
}

PRIVATE void sef_local_startup()
{
    /*
     * Register init callbacks. Use the same function for all event types
     */
    sef_setcb_init_fresh(sef_cb_init);
    sef_setcb_init_lu(sef_cb_init);
    sef_setcb_init_restart(sef_cb_init);

    /*
     * Register live update callbacks.
     */
    /* - Agree to update immediately when LU is requested in a valid state. */
    sef_setcb_lu_prepare(sef_cb_lu_prepare_always_ready);
    /* - Support live update starting from any standard state. */
    sef_setcb_lu_state_isvalid(sef_cb_lu_state_isvalid_standard);
    /* - Register a custom routine to save the state. */
    sef_setcb_lu_state_save(sef_cb_lu_state_save);

    /* Let SEF perform startup. */
    sef_startup();
}

PRIVATE int sef_cb_init(int type, sef_init_info_t *info)
{
/* Initialize the secret driver. */
    // int do_announce_driver = TRUE;

    open_counter = 0;
    switch(type) {
        case SEF_INIT_FRESH:
            printf("fresh init\n");
        break;

        case SEF_INIT_LU:
            /* Restore the state. */
            lu_state_restore();
            // do_announce_driver = FALSE;

            printf("%sHey, I'm a new version!\n");
        break;

        case SEF_INIT_RESTART:
            printf("Hey, I've just been restarted!\n");
        break;
    }

    /* Announce we are up when necessary. */
    // if (do_announce_driver) {
    //     driver_announce();
    // }
    // dont need this??

    /* Initialization completed successfully. */
    return OK;
}

PUBLIC int main(int argc, char **argv)
{
    /*
     * Perform initialization.
     */
    sef_local_startup();

    /*
     * Run the main loop.
     */
    driver_task(&secret_tab, DRIVER_STD);
    return OK;
}

