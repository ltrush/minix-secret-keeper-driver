/**
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

#define STATE_VARS_NAME "my_state_vars"

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

/* SEF functions and variables. */
FORWARD _PROTOTYPE( void sef_local_startup, (void) );
FORWARD _PROTOTYPE( int sef_cb_init, (int type, sef_init_info_t *info) );
FORWARD _PROTOTYPE( int sef_cb_lu_state_save, (int) );
FORWARD _PROTOTYPE( int lu_state_restore, (void) );

/* Entry points to the secret driver. */
PRIVATE struct driver secret_tab = {
    secret_name,
    secret_open,
    secret_close,
    secret_ioctl,
    secret_prepare,
    secret_transfer,
    nop_cleanup,
    secret_geometry,
    nop_alarm,
    nop_cancel,
    nop_select,
    nop_ioctl,
    do_nop,
};

/* used to save state for a live update */
struct state_vars {
    int open_counter;
    uid_t owner;
    int owned;
    int opened_for_read;
    uint8_t secret[SECRET_SIZE];
    uint8_t *read_end;
    uint8_t *write_end;
};

/** Represents the /dev/secret device. */
PRIVATE struct device secret_device;


PRIVATE int open_counter; /** count times the device has been opened */
PRIVATE uid_t owner; /* who currently owns the secret */
PRIVATE int owned = FALSE; /* is the secret owned */
PRIVATE int opened_for_read = FALSE; /* has the secret been opened for read */

PRIVATE uint8_t secret[SECRET_SIZE]; /* buffer for the secret */
PRIVATE uint8_t *read_end = secret; /* where to get bytes for reading */
PRIVATE uint8_t *write_end = secret; /* where to put bytes for writing */

PRIVATE char * secret_name(void) {
    printf("secret_name()\n");
    return "secret";
}

PRIVATE int secret_open(struct driver *d, message *m) {
    int read, write; 
    struct ucred caller;

    /* see who tried to open */
    if (getnucred(m->IO_ENDPT, &caller) == -1) {
        perror("getnucred");
        return EACCES;
    }
    
    /* are they asking for read or write permissions? or both? */
    read = m->COUNT & R_BIT;
    write = m->COUNT & W_BIT;

    if (read && write) {
        return EACCES; /* can't open for read AND write access */
    } else if (write) {
        if (owned) {
            return ENOSPC; /* can't open for write if secret is full */
        }
    } else if (read) {
        /* can read if not owned or if user is owner */
        if (owned && caller.uid != owner) {
            return EACCES;
        }
        opened_for_read = TRUE;
    } else {
        /* open() should require one of O_RDONLY, O_WRONLY, or O_RDWR
         * but I'd rather be safe then sorry
         */
        return EACCES;
    }

    /* opening for read or write was successful */
    owner = caller.uid;
    owned = TRUE;
    open_counter++;

    return OK;
}

PRIVATE int secret_close(struct driver * d, message *m) {
    open_counter--;
    if (open_counter == 0 && opened_for_read) {
        /* someone has opened for read and now all FDs are closed
         * so we reset the secret
         */
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

    /* only allow one type of ioctl request */
    if (m->REQUEST != SSGRANT) {
        return ENOTTY;
    }

    /* who are we changing ownership to? */
    res = sys_safecopyfrom(m->IO_ENDPT, (vir_bytes)m->IO_GRANT,
                    0, (vir_bytes)&grantee, sizeof(grantee), D);

    if (res != OK) {
        perror("sys_safecopyfrom");
    } else {
        owner = grantee;
    }

    return res;
}

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
                        
    bytes_requested = iov->iov_size;

    /* if user writes/reads zero bytes, just say OK! */
    if (bytes_requested == 0) {
        return OK;
    }

    if (opcode == DEV_GATHER_S) {
        /* if reading, get bytes avaliable to read */
        bytes_avaliable = write_end - read_end;
    }
    else {
        /* otherwise get bytes left for write */
        bytes_avaliable = (secret + SECRET_SIZE) - write_end;
    }

    /* will transfer min(bytes_avaliable, bytes_requested) */
    bytes_to_transfer = bytes_avaliable <= bytes_requested 
                            ? bytes_avaliable : bytes_requested;

    switch (opcode) {
        case DEV_GATHER_S:
            /* nothing left to read */
            if (bytes_to_transfer <= 0) {
                return OK; 
            }
            ret = sys_safecopyto(proc_nr, iov->iov_addr, 0,
                                (vir_bytes) read_end,
                                 bytes_to_transfer, D);
            if (ret == OK) {
                iov->iov_size -= bytes_to_transfer;
                /* move read pointer */
                read_end += bytes_to_transfer;
            }
            break;
        
        case DEV_SCATTER_S:
            if (bytes_to_transfer <= 0) {
                return ENOSPC;
            }
            ret = sys_safecopyfrom(proc_nr, iov->iov_addr, 0,
                                (vir_bytes) write_end,
                                 bytes_to_transfer, D);
            if (ret == OK) {
                iov->iov_size -= bytes_to_transfer;
                /* move write pointer */
                write_end += bytes_to_transfer;
            }
            break;
        default:
            return EINVAL;
    }
    
    return ret;
}

PRIVATE void secret_geometry(struct partition * entry) {
    printf("secret_geometry()\n");
    entry->cylinders = 0;
    entry->heads     = 0;
    entry->sectors   = 0;
}

PRIVATE int sef_cb_lu_state_save(int state) {
    /* Save the state. */
    struct state_vars my_state_vars;
    my_state_vars.open_counter = open_counter;
    my_state_vars.owner = owner;
    my_state_vars.owned = owned;
    my_state_vars.opened_for_read = opened_for_read;
    my_state_vars.read_end = read_end;
    my_state_vars.write_end = write_end;
    memcpy(my_state_vars.secret, secret, SECRET_SIZE);

    ds_publish_mem(STATE_VARS_NAME, (void *)&my_state_vars, 
                            sizeof(my_state_vars), DSF_OVERWRITE);

    return OK;
}

PRIVATE int lu_state_restore() {
    /* Restore the state. */
    struct state_vars my_state_vars;
    /* ds_retrieve_mem modifies size, so need to have a variable */
    uint32_t state_vars_size = sizeof(my_state_vars);

    ds_retrieve_mem(STATE_VARS_NAME, (char *)&my_state_vars, 
                                                 &state_vars_size);
    ds_delete_mem(STATE_VARS_NAME);
    
    open_counter = my_state_vars.open_counter;
    owner = my_state_vars.owner;
    owned = my_state_vars.owned;
    opened_for_read = my_state_vars.opened_for_read;
    read_end = my_state_vars.read_end;
    write_end = my_state_vars.write_end;
    memcpy(secret, my_state_vars.secret, SECRET_SIZE);

    return OK;
}

PRIVATE void sef_local_startup() {
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

PRIVATE int sef_cb_init(int type, sef_init_info_t *info) {
/* Initialize the secret driver. */
    int do_announce_driver = TRUE;

    open_counter = 0;
    switch(type) {
        case SEF_INIT_FRESH:
            printf("Fresh init\n");
        break;

        case SEF_INIT_LU:
            /* Restore the state. */
            lu_state_restore();
            do_announce_driver = FALSE;

            printf("Hey, I'm a new version!\n");
        break;

        case SEF_INIT_RESTART:
            printf("Hey, I've just been restarted!\n");
        break;
    }

    /* Announce we are up when necessary. */
    if (do_announce_driver) {
        driver_announce();
    }

    /* Initialization completed successfully. */
    return OK;
}

PUBLIC int main(int argc, char **argv) {
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

