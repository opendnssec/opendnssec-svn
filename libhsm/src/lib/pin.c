/* $Id$ */

/*
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <semaphore.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "libhsm.h"

/* Constants */
#define SHM_KEY (key_t)0x0d50d5ec
#define SEM_NAME "/ods_libhsm_pin"
#define SHM_PERM S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP

/* Remember PIN that we can save */
static char pin[HSM_MAX_PIN_LENGTH+1];

char *
hsm_prompt_pin(unsigned int id, const char *repository, void *data, unsigned int mode)
{
    /* Shared memory */
    int shmid;
    int created = 0;
    struct shmid_ds buf;
    char *pins = NULL;
    sem_t *pin_semaphore = NULL;
    int index = id * (HSM_MAX_PIN_LENGTH + 1);

    /* PIN from getpass */
    char prompt[64];
    char *prompt_pin = NULL;
    unsigned int size = 0;

    /* Unused variable */
    (void) data;

    /* Check input data */
    if (id >= HSM_MAX_SESSIONS) return NULL;
    if (repository == NULL) return NULL;
    if (mode != HSM_PIN_FIRST && mode != HSM_PIN_RETRY && mode != HSM_PIN_SAVE) return NULL;

    /* Create/get the semaphore */
    pin_semaphore = sem_open(SEM_NAME, O_CREAT, SHM_PERM, 1);
    if (pin_semaphore == SEM_FAILED) return NULL;

    /* Lock the semaphore */
    if (sem_wait(pin_semaphore) != 0) {
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Create/get the shared memory */
    shmid = shmget(SHM_KEY, sizeof(char)*HSM_MAX_SESSIONS*(HSM_MAX_PIN_LENGTH+1), IPC_CREAT|IPC_EXCL|SHM_PERM);
    if (shmid == -1) {
        shmid = shmget(SHM_KEY, sizeof(char)*HSM_MAX_SESSIONS*(HSM_MAX_PIN_LENGTH+1), IPC_CREAT|SHM_PERM);
        if (shmid == -1) {
            sem_post(pin_semaphore);
            sem_close(pin_semaphore);
            pin_semaphore = NULL;
            return NULL;
        }
    } else {
        created = 1;
    }

    /* Get information about the shared memory */
    if (shmctl(shmid, IPC_STAT, &buf) != 0) {
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Check permission to avoid an attack */
    if (buf.shm_perm.mode != (SHM_PERM) || buf.shm_perm.cgid != getegid()) {
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Attach to the shared memory */
    pins = (char *)shmat(shmid, NULL, 0);
    if (pins == (char *)-1) {
        pins = NULL;
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Zeroize if we created the memory area */
    if (created == 1) {
        memset(pins, '\0', sizeof(char)*HSM_MAX_SESSIONS*(HSM_MAX_PIN_LENGTH+1));
    }

    /* Get the PIN */
    if (mode != HSM_PIN_SAVE) {
        /* Do we have a PIN in the cache? */
        if (mode == HSM_PIN_FIRST && pins[index] != '\0') {
            size = strlen(&pins[index]);
            if (size > HSM_MAX_PIN_LENGTH) size = HSM_MAX_PIN_LENGTH;
            memcpy(pin, &pins[index], size);
            pin[size] = '\0';
        } else {
            snprintf(prompt, 64, "Enter PIN for token %s: ", repository);
#ifdef HAVE_GETPASSPHRASE
            prompt_pin = getpassphrase(prompt);
#else
            prompt_pin = getpass(prompt);
#endif

            /* Remember PIN */
            size = strlen(prompt_pin);
            if (size > HSM_MAX_PIN_LENGTH) size = HSM_MAX_PIN_LENGTH;
            memset(pin, '\0', HSM_MAX_PIN_LENGTH+1);
            memcpy(pin, prompt_pin, size);

            /* Zeroize the getpass PIN */
            memset(prompt_pin, '\0', strlen(prompt_pin));
        }
    } else {
        /* Save the PIN */
        memcpy(&pins[index], pin, HSM_MAX_PIN_LENGTH+1);

        /* Zeroize the PIN */
        memset(pin, '\0', HSM_MAX_PIN_LENGTH+1);
    }

    /* Unlock the semaphore */
    sem_post(pin_semaphore);

    /* Detach from the shared memory */
    shmdt(pins);
    pins = NULL;

    /* Close semaphore */
    sem_close(pin_semaphore);
    pin_semaphore = NULL;

    return pin;
}

char *
hsm_block_pin(unsigned int id, const char *repository, void *data, unsigned int mode)
{
    /* Shared memory */
    int shmid;
    int created = 0;
    struct shmid_ds buf;
    char *pins = NULL;
    sem_t *pin_semaphore = NULL;
    int index = id * (HSM_MAX_PIN_LENGTH + 1);

    unsigned int size = 0;

    /* Unused variable */
    (void) data;

    /* Check input data */
    if (id >= HSM_MAX_SESSIONS) return NULL;
    if (repository == NULL) return NULL;
    if (mode != HSM_PIN_FIRST && mode != HSM_PIN_RETRY && mode != HSM_PIN_SAVE) return NULL;

    /* Create/get the semaphore */
    pin_semaphore = sem_open(SEM_NAME, O_CREAT, SHM_PERM, 1);
    if (pin_semaphore == SEM_FAILED) return NULL;

    /* Lock the semaphore */
    if (sem_wait(pin_semaphore) != 0) {
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Create/get the shared memory */
    shmid = shmget(SHM_KEY, sizeof(char)*HSM_MAX_SESSIONS*(HSM_MAX_PIN_LENGTH+1), IPC_CREAT|IPC_EXCL|SHM_PERM);
    if (shmid == -1) {
        shmid = shmget(SHM_KEY, sizeof(char)*HSM_MAX_SESSIONS*(HSM_MAX_PIN_LENGTH+1), IPC_CREAT|SHM_PERM);
        if (shmid == -1) {
            sem_post(pin_semaphore);
            sem_close(pin_semaphore);
            pin_semaphore = NULL;
            return NULL;
        }
    } else {
        created = 1;
    }

    /* Get information about the shared memory */
    if (shmctl(shmid, IPC_STAT, &buf) != 0) {
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Check permission to avoid an attack */
    if (buf.shm_perm.mode != (SHM_PERM) || buf.shm_perm.cgid != getegid()) {
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Attach to the shared memory */
    pins = (char *)shmat(shmid, NULL, 0);
    if (pins == (char *)-1) {
        pins = NULL;
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Zeroize if we created the memory area */
    if (created == 1) {
        memset(pins, '\0', sizeof(char)*HSM_MAX_SESSIONS*(HSM_MAX_PIN_LENGTH+1));
    }

    /* Zeroize any PIN */
    memset(pin, '\0', HSM_MAX_PIN_LENGTH+1);

    /* Get the PIN */
    if (mode != HSM_PIN_SAVE) {
        /* Unlock the semaphore */
        if (sem_post(pin_semaphore) != 0) {
            shmdt(pins);
            pins = NULL;
            sem_close(pin_semaphore);
            pin_semaphore = NULL;
            return NULL;
        }

        /* Wait until we have a PIN. User must use "ods-hsmutil login" or similar */
        while (pin[0] == '\0') {
            sleep(1);

            /* Check if we have no PIN in the cache */
            if (pins[index] == '\0') continue;

            /* Lock the semaphore */
            if (sem_wait(pin_semaphore) != 0) {
                shmdt(pins);
                pins = NULL;
                sem_close(pin_semaphore);
                pin_semaphore = NULL;
                return NULL;
            }

            /* Check if the PIN is in the cache */
            if (pins[index] != '\0') {
                size = strlen(&pins[index]);
                if (size > HSM_MAX_PIN_LENGTH) size = HSM_MAX_PIN_LENGTH;
                memcpy(pin, &pins[index], size);
                pin[size] = '\0';
            }
        }
    } else {
        /* Nothing to do */
    }

    /* Unlock the semaphore */
    sem_post(pin_semaphore);

    /* Detach from the shared memory */
    shmdt(pins);
    pins = NULL;

    /* Close semaphore */
    sem_close(pin_semaphore);
    pin_semaphore = NULL;

    return pin;
}
