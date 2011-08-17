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
#include "pin.h"

#include <pkcs11.h>

/* Constants */
#define SHM_KEY (key_t)1234
#define SEM_NAME "/ods_libhsm_pin"
#define SHM_PERM S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP

/* Semaphore */
static sem_t *pin_semaphore = NULL;

/* Shared memory */
static char *pins = NULL;

/* Callback */
static char *(*pin_callback)(const char *, void *) = NULL;
static void *pin_callback_data = NULL;

int
hsm_pin_init(char *(callback)(const char *repository, void *), void *data)
{
    sem_t *new_semaphore = NULL;
    int shmid;
    int created = 0;
    struct shmid_ds buf;

    /* Create/get the semaphore */
    if (pin_semaphore == NULL) {
        new_semaphore = sem_open(SEM_NAME, O_CREAT, SHM_PERM, 1);
        if (new_semaphore == SEM_FAILED) return HSM_SEMAPHORE_ERROR;

        pin_semaphore = new_semaphore;
    }

    /* Lock the semaphore */
    if (sem_wait(pin_semaphore) != 0) {
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return HSM_SEMAPHORE_ERROR;
    }

    /* Create/get the shared memory */
    shmid = shmget(SHM_KEY, sizeof(char)*HSM_MAX_SESSIONS*(HSM_MAX_PIN_LENGTH+1), IPC_CREAT|IPC_EXCL|SHM_PERM);
    if (shmid == -1) {
        shmid = shmget(SHM_KEY, sizeof(char)*HSM_MAX_SESSIONS*(HSM_MAX_PIN_LENGTH+1), IPC_CREAT|SHM_PERM);
        if (shmid == -1) {
            sem_post(pin_semaphore);
            sem_close(pin_semaphore);
            pin_semaphore = NULL;
            return HSM_ERROR;
        }
    } else {
        created = 1;
    }

    /* Get information about the shared memory */
    if (shmctl(shmid, IPC_STAT, &buf) != 0) {
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return HSM_ERROR;
    }

    /* Check permission to avoid an attack */
    if (buf.shm_perm.mode != (SHM_PERM) || buf.shm_perm.cgid != getegid()) {
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return HSM_ERROR;
    }

    /* Attach to the shared memory */
    pins = (char *)shmat(shmid, NULL, 0);
    if ((int)pins == -1) {
        pins = NULL;
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return HSM_ERROR;
    }

    pin_callback = callback;
    pin_callback_data = data;

    /* Zeroize if we created the memory area */
    if (created == 1) {
        memset(pins, '\0', sizeof(char)*HSM_MAX_SESSIONS*(HSM_MAX_PIN_LENGTH+1));
    }

    /* Unlock the semaphore */
    sem_post(pin_semaphore);

    return HSM_OK;
}

int
hsm_pin_login(unsigned int id, const char *repository, CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, const char *config_pin)
{
    int tries = 3;
    int save_pin = 0;
    int size = 0;
    char cached_pin[HSM_MAX_PIN_LENGTH+1];
    char *pin = NULL;
    CK_RV rv = CKR_PIN_INCORRECT;
    int index = id * (HSM_MAX_PIN_LENGTH + 1);

    /* Check input data */
    if (id >= HSM_MAX_SESSIONS) return HSM_ERROR;
    if (repository == NULL) return HSM_ERROR;
    if (p11 == NULL) return HSM_ERROR;
    if (config_pin != NULL) size = strlen(config_pin);
    if (size > HSM_MAX_PIN_LENGTH) return HSM_ERROR;

    /* Lock the semaphore */
    if (sem_wait(pin_semaphore) != 0) return HSM_SEMAPHORE_ERROR;

    /* Use the configured PIN if possible */
    if (config_pin) {
        memcpy(cached_pin, config_pin, size+1);
        pin = cached_pin;
        /* Only try one time */
        tries = 1;
    } else {
        /* Check if the PIN is in the cache */
        if (pins[index] != '\0') {
            size = strlen(&pins[index]);
            if (size > HSM_MAX_PIN_LENGTH) size = HSM_MAX_PIN_LENGTH;
            memcpy(cached_pin, &pins[index], size);
            cached_pin[size] = '\0';
            pin = cached_pin;
            /* Do not count the PIN from cache as a try */
            tries++;
        }
    }

    /* Check if we can interact with the user */
    if (pin_callback != NULL) {
        while (rv == CKR_PIN_INCORRECT && tries > 0) {
            /* Get PIN from user */
            if (pin == NULL) {
                pin = pin_callback(repository, pin_callback_data);
                if (pin == NULL) {
                    tries--;
                    continue;
                }
                save_pin = 1;
            }

            /* Try to login */
            size = strlen(pin);
            if (size <= HSM_MAX_PIN_LENGTH) {
                rv = p11->C_Login(session, CKU_USER, (unsigned char *) pin, size);
            }

            /* Save PIN */
            if (rv == CKR_OK && save_pin != 0) {
                memset(&pins[index], '\0', HSM_MAX_PIN_LENGTH+1);
                memcpy(&pins[index], pin, size);
            }

            /* Zeroize */
            memset(pin, 0, size);
            pin = NULL;
            tries--;
        }

        /* Unlock the semaphore */
        if (sem_post(pin_semaphore) != 0) return HSM_SEMAPHORE_ERROR;
    } else {
        /* Unlock the semaphore */
        if (sem_post(pin_semaphore) != 0) return HSM_SEMAPHORE_ERROR;

        /* Wait until we have a PIN. User must use "ods-hsmutil login" or similar */
        while (pin == NULL) {
            sleep(1);

            /* Check if we have no PIN in the cache */
            if (pins[index] == '\0') continue;

            /* Lock the semaphore */
            if (sem_wait(pin_semaphore) != 0) return HSM_SEMAPHORE_ERROR;

            /* Check if the PIN is in the cache */
            if (pins[index] != '\0') {
                size = strlen(&pins[index]);
                if (size > HSM_MAX_PIN_LENGTH) size = HSM_MAX_PIN_LENGTH;
                memcpy(cached_pin, &pins[index], size);
                cached_pin[size] = '\0';
                pin = cached_pin;
            }

            /* Unlock the semaphore */
            if (sem_post(pin_semaphore) != 0) return HSM_SEMAPHORE_ERROR;
        }

        /* Try to login */
        rv = p11->C_Login(session, CKU_USER, (unsigned char *) pin, size);

        /* Zeroize */
        memset(pin, 0, size);
        pin = NULL;
    }

    /* Check error codes */
    switch(rv) {
        case CKR_OK:
            break;
        case CKR_PIN_INCORRECT:
            return HSM_PIN_INCORRECT;
        default:
            return HSM_ERROR;
    }

    return HSM_OK;
}

void
hsm_pin_final()
{
    /* Detach from the shared memory */
    if (pins != NULL) {
        shmdt(pins);
        pins = NULL;
    }

    /* Close semaphore */
    if (pin_semaphore != NULL) {
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
    }
}
