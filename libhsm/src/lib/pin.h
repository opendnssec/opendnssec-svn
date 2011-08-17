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

#ifndef PIN_H
#define PIN_H 1

#include <pkcs11.h>

/*! Initialize the PIN module

\param pin_callback This function will be called for tokens that have
                    no PIN configured. The default hsm_prompt_pin() can
                    be used.
\param data Optional data that will be directly passed to the callback
            function.
\return 0 if successful, !0 if failed

Create and attach the shared PIN memory.
*/
int
hsm_pin_init(char *(pin_callback)(const char *repository, void *), void *data);


/*! Login on the token

\param id
\param repository The repository name.
\param p11 Function pointers to repository.
\param seesion Session handle to the respository.
\param pin The PIN from the configuration
\return 0 if successful, !0 if failed
*/
int
hsm_pin_login(unsigned int id, const char *repository, CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, const char *pin);


/*! Finalize the PIN module
*/
void
hsm_pin_final(void);

#endif /* PIN_H */
