/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape Security Services for Java.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1998-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */
/*
 * This is adapted from the Mozilla Security Services for Java (JSS)
 * implementation of the function:
 *
 *     Java_org_mozilla_jss_pkcs11_PK11KeyGenerator_generatePBE
 *
 * in the file:
 *
 *     mozilla/jss/security/jss/org/mozilla/jss/pkcs11/PK11KeyGenerator.c.
 *
 * The full header for that file is repeated above.
 */

#include <secitem.h>
#include <secoidt.h>
#include <secmodt.h>
#include <pkcs11t.h>
#include <pk11pub.h>
#include <certt.h>
#include <nspr.h>

#include <jni.h>

#include <pk11util.h>

#include <jss_exceptions.h>
#include <jssutil.h>

JNIEXPORT jobject JNICALL
Java_org_jboss_security_fips_utils_FIPSCryptoUtil_deriveKeyFromPassword
    (JNIEnv *env, jclass clazz, jobject token, jbyteArray passBA,
    jbyteArray saltBA, jint iterationCount, jint keyLength)
{
    PK11SlotInfo *slot=NULL;
    PK11SymKey *skey=NULL;
    SECAlgorithmID *algid=NULL;
    SECItem *salt=NULL;
    SECItem *pwitem=NULL;
    jobject keyObj=NULL;

    PR_ASSERT(env!=NULL && clazz!=NULL && token!=NULL
        && passBA!=NULL && saltBA!=NULL);

    /* suppresses warning for unused parameter */
    (void)clazz;

    /* get the slot */
    if( JSS_PK11_getTokenSlotPtr(env, token, &slot) != PR_SUCCESS) {
        goto finish;
    }

    /* convert salt to SECItem */
    salt = JSS_ByteArrayToSECItem(env, saltBA);
    if(salt == NULL) {
        goto finish;
    }

    /* convert password to SECItem */
    pwitem = JSS_ByteArrayToSECItem(env, passBA);
    if(pwitem==NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    algid = PK11_CreatePBEV2AlgorithmID(SEC_OID_PKCS5_PBKDF2,
                            SEC_OID_DES_EDE3_CBC,
                            SEC_OID_HMAC_SHA1,
                            keyLength / 8,
                            iterationCount,
                            salt);
    if( algid == NULL ) {
        JSS_throwMsg(env, TOKEN_EXCEPTION,
                   "Unable to process PBE parameters");
        goto finish;
    }

    skey = PK11_PBEKeyGen(slot, algid, pwitem,
               PR_FALSE /* faulty 3Des */, NULL /* wincx */ );
    if( skey == NULL ) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Failed to generate PBE key");
        goto finish;
    }
    /* wrap the key. This sets skey to NULL. */
    keyObj = JSS_PK11_wrapSymKey(env, &skey);

finish:
    if(algid) {
        SECOID_DestroyAlgorithmID(algid, PR_TRUE /*freeit*/);
    }
    if(salt) {
        SECITEM_FreeItem(salt, PR_TRUE /*freeit*/);
    }
    if(pwitem) {
        SECITEM_ZfreeItem(pwitem, PR_TRUE /*freeit*/);
    }
    if(skey) {
        /* skey will be NULL if everything worked */
        PK11_FreeSymKey(skey);
    }
    return keyObj;
}

