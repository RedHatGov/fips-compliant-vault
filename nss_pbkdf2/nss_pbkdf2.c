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
Java_org_jboss_security_fips_plugins_FIPSCompliantVault_deriveKeyFromPassword
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

