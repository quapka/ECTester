#include "native.h"

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
#include <sstream>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <cstdlib>
using std::exit;

#include <cstdint>

#include <spect_iss_dpi.h>
#include <spect_iss_lib.h>
#include <spect_defs.h>
#include <cassert>

#include "cpp_utils.hpp"
#include "c_timing.h"

static jclass provider_class;

/* **  Operation on the DPI model can be done like so: */
/* **      spect_dpi_init(); */
/* ** */
/* **      spect_dpi_compile_program(S_FILE_PATH, HEX_FILE_PATH, ISS_WORD); */
/* **      spect_dpi_load_hex_file(HEX_FILE_PATH); */
/* ** */
/* **      uint32_t start_pc = spect_dpi_get_compiled_program_start_address(); */
/* **      spect_dpi_set_model_start_pc(start_pc); */
/* ** */
/* **      // One of following actions executes start of program, both should have the same effect: */
/* **      spect_dpi_start() */
/* **      Write COMMAND[START] via spect_ahb_write() */
/* ** */
/* **      // Step through the program */
/* **      while (!spect_dpi_is_program_finished()) { */
/* **          spect_dpi_program_step(<NUMBER_OF_CYCLES_EXECUTION_OF_LAST_INSTRUCTION_TOOK_ON_RTL>) */
/* **      } */
/* ** */
/* **      spect_dpi_exit(); */


JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_TropicSquareFirmware_createProvider(JNIEnv *env, jobject self){
    /* /1* Create the custom provider. *1/ */
    /* jclass local_provider_class = (*env)->FindClass(env, "cz/crcs/ectester/standalone/libs/jni/NativeProvider$TropicSquare"); */
    /* provider_class = (*env)->NewGlobalRef(env, local_provider_class); */

    /* jmethodID init = (*env)->GetMethodID(env, local_provider_class, "<init>", "(Ljava/lang/String;DLjava/lang/String;)V"); */

    /* jstring name =  (*env)->NewStringUTF(env, "TropicSquare"); */

    /* double version = 2.0; */
    /* return (*env)->NewObject(env, provider_class, init, name, version, name); */
    /* Create the custom provider. */
    jclass local_provider_class = env->FindClass("cz/crcs/ectester/standalone/libs/jni/NativeProvider$TropicSquare");
    provider_class = (jclass) env->NewGlobalRef(local_provider_class);

    jmethodID init = env->GetMethodID(local_provider_class, "<init>", "(Ljava/lang/String;DLjava/lang/String;)V");

    std::string lib_name = "TropicSquare";

    // TODO - which version to use? Use ISA version?
    int lib_version = 0;
    std::string info_str = std::to_string(lib_version);
    std::stringstream ss;
    ss << lib_name << " ";
    ss << info_str[0];
    for (size_t i = 1; i < info_str.size(); ++i) {
        ss << "." << info_str[i];
    }

    jstring name = env->NewStringUTF(lib_name.c_str());
    double version = 2.0; // lib_version / 100;
    jstring info = env->NewStringUTF(ss.str().c_str());

    return env->NewObject(provider_class, init, name, version, info);
}

JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeProvider_00024TropicSquare_setup(JNIEnv *env, jobject self) {
    jmethodID provider_put = env->GetMethodID(provider_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    add_kpg(env, "EC", "TropicSquare", self, provider_put);
    add_kpg(env, "ECDSA", "TropicSquareECDSA", self, provider_put);
    
    /* add_ka(env, "ECDH", "TropicSquareECDH", self, provider_put); */
    
    /* add_sig(env, "SHA1withECDSA", "TropicSquareECDSAwithSHA1", self, provider_put); */
    /* add_sig(env, "SHA224withECDSA", "TropicSquareECDSAwithSHA224", self, provider_put); */
    /* add_sig(env, "SHA256withECDSA", "TropicSquareECDSAwithSHA256", self, provider_put); */
    /* add_sig(env, "SHA384withECDSA", "TropicSquareECDSAwithSHA384", self, provider_put); */
    /* add_sig(env, "SHA512withECDSA", "TropicSquareECDSAwithSHA512", self, provider_put); */
    add_sig(env, "NONEwithECDSA", "TropicSquareECDSAwithNONE", self, provider_put);


    const int ISA_VERSION = 2;
    spect_iss_init(ISA_VERSION);

    spect_iss_load_s_file("/home/qup/projects/ts-spect-fw/src/main.s");
    // TODO how to decide on generating the random data?
    spect_iss_set_grv_hex_file("/home/qup/projects/ts-spect-fw/tests/rng.hex");
    spect_iss_set_const_rom_hex_file("/home/qup/projects/ts-spect-fw/build/constants.hex");
    /* uint32_t rv; */

    /* rv = spect_dpi_init(); */
    /* assert(rv == 0 && "DPI Library initialized"); */

    /* spect_dpi_set_verbosity(3); */

    /* spect_dpi_reset(); */

    /* // TODO: Adjust paths to be raltive to some var */
    /* rv = spect_dpi_compile_program("/home/qup/projects/ts-spect-compiler/test/dpi/dpi_simple_test.s", */
    /*                                 "tmp.hex", */
    /*                                DPI_HEX_ISS_WORD, DPI_PARITY_NONE, */
    /*                                SPECT_INSTR_MEM_BASE); */
    /* printf("RV: %d", rv); */
    /* assert(rv == 0); */

    /* spect_dpi_exit(); */

    init_classes(env, "TropicSquare");
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_TropicSquareFirmware_getCurves(JNIEnv *env, jobject self) {
    // FIXME
    jclass set_class = env->FindClass("java/util/TreeSet");

    jmethodID set_ctr = env->GetMethodID(set_class, "<init>", "()V");
    jmethodID set_add = env->GetMethodID(set_class, "add", "(Ljava/lang/Object;)Z");

    jobject result = env->NewObject(set_class, set_ctr);

    // FIXME
    jstring name_str = env->NewStringUTF("Curve25519");
    env->CallBooleanMethod(result, set_add, name_str);

    return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024TropicSquare_keysizeSupported
  (JNIEnv *env, jobject self, jint keysize) {
    // FIXME
    if ( keysize == 256 ) {
        return JNI_TRUE;
    }
    return JNI_FALSE;
}

/* This function is implemented directly in Java */
/* JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024TropicSquare_paramsSupported(JNIEnv *env, jobject self, jobject params){ */
/*     // NOTE choosing the correct params is handled one level higher */
/*     if (params == nullptr) { */
/*         return JNI_FALSE; */
/*     } */

/*     if (env->IsInstanceOf(params, ec_parameter_spec_class)) { */
/*         // Any custom params should be supported. */
/*         return JNI_FALSE; */
/*     } else if (env->IsInstanceOf(params, ecgen_parameter_spec_class)) { */
/*         // Here we assume secg/secp256k1 */
/*         return JNI_TRUE; */

/*         /1* jmethodID get_name = env->GetMethodID(ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;"); *1/ */
/*         /1* jstring name = (jstring) env->CallObjectMethod(params, get_name); *1/ */
/*         /1* const char *utf_name = env->GetStringUTFChars(name, nullptr); *1/ */
/*         /1* std::string str_name(utf_name); *1/ */
/*         /1* env->ReleaseStringUTFChars(name, utf_name); *1/ */

/*         /1* std::vector<OID> all_oids = get_all_curve_oids(); *1/ */
/*         /1* for (auto & all_oid : all_oids) { *1/ */
/*         /1*     std::string oid_s = oid_to_str(all_oid); *1/ */
/*         /1*     if (str_name == oid_s) { *1/ */
/*         /1*         return JNI_TRUE; *1/ */
/*         /1*     } *1/ */
/*         /1* } *1/ */
/*     } */
/*     return JNI_FALSE; */
/* } */


/* void printKeyDirectly(uint8_t type, uint8_t slot, uint8_t offset, ) { */
/*     for(uint32_t i=offset; i < offset + 8; i++) { */
/*         printf("%08x\n", simulator->key_memory_->Get(type, slot, i)); */
/*     } */
/* } */

/* JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024TropicSquare_generate__ILjava_security_SecureRandom_2(JNIEnv *env, jobject self, jint keysize, jobject random) { */
JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024TropicSquare_generateInner__ILjava_security_SecureRandom_2(JNIEnv *env, jobject self, jint keysize, jobject random) {
    // FIXME generate ECDSA key
    // TODO switch order of public and private?
    printf("keeeeeeeeeeeeeeeys copieeeeeeeed");
    spect_iss_execute_cmd_file("/home/qup/projects/ectester/standalone/src/main/resources/cz/crcs/ectester/standalone/libs/jni/ecc_key_gen_cmd");

    // NOTE the type needs shall not be fixed
    const uint8_t type = 4;
    const uint8_t P256_PRIVATE_BYTE_SIZE = 32;
    const uint8_t P256_PUBLIC_BYTE_SIZE = 32;

    jbyteArray pub_bytearray = env->NewByteArray(P256_PUBLIC_BYTE_SIZE);
    jbyte *pub_bytes = env->GetByteArrayElements(pub_bytearray, nullptr);

    uint8_t P256_PRIVKEY_SLOT = 0;
    uint8_t P256_PUBKEY_SLOT = 1;

    uint8_t P256_PRIVKEY_OFFSET = 8;
    uint8_t P256_PUBKEY_OFFSET = 16;

    uint32_t priv_words[8] = { 0 };
    uint8_t priv[32] = { 0 };
    uint32_t pub_words[8] = { 0 };
    uint8_t pub[32] = { 0 };

    spect_iss_read_key_raw(type, P256_PUBKEY_SLOT, P256_PUBKEY_OFFSET, pub_words);
    spect_iss_read_key_raw(type, P256_PRIVKEY_SLOT, P256_PRIVKEY_OFFSET, priv_words);

    for (uint8_t i = 0; i < 8; i++ ) {
        uint32_t key_word = pub_words[i];
        pub[0 + 4 * i] = (key_word >> 0) & 0xFF;
        pub[1 + 4 * i] = (key_word >> 2) & 0xFF;
        pub[2 + 4 * i] = (key_word >> 4) & 0xFF;
        pub[3 + 4 * i] = (key_word >> 6) & 0xFF;
    }


    for (uint8_t i = 0; i < 8; i++ ) {
        uint32_t key_word = priv_words[i];
        priv[0 + 4 * i] = (key_word >> 0) & 0xFF;
        priv[1 + 4 * i] = (key_word >> 2) & 0xFF;
        priv[2 + 4 * i] = (key_word >> 4) & 0xFF;
        priv[3 + 4 * i] = (key_word >> 6) & 0xFF;
    }

    printf("twwwwwwwwwwwwwwwwwwwwwwwo");


    /* uint32_t key_word = 0; */
    /* for(uint32_t i=P256_PUBKEY_OFFSET; i < P256_PUBKEY_OFFSET + 8; i++) { */
    /*     key_word = simulator->key_memory_->Get(4, P256_PUBKEY_SLOT, i); */
    /*     /1* std::copy(pub.BytePtr(), pub.BytePtr()+pub.SizeInBytes(), pub_bytes); *1/ */
    /*     pub_bytes[0 + 4 * i] = key_word && 0xFF; */
    /*     pub_bytes[1 + 4 * i] = key_word && 0xFFFF; */
    /*     pub_bytes[2 + 4 * i] = key_word && 0xFFFFFF; */
    /*     pub_bytes[3 + 4 * i] = key_word && 0xFFFFFFFF; */
    /* } */

    std::copy(pub, pub + 32, pub_bytes);

    env->ReleaseByteArrayElements(pub_bytearray, pub_bytes, 0);

    printf("\npub1");
    jobject ec_pub_param_spec = env->NewLocalRef(nullptr);
    printf("\npub2");
    jmethodID ec_pub_init = env->GetMethodID(pubkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    printf("\npub3");
    jobject pubkey = env->NewObject(pubkey_class, ec_pub_init, pub_bytearray, ec_pub_param_spec);
    printf("\npub4");

    jbyteArray priv_bytearray = env->NewByteArray(32);
    jbyte *priv_bytes = env->GetByteArrayElements(priv_bytearray, nullptr);

    std::copy(priv, priv + 32, priv_bytes);
    env->ReleaseByteArrayElements(priv_bytearray, priv_bytes, 0);

    jobject ec_priv_param_spec = env->NewLocalRef(nullptr);
    jmethodID ec_priv_init = env->GetMethodID(privkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject privkey = env->NewObject(privkey_class, ec_priv_init, priv_bytearray, ec_priv_param_spec);

    jmethodID keypair_init = env->GetMethodID(keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");



    return env->NewObject(keypair_class, keypair_init, pubkey, privkey);
    /* return env->NewObject(keypair_class, keypair_init, pubkey, privkey); */
}

/* JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024TropicSquare_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(JNIEnv *env, jobject self, jobject params, jobject random) { */
/*     return nullptr; */
/* } */

/* JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024TropicSquare_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2(JNIEnv *env, jobject self, jbyteArray pubkey, jbyteArray privkey, jobject params) {} */

/* JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024TropicSquare_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2Ljava_lang_String_2(JNIEnv *env, jobject self, jbyteArray pubkey, jbyteArray privkey, jobject params, jstring algorithm) {} */

/* JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024TropicSquare_sign */
/*   (JNIEnv *, jobject, jbyteArray, jbyteArray, jobject); */
/* JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024TropicSquare_verify */
/*   (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray, jobject); */
