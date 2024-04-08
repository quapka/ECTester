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


JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_TropicSquareFirmware_createProvider(JNIEnv *env, jobject){
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

    // TODO - which version to use?
    int lib_version = 0;
    std::string info_str = std::to_string(lib_version);
    std::stringstream ss;
    ss << lib_name << " ";
    ss << info_str[0];
    for (size_t i = 1; i < info_str.size(); ++i) {
        ss << "." << info_str[i];
    }

    jstring name = env->NewStringUTF(lib_name.c_str());
    double version = lib_version / 100;
    jstring info = env->NewStringUTF(ss.str().c_str());

    return env->NewObject(provider_class, init, name, version, info);
}

JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeProvider_00024TropicSquare_setup(JNIEnv *env, jobject self) {
    jmethodID provider_put = env->GetMethodID(provider_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    /* add_kpg(env, "ECDH", "TropicSquareECDH", self, provider_put); */
    add_kpg(env, "ECDSA", "TropicSquareECDSA", self, provider_put);
    
    /* add_ka(env, "ECDH", "TropicSquareECDH", self, provider_put); */
    
    /* add_sig(env, "SHA1withECDSA", "TropicSquareECDSAwithSHA1", self, provider_put); */
    /* add_sig(env, "SHA224withECDSA", "TropicSquareECDSAwithSHA224", self, provider_put); */
    /* add_sig(env, "SHA256withECDSA", "TropicSquareECDSAwithSHA256", self, provider_put); */
    /* add_sig(env, "SHA384withECDSA", "TropicSquareECDSAwithSHA384", self, provider_put); */
    add_sig(env, "SHA512withECDSA", "TropicSquareECDSAwithSHA512", self, provider_put);
    add_sig(env, "NONEwithECDSA", "TropicSquareECDSAwithNONE", self, provider_put);


    uint32_t rv;

    rv = spect_dpi_init();
    assert(rv == 0 && "DPI Library initialized");

    spect_dpi_set_verbosity(3);

    spect_dpi_reset();

    // TODO: Adjust paths to be raltive to some var
    rv = spect_dpi_compile_program("/home/qup/projects/ts-spect-compiler/test/dpi/dpi_simple_test.s",
                                    "tmp.hex",
                                   DPI_HEX_ISS_WORD, DPI_PARITY_NONE,
                                   SPECT_INSTR_MEM_BASE);
    printf("RV: %d", rv);
    assert(rv == 0);

    spect_dpi_exit();

    init_classes(env, "TropicSquare");
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_TropicSquareFirmware_getCurves(JNIEnv *env, jobject self) {
    // FIXME
    jclass set_class = env->FindClass("java/util/TreeSet");

    jmethodID set_ctr = env->GetMethodID(set_class, "<init>", "()V");
    jmethodID set_add = env->GetMethodID(set_class, "add", "(Ljava/lang/Object;)Z");

    jobject result = env->NewObject(set_class, set_ctr);

    /* std::vector<OID> all_oids = get_all_curve_oids(); */

    /* for (auto & all_oid : all_oids) { */
    /*     jstring name_str = env->NewStringUTF(oid_to_str(all_oid).c_str()); */
    /*     env->CallBooleanMethod(result, set_add, name_str); */
    /* } */

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

/* JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024TropicSquare_generate__ILjava_security_SecureRandom_2(JNIEnv *, jobject, jint, jobject) { */
/* } */

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024TropicSquare_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(JNIEnv *env, jobject self, jobject params, jobject random) {
}

/* JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024TropicSquare_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2 */
/*   (JNIEnv *, jobject, jbyteArray, jbyteArray, jobject); */
/* JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024TropicSquare_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2Ljava_lang_String_2 */
/*   (JNIEnv *, jobject, jbyteArray, jbyteArray, jobject, jstring); */
/* JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024TropicSquare_paramsSupported */
/*   (JNIEnv *, jobject, jobject); */
/* JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024TropicSquare_sign */
/*   (JNIEnv *, jobject, jbyteArray, jbyteArray, jobject); */
/* JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024TropicSquare_verify */
/*   (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray, jobject); */
/* JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_TropicSquareFirmware_createProvider */
/*   (JNIEnv *, jobject); */
