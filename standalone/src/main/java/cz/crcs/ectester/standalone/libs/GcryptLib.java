package cz.crcs.ectester.standalone.libs;

import java.security.Provider;
import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class GcryptLib extends NativeECLibrary {

    public GcryptLib() {
        super("libgcrypt","gcrypt_provider", "gcrypt", "gpg-error");
    }

    @Override
    native Provider createProvider();

    @Override
    public native Set<String> getCurves();

    @Override
    public boolean supportsDeterministicPRNG() {
        // This is provided by the native preload that hooks all randomness sources.
        return true;
    }
}
