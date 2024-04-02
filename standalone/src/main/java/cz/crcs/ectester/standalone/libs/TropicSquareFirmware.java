package cz.crcs.ectester.standalone.libs;

import java.security.Provider;
import java.util.Set;

/**
 * @author Jan Kvapil x408788@fi.muni.cz
 */
public class TropicSquareFirmware extends NativeECLibrary {
    public TropicSquareFirmware() {
        super("TropicSquare", "tropicsquare_provider", "libspect_iss_dpi.so");
    }

    @Override
    native Provider createProvider();

    @Override
    public native Set<String> getCurves();
}
