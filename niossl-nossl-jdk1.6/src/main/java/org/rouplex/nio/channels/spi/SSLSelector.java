package org.rouplex.nio.channels.spi;

import org.rouplex.nio.channels.SSLSocketChannel;

import java.io.IOException;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

/**
 * A Selector subclass that can be used to register and select on {@link SSLSocketChannel}s the same way as a
 * {@link Selector} is used with an {@link SocketChannel}.
 * <p>
 * As with the rest of the package, we have stayed faithful to the requirements of the API, laid out at
 * http://docs.oracle.com/javase/6/docs/api/java/nio/channels/Selector.html. The synchronization could be simplified
 * by removing some of the locks during selection, but we would not want to run the risk of breaking any existing code
 * proven to work with the existing non-ssl Selectors.
 *
 * @author Andi Mullaraj (andimullaraj at gmail.com)
 */
public class SSLSelector {
    public static Selector open() throws IOException {
        return Selector.open();
    }
}
