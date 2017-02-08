package org.rouplex.nio.channels;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.nio.channels.ServerSocketChannel;

/**
 * @author Andi Mullaraj (andimullaraj at gmail.com)
 */
public abstract class SSLServerSocketChannel {
    public static ServerSocketChannel open() throws IOException {
        return ServerSocketChannel.open();
    }

    public static ServerSocketChannel open(SSLContext sslContext) throws IOException {
        return ServerSocketChannel.open();
    }
}
