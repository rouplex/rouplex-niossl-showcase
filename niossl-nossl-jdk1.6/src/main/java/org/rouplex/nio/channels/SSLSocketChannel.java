package org.rouplex.nio.channels;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.util.concurrent.ExecutorService;

/**
 * @author Andi Mullaraj (andimullaraj at gmail.com)
 */
public abstract class SSLSocketChannel extends SocketChannel {
    protected SSLSocketChannel(SelectorProvider selectorProvider) {
        super(selectorProvider);
    }

    public static SocketChannel open(SSLContext sslContext) throws IOException {
        return SocketChannel.open();
    }

    public static SocketChannel open(SocketAddress socketAddress, SSLContext sslContext) throws IOException {
        return SocketChannel.open(socketAddress);
    }

    public static SSLSocketChannel open(SocketAddress socketAddress, SSLContext sslContext,
            boolean clientMode, ExecutorService tasksExecutorService, SocketChannel innerChannel) throws IOException {
        throw new Error("Not implemented");
    }
}

