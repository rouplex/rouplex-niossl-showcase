package org.rouplex.util;

/**
 * @author Andi Mullaraj (andimullaraj at gmail.com)
 */

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class SSLServer extends SSLEntity implements Closeable {
    ServerSocket serverSocket;
    ServerSocketChannel serverSocketChannel;

    ExecutorService executorService = Executors.newCachedThreadPool();
    final Map<String, ServerSession> serverSessions = new HashMap<String, ServerSession>();
    private int sessionsAvailable = 1;
    int serverBackLog;

    public static void main(String[] args) throws Exception {
        new SSLServer().start();
    }

    /**
     * Properties are normally set via the running script, keeping this method to remember the settings
     */
    private static void setSystemProperties() {
        System.setProperty("javax.net.ssl.keyStore", "src/testServerReceivedWhatSocketSent/resources/server-keystore");
        System.setProperty("javax.net.ssl.keyStorePassword", "kotplot");
        System.setProperty("java.protocol.handler.pkgs", "com.sun.net.ssl.internal.www.protocol");
        System.setProperty("javax.net.debug", "ssl");
    }

    public static class SSLServerBuilder extends SSLEntityBuilder<SSLServer, SSLServerBuilder> {
        SSLServerBuilder() {
            super(new SSLServer());
        }

        public SSLServerBuilder withMaxParallelServerConnections(int maxParallelServerConnections) {
            checkCanConfigure();

            sslEntity.sessionsAvailable = maxParallelServerConnections;
            return builder;
        }

        public SSLServerBuilder withServerBackLog(int serverBacklog) {
            checkCanConfigure();

            sslEntity.serverBackLog = serverBacklog;
            return builder;
        }

        @Override
        public SSLServer build(boolean start) throws Exception {
            checkCanBuild();

            if (start) {
                sslEntity.start();
            }

            SSLServer sslServer = sslEntity;
            sslEntity = null;
            return sslServer;
        }
    }

    public static SSLServerBuilder newSSLServerBuilder() {
        return new SSLServerBuilder();
    }

    public class ServerSession extends SSLClient implements Runnable, Closeable {
        ServerSession() {
            super(false);
        }

        @Override
        public void run() {
            try {
                exchangeSessionId();

                while (true) {
                    String line = readThenWriteLine();
                    if (line == null) {
                        break;
                    }

                    if (UPGRADE_TO_SSL_MAGIC_WORD.equals(line)) {
                        upgradeToSsl("client wire request");
                    }

                    if (CLOSE_SESSION_MAGIC_WORD.equals(line)) {
                        close(true, false);
                    }

                    if (SHUTDOWN_INPUT_MAGIC_WORD.equals(line)) {
                        shutdownInput();
                    }

                    if (SHUTDOWN_OUTPUT_MAGIC_WORD.equals(line)) {
                        shutdownOutput();
                    }
                }

                logger.info(String.format("Finished session [%s] (other end closed)", entityId));
            } catch (Exception e) {
                exception = e;
                logger.info(String.format("Finished session [%s] due to exception %s", entityId, e.getMessage()));
            }

            synchronized (serverSessions) {
                if (sessionsAvailable++ == 0) {
                    serverSessions.notifyAll();
                }
            }

            tryClose();
        }

        @Override
        public void exchangeSessionId() throws IOException {
            if (sharedClientGeneratesSessionId) {
                setEntityId(readExpectedLine());
            } else {
                setEntityId(UUID.randomUUID().toString());
            }

            Thread.currentThread().setName(entityReadableId);
            synchronized (serverSessions) {
                serverSessions.put(entityId, this);
            }

            if (sharedClientGeneratesSessionId) {
                writeLine(entityId);
            } else {
                protocolExchangeSessionId();
            }
        }
    }

    SSLServer() {
        clientMode = false;
    }

    public Collection<ServerSession> getServerSessions() {
        return serverSessions.values();
    }

    public ServerSession getServerSession(String sessionId) {
        synchronized (serverSessions) {
            return serverSessions.get(sessionId);
        }
    }

    public InetSocketAddress getLocalAddress() {
        return localAddress;
    }

    public void start() throws Exception {
        synchronized (serverSessions) {
            if (serverSocketChannel != null || serverSocket != null) {
                throw new Exception("Server can only be run once.");
            }

            createServer();
        }

        executorService.submit(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.currentThread().setName("SSLServer-Listener");

                    while (!executorService.isShutdown()) {
                        synchronized (serverSessions) {
                            while (sessionsAvailable == 0) {
                                logger.info("Server not accepting new connections (no more available)");
                                serverSessions.wait(); // this wait is only when we have N parallel connections
                                if (executorService.isShutdown()) {
                                    throw new Exception("Server stopped");
                                }
                            }

                            sessionsAvailable--;
                        }

                        logger.info("Server accepting new connections");
                        ServerSession serverSession = acceptServerSession();
                        logger.info("Server handling a new connection");
                        executorService.submit(serverSession);
                    }
                } catch (InterruptedException ie) {
                    logger.info("Server finished accepting new connections. Cause: " + exception.getMessage());
                } catch (Exception e) {
                    logger.info("Server finished accepting new connections. Cause: " + e.getMessage());
                }

                try {
                    close();
                } catch (IOException e2) {
                    logger.info("Failed stopping server. Cause: " + e2.getMessage());
                }
            }
        });
    }

    void createServer() throws Exception {
        logger.info("Server starting");

        if (localAddress == null) {
            for (int port = 10000; localAddress == null; port++) {
                if (port == 60000) {
                    throw new IOException("No more available ports for listening");
                }

                try {
                    InetSocketAddress localAddress = new InetSocketAddress("localhost", port);
                    createServer(localAddress);
                    this.localAddress = localAddress;
                } catch (IOException e) {
                    logger.warning(String.format(
                            "Failed to create server listening at port %s. Cause: %s. Retrying with next port",
                            port, e.getMessage()));

                    if (e.getCause() instanceof GeneralSecurityException) {
                        throw e;
                    }
                }
            }
        } else {
            createServer(localAddress);
        }

        logger.info(String.format("Server started listening at port %d", localAddress.getPort()));
    }

    void createServer(InetSocketAddress localAddress) throws IOException {
        switch (componentUsage) {
            case IO_CLASSIC:
                serverSocket = newServerSocket(sslContext);
                serverSocket.bind(localAddress, serverBackLog);
                break;
            case NIO_BLOCKING:
            case NIO_NON_BLOCKING_NO_SELECTORS:
            case NIO_NON_BLOCKING_CREATE_SELECTORS:
            case NIO_NON_BLOCKING_REUSE_SELECTORS:
                serverSocketChannel = newServerSocketChannel(sslContext);
                serverSocketChannel.socket().bind(localAddress, serverBackLog);
                break;
        }
    }

    SSLClient.SSLClientBuilder<ServerSession, ?> newServerSessionBuilder() {
        return new SSLClient.SSLClientBuilder(new ServerSession());
    }

    ServerSession acceptServerSession() throws Exception {
        Socket socket;
        SocketChannel socketChannel;

        switch (componentUsage) {
            case IO_CLASSIC:
                socket = serverSocket.accept();
                socketChannel = null;
                break;
            default:
                socketChannel = serverSocketChannel.accept();
                socket = null;
                break;
        }

        return newServerSessionBuilder()
                .withExistingSocket(socket)
                .withExistingSocketChannel(socketChannel)
                .withSharedSecure(sslContext != null, sslContext)
                .withSharedConnectionScheme(sharedConnectionScheme)
                .withComponentUsage(componentUsage)
                .withShutdownScheme(shutdownScheme)
                .withCloseScheme(closeScheme)
                .withSharedClientGeneratesSessionId(sharedClientGeneratesSessionId)
                .withRecordBytes(maxRecordBytes)
                .withRecordLines(readLines != null)
                .build(false);
    }

    @Override
    public void close() throws IOException {
        synchronized (serverSessions) {
            if (executorService.isShutdown()) {
                return;
            }

            executorService.shutdownNow();

            for (ServerSession serverSession : serverSessions.values()) {
                serverSession.close();
            }
        }

        logger.info("Server stopping");

        if (serverSocketChannel != null) {
            try {
                serverSocketChannel.close();
            } catch (IOException ioe) {
            }
        }

        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException ioe) {
            }
        }

        try {
            if (!executorService.awaitTermination(100, TimeUnit.SECONDS)) {
                logger.warning("Executor not finished");
                throw new IOException("Executor not finished");
            }
        } catch (InterruptedException ie) {
            logger.warning("Executor interrupted");
            //throw new IOException(ie);
        }

        logger.info("Server stopped");
    }

    public void tryClose() {
        try {
            close();
        } catch (Exception ioe) {
            logger.warning(String.format("Exception during server close. Cause: %s", ioe.getMessage()));
        }
    }
}