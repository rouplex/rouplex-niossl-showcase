package org.rouplex.util;

import com.sun.management.UnixOperatingSystemMXBean;
import org.rouplex.nio.channels.SSLServerSocketChannel;
import org.rouplex.nio.channels.SSLSocketChannel;
import org.rouplex.nio.channels.spi.SSLSelector;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * @author Andi Mullaraj (andimullaraj at gmail.com)
 */
public class SSLEntity {
    protected final static String UPGRADE_TO_SSL_MAGIC_WORD = "UPGRADE_TO_SSL";
    protected final static String CLOSE_SESSION_MAGIC_WORD = "CLOSE_SESSION";
    protected final static String SHUTDOWN_INPUT_MAGIC_WORD = "SHUTDOWN_INPUT";
    protected final static String SHUTDOWN_OUTPUT_MAGIC_WORD = "SHUTDOWN_OUTPUT";

    protected final static char LF = '\n';
    protected final static byte[] newLine = new byte[]{LF};

    public static UnixOperatingSystemMXBean unixMXBean = (UnixOperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();

    public enum SharedConnectionScheme {
        CONNECT_PLAIN_AND_STAY_PLAIN,
        CONNECT_PLAIN_AND_SWITCH_TO_SSL_AFTER_EXCHANGING_SESSIONID,
        CONNECT_SSL_AND_STAY_SSL
    }

    public static final SharedConnectionScheme[] ALL_SHARED_CONNECTION_SCHEMES = {
            SharedConnectionScheme.CONNECT_PLAIN_AND_STAY_PLAIN,
            SharedConnectionScheme.CONNECT_PLAIN_AND_SWITCH_TO_SSL_AFTER_EXCHANGING_SESSIONID,
            SharedConnectionScheme.CONNECT_SSL_AND_STAY_SSL
    };

    public enum ComponentUsage {
        IO_CLASSIC,
        NIO_BLOCKING, // Easy IO, performance comparable to classic SSLSocket
        NIO_NON_BLOCKING_NO_SELECTORS, // Simple IO, User defines the threading model
        NIO_NON_BLOCKING_CREATE_SELECTORS, // Performant IO, creating selectors per client as needed
        NIO_NON_BLOCKING_REUSE_SELECTORS, // Performant IO, creating only one selector per client and reusing it
    }

    public static final ComponentUsage[] ALL_COMPONENT_USAGES = {
            ComponentUsage.IO_CLASSIC,
            ComponentUsage.NIO_BLOCKING,
            ComponentUsage.NIO_NON_BLOCKING_NO_SELECTORS,
            ComponentUsage.NIO_NON_BLOCKING_CREATE_SELECTORS,
            ComponentUsage.NIO_NON_BLOCKING_REUSE_SELECTORS
    };

    public enum ShutdownScheme {
        NO_SHUTDOWN,
        SHUTDOWN_INPUT,
        SHUTDOWN_OUTPUT,
        SHUTDOWN_INPUT_THEN_OUTPUT,
        SHUTDOWN_OUTPUT_THEN_INPUT,
    }

    public static final ShutdownScheme[] ALL_SHUTDOWN_SCHEMES = {
            ShutdownScheme.NO_SHUTDOWN,
            ShutdownScheme.SHUTDOWN_INPUT,
            ShutdownScheme.SHUTDOWN_OUTPUT,
            ShutdownScheme.SHUTDOWN_INPUT_THEN_OUTPUT,
            ShutdownScheme.SHUTDOWN_OUTPUT_THEN_INPUT,
    };

    public static final ShutdownScheme[] GOOD_SHUTDOWN_SCHEMES = {
            ShutdownScheme.SHUTDOWN_INPUT_THEN_OUTPUT,
            ShutdownScheme.SHUTDOWN_OUTPUT_THEN_INPUT,
    };

    public enum CloseScheme {
        NO_CLOSE,
        CLOSE,
    }

    public static final CloseScheme[] ALL_CLOSE_SCHEMES = {
            CloseScheme.NO_CLOSE,
            CloseScheme.CLOSE,
    };

    public static final CloseScheme[] GOOD_CLOSE_SCHEMES = {
            CloseScheme.CLOSE,
    };

    public abstract static class SSLEntityBuilder<E extends SSLEntity, B extends SSLEntityBuilder<E, B>> {
        E sslEntity;
        B builder;

        protected SSLEntityBuilder(E sslEntity) {
            this.sslEntity = sslEntity;
            builder = (B) this;
        }

        protected void checkCanConfigure() {
            if (sslEntity == null) {
                throw new IllegalStateException("SSLEntity is already built and cannot change anymore");
            }
        }

        protected void checkCanBuild() {
            if (sslEntity.clientMode == null) {
                throw new IllegalStateException(
                        "Please define the [clientMode] parameter in order to build an SSLEntity");
            }

            if (sslEntity.sharedClientGeneratesSessionId == null) {
                throw new IllegalStateException(
                        "Please define the [sharedClientGeneratesSessionId] parameter in order to build an SSLEntity");
            }

            if (sslEntity.componentUsage == null) {
                throw new IllegalStateException(
                        "Please define the [componentUsage] parameter in order to build an SSLEntity");
            }
        }

        public B withComponentUsage(ComponentUsage componentUsage) {
            checkCanConfigure();

            sslEntity.componentUsage = componentUsage;
            return builder;
        }

        public B withSharedConnectionScheme(SharedConnectionScheme sharedConnectionScheme) {
            checkCanConfigure();

            sslEntity.sharedConnectionScheme = sharedConnectionScheme;
            return builder;
        }

        public B withShutdownScheme(ShutdownScheme shutdownScheme) {
            checkCanConfigure();

            sslEntity.shutdownScheme = shutdownScheme;
            return builder;
        }

        public B withCloseScheme(CloseScheme closeScheme) {
            checkCanConfigure();

            sslEntity.closeScheme = closeScheme;
            return builder;
        }

        public B withLocalAddress(InetSocketAddress localAddress) {
            checkCanConfigure();

            sslEntity.localAddress = localAddress;
            return builder;
        }

        public B withRemoteAddress(InetSocketAddress remoteAddress) {
            checkCanConfigure();

            sslEntity.remoteAddress = remoteAddress;
            return builder;
        }

        public B withSharedSecure(boolean sharedSecure, SSLContext sslContext) throws Exception {
            checkCanConfigure();

            sslEntity.sslContext = sharedSecure ? sslContext != null ? sslContext :
                    sslEntity.clientMode ? buildRelaxedSSLContext() : SSLContext.getDefault() : null;

            return builder;
        }

        public B withSharedClientGeneratesSessionId(boolean sharedClientGeneratesSessionId) {
            checkCanConfigure();

            sslEntity.sharedClientGeneratesSessionId = sharedClientGeneratesSessionId;
            return builder;
        }

        public B withExtraSystemProperties(Properties systemProperties) {
            checkCanConfigure();

            for (Map.Entry<Object, Object> property : systemProperties.entrySet()) {
                System.setProperty((String) property.getKey(), (String) property.getValue());
            }

            return builder;
        }

        public B withRecordBytes(int maxRecordBytes) {
            checkCanConfigure();

            sslEntity.maxRecordBytes = maxRecordBytes;
            return builder;
        }

        public B withRecordLines(boolean recordLines) {
            checkCanConfigure();

            if (recordLines) {
                sslEntity.readLines = new StringBuilder();
                sslEntity.writtenLines = new StringBuilder();
            } else {
                sslEntity.readLines = sslEntity.writtenLines = null;
            }

            return builder;
        }

        public abstract E build(boolean start) throws Exception;
    }

    public static SSLContext buildRelaxedSSLContext() throws Exception {
        TrustManager tm = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{tm}, null);

        return sslContext;
    }

    static Selector newSelector(boolean secure) throws IOException {
        return secure ? SSLSelector.open() : Selector.open();
    }

    static SocketChannel newSocketChannel(SSLContext sslContext) throws IOException {
        return sslContext != null ? SSLSocketChannel.open(sslContext) : SocketChannel.open();
    }

    static SSLSocketChannel newSSLSocketChannel(SSLContext sslContext, boolean clientMode, SocketChannel innerChannel) throws IOException {
        return SSLSocketChannel.open(innerChannel.socket().getRemoteSocketAddress(), sslContext, clientMode, null, innerChannel);
    }

    static ServerSocketChannel newServerSocketChannel(SSLContext sslContext) throws IOException {
        return sslContext != null ? SSLServerSocketChannel.open(sslContext) : ServerSocketChannel.open();
    }

    static Socket newSocket(SSLContext sslContext) throws IOException {
        return (sslContext != null ? sslContext.getSocketFactory() : SocketFactory.getDefault()).createSocket();
    }

    static SSLSocket newSSLSocket(SSLContext sslContext, boolean clientMode, Socket socket) throws IOException {
        SSLSocket sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(socket,
                ((InetSocketAddress) socket.getRemoteSocketAddress()).getHostName(), socket.getPort(), true);
        sslSocket.setUseClientMode(clientMode);
        return sslSocket;
    }

    static ServerSocket newServerSocket(SSLContext sslContext) throws IOException {
        return (sslContext != null ? sslContext.getServerSocketFactory() : ServerSocketFactory.getDefault()).createServerSocket();
    }

    protected final Logger logger = Logger.getLogger(getClass().getSimpleName());

    protected ComponentUsage componentUsage;
    protected SharedConnectionScheme sharedConnectionScheme;
    protected ShutdownScheme shutdownScheme;
    protected CloseScheme closeScheme;
    protected InetSocketAddress localAddress;
    protected InetSocketAddress remoteAddress;
    protected SSLContext sslContext;

    protected Boolean sharedClientGeneratesSessionId;
    protected int maxRecordBytes;
    protected StringBuilder readLines; // access is always from same thread, so ok not to use StringBuffer
    protected StringBuilder writtenLines; // access is always from same thread, so ok not to use StringBuffer

    protected Boolean clientMode;
    protected String entityId;
    protected String entityReadableId;
    protected Exception exception;

    public String getEntityId() {
        return entityId;
    }

    public void setEntityId(String entityId) {
        this.entityId = entityId;
        entityReadableId = (clientMode ? "Client-" : "Session-") + entityId;
    }

    public Exception getException() {
        return exception;
    }

    static void transfer(ByteBuffer source, ByteBuffer destination) {
        int remaining = destination.remaining();

        if (source.remaining() > remaining) {
            int limit = source.limit();
            source.limit(source.position() + remaining);
            destination.put(source);
            source.limit(limit);
        } else {
            destination.put(source);
        }
    }
}
