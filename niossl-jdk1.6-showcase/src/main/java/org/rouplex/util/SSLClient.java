package org.rouplex.util;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.Closeable;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.UUID;

/**
 * @author Andi Mullaraj (andimullaraj at gmail.com)
 */
public class SSLClient extends SSLEntity implements Closeable {
    protected Socket socket;
    protected Socket plainSocket;
    public SocketChannel socketChannel;

    protected ByteBuffer readBuffer;
    protected ByteBuffer writtenBuffer;

    protected ByteBuffer lineBuffer = ByteBuffer.allocate(1000000);
    protected SelectionKey selectionKey;

    protected SSLServer remoteSslServer;
    public SSLServer.ServerSession remoteSslServerSession;

    public static class SSLClientBuilder<E extends SSLClient, B extends SSLClientBuilder<E, B>> extends SSLEntityBuilder<E, B> {

        SSLClientBuilder(E sslEntity) {
            super(sslEntity);
        }

        public SSLClientBuilder<E, B> forRemoteSSLServer(SSLServer sslServer) throws Exception {
            checkCanConfigure();

            sslEntity.remoteSslServer = sslServer;

            return builder
                .withRemoteAddress(sslServer.localAddress)
                .withSharedConnectionScheme(sslServer.sharedConnectionScheme)
                .withSharedClientGeneratesSessionId(sslServer.sharedClientGeneratesSessionId)
                .withSharedSecure(sslServer.sslContext != null, null);
        }

        // for server side use
        public SSLClientBuilder<E, B> withExistingSocket(Socket socket) {
            checkCanConfigure();

            sslEntity.socket = socket;
            return builder;
        }

        // for server side use
        public SSLClientBuilder<E, B> withExistingSocketChannel(SocketChannel socketChannel) {
            checkCanConfigure();

            sslEntity.socketChannel = socketChannel;
            return builder;
        }

        @Override
        public E build(boolean connect) throws Exception {
            checkCanBuild();

            sslEntity.build();

            if (connect) {
                sslEntity.connect();
            }

            E sslClient = sslEntity;
            sslEntity = null;
            return sslClient;
        }
    }

    public static SSLClientBuilder<SSLClient, ?> newSSLClientBuilder() {
        return new SSLClientBuilder(new SSLClient(true));
    }

    protected SSLClient(boolean clientMode) {
        this.clientMode = clientMode;
    }

    protected void build() throws Exception {
        if (maxRecordBytes > 0) {
            readBuffer = ByteBuffer.allocate(maxRecordBytes);
            writtenBuffer = ByteBuffer.allocate(maxRecordBytes);
        }

        if (componentUsage == ComponentUsage.IO_CLASSIC) {
            if (socket == null) { // null if on client side, non null if on server
                socket = newSocket(sslContext);
            }

            return;
        }

        if (socketChannel == null) { // null if on client side, non null if on server
            socketChannel = newSocketChannel(sslContext);
        }

        if (componentUsage == ComponentUsage.NIO_BLOCKING) {
            socketChannel.configureBlocking(true);
            return;
        }

        socketChannel.configureBlocking(false);
        if (componentUsage == ComponentUsage.NIO_NON_BLOCKING_REUSE_SELECTORS) {
            selectionKey = socketChannel.register(newSelector(sslContext != null), 0);
        }
    }

    // ThreadSafe
    public void connect() throws IOException {
        logger.info(String.format("Connecting [%s] to [%s] at port [%d]",
                entityReadableId, remoteAddress.getHostName(), remoteAddress.getPort()));

        Selector selector = null;

        try {
            switch (componentUsage) {
                case IO_CLASSIC:
                    socket.connect(remoteAddress);
                    break;
                case NIO_BLOCKING:
                    assert socketChannel.connect(remoteAddress);
                    break;
                default:
                    socketChannel.connect(remoteAddress);
                    break;
            }

            switch (componentUsage) {
                case NIO_NON_BLOCKING_NO_SELECTORS:
                    while (!socketChannel.finishConnect()) {
                        sleepSome();
                    }
                    break;
                case NIO_NON_BLOCKING_CREATE_SELECTORS:
                    selectionKey = socketChannel.register(newSelector(sslContext != null), SelectionKey.OP_CONNECT);
                    break;
                case NIO_NON_BLOCKING_REUSE_SELECTORS:
                    selectionKey.interestOps(SelectionKey.OP_CONNECT);
                    break;
            }

            if (selectionKey != null) {
                selector = selectionKey.selector();

                while (true) {
                    selector.selectedKeys().clear();
                    int selectResult = selector.select();
                    /// System.out.println("Selector hinted connect");

                    if (selectResult == 0) {
                        /// System.out.println("Empty connect select");
                        continue;
                    }

                    if (!selector.selectedKeys().contains(selectionKey)) {
                        logger.warning("Select result does not contain OP_CONNECT");
                    }

                    if (!selectionKey.isConnectable()) {
                        logger.warning("Selected key is not connectable");
                    }

                    if (socketChannel.finishConnect()) {
                        logger.warning("FinishConnect SUCCESS");
                        /// System.out.println("FinishConnect SUCCESS");
                        break;
                    }
                }
            }

            logger.info(String.format("Connected [%s] to server [%s] at port [%d]",
                    entityReadableId, remoteAddress.getHostName(), remoteAddress.getPort()));
        } finally {
            switch (componentUsage) {
                case NIO_NON_BLOCKING_CREATE_SELECTORS:
                    if (selector != null) {
                        selector.close();
                    }
                    break;
                case NIO_NON_BLOCKING_REUSE_SELECTORS:
                    selectionKey.interestOps(selectionKey.interestOps() & ~SelectionKey.OP_CONNECT);
            }
        }
    }

    public void upgradeToSsl() throws IOException {
        upgradeToSsl("api request");
    }

    protected void upgradeToSsl(String requestParty) throws IOException {
        logger.info(String.format("Securing [%s] (%s)", entityReadableId, requestParty));

        if (sslContext != null) {
            throw new IOException(String.format("[%s] is already secure", entityReadableId));
        }

        try {
            sslContext = clientMode ? buildRelaxedSSLContext() : SSLContext.getDefault();
        } catch (Exception e) {
            throw new IOException("Could not build SSLContext", e);
        }

        if (componentUsage == ComponentUsage.IO_CLASSIC) {
            plainSocket = socket;
            socket = newSSLSocket(sslContext, clientMode, socket);
        }
        else {
            socketChannel = newSSLSocketChannel(sslContext, clientMode, socketChannel);

            if (componentUsage == ComponentUsage.NIO_BLOCKING) {
                socketChannel.configureBlocking(true);
            }

            else {
                socketChannel.configureBlocking(false);
                if (componentUsage == ComponentUsage.NIO_NON_BLOCKING_REUSE_SELECTORS) {
                    selectionKey.selector().close();
                    selectionKey = socketChannel.register(newSelector(sslContext != null), 0);
                }
            }
        }

        logger.info(String.format("Secured [%s] (%s)", entityReadableId, requestParty));
    }

    void sleepSome() throws IOException {
        try {
            Thread.sleep(1);
        } catch (InterruptedException e) {
            throw new IOException("Interrupted");
        }
    }

    // NotThreadSafe
    public void connectAndExchangeSessionId() throws IOException {
        connect();
        exchangeSessionId();

        if (remoteSslServer != null) {
            remoteSslServerSession = remoteSslServer.getServerSession(entityId);
        }

        if (sharedConnectionScheme == SharedConnectionScheme.CONNECT_PLAIN_AND_SWITCH_TO_SSL_AFTER_EXCHANGING_SESSIONID) {
            protocolAskRemoteToUpgradeToSsl();
            upgradeToSsl();
        }
    }

    // NotThreadSafe
    public void exchangeSessionId() throws IOException {
        if (sharedClientGeneratesSessionId) {
            setEntityId(UUID.randomUUID().toString());
            protocolExchangeSessionId();
        } else {
            setEntityId(readExpectedLine());
            writeLine(entityId);
        }
    }

    /**
     * Read the expected line. Lines are broken with LF and the last line does not need to have one.
     *
     * @return the line or null if EOS was reached
     * @throws IOException
     */
    // NotThreadSafe
    public String readExpectedLine() throws IOException {
        logger.info(String.format("[%s] reading expected line", entityReadableId));

        int position = 0;
        String line;

        loop:
        while (true) {
            for (; position < lineBuffer.position(); position++) {
                if (lineBuffer.array()[position] == LF) {
                    line = new String(lineBuffer.array(), 0, position);
                    lineBuffer.flip();
                    lineBuffer.position(position + 1);
                    lineBuffer.compact();
                    logger.info(String.format("[%s] received a line of %d bytes long", entityReadableId, line.length()));
                    logger.fine(String.format("[%s] received %s LF", entityReadableId, line));
                    if (readLines != null) {
                        readLines.append(line).append(LF);
                    }
                    break loop;
                }
            }

            if (read(lineBuffer, -1) == -1) {
                line = lineBuffer.position() != 0 ? new String(lineBuffer.array(), 0, lineBuffer.position()) : null;
                int lineLength = line != null ? line.length() : 0;

                logger.info(String.format("[%s] received a line of %d bytes long", entityReadableId, lineLength));
                logger.fine(String.format("[%s] received %s", entityReadableId, line));
                if (readLines != null && line != null) {
                    readLines.append(line);
                }
                break;
            }
        }

        return line;
    }

    /**
     * Read from the underlying channel into the provided buffer. Return as soon as there are some bytes read, or
     * the timeout has expired.
     *
     * Record the read content if the client has been configured to record. There is no guarantee that another thread is
     * not simultaneously calling this same method, producing incoherent reads.
     *
     * @param bb the buffer to read the data into
     * @param timeoutMillis
     *          The time beyond which the call should return; it may not be honored if the underlying channel is set in
     *          blocking mode.
     *          -1: infinite wait, 0: no wait, > 0 wait millis
     * @return the number of bytes read, possibly 0, or even -1 if the EOS is reached
     * @throws IOException in case of an exception (such as a closed exception)
     */
    //ThreadSafe
    public int read(ByteBuffer bb, int timeoutMillis) throws IOException {
        long expirationTimestamp = 0;

        if (timeoutMillis != 0) {
            expirationTimestamp = System.currentTimeMillis() + timeoutMillis;

            switch (componentUsage) {
                case IO_CLASSIC:
                    socket.setSoTimeout(timeoutMillis < 0 ? 0 : timeoutMillis + 1);
                    break;
                case NIO_NON_BLOCKING_CREATE_SELECTORS:
                    selectionKey = socketChannel.register(newSelector(sslContext != null), SelectionKey.OP_READ);
                    break;
                case NIO_NON_BLOCKING_REUSE_SELECTORS:
                    selectionKey.interestOps(SelectionKey.OP_READ);
            }
        }

        Selector selector = selectionKey == null ? null : selectionKey.selector();
        int initialPosition = bb.position();
        int read = 0;

        try {
            while (bb.hasRemaining()) {
                if (selector != null) {
                    long selectTimeout = 0;

                    if (timeoutMillis != -1) {
                        selectTimeout = expirationTimestamp - System.currentTimeMillis();
                        if (selectTimeout <= 0) { // important to discard 0 as wait time
                            break;
                        }
                    }

                    selector.selectedKeys().clear();
                    int selectResult = selector.select(selectTimeout);
                    if (selectResult == 0) {
                        //aaa /// System.out.println("Empty read select");
                        continue;
                    }

                    if (!selector.selectedKeys().contains(selectionKey)) {
                        logger.warning("Select result does not contain OP_READ");
                    }

                    if (!selectionKey.isReadable()) {
                        logger.warning("Selected key is not readable even though it is in selection set");
                    }
                }

                if (socketChannel != null) {
                    read = socketChannel.read(bb);
                } else {
                    read = socket.getInputStream().read(bb.array(), bb.position(), bb.remaining());

                    if (read != -1) {
                        bb.position(bb.position() + read);
                    }
                }

                logger.info(String.format("Read %s bytes", read));
                if (read == -1) {
                    break;
                }

                if (read > 0) {
                    if (readBuffer != null) {
                        synchronized (readBuffer) { // warning is no issue
                            transfer(ByteBuffer.wrap(bb.array(), bb.position() - read, read), readBuffer);
                        }
                    }

                    break;
                }

                if (selector != null) {
                    logger.warning("Nothing was read even though selector hinted so");
                } else {
                    sleepSome();
                }
            }
        } catch (IOException e) {
            throw e;
        } finally {
            if (selectionKey != null) {
                switch (componentUsage) {
                    case NIO_NON_BLOCKING_CREATE_SELECTORS:
                        selector.close(); // warning is no issue
                        break;
                    case NIO_NON_BLOCKING_REUSE_SELECTORS:
                        selectionKey.interestOps(selectionKey.interestOps() & ~SelectionKey.OP_READ);
                }
            }
        }

        return read == -1 ? -1 : bb.position() - initialPosition;
    }

    /**
     * Write the buffer content into the underlying channel. Record the partial writes (if recording is requested).
     * There is no guarantee that another thread is not simultaneously calling this same method, producing incoherent
     * output (but the sum of all bytes sent will have to add up with what has been requested)
     *
     * @param bb the content to be sent
     * @param timeoutMillis
     *          The time beyond which the call should return no matter how many bytes has been able to write.
     *          This parameter may not be honored if the underlying channel is set in blocking mode.
     *           -1: infinite wait, 0: no wait, > 0 wait millis
     * @return the number of bytes written, possibly 0
     * @throws IOException in case of an exception (such as a closed exception)
     */
    //ThreadSafe
    public int write(ByteBuffer bb, int timeoutMillis) throws IOException {
        long expirationTimestamp = 0;

        if (timeoutMillis != 0) {
            expirationTimestamp = System.currentTimeMillis() + timeoutMillis;

            switch (componentUsage) {
                case NIO_NON_BLOCKING_CREATE_SELECTORS:
                    selectionKey = socketChannel.register(newSelector(sslContext != null), SelectionKey.OP_WRITE);
                    break;
                case NIO_NON_BLOCKING_REUSE_SELECTORS:
                    selectionKey.interestOps(SelectionKey.OP_WRITE);
            }
        }

        Selector selector = selectionKey == null ? null : selectionKey.selector();
        int initialPosition = bb.position();

        try {
            while (bb.hasRemaining()) {
                if (selector != null) {
                    long selectTimeout = 0;

                    if (timeoutMillis != -1) {
                        selectTimeout = expirationTimestamp - System.currentTimeMillis();
                        if (selectTimeout <= 0) { // important to discard 0 as wait time
                            break;
                        }
                    }

                    selector.selectedKeys().clear();
                    int selectResult = selector.select(selectTimeout);
                    if (selectResult == 0) {
                        logger.warning("Select result == 0");
                        continue;
                    }

                    if (!selector.selectedKeys().contains(selectionKey)) {
                        logger.warning("Select result does not contain OP_WRITE");
                    }

                    if (!selectionKey.isWritable()) {
                        logger.warning("Selected key is not writable even though it is in selection set");
                    }
                }

                if (socket != null) {
                    socket.getOutputStream().write(bb.array(), bb.position(), bb.remaining());
                    socket.getOutputStream().flush();
                    bb.position(bb.limit());
                    continue;
                }

                int written = socketChannel.write(bb);
                if (written == 0) {
                    if (selector != null) {
                        logger.warning("Nothing was read even though selector hinted so");
                    } else {
                        sleepSome();
                    }
                    continue;
                }

                if (writtenBuffer != null) {
                    synchronized (writtenBuffer) { // warning is no issue
                        transfer(ByteBuffer.wrap(bb.array(), bb.position() - written, written), writtenBuffer);
                    }
                }
            }
        } finally {
            if (selectionKey != null) {
                switch (componentUsage) {
                    case NIO_NON_BLOCKING_CREATE_SELECTORS:
                        selector.close(); // warning is no issue
                        break;
                    case NIO_NON_BLOCKING_REUSE_SELECTORS:
                        selectionKey.interestOps(selectionKey.interestOps() & ~SelectionKey.OP_WRITE);
                }
            }
        }

        return bb.position() - initialPosition;
    }

    public void writeLine(String line) throws IOException {
        logger.info(String.format("[%s] sending line of %d bytes", entityReadableId, line.length()));
        logger.fine(String.format("[%s] sending line: %s", entityReadableId, line));
        int written = write(ByteBuffer.wrap(line.getBytes()), -1);
        if (writtenLines != null) {
            writtenLines.append(line);
        }
        logger.info(String.format("[%s] sent line of %d bytes", entityReadableId, written));
        logger.fine(String.format("[%s] sent line: %s", entityReadableId, line));

        write(ByteBuffer.wrap(newLine), -1);
        if (writtenLines != null) {
            writtenLines.append(LF);
        }
    }

    /**
     * Used for testing scenarios where the communication must fail.
     *
     * @param bytes
     * @throws IOException
     */
    public void writePlain(byte[] bytes)  throws IOException {
        switch (componentUsage) {
            case IO_CLASSIC:
                if (plainSocket == null) {
                    throw new IOException(String.format(
                            "[%s] cannot write in plain (since it was not stared in plain mode)", entityReadableId));
                }

                plainSocket.getOutputStream().write(bytes);
                break;
            default:
                throw new Error("writePlain not implemented for niossl-nossl");
//                if (socketChannel instanceof SSLSocketChannelBaseImpl) {
//                    ((SocketChannel) ((SSLSocketChannelBaseImpl) socketChannel)
//                            .getInnerChannel()).write(ByteBuffer.wrap(bytes));
//                }
        }
    }

    public String readThenWriteLine() throws IOException {
        String line = readExpectedLine();

        if (line != null) {
            writeLine(line);
        }

        return line;
    }

    public String writeThenReadLine(String line) throws IOException {
        writeLine(line);
        return readExpectedLine();
    }

    public void protocolExchangeSessionId() throws IOException {
        writeLine(entityId);
        readExpectedLine();
    }

    public void protocolAskRemoteShutdownInput() throws IOException {
        writeLine(SHUTDOWN_INPUT_MAGIC_WORD);
        readExpectedLine();
    }

    public void protocolAskRemoteShutdownOutput() throws IOException {
        writeLine(SHUTDOWN_OUTPUT_MAGIC_WORD);
        readExpectedLine();
    }

    public void protocolAskRemoteClose() throws IOException {
        writeLine(CLOSE_SESSION_MAGIC_WORD);
        readExpectedLine();
    }

    public void protocolAskRemoteToUpgradeToSsl() throws IOException {
        writeLine(UPGRADE_TO_SSL_MAGIC_WORD);
        readExpectedLine();
    }

    public String getReadLines() {
        return readLines.toString();
    }

    public String getWrittenLines() {
        return writtenLines.toString();
    }

    public ByteBuffer getReadBytes() {
        return readBuffer;
    }

    public ByteBuffer getWrittenBytes() {
        return writtenBuffer;
    }

    public boolean isConnecting() {
        if (componentUsage == ComponentUsage.IO_CLASSIC) {
            throw new Error("isConnecting is not available when the SSLEntity is using an SSLSocket");
        }

        return socketChannel.isConnectionPending();
    }

    public boolean isClosed() {
        switch (componentUsage) {
            case IO_CLASSIC:
                return socket.isClosed();
            default:
                return !socketChannel.isOpen();
        }
    }

    public boolean shutdownInput(boolean tolerateClosed) throws IOException {
        try {
            shutdownInput();
            return true;
        } catch (IOException ioe) {
            if (!tolerateClosed) {
                throw ioe;
            }
            return false;
        }
    }

    public void shutdownInput() throws IOException {
        logger.info(String.format("Shutting down input of [%s]", entityReadableId));
        switch (componentUsage) {
            case IO_CLASSIC:
                if (!(socket instanceof SSLSocket)) { // classic SSLSockets dont have this implemented
                    socket.shutdownInput();
                    logger.info(String.format("Shut down input of [%s]", entityReadableId));
                }
                else {
                    logger.info(String.format("Shut down input of [%s] not available for [%s]", entityReadableId, componentUsage));
                }
                break;
            default:
//                if (socketChannel instanceof SSLSocketChannelBaseImpl) {
//                    ((SSLSocketChannelBaseImpl) socketChannel).shutdownInput();
//                    logger.info(String.format("Shut down input of [%s]", entityReadableId));
//                }
//                else {
                    logger.info(String.format("Shut down input of [%s] not available for [%s]", entityReadableId, componentUsage));
//                }
        }
    }

    public boolean shutdownOutput(boolean tolerateClosed) throws IOException {
        try {
            shutdownOutput();
            return true;
        } catch (IOException ioe) {
            if (!tolerateClosed) {
                throw ioe;
            }
            return false;
        }
    }

    public void shutdownOutput() throws IOException {
        logger.info(String.format("Shutting down output of [%s]", entityReadableId));
        switch (componentUsage) {
            case IO_CLASSIC:
                if (!(socket instanceof SSLSocket)) { // classic SSLSockets dont have this implemented
                    socket.shutdownOutput();
                    logger.info(String.format("Shut down output of [%s]", entityReadableId));
                }
                else {
                    logger.info(String.format("Shut down output of [%s] not available for [%s]", entityReadableId, componentUsage));
                }
                break;
            default:
//                if (socketChannel instanceof SSLSocketChannelBaseImpl) {
//                    ((SSLSocketChannelBaseImpl) socketChannel).shutdownOutput();
//                    logger.info(String.format("Shut down output of [%s]", entityReadableId));
//                }
//                else {
                    logger.info(String.format("Shut down output of [%s] not available for [%s]", entityReadableId, componentUsage));
//                }
        }
    }

    @Override
    public void close() throws IOException {
        close(true, false);
    }

    public boolean close(boolean blocking, boolean tolerateClosed) throws IOException {
        logger.info(String.format("Closing [%s]. File Handles [%d]", entityReadableId, unixMXBean.getOpenFileDescriptorCount()));
        boolean success = true;

        switch (shutdownScheme) {
            case NO_SHUTDOWN:
                break;
            case SHUTDOWN_INPUT:
                success &= shutdownInput(tolerateClosed);
                break;
            case SHUTDOWN_OUTPUT:
                success &= shutdownOutput(tolerateClosed);
                break;
            case SHUTDOWN_INPUT_THEN_OUTPUT:
                success &= shutdownInput(tolerateClosed);
                success &= shutdownOutput(tolerateClosed);
                break;
            case SHUTDOWN_OUTPUT_THEN_INPUT:
                success &= shutdownOutput(tolerateClosed);
                success &= shutdownInput(tolerateClosed);
                break;
        }

        switch (closeScheme) {
            case NO_CLOSE:
                break;
            case CLOSE:
                if (blocking) {
                    success &= closeComponents(tolerateClosed);
                    logger.info(String.format("Closed [%s]. File Handles [%d]", entityReadableId, unixMXBean.getOpenFileDescriptorCount()));
                } else {
                    (new Thread() {
                        public void run() {
                            try {
                                closeComponents(true);
                                logger.info(String.format("Closed [%s]", entityReadableId));
                            } catch (IOException ioe) {
                                // can't happen but no big deal either
                            }
                        }
                    }).start();
                    logger.info(String.format("Scheduled close [%s]", entityReadableId));
                }
        }

        return success;
    }

    private boolean closeComponents(boolean tolerateClosed) throws IOException {
        boolean success = true;

        switch (componentUsage) {
            case IO_CLASSIC:
                try {
                    socket.close();
                } catch (IOException ioe) {
                    if (!tolerateClosed) {
                        throw ioe;
                    }

                    success = false;
                }
                break;

            case NIO_NON_BLOCKING_CREATE_SELECTORS:
            case NIO_NON_BLOCKING_REUSE_SELECTORS:
                try {
                    selectionKey.selector().close();
                } catch (IOException ioe) {
                    if (!tolerateClosed) {
                        throw ioe;
                    }

                    success = false;
                }
                // fall through
            default:
                try {
                    socketChannel.close();
                } catch (IOException ioe) {
                    if (!tolerateClosed) {
                        throw ioe;
                    }

                    success = false;
                }
        }

        return success;
    }

    public void tryClose() {
        try {
            close(true, true);
        } catch (Exception ioe) {
            logger.warning(String.format("Exception during [%s] close. Cause: %s", entityReadableId, ioe.getMessage()));
        }
    }
}
