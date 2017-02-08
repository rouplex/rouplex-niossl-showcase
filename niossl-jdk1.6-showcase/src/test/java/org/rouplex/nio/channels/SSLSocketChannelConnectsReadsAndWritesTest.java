package org.rouplex.nio.channels;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.rouplex.util.*;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import static org.rouplex.util.SSLEntity.*;

/**
 * @author Andi Mullaraj (andimullaraj at gmail.com)
 */
@RunWith(Parameterized.class)
public class SSLSocketChannelConnectsReadsAndWritesTest {
    private static final Logger logger = Logger.getLogger("SSLSocketChannelConnectsReadsAndWritesTest");

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        List<Object[]> data = new ArrayList<Object[]>();
        boolean[] t = {true};
        boolean[] f = {false};
        boolean[] tf = {true, false};
        int[] messageSizes = {1};
        int[] iterationCounts = {1};
        int[] clientCounts = {1};

        SharedConnectionScheme[] sharedConnectionSchemes = ALL_SHARED_CONNECTION_SCHEMES;
        ComponentUsage[] serverComponentUsages = ALL_COMPONENT_USAGES;
        ComponentUsage[] clientComponentUsages = ALL_COMPONENT_USAGES;
        ShutdownScheme[] serverShutdownSchemes = GOOD_SHUTDOWN_SCHEMES;
        ShutdownScheme[] clientShutdownSchemes = GOOD_SHUTDOWN_SCHEMES;
        CloseScheme[] serverCloseSchemes = GOOD_CLOSE_SCHEMES;
        CloseScheme[] clientCloseSchemes = GOOD_CLOSE_SCHEMES;

        // todo remove this line once all is passing
        //sharedConnectionSchemes = new SharedConnectionScheme[]{SharedConnectionScheme.CONNECT_SSL_AND_STAY_SSL, SharedConnectionScheme.CONNECT_PLAIN_AND_SWITCH_TO_SSL_AFTER_EXCHANGING_SESSIONID};
        // todo remove this line once all is passing
        //serverComponentUsages = new ComponentUsage[]{ComponentUsage.NIO_NON_BLOCKING_REUSE_SELECTORS};//, ComponentUsage.NIO_NON_BLOCKING_NO_SELECTORS, ComponentUsage.NIO_NON_BLOCKING_REUSE_SELECTORS, ComponentUsage.NIO_BLOCKING};//, ComponentUsage.NIO_NON_BLOCKING_CREATE_SELECTORS};
        // todo remove this line once all is passing
        //clientComponentUsages = new ComponentUsage[]{ComponentUsage.IO_CLASSIC};//, ComponentUsage.NIO_NON_BLOCKING_NO_SELECTORS, ComponentUsage.NIO_NON_BLOCKING_REUSE_SELECTORS, ComponentUsage.NIO_BLOCKING};//, ComponentUsage.NIO_NON_BLOCKING_CREATE_SELECTORS};
        // todo remove this line once all is passing
        //serverShutdownSchemes = new ShutdownScheme[]{ShutdownScheme.SHUTDOWN_OUTPUT_THEN_INPUT};
        // todo remove this line once all is passing
        //clientShutdownSchemes = new ShutdownScheme[]{ShutdownScheme.SHUTDOWN_OUTPUT_THEN_INPUT};

        for (SharedConnectionScheme sharedConnectionScheme : sharedConnectionSchemes) {
            for (ComponentUsage serverComponentUsage : serverComponentUsages) {
                if (serverComponentUsage == ComponentUsage.IO_CLASSIC) {
                    continue;
                }
                for (ComponentUsage clientComponentUsage : clientComponentUsages) {
                    if (clientComponentUsage == ComponentUsage.IO_CLASSIC) {
                        continue;
                    }
                    for (ShutdownScheme serverShutdownScheme : serverShutdownSchemes) {
                        for (ShutdownScheme clientShutdownScheme : clientShutdownSchemes) {
                            for (CloseScheme serverCloseScheme : serverCloseSchemes) {
                                for (CloseScheme clientCloseScheme : clientCloseSchemes) {
                                    for (boolean sharedClientGeneratesSessionId : tf) {
                                        for (boolean clientGeneratesMessages : t) {
                                            for (boolean clientInitiatesClose : tf) {
                                                for (int messageSize : messageSizes) {
                                                    for (int iterationCount : iterationCounts) {
                                                        for (boolean checkIntegrity : f) {
                                                            for (int clientCount : clientCounts) {
                                                                data.add(new Object[]{
                                                                        sharedConnectionScheme,
                                                                        serverComponentUsage,
                                                                        clientComponentUsage,
                                                                        serverShutdownScheme,
                                                                        clientShutdownScheme,
                                                                        serverCloseScheme,
                                                                        clientCloseScheme,
                                                                        sharedClientGeneratesSessionId,
                                                                        clientGeneratesMessages,
                                                                        clientInitiatesClose,
                                                                        messageSize,
                                                                        iterationCount,
                                                                        checkIntegrity,
                                                                        clientCount
                                                                });
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return data;
    }

    SharedConnectionScheme sharedConnectionScheme;
    ComponentUsage serverComponentUsage;
    ComponentUsage clientComponentUsage;
    ShutdownScheme serverShutdownScheme;
    ShutdownScheme clientShutdownScheme;
    CloseScheme serverCloseScheme;
    CloseScheme clientCloseScheme;
    boolean sharedClientGeneratesSessionId;
    boolean clientGeneratesMessagesFalseIsNotImplemented;
    boolean clientInitiatesClose;
    int messageSize;
    int iterationCount;
    boolean checkIntegrity;
    int clientCount;

    long startTime;
    long initialOpenHandles;
    ExecutorService clientsRunner;

    SSLServer sslServer;
    List<SSLClient> sslClients = new ArrayList<SSLClient>();

    public SSLSocketChannelConnectsReadsAndWritesTest(
            SharedConnectionScheme sharedConnectionScheme, ComponentUsage serverComponentUsage,
            ComponentUsage clientComponentUsage, ShutdownScheme serverShutdownScheme,
            ShutdownScheme clientShutdownScheme, CloseScheme serverCloseScheme, CloseScheme clientCloseScheme,
            boolean sharedClientGeneratesSessionId, boolean clientGeneratesMessagesFalseIsNotImplemented,
            boolean clientInitiatesClose, int messageSize, int iterationCount, boolean checkIntegrity, int clientCount) {

        this.sharedConnectionScheme = sharedConnectionScheme;
        this.serverComponentUsage = serverComponentUsage;
        this.clientComponentUsage = clientComponentUsage;
        this.serverShutdownScheme = serverShutdownScheme;
        this.clientShutdownScheme = clientShutdownScheme;
        this.serverCloseScheme = serverCloseScheme;
        this.clientCloseScheme = clientCloseScheme;
        this.sharedClientGeneratesSessionId = sharedClientGeneratesSessionId;
        this.clientGeneratesMessagesFalseIsNotImplemented = clientGeneratesMessagesFalseIsNotImplemented;
        this.clientInitiatesClose = clientInitiatesClose;
        this.messageSize = messageSize;
        this.iterationCount = iterationCount;
        this.checkIntegrity = checkIntegrity;
        this.clientCount = clientCount;
    }

    @Before
    public void before() throws Exception {
        initialOpenHandles = unixMXBean.getOpenFileDescriptorCount();
        System.out.println("initialOpenHandles: " + initialOpenHandles);
        if (initialOpenHandles > 10000) {
            System.exit(1);
        }

        // logger.warning("Starting testServerReceivedWhatSocketSent permutation: \n\n" + toString());
        System.out.println("Starting testServerReceivedWhatSocketSent permutation: \n\n" + toString());

        sslServer = SSLServer.newSSLServerBuilder()
                .withSharedConnectionScheme(sharedConnectionScheme)
                .withComponentUsage(serverComponentUsage)
                .withShutdownScheme(serverShutdownScheme)
                .withCloseScheme(serverCloseScheme)
                .withSharedSecure(sharedConnectionScheme == SharedConnectionScheme.CONNECT_SSL_AND_STAY_SSL, null)
                .withSharedClientGeneratesSessionId(sharedClientGeneratesSessionId)
                .withRecordLines(checkIntegrity)
                .withMaxParallelServerConnections(clientCount)
                .withServerBackLog(clientCount)
                .build(true);

        for (int c = 0; c < clientCount; c++) {
            sslClients.add(SSLClient.newSSLClientBuilder()
                    .forRemoteSSLServer(sslServer)
                    .withComponentUsage(clientComponentUsage)
                    .withShutdownScheme(clientShutdownScheme)
                    .withCloseScheme(clientCloseScheme)
                    .withRecordLines(checkIntegrity)
                    .build(false));
        }

        clientsRunner = Executors.newFixedThreadPool(clientCount);
        startTime = System.currentTimeMillis();
    }

    @Test(timeout = 1000000)
    public void testConnectSendAndReceive() throws Exception {
        final Set<Exception> thrownExceptions = new HashSet<Exception>();

        for (SSLClient sslClientTmp : sslClients) {
            final SSLClient sslClient = sslClientTmp;

            clientsRunner.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        Thread.currentThread().setName("Client-runner_");
                        sslClient.connectAndExchangeSessionId();
                        Thread.currentThread().setName("Client-runner-" + sslClient.getEntityId());

                        String line = messageSize == 0 ? "" : String.format("%1$" + messageSize + "s", "a");

                        if (clientGeneratesMessagesFalseIsNotImplemented) {
                            for (int i = 0; i < iterationCount; i++) {
                                String echoedLine = sslClient.writeThenReadLine(line);
                                Assert.assertEquals(line, echoedLine);
                            }
                        } else {
                            // not implemented yet -- as of now, the server echoes what comes its way
                            for (int i = 0; i < iterationCount; i++) {
                                String echoedLine = sslClient.remoteSslServerSession.writeThenReadLine(line);
                                Assert.assertEquals(line, echoedLine);
                            }
                        }

                        /**
                         * In all these try/catch blocks, an exception can be thrown when shutting down or closing on a channel with
                         * pending read (or write, but that is hard to catch, since it will happen fast), so we intruct the component
                         * to tolerate that when expected.
                         */
                        if (clientInitiatesClose) {
                            boolean success = sslClient.close(true, !clientGeneratesMessagesFalseIsNotImplemented);
                            sslClient.remoteSslServerSession.close(true, !success || clientGeneratesMessagesFalseIsNotImplemented);
                        } else {
                            boolean success = sslClient.remoteSslServerSession.close(true, clientGeneratesMessagesFalseIsNotImplemented);
                            try {
                                sslClient.close(true, !success || !clientGeneratesMessagesFalseIsNotImplemented);
                            } catch (IOException e) {
                                //   throw e;
                            }
                        }

                        if (checkIntegrity) {
                            Assert.assertEquals(sslClient.getWrittenLines(), sslClient.remoteSslServerSession.getReadLines());
                            Assert.assertEquals(sslClient.remoteSslServerSession.getReadLines(), sslClient.remoteSslServerSession.getWrittenLines());
                            Assert.assertEquals(sslClient.remoteSslServerSession.getWrittenLines(), sslClient.getReadLines());
                        }
                    } catch (Exception e) {
                        synchronized (thrownExceptions) {
                            long openFiles = unixMXBean.getOpenFileDescriptorCount();
                            long maxOpenFiles = unixMXBean.getMaxFileDescriptorCount();
                            thrownExceptions.add(e);
                        }
                    }
                }
            });
        }

        clientsRunner.shutdown();

        if (!clientsRunner.awaitTermination(100, TimeUnit.MINUTES)) {
            Assert.fail("Clients did not finish communicating with server in a timely manner (1 min)");
        }

        if (!thrownExceptions.isEmpty()) {
            throw thrownExceptions.iterator().next(); // throw one that comes out first, it does not matter much at this point
        }
    }

    @After
    public void after() throws Exception {
//        logger.warning("Finishing testServerReceivedWhatSocketSent permutation: \n\n" + toString());
        System.out.println("Finishing testServerReceivedWhatSocketSent permutation (time: " + (System.currentTimeMillis() - startTime) + "): \n\n" + toString());

        for (SSLClient sslClient : sslClients) {
            sslClient.tryClose();
        }

        sslServer.tryClose();

        clientsRunner.shutdownNow();

        long finalOpenHandles = unixMXBean.getOpenFileDescriptorCount();
        System.out.println("finalOpenHandles: " + finalOpenHandles);

        if (unixMXBean.getOpenFileDescriptorCount() != initialOpenHandles) {
            int i = 1;
        }
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("SSLSocketChannelConnectsReadsAndWritesTest {").append('\n');
        sb.append("\tsharedConnectionScheme=").append(sharedConnectionScheme).append('\n');
        sb.append("\tserverComponentUsage=").append(serverComponentUsage).append('\n');
        sb.append("\tclientComponentUsage=").append(clientComponentUsage).append('\n');
        sb.append("\tserverShutdownScheme=").append(serverShutdownScheme).append('\n');
        sb.append("\tclientShutdownScheme=").append(clientShutdownScheme).append('\n');
        sb.append("\tserverCloseScheme=").append(serverCloseScheme).append('\n');
        sb.append("\tclientCloseScheme=").append(clientCloseScheme).append('\n');
        sb.append("\tsharedClientGeneratesSessionId=").append(sharedClientGeneratesSessionId).append('\n');
        sb.append("\tclientGeneratesMessagesFalseIsNotImplemented=").append(clientGeneratesMessagesFalseIsNotImplemented).append('\n');
        sb.append("\tclientInitiatesClose=").append(clientInitiatesClose).append('\n');
        sb.append("\tmessageSize=").append(messageSize).append('\n');
        sb.append("\titerationCount=").append(iterationCount).append('\n');
        sb.append("\tcheckIntegrity=").append(checkIntegrity).append('\n');
        sb.append("\tsslServer=").append(sslServer).append('\n');
        sb.append("\tclientCount=").append(clientCount).append('\n');
        sb.append('}').append('\n');
        return sb.toString();
    }

}
