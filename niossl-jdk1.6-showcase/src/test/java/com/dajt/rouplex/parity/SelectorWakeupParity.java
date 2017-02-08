package com.dajt.rouplex.parity;

import com.dajt.rouplex.util.TestUtil;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

/**
 * @author Andi Mullaraj (andimullaraj at gmail.com)
 */
@RunWith(Parameterized.class)
public class SelectorWakeupParity {
    private static final Logger logger = Logger.getLogger("SelectorWakeupParity");

    @Parameterized.Parameters
    public static Collection<Object[]> data() throws IOException {
        return Arrays.asList(new Object[][] {{true}, {false}});
    }

    final ExecutorService executorService;
    final SocketChannel socketChannel;
    final Selector selector;

    public SelectorWakeupParity(boolean secure) throws IOException {
        if (!secure) {
            socketChannel = SocketChannel.open();
            socketChannel.connect(new InetSocketAddress("www.amazon.com", 80));
            selector = Selector.open();
        } else {
            socketChannel = SocketChannel.open(); // todo, add SSL when done
            socketChannel.connect(new InetSocketAddress("www.amazon.com", 443));
            selector = Selector.open(); // todo, add SSL when done
        }

        socketChannel.configureBlocking(false);
        socketChannel.register(selector, SelectionKey.OP_READ);
        executorService = Executors.newSingleThreadExecutor();
    }

    @Test
    public void verifySelectDoesNotRelenquishMonitors() throws Exception {
        final CountDownLatch cdLatch = new CountDownLatch(1);

        executorService.submit(new Runnable() {
            public void run() {
                try {
                    logger.info("Select called");
                    cdLatch.countDown();
                    selector.select(); // should not return since server is expecting request
                    logger.info("Select returned");
                } catch (Exception e) {
                    logger.info("Select failed " + e.getMessage());
                }
            }
        });

        System.out.println("Sleeping: giving time the select() to get called");
        cdLatch.await();
        Thread.sleep(10);

        boolean entered = TestUtil.trySynchronize(selector);
        if (entered) {
            TestUtil.unsynchronize(selector);
        }

        // There can be false alarms in the extreme cases where the sleep(10) was not long enough
        Assert.assertFalse("We were able to synchronize, meaning that select() has relinquished its monitors", entered);
    }

    @After
    public void after() throws IOException {
        executorService.shutdownNow();
        try {
            socketChannel.close();
        } finally {
            selector.close();
        }
    }
}
