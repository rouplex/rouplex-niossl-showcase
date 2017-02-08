package com.dajt.rouplex.parity;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.ClosedSelectorException;
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
public class SelectorLockParity {
    private static final Logger logger = Logger.getLogger("SelectorLockParity");

    @Parameterized.Parameters
    public static Collection<Object[]> data() throws IOException {
        return Arrays.asList(new Object[][] {{true}, {false}});
    }

    final ExecutorService executorService;
    final SocketChannel socketChannel;
    final Selector selector;

    public SelectorLockParity(boolean secure) throws IOException {
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
        executorService = Executors.newFixedThreadPool(2);
    }

    @Test
    public void verifySelectNowIsLockedOutDuringAnotherSelect() throws Exception {
        final CountDownLatch cdLatch1 = new CountDownLatch(1);

        executorService.submit(new Runnable() {
            @Override
            public void run() {
                try {
                    logger.info("Select called");
                    cdLatch1.countDown();
                    selector.select(); // should not return since server is expecting request
                    logger.info("Select returned");
                } catch (Exception e) {
                    logger.info("Select failed " + e.getMessage());
                }
            }
        });

        System.out.println("Sleeping: giving time the select() to get called");
        cdLatch1.await();
        Thread.sleep(10);

        executorService.submit(new Runnable() { // this task to teardown the test really
            @Override
            public void run() {
                try {
                    Thread.sleep(10);
                    logger.info("Selector.close() called");
                    selector.close();
                    logger.info("Selector.close() returned");
                } catch (Exception e) {
                    logger.info("Selector.close() failed " + e.getMessage());
                }
            }
        });

        try {
            selector.selectNow();
            Assert.fail("Selector.SelectNow() returned right away -- not expected in this scenario");
        } catch (ClosedSelectorException ioe) {
            // expected
        }
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
