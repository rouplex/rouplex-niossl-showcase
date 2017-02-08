package com.dajt.rouplex.util;

import sun.misc.*;

import java.lang.reflect.*;

public class TestUtil {
    private static Unsafe unsafe = getUnsafe();

    public static boolean trySynchronize(Object monitor) {
        return unsafe.tryMonitorEnter(monitor);
    }

    public static void unsynchronize(Object monitor) {
        unsafe.monitorExit(monitor);
    }

    private static Unsafe getUnsafe() {
        try {
            for (Field field : Unsafe.class.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers())) {
                    if (field.getType() == Unsafe.class) {
                        field.setAccessible(true);
                        return (Unsafe) field.get(null);
                    }
                }
            }
            throw new IllegalStateException("Unsafe field not found");
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Could not initialize unsafe", e);
        }
    }
}
