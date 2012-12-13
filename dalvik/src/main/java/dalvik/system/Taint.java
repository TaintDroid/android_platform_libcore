/*
 * Copyright (c) 2010 The Pennsylvania State University
 * Systems and Internet Infrastructure Security Laboratory
 *
 * Author: William Enck <enck@cse.psu.edu>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dalvik.system;

import java.nio.ByteBuffer;

/**
 * Provides a Taint interface for the Dalvik VM. This class is used for
 * implementing Taint Source and Sink functionality.
 * 
 */
public final class Taint {

    public static final int TAINT_CLEAR         = 0x00000000;
    public static final int TAINT_LOCATION      = 0x00000001;
    public static final int TAINT_CONTACTS      = 0x00000002;
    public static final int TAINT_MIC           = 0x00000004;
    public static final int TAINT_PHONE_NUMBER  = 0x00000008;
    public static final int TAINT_LOCATION_GPS  = 0x00000010;
    public static final int TAINT_LOCATION_NET  = 0x00000020;
    public static final int TAINT_LOCATION_LAST = 0x00000040;
    public static final int TAINT_CAMERA        = 0x00000080;
    public static final int TAINT_ACCELEROMETER = 0x00000100;
    public static final int TAINT_SMS           = 0x00000200;
    public static final int TAINT_IMEI          = 0x00000400;
    public static final int TAINT_IMSI          = 0x00000800;
    public static final int TAINT_ICCID         = 0x00001000;
    public static final int TAINT_DEVICE_SN     = 0x00002000;
    public static final int TAINT_ACCOUNT       = 0x00004000;
    public static final int TAINT_HISTORY       = 0x00008000;
    
    // how many bytes of tainted network output data to print to log?
    public static final int dataBytesToLog = 100;

    /**
     * Updates the target String's taint tag.
     *
     * @param str
     *	    the target string
     * @param tag
     *	    tag to update (bitwise or) onto the object
     */
    native public static void addTaintString(String str, int tag);
    
    /**
     * Updates the target Object array's taint tag.
     *
     * @param array
     *	    the target object array
     * @param tag
     *	    tag to update (bitwise or) onto the object array
     */
    native public static void addTaintObjectArray(Object[] array, int tag);

    /**
     * Updates the target boolean array's taint tag.
     *
     * @param array
     *	    the target boolean array
     * @param tag
     *	    tag to update (bitwise or) onto the boolean array
     */
    native public static void addTaintBooleanArray(boolean[] array, int tag);

    /**
     * Updates the target char array's taint tag.
     *
     * @param array
     *	    the target char array
     * @param tag
     *	    tag to update (bitwise or) onto the char array
     */
    native public static void addTaintCharArray(char[] array, int tag);

    /**
     * Updates the target byte array's taint tag.
     *
     * @param array
     *	    the target byte array
     * @param tag
     *	    tag to update (bitwise or) onto the byte array
     */
    native public static void addTaintByteArray(byte[] array, int tag);
    
    /**
     * Updates the target direct ByteBuffer's taint tag.
     *
     * @param dByteBuffer 
     *	    the target direct ByteBuffer
     * @param tag
     *      tag to update (bitwise or) onto the direct ByteBuffer
     */
    public static void addTaintDirectByteBuffer(ByteBuffer dByteBuffer, int tag) {
        if (dByteBuffer.isDirect()) {
            dByteBuffer.addDirectByteBufferTaint(tag);
        }
    }

    /**
     * Updates the target int array's taint tag.
     *
     * @param array
     *	    the target int array
     * @param tag
     *	    tag to update (bitwise or) onto the int array
     */
    native public static void addTaintIntArray(int[] array, int tag);
    
    /**
     * Updates the target short array's taint tag.
     *
     * @param array
     *	    the target short array
     * @param tag
     *	    tag to update (bitwise or) onto the int array
     */
    native public static void addTaintShortArray(short[] array, int tag);

    /**
     * Updates the target long array's taint tag.
     *
     * @param array
     *	    the target long array
     * @param tag
     *	    tag to update (bitwise or) onto the long array
     */
    native public static void addTaintLongArray(long[] array, int tag);

    /**
     * Updates the target float array's taint tag.
     *
     * @param array
     *	    the target float array
     * @param tag
     *	    tag to update (bitwise or) onto the float array
     */
    native public static void addTaintFloatArray(float[] array, int tag);

    /**
     * Updates the target double array's taint tag.
     *
     * @param array
     *	    the target double array
     * @param tag
     *	    tag to update (bitwise or) onto the double array
     */
    native public static void addTaintDoubleArray(double[] array, int tag);
    
    /**
     * Add taint to a primitive boolean value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static boolean addTaintBoolean(boolean val, int tag);
    
    /**
     * Add taint to a primitive char value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static char addTaintChar(char val, int tag);
    
    /**
     * Add taint to a primitive byte value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static byte addTaintByte(byte val, int tag);

    /**
     * Add taint to a primitive int value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static int addTaintInt(int val, int tag);
    
    /**
     * Add taint to a primitive short value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static short addTaintShort(short val, int tag);

    /**
     * Add taint to a primitive long value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static long addTaintLong(long val, int tag);

    /**
     * Add taint to a primitive float value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static float addTaintFloat(float val, int tag);

    /**
     * Add taint to a primitive double value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static double addTaintDouble(double val, int tag);

    /**
     * Get the current taint tag from a String.
     *
     * @param str
     *	    the target String
     * @return the taint tag
     */
    native public static int getTaintString(String str);

    /**
     * Get the current taint tag from an Object array.
     *
     * @param array 
     *	    the target Object array
     * @return the taint tag
     */
    native public static int getTaintObjectArray(Object[] array);

    /**
     * Get the current taint tag from a boolean array.
     *
     * @param array 
     *	    the target boolean array
     * @return the taint tag
     */
    native public static int getTaintBooleanArray(boolean[] array);

    /**
     * Get the current taint tag from a char array.
     *
     * @param array 
     *	    the target char array
     * @return the taint tag
     */
    native public static int getTaintCharArray(char[] array);

    /**
     * Get the current taint tag from a byte array.
     *
     * @param array 
     *	    the target byte array
     * @return the taint tag
     */
    native public static int getTaintByteArray(byte[] array);

    /**
     * Get the current taint tag from a direct ByteBuffer.
     *
     * @param dByteBuffer 
     *	    the target direct ByteBuffer
     * @return the taint tag
     */
    public static int getTaintDirectByteBuffer(ByteBuffer dByteBuffer) {
        if (dByteBuffer.isDirect()) {
            return dByteBuffer.getDirectByteBufferTaint();
        } else {
            return -1;
        }
    }

    /**
     * Get the current taint tag from an int array.
     *
     * @param array 
     *	    the target int array
     * @return the taint tag
     */
    native public static int getTaintIntArray(int[] array);

    /**
     * Get the current taint tag from a short array.
     *
     * @param array 
     *	    the target short array
     * @return the taint tag
     */
    native public static int getTaintShortArray(short[] array);

    /**
     * Get the current taint tag from a long array.
     *
     * @param array 
     *	    the target long array
     * @return the taint tag
     */
    native public static int getTaintLongArray(long[] array);

    /**
     * Get the current taint tag from a float array.
     *
     * @param array 
     *	    the target float array
     * @return the taint tag
     */
    native public static int getTaintFloatArray(float[] array);

    /**
     * Get the current taint tag from a double array.
     *
     * @param array 
     *	    the target double array
     * @return the taint tag
     */
    native public static int getTaintDoubleArray(double[] array);

    /**
     * Get the current taint tag from a primitive boolean.
     *
     * @param val
     *	    the target boolean
     * @return the taint tag
     */
    native public static int getTaintBoolean(boolean val);

    /**
     * Get the current taint tag from a primitive char.
     *
     * @param val
     *	    the target char 
     * @return the taint tag
     */
    native public static int getTaintChar(char val);

    /**
     * Get the current taint tag from a primitive byte.
     *
     * @param val
     *	    the target byte 
     * @return the taint tag
     */
    native public static int getTaintByte(byte val);

    /**
     * Get the current taint tag from a primitive int.
     *
     * @param val
     *	    the target int 
     * @return the taint tag
     */
    native public static int getTaintInt(int val);
    
    /**
     * Get the current taint tag from a primitive short.
     *
     * @param val
     *	    the target short 
     * @return the taint tag
     */
    native public static int getTaintShort(short val);

    /**
     * Get the current taint tag from a primitive long.
     *
     * @param val
     *	    the target long 
     * @return the taint tag
     */
    native public static int getTaintLong(long val);

    /**
     * Get the current taint tag from a primitive float.
     *
     * @param val
     *	    the target float 
     * @return the taint tag
     */
    native public static int getTaintFloat(float val);

    /**
     * Get the current taint tag from a primitive double.
     *
     * @param val
     *	    the target double 
     * @return the taint tag
     */
    native public static int getTaintDouble(double val);

    /**
     * Get the current taint tag from an Object reference.
     *
     * @param obj
     *	    the target Object reference
     * @return the taint tag
     */
    native public static int getTaintRef(Object obj);
    
    /**
     * Get the taint tag from a file identified by a descriptor.
     *
     * @param fd
     *	    the target file descriptor
     * @return the taint tag
     */
    native public static int getTaintFile(int fd);
    
    /**
     * add a taint tag to a file identified by a descriptor
     *
     * @param fd
     *	    the target file descriptor
     * @param tag
     *	    the tag to add (bitwise or) to the file
     */
    native public static void addTaintFile(int fd, int tag);

    /**
     * Logging utility accessible from places android.util.Log
     * is not.
     *
     * @param msg
     *	    the message to log
     */
    native public static void log(String msg);


    /**
     * Logging utility to obtain the file path for a file descriptor
     *
     * @param fd
     *	    the file descriptor
     */
    native public static void logPathFromFd(int fd);

    /**
     * Logging utility to obtain the peer IP addr for a file descriptor
     *
     * @param fd
     *	    the file descriptor
     */
    native public static void logPeerFromFd(int fd);
}

