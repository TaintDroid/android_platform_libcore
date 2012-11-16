/*
 * Copyright (C) 2011 The Android Open Source Project
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

package libcore.io;

import java.io.FileDescriptor;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.NioUtils;
import libcore.util.MutableInt;
import libcore.util.MutableLong;

// begin WITH_TAINT_TRACKING
import dalvik.system.Taint;
// end WITH_TAINT_TRACKING

public final class Posix implements Os {
    Posix() { }

    public native FileDescriptor accept(FileDescriptor fd, InetSocketAddress peerAddress) throws ErrnoException;
    public native boolean access(String path, int mode) throws ErrnoException;
    public native void bind(FileDescriptor fd, InetAddress address, int port) throws ErrnoException;
    public native void chmod(String path, int mode) throws ErrnoException;
    public native void close(FileDescriptor fd) throws ErrnoException;
// begin WITH_TAINT_TRACKING
    //public native void connect(FileDescriptor fd, InetAddress address, int port) throws ErrnoException;
    public native void connectImpl(FileDescriptor fd, InetAddress address, int port) throws ErrnoException;
    public void connect(FileDescriptor fd, InetAddress address, int port) throws ErrnoException {
        String addr = address.getHostAddress();
        if (addr != null) {
             fd.hasName = true;
             fd.name = addr;
    	}
        connectImpl(fd, address, port);
    }
// end WITH_TAINT_TRACKING
    public native FileDescriptor dup(FileDescriptor oldFd) throws ErrnoException;
    public native FileDescriptor dup2(FileDescriptor oldFd, int newFd) throws ErrnoException;
    public native String[] environ();
    public native int fcntlVoid(FileDescriptor fd, int cmd) throws ErrnoException;
    public native int fcntlLong(FileDescriptor fd, int cmd, long arg) throws ErrnoException;
    public native int fcntlFlock(FileDescriptor fd, int cmd, StructFlock arg) throws ErrnoException;
    public native void fdatasync(FileDescriptor fd) throws ErrnoException;
    public native StructStat fstat(FileDescriptor fd) throws ErrnoException;
    public native StructStatFs fstatfs(FileDescriptor fd) throws ErrnoException;
    public native void fsync(FileDescriptor fd) throws ErrnoException;
    public native void ftruncate(FileDescriptor fd, long length) throws ErrnoException;
    public native String gai_strerror(int error);
    public native InetAddress[] getaddrinfo(String node, StructAddrinfo hints) throws GaiException;
    public native int getegid();
    public native int geteuid();
    public native int getgid();
    public native String getenv(String name);
    public native String getnameinfo(InetAddress address, int flags) throws GaiException;
    public native int getpid();
    public native int getppid();
    public native StructPasswd getpwnam(String name) throws ErrnoException;
    public native StructPasswd getpwuid(int uid) throws ErrnoException;
    public native SocketAddress getsockname(FileDescriptor fd) throws ErrnoException;
    public native int getsockoptByte(FileDescriptor fd, int level, int option) throws ErrnoException;
    public native InetAddress getsockoptInAddr(FileDescriptor fd, int level, int option) throws ErrnoException;
    public native int getsockoptInt(FileDescriptor fd, int level, int option) throws ErrnoException;
    public native StructLinger getsockoptLinger(FileDescriptor fd, int level, int option) throws ErrnoException;
    public native StructTimeval getsockoptTimeval(FileDescriptor fd, int level, int option) throws ErrnoException;
    public native int getuid();
    public native String if_indextoname(int index);
    public native InetAddress inet_pton(int family, String address);
    public native InetAddress ioctlInetAddress(FileDescriptor fd, int cmd, String interfaceName) throws ErrnoException;
    public native int ioctlInt(FileDescriptor fd, int cmd, MutableInt arg) throws ErrnoException;
    public native boolean isatty(FileDescriptor fd);
    public native void kill(int pid, int signal) throws ErrnoException;
    public native void listen(FileDescriptor fd, int backlog) throws ErrnoException;
    public native long lseek(FileDescriptor fd, long offset, int whence) throws ErrnoException;
    public native StructStat lstat(String path) throws ErrnoException;
    public native void mincore(long address, long byteCount, byte[] vector) throws ErrnoException;
    public native void mkdir(String path, int mode) throws ErrnoException;
    public native void mlock(long address, long byteCount) throws ErrnoException;
    public native long mmap(long address, long byteCount, int prot, int flags, FileDescriptor fd, long offset) throws ErrnoException;
    public native void msync(long address, long byteCount, int flags) throws ErrnoException;
    public native void munlock(long address, long byteCount) throws ErrnoException;
    public native void munmap(long address, long byteCount) throws ErrnoException;
    public native FileDescriptor open(String path, int flags, int mode) throws ErrnoException;
    public native FileDescriptor[] pipe() throws ErrnoException;
    public native int poll(StructPollfd[] fds, int timeoutMs) throws ErrnoException;
    public int pread(FileDescriptor fd, ByteBuffer buffer, long offset) throws ErrnoException {
        if (buffer.isDirect()) {
            return preadBytes(fd, buffer, buffer.position(), buffer.remaining(), offset);
        } else {
            return preadBytes(fd, NioUtils.unsafeArray(buffer), NioUtils.unsafeArrayOffset(buffer) + buffer.position(), buffer.remaining(), offset);
        }
    }
    public int pread(FileDescriptor fd, byte[] bytes, int byteOffset, int byteCount, long offset) throws ErrnoException {
        // This indirection isn't strictly necessary, but ensures that our public interface is type safe.
        return preadBytes(fd, bytes, byteOffset, byteCount, offset);
    }
// begin WITH_TAINT_TRACKING
    //private native int preadBytes(FileDescriptor fd, Object buffer, int bufferOffset, int byteCount, long offset) throws ErrnoException;
    private native int preadBytesImpl(FileDescriptor fd, Object buffer, int bufferOffset, int byteCount, long offset) throws ErrnoException;
    private int preadBytes(FileDescriptor fd, Object buffer, int bufferOffset, int byteCount, long offset) throws ErrnoException {
        if (buffer == null) {
            throw new NullPointerException();
        }
        int bytesRead = preadBytesImpl(fd, buffer, bufferOffset, byteCount, offset);
        int fdInt = fd.getDescriptor();
        int tag = Taint.getTaintFile(fdInt);
        if (tag != Taint.TAINT_CLEAR) {
            String dstr = new String((byte[])buffer, bufferOffset, ((byteCount > Taint.dataBytesToLog) ? Taint.dataBytesToLog : byteCount));
            // replace non-printable characters
            dstr = dstr.replaceAll("\\p{C}", ".");
            String tstr = "0x" + Integer.toHexString(tag);
            Taint.log("libcore.os.read(" + fdInt + ") reading with tag " + tstr + " data[" + dstr + "]");
            Taint.addTaintByteArray((byte[])buffer, tag);
        }
        return bytesRead;
    }
// end WITH_TAINT_TRACKING
    public int pwrite(FileDescriptor fd, ByteBuffer buffer, long offset) throws ErrnoException {
        if (buffer.isDirect()) {
// begin WITH_TAINT_TRACKING
            int tag = buffer.getDirectByteBufferTaint();
            if (tag != Taint.TAINT_CLEAR) {
                int fdInt = fd.getDescriptor();
                Taint.logPathFromFd(fdInt);
                String tstr = "0x" + Integer.toHexString(tag);
                Taint.log("libcore.os.pwrite(" + fdInt + ") writing a direct ByteBuffer with tag " + tstr);
                Taint.addTaintFile(fdInt, tag);
            }
// end WITH_TAINT_TRACKING
            return pwriteBytes(fd, buffer, buffer.position(), buffer.remaining(), offset);
        } else {
            return pwriteBytes(fd, NioUtils.unsafeArray(buffer), NioUtils.unsafeArrayOffset(buffer) + buffer.position(), buffer.remaining(), offset);
        }
    }
    public int pwrite(FileDescriptor fd, byte[] bytes, int byteOffset, int byteCount, long offset) throws ErrnoException {
        // This indirection isn't strictly necessary, but ensures that our public interface is type safe.
        return pwriteBytes(fd, bytes, byteOffset, byteCount, offset);
    }
// begin WITH_TAINT_TRACKING
    //private native int pwriteBytes(FileDescriptor fd, Object buffer, int bufferOffset, int byteCount, long offset) throws ErrnoException;
    private native int pwriteBytesImpl(FileDescriptor fd, Object buffer, int bufferOffset, int byteCount, long offset) throws ErrnoException;
    private int pwriteBytes(FileDescriptor fd, Object buffer, int bufferOffset, int byteCount, long offset) throws ErrnoException {
        if (buffer == null) {
            throw new NullPointerException();
        }
		
        if (buffer instanceof byte[]) {
            int fdInt = fd.getDescriptor();
            int tag = Taint.getTaintByteArray((byte[]) buffer);
            if (tag != Taint.TAINT_CLEAR) {
                String dstr = new String((byte[]) buffer, bufferOffset, ((byteCount > Taint.dataBytesToLog) ? Taint.dataBytesToLog : byteCount));
                // replace non-printable characters
                dstr = dstr.replaceAll("\\p{C}", ".");
                Taint.logPathFromFd(fdInt);
                String tstr = "0x" + Integer.toHexString(tag);
                Taint.log("libcore.os.pwrite(" + fdInt + ") writing with tag " + tstr + " data[" + dstr + "]");
                Taint.addTaintFile(fdInt, tag);
            }
        }
        int bytesWritten = pwriteBytesImpl(fd, buffer, bufferOffset, byteCount, offset);
        return bytesWritten;
    }
// end WITH_TAINT_TRACKING
	public int read(FileDescriptor fd, ByteBuffer buffer) throws ErrnoException {
        if (buffer.isDirect()) {
            return readBytes(fd, buffer, buffer.position(), buffer.remaining());
        } else {
            return readBytes(fd, NioUtils.unsafeArray(buffer), NioUtils.unsafeArrayOffset(buffer) + buffer.position(), buffer.remaining());
        }
    }
    public int read(FileDescriptor fd, byte[] bytes, int byteOffset, int byteCount) throws ErrnoException {
        // This indirection isn't strictly necessary, but ensures that our public interface is type safe.
        return readBytes(fd, bytes, byteOffset, byteCount);
    }
	
// begin WITH_TAINT_TRACKING
    //private native int readBytes(FileDescriptor fd, Object buffer, int offset, int byteCount) throws ErrnoException;
    private native int readBytesImpl(FileDescriptor fd, Object buffer, int offset, int byteCount) throws ErrnoException;
    private int readBytes(FileDescriptor fd, Object buffer, int offset, int byteCount) throws ErrnoException {
        if (buffer == null) {
            throw new NullPointerException();
        }
        int bytesRead = readBytesImpl(fd, buffer, offset, byteCount);
        int fdInt = fd.getDescriptor();
        int tag = Taint.getTaintFile(fdInt);
        if (tag != Taint.TAINT_CLEAR) {
            String dstr = new String((byte[])buffer, offset, ((byteCount > Taint.dataBytesToLog) ? Taint.dataBytesToLog : byteCount));
            // replace non-printable characters
            dstr = dstr.replaceAll("\\p{C}", ".");
            String tstr = "0x" + Integer.toHexString(tag);
            Taint.log("libcore.os.read(" + fdInt + ") reading with tag " + tstr + " data[" + dstr + "]");
            Taint.addTaintByteArray((byte[])buffer, tag);
        }
        return bytesRead;
    }
// end WITH_TAINT_TRACKING
    public native int readv(FileDescriptor fd, Object[] buffers, int[] offsets, int[] byteCounts) throws ErrnoException;
    public int recvfrom(FileDescriptor fd, ByteBuffer buffer, int flags, InetSocketAddress srcAddress) throws ErrnoException {
        if (buffer.isDirect()) {
            return recvfromBytes(fd, buffer, buffer.position(), buffer.remaining(), flags, srcAddress);
        } else {
            return recvfromBytes(fd, NioUtils.unsafeArray(buffer), NioUtils.unsafeArrayOffset(buffer) + buffer.position(), buffer.remaining(), flags, srcAddress);
        }
    }
    public int recvfrom(FileDescriptor fd, byte[] bytes, int byteOffset, int byteCount, int flags, InetSocketAddress srcAddress) throws ErrnoException {
        // This indirection isn't strictly necessary, but ensures that our public interface is type safe.
        return recvfromBytes(fd, bytes, byteOffset, byteCount, flags, srcAddress);
    }
    private native int recvfromBytes(FileDescriptor fd, Object buffer, int byteOffset, int byteCount, int flags, InetSocketAddress srcAddress) throws ErrnoException;
    public native void remove(String path) throws ErrnoException;
    public native void rename(String oldPath, String newPath) throws ErrnoException;
    public native long sendfile(FileDescriptor outFd, FileDescriptor inFd, MutableLong inOffset, long byteCount) throws ErrnoException;
    public int sendto(FileDescriptor fd, ByteBuffer buffer, int flags, InetAddress inetAddress, int port) throws ErrnoException {
        if (buffer.isDirect()) {
// begin WITH_TAINT_TRACKING
            int tag = buffer.getDirectByteBufferTaint();
            if (tag != Taint.TAINT_CLEAR) {
                String addr = (fd.hasName) ? fd.name : "unknown";
                String tstr = "0x" + Integer.toHexString(tag);
                Taint.log("libcore.os.sendto(" + addr + ") received a ByteBuffer with tag " + tstr);
            }
// end WITH_TAINT_TRACKING
            return sendtoBytes(fd, buffer, buffer.position(), buffer.remaining(), flags, inetAddress, port);
        } else {
            return sendtoBytes(fd, NioUtils.unsafeArray(buffer), NioUtils.unsafeArrayOffset(buffer) + buffer.position(), buffer.remaining(), flags, inetAddress, port);
        }
    }
    public int sendto(FileDescriptor fd, byte[] bytes, int byteOffset, int byteCount, int flags, InetAddress inetAddress, int port) throws ErrnoException {
        // This indirection isn't strictly necessary, but ensures that our public interface is type safe.
        return sendtoBytes(fd, bytes, byteOffset, byteCount, flags, inetAddress, port);
    }
	
// begin WITH_TAINT_TRACKING
    //private native int sendtoBytes(FileDescriptor fd, Object buffer, int byteOffset, int byteCount, int flags, InetAddress inetAddress, int port) throws ErrnoException;
    private native int sendtoBytesImpl(FileDescriptor fd, Object buffer, int byteOffset, int byteCount, int flags, InetAddress inetAddress, int port) throws ErrnoException;
    private int sendtoBytes(FileDescriptor fd, Object buffer, int byteOffset, int byteCount, int flags, InetAddress inetAddress, int port) throws ErrnoException {
        if (buffer instanceof byte[]) {
            int tag = Taint.getTaintByteArray((byte[]) buffer);
    	    if (tag != Taint.TAINT_CLEAR) {
                String dstr = new String((byte[]) buffer, byteOffset, ((byteCount > Taint.dataBytesToLog) ? Taint.dataBytesToLog : byteCount));
                // replace non-printable characters
                dstr = dstr.replaceAll("\\p{C}", ".");
                String addr = (fd.hasName) ? fd.name : "unknown";
    	        String tstr = "0x" + Integer.toHexString(tag);
                Taint.log("libcore.os.send("+addr+") received data with tag " + tstr + " data=["+dstr+"] ");
            }
        }
	return sendtoBytesImpl(fd, buffer, byteOffset, byteCount, flags, inetAddress, port);
    }
// end WITH_TAINT_TRACKING
	
    public native void setegid(int egid) throws ErrnoException;
    public native void seteuid(int euid) throws ErrnoException;
    public native void setgid(int gid) throws ErrnoException;
    public native void setsockoptByte(FileDescriptor fd, int level, int option, int value) throws ErrnoException;
    public native void setsockoptIfreq(FileDescriptor fd, int level, int option, String value) throws ErrnoException;
    public native void setsockoptInt(FileDescriptor fd, int level, int option, int value) throws ErrnoException;
    public native void setsockoptIpMreqn(FileDescriptor fd, int level, int option, int value) throws ErrnoException;
    public native void setsockoptGroupReq(FileDescriptor fd, int level, int option, StructGroupReq value) throws ErrnoException;
    public native void setsockoptLinger(FileDescriptor fd, int level, int option, StructLinger value) throws ErrnoException;
    public native void setsockoptTimeval(FileDescriptor fd, int level, int option, StructTimeval value) throws ErrnoException;
    public native void setuid(int uid) throws ErrnoException;
    public native void shutdown(FileDescriptor fd, int how) throws ErrnoException;
    public native FileDescriptor socket(int domain, int type, int protocol) throws ErrnoException;
    public native StructStat stat(String path) throws ErrnoException;
    public native StructStatFs statfs(String path) throws ErrnoException;
    public native String strerror(int errno);
    public native void symlink(String oldPath, String newPath) throws ErrnoException;
    public native long sysconf(int name);
    public native StructUtsname uname();
    public native int waitpid(int pid, MutableInt status, int options) throws ErrnoException;
    public int write(FileDescriptor fd, ByteBuffer buffer) throws ErrnoException {
        if (buffer.isDirect()) {
// begin WITH_TAINT_TRACKING
            int tag = buffer.getDirectByteBufferTaint();
            if (tag != Taint.TAINT_CLEAR) {
                int fdInt = fd.getDescriptor();
                Taint.logPathFromFd(fdInt);
                String tstr = "0x" + Integer.toHexString(tag);
                Taint.log("libcore.os.write(" + fdInt + ") writing a direct ByteBuffer with tag " + tstr);
                Taint.addTaintFile(fdInt, tag);
            }
// end WITH_TAINT_TRACKING
            return writeBytes(fd, buffer, buffer.position(), buffer.remaining());
        } else {
            return writeBytes(fd, NioUtils.unsafeArray(buffer), NioUtils.unsafeArrayOffset(buffer) + buffer.position(), buffer.remaining());
        }
    }
    public int write(FileDescriptor fd, byte[] bytes, int byteOffset, int byteCount) throws ErrnoException {
        // This indirection isn't strictly necessary, but ensures that our public interface is type safe.
        return writeBytes(fd, bytes, byteOffset, byteCount);
    }
	
//begin WITH_TAINT_TRACKING
    //private native int writeBytes(FileDescriptor fd, Object buffer, int offset, int byteCount) throws ErrnoException;
    private native int writeBytesImpl(FileDescriptor fd, Object buffer, int offset, int byteCount) throws ErrnoException;
    private int writeBytes(FileDescriptor fd, Object buffer, int offset, int byteCount) throws ErrnoException {
        if (buffer == null) {
            throw new NullPointerException();
        }
	
        if (buffer instanceof byte[]) {
            int fdInt = fd.getDescriptor();
            int tag = Taint.getTaintByteArray((byte[]) buffer);
            if (tag != Taint.TAINT_CLEAR) {
                //We only display at most Taint.dataBytesToLog characters of the data in logcat, to avoid the overflow
                String dstr = new String((byte[]) buffer, offset, ((byteCount > Taint.dataBytesToLog) ? Taint.dataBytesToLog : byteCount));
                // replace non-printable characters
                dstr = dstr.replaceAll("\\p{C}", ".");
                Taint.logPathFromFd(fdInt);
                String tstr = "0x" + Integer.toHexString(tag);
                Taint.log("libcore.os.write(" + fdInt + ") writing with tag " + tstr + " data[" + dstr + "]");
                Taint.addTaintFile(fdInt, tag);
            }
        }
        int bytesWritten = writeBytesImpl(fd, buffer, offset, byteCount);
        return bytesWritten;
    }
//end WITH_TAINT_TRACKING
    public native int writev(FileDescriptor fd, Object[] buffers, int[] offsets, int[] byteCounts) throws ErrnoException;
}
