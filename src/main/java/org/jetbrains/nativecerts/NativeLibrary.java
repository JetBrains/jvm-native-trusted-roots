package org.jetbrains.nativecerts;

import org.jetbrains.annotations.ApiStatus;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.ADDRESS;

/**
 * A thin wrapper around {@link SymbolLookup} and {@link Linker} for a single native library.
 * <p>
 * Binding classes ({@code SecurityFramework}, {@code CoreFoundationExt}, {@code Crypt32Ext}, ...) create one
 * {@link MethodHandle} per native function via {@link #downcall} and expose it as a typed static Java method
 * named exactly like the native function, so that the code can be read side by side with Apple/Microsoft
 * documentation.
 */
@ApiStatus.Internal
public final class NativeLibrary {
    private final String path;
    private final SymbolLookup lookup;

    /**
     * @param path Absolute path of the library or framework binary. The library is loaded once and stays loaded
     *             for the lifetime of the JVM ({@link Arena#global()}).
     */
    public NativeLibrary(String path) {
        this.path = path;
        this.lookup = SymbolLookup.libraryLookup(path, Arena.global());
    }

    /**
     * @return Address of an exported symbol (a function or a global variable).
     * @throws UnsatisfiedLinkError if the symbol is not exported by the library
     */
    public MemorySegment symbol(String name) {
        return lookup.find(name).orElseThrow(() -> new UnsatisfiedLinkError("Native symbol '" + name + "' not found in " + path));
    }

    /**
     * Reads the value of an exported pointer-sized global variable, e.g. {@code kSecClass} or {@code kCFBooleanTrue}.
     * The symbol itself is the address of the variable; the variable holds the pointer we are interested in.
     */
    public MemorySegment pointerVariable(String name) {
        return symbol(name).reinterpret(ADDRESS.byteSize()).get(ADDRESS, 0);
    }

    /**
     * Creates a downcall handle for an exported function.
     */
    public MethodHandle downcall(String name, FunctionDescriptor descriptor, Linker.Option... options) {
        return Linker.nativeLinker().downcallHandle(symbol(name), descriptor, options);
    }

    /**
     * Converts a {@link Throwable} thrown by {@link MethodHandle#invokeExact} into an unchecked exception.
     * Downcall handles do not throw checked exceptions in practice; this exists only to satisfy the compiler
     * without hiding a real failure.
     */
    public static RuntimeException rethrow(String function, Throwable exception) {
        if (exception instanceof RuntimeException runtimeException) {
            return runtimeException;
        }
        if (exception instanceof Error error) {
            throw error;
        }
        return new IllegalStateException("Native call " + function + " failed", exception);
    }
}
