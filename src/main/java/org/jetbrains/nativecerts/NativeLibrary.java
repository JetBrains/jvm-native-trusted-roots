package org.jetbrains.nativecerts;

import org.jetbrains.annotations.ApiStatus;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;

@ApiStatus.Internal
public final class NativeLibrary {
    private final SymbolLookup lookup;

    public NativeLibrary(String path) {
        lookup = SymbolLookup.libraryLookup(path, Arena.global());
    }

    public MemorySegment symbol(String name) {
        return lookup.find(name).orElseThrow(() -> new UnsatisfiedLinkError("Native symbol not found: " + name));
    }

    public Function function(String name, FunctionDescriptor descriptor, Linker.Option... options) {
        return new Function(name, Linker.nativeLinker().downcallHandle(symbol(name), descriptor, options));
    }

    public record Function(String name, MethodHandle handle) {
        public Object invoke(Object... arguments) {
            try {
                return handle.invokeWithArguments(arguments);
            } catch (RuntimeException | Error exception) {
                throw exception;
            } catch (Throwable exception) {
                throw new IllegalStateException("Native call failed: " + name, exception);
            }
        }
    }
}
