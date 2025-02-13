from io import RawIOBase, BufferedReader, DEFAULT_BUFFER_SIZE
from os import SEEK_SET, SEEK_CUR, SEEK_END

class _ConcatReader(RawIOBase):
    def __init__(self, io_iter):
        self._io_tup = tuple(io_iter)
        self._io_idx = 0
        self._io_range = []
        self._pos = 0
        self._closed = False

        pos = 0
        for io in self._io_tup:
            try:
                end = pos + io.seek(0, SEEK_END)
                self._io_range.append((pos, end - 1))
                pos = end
                io.seek(0, SEEK_SET)
            except:
                self._io_range = None

    def _get_io(self):
        if len(self._io_tup) > self._io_idx:
            return self._io_tup[self._io_idx]
        else:
            return None

    def _read(self, size=-1, /):
        if size == 0:
            return 0

        if io := self._get_io():
            result = io.read(size)
            if result != 0:
                return result

            if not io.closed:
                io.close()

            self._io_idx += 1
            return self._read(size)

        return None

    # RawIOBase
    def readall(self):
        result = None
        while data := self._read():
            if result is None:
                result = data
            else:
                result += data

        return result

    def readinto(self, b, /):
        n = len(b)
        if n == 0:
            return 0

        if io := self._get_io():
            result = io.readinto(b)
            if result == n:
                return result
            elif result is None:
                return None
            elif result == 0:
                if not io.closed:
                    io.close()

                self._io_idx += 1

            return result + self.readinto(b[result:])

        return 0

    def write(self, b, /):
        raise OSError('Not implemented: write')

    # IOBase
    def close(self):
        for io in self._io_tup:
            if not io.closed:
                io.close()

        self._closed = True

    @property
    def closed(self):
        return self._closed

    def fileno(self):
        raise OSError('Not implemented: fileno')

    def flush(self):
        pass

    def isatty(self):
        return False

    def readable(self):
        if io := self._get_io():
            return io.readable()
        else:
            return False

    def seek(self, offset, whence=None, /):
        if not self.seekable():
            raise OSError('Not implemented: seek')
        else:
            if whence == SEEK_SET:
                new_pos = offset
            elif whence == SEEK_CUR:
                new_pos += offset
            elif whence == SEEK_END:
                new_pos = self._io_range[-1][1] + 1 + offset
            else:
                raise OSError(f'bad whence value: {whence}')

            for idx in range(len(self._io_tup)):
                start, end = self._io_range[idx]
                if new_pos >= start and new_pos <= end:
                    self._io_idx = idx
                    self._io_tup[idx].seek(new_pos - start, SEEK_SET)
                    break

            self._pos = new_pos
            return self.tell()

    def seekable(self):
        return self._io_range is not None

    def tell(self):
        return self._pos

    def truncate(self):
        raise OSError('Not implemented: truncate')

    def writeable(self):
        return False

    def writelines(self, lines, /):
        raise OSError('Not implemented: writelines')

'''
    def readline(self, size=-1, /):
        ...

    def readlines(self, hint=-1, /):
        ...
'''

class ConcatReader(BufferedReader):
    def __init__(self, raw_iter, buffer_size=DEFAULT_BUFFER_SIZE):
        super(ConcatReader, self).__init__(_ConcatReader(raw_iter))
