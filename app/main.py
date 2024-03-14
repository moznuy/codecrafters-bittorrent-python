import json
import sys

# import bencodepy - available if you need it!
# import requests - available if you need it!


def decode_bencode(bencoded_value: bytes):
    if chr(bencoded_value[0]).isdigit():
        index = bencoded_value.find(b":")
        if index == -1:
            raise ValueError("Invalid encoded string")
        return bencoded_value[index+1:]
    elif chr(bencoded_value[0]) == 'i':
        index = bencoded_value.index(b'e')
        if index == -1:
            raise ValueError("Invalid encoded integer")
        return int(bencoded_value[1:index])
    else:
        raise NotImplementedError("Only strings are supported at the moment")


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
