/// <reference path="../TypeScript-Base/TS-Base.d.ts" />
declare namespace TS {
    namespace Security {
        /**
        * @description An enumeration which declares the two possible cipher operations. (ENCRYPT, DECRYPT).
        */
        enum CipherOperationEnum {
            DECRYPT = 0,
            ENCRYPT = 1,
        }
        /**
        * @description An enumeration which declares the possible stream states.
        */
        enum StreamStateEnum {
            CREATED = 0,
            INITIALIZED = 1,
            REQUEST_FOR_CLOSE = 2,
            CLOSED = 3,
        }
        const MD5_KEY_SIZE: number;
        const MD5_HASH_SIZE: number;
        const SHA1_KEY_SIZE: number;
        const SHA1_HASH_SIZE: number;
        const SHA224_KEY_SIZE: number;
        const SHA224_HASH_SIZE: number;
        const SHA256_KEY_SIZE: number;
        const SHA256_HASH_SIZE: number;
        const SHA384_KEY_SIZE: number;
        const SHA384_HASH_SIZE: number;
        const SHA512_KEY_SIZE: number;
        const SHA512_HASH_SIZE: number;
        const HMAC_SHA256_KEY_SIZE: number;
        const HMAC_SHA256_HASH_SIZE: number;
        const HMAC_SHA384_KEY_SIZE: number;
        const HMAC_SHA384_HASH_SIZE: number;
        const HMAC_SHA512_KEY_SIZE: number;
        const HMAC_SHA512_HASH_SIZE: number;
        /**
        * @description Slices the data array given in argument 'data' in pieces of the length given in argument
        *  'sliceLengthInByte'. Each slice is an array of byte of the given length and represents one element of the return
        *  array. Thus the return array is a 2 dimensional byte array of the dimension 'n * sliceLengthInByte' where n is
        *  the number of slices.
        *
        * @param {Array<number>} data, The data array to slice.
        * @param { number} sliceLengthInByte, The length of the slices. That value should match wiht the encryption block length.
        *  sliceLengthInByte has a default value of 4.
        *
        * @returns {Array<Array<number>}, The array of slices.
        *
        * @throws {TS.ArgumentOutOfRangeException}
        * @throws {TS.InvalidOperationException}
        * @throws {TS.ArgumentNullOrUndefinedException}
        * @throws {TS.InvalidTypeException}
        */
        function sliceData(data: Array<number>, sliceLengthInByte?: number): Array<Array<number>>;
        /**
        * @description Pads the byte array of given in argument data as required by the SHA(x) algorithm.
        *
        * @param {Array<number> | string} data
        * @returns {Array<number>}, An array of unsigned integers where each element represents four byte in the order
        *  [byte0][byte1][byte2][byte3].
        *
        * @throws {TS.ArgumentNullOrUndefinedException}
        * @throws {TS.InvalidTypeException}
        */
        function pad_SHA(data: Array<number> | string): Array<number>;
        /**
        * @description Pads the byte array  given in argument data as required by the MD5 algorithm.
        *
        * @param {Array<number> | string} data
        * @returns {Array<number>}, An array of unsigned integers where each element represents four byte in the order
        *  [byte0][byte1][byte2][byte3].
        *
        * @throws {TS.ArgumentNullOrUndefinedException}
        * @throws {TS.InvalidTypeException}
        */
        function pad_MD5(data: Array<number> | string): Array<number>;
        /**
         * @description Takes an array of up to four unsigned byte values and returns them as four byte word, which is an
        *  unsigned integer in JavaScript. The bytes are arranged in the order of appearence. That means the first byte
        *  is stored at the most significant position and the last byte at the least significant position.
        *  [byte0][byte1][byte2][byte3] <=> UnsignedInteger
        *  That conversion is equivalent to:
        *
        *  byte0 * 0xFFFFFF + byte1 * 0xFFFF + byte2 * 0xFF + byte3
        * @param { Array<number>} byteArray, An array of up to 4 unsigned byte values.
        *
        * @returns {number}, The four byte word as unsigned integer.
        *
        * @throws {TS.ArgumentNullOrUndefinedException}
        * @throws {TS.InvalidTypeException}
        * @throws {TS.ArgumentOutOfRangeException}
        */
        function UByteArrayToFourByteWord(byteArray: Array<number>): number;
        /**
        * @description An implementation of the padding algorithm as described in RFC2315. That algorithm is also known as
        *  PKCS7 padding.
        *
        * @param {Array<number>} data, The data array which gets padded.
        * @param {number} requiredBlockLength, The required length of the array. That value should match with the
        *  encryption block length. The default value is 16.
        *
        * @returns {Array<number>}, The padded data array
        *
        * @throws {TS.ArgumentOutOfRangeException}
        * @throws {TS.ArgumentNullOrUndefinedException}
        * @throws {TS.InvalidTypeException}
        */
        function padData(data: Array<number>, requiredBlockLength?: number): Array<number>;
        /**
        * @description Removes the pad bytes from the data which were added by the padData function before.
        *
        * @see TS.Security.padData
        *
        * @param data, The data array which gets unpadded.
        *
        * @returns {Array<number>}, The unpadded data array
        *
        * @throws {TS.ArgumentException}
        * @throws {TS.ArgumentNullOrUndefinedException}
        * @throws {TS.InvalidTypeException}
        */
        function unpadData(data: Array<number>): Array<number>;
        /**
        * @description Execute the XOR function on corresponding elements of the input byte arrays and returns the result
        *  in a new byte array. Correspoding byte array elements are those which have a common index inside their array.
        *
        * @param {Array<number>} firstArray
        * @param {Array<number>} secondArray
        *
        * @returns {Array<number>}
        *
        * @throws {TS.ArgumentNullOrUndefinedException}
        * @throws {TS.InvalidTypeException}
        */
        function XORByteArray(firstArray: Array<number>, secondArray: Array<number>): Array<number>;
        /**
        * @description Returns an array of round constants as required for the SHA-224 and SHA-256 hash algorithm.
        *
        * @returns {Array<number>}
        */
        function getSHA224_256RoundConstants(): Array<number>;
        /**
        * @descriptions Returns a precalculated array of integer sine values from the values [1..64] multiplied by
        *  0x100000000.
        *
        * @see {@link https://www.ietf.org/rfc/rfc1321.txt | RFC 1321,3.4 Step 4. Process Message in 16‐Word Blocks}
        *
        * @returns {Array<number>}
        */
        function getMD5_SineTable(): Array<number>;
        /**
        * @description Returns the substitution table as defined for the MD5 algorithm.
        *
        * @see {@link https://www.ietf.org/rfc/rfc1321.txt | IETF}
        *
        * @returns {Array<number>}
        */
        function getMD5_PerRoundShiftAmountTable(): Array<number>;
        /**
        * @description Returns an array of precalculated modulo operation values over the set {0..255}.
        *
        * @returns {Array<number>}
        */
        function getAES_multByTwoArray(): number[];
        /**
        * @description Returns an array of precalculated modulo operation values over the set {0..255}.
        *
        * @returns {Array<number>}
        */
        function getAES_multByThreeArray(): number[];
        /**
        * @description Returns an array of precalculated modulo operation values over the set {0..255}.
        *
        * @returns {Array<number>}
        */
        function getAES_multByFourteenArray(): number[];
        /**
        * @description Returns an array of precalculated modulo operation values over the set {0..255}.
        *
        * @returns {Array<number>}
        */
        function getAES_multByThirteenArray(): number[];
        /**
        * @description Returns an array of precalculated modulo operation values over the set {0..255}.
        *
        * @returns {Array<number>}
        */
        function getAES_multByElevenArray(): number[];
        /**
        * @description Returns an array of precalculated modulo operation values over the set {0..255}.
        *
        * @returns {Array<number>}
        */
        function getAES_multByNineArray(): number[];
        /**
        * @description Returns an array of substitution values as defined in the AES algorithm.
        *
        * @returns {Array<number>}
        */
        function getAES_substitutionTable(): number[];
        /**
        * @description Returns an array of inverse substitution values as defined in the AES algorithm.
        *
        * @returns {Array<number>}
        */
        function getAES_inverseSubstitutionTable(): number[];
        /**
        * @description Returns an array of round constant values as defined in the AES algorithm.
        *
        * @returns {Array<number>}
        */
        function getAES_roundConstants(): number[];
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.Cryptography
        *
        * @descriptions This is the base class of the hash and crypto classes in the 'TS.Security' namespace. and
        *  implements some common used functions.
        */
        class Cryptography {
            /**
            * @constructor
            *
            * @description Creates a new instance of the 'TS.Security.Cryptography' class.
            */
            constructor();
            /**
            * @description Corrects a negative result which may occure after a bitoperation on a positive integer.
            *
            * @param {number} value, The value to correct.
            *
            * @returns {number}, The corrected value
            */
            protected static correctNegative(value: number): number;
            protected static MD5FuncOne(roundB: number, roundC: number, roundD: number): number;
            protected static MD5FuncTwo(roundB: number, roundC: number, roundD: number): number;
            protected static MD5FuncThree(roundB: number, roundC: number, roundD: number): number;
            protected static MD5FuncFour(roundB: number, roundC: number, roundD: number): number;
            /**
            * @description This function excutes the XOR operation on the arguments 'firstWord' and 'secondWord' and returns
            *  the result as a byte array.
            *
            * @param {number} firstWord
            * @param {number} secondWord
            *
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentException}
            *
            * @returns {Array<number>}
            */
            protected static xorWord(firstWord: Array<number>, secondWord: Array<number>): Array<number>;
            /**
            * @description Rotates the elements of the array given in argument 'data' leftwise for as many positions as given
            *  in argument 'positions'.
            *
            * @params {Array<any>} data, The array which will be rotated.
            * @params {number} positions, The number of positions to rotate.
            *
            * @returns {Array<any>}, The result array.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static rotateLeft(data: Array<any>, positions: number): Array<any>;
            /**
            * @description Performs: (x & y) ^ (~x & z)
            *
            * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.1 SHA-1 Functions }
            *
            * @param {number} x
            * @param {number} y
            * @param {number} z
            *
            * @returns {number}
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static ch32(x: number, y: number, z: number): number;
            /**
            * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.1 SHA-1 Functions }
            *
            * @param {TS.TypeCode.UInt64} x
            * @param {TS.TypeCode.UInt64} y
            * @param {TS.TypeCode.UInt64} z
            *
            * @returns {TS.TypeCode.UInt64}
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static ch64(x: TS.TypeCode.UInt64, y: TS.TypeCode.UInt64, z: TS.TypeCode.UInt64): TS.TypeCode.UInt64;
            /**
            * @description Performs: (ror 7) ^ (ror 18) ^ (shr 3)
            *
            * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.2 SHA-224 and SHA-256 Functions }
            *
            * @param {number} x
            *
            * @returns {number}
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static gamma0_32(x: number): number;
            /**
            * @description Performs: (ror 17) ^ (ror 19) ^ (shr 10)
            *
            * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.2 SHA-224 and SHA-256 Functions }
            *
            * @param {number} x
            *
            * @returns {number}
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static gamma1_32(x: number): number;
            /**
            * @description Performs: (x & y) ^ (x & z) ^ (y & z)
            *
            * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.1 SHA-1 Functions }
            *
            * @param {number} x
            * @param {number} y
            * @param {number} z
            *
            * @returns {number}
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static maj32(x: number, y: number, z: number): number;
            /**
            * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.1 SHA-1 Functions }
            *
            * @param {TS.TypeCode.UInt64} x
            * @param {TS.TypeCode.UInt64} y
            * @param {TS.TypeCode.UInt64} z
            *
            * @returns {TS.TypeCode.UInt64}
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static maj64(x: TS.TypeCode.UInt64, y: TS.TypeCode.UInt64, z: TS.TypeCode.UInt64): TS.TypeCode.UInt64;
            /**
            * @description Performs: (x ^ y ^ z)
            *
            * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.1 SHA-1 Functions }
            *
            * @param {number} x
            * @param {number} y
            * @param {number} z
            *
            * @returns {number}
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static parity(x: number, y: number, z: number): number;
            /**
            * @description Rotates the bits in the unsigned 32 bit integer given in argument 'value' as many positions
            *  leftwise as given in argument 'positions'. Returns the value after rotation.
            *
            * @params {number} value, An unsigned 32 bit integer number.
            * @params {number} positions, Number of positions to rotate.
            *
            * @returns {number}, The resulting number after rotation.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static rotateLeft32(value: number, positions: number): number;
            /**
            * @description Rotates the bits in the unsigned 32 bit integer given in argument 'value' as many positions
            *  rightwise as given in argument 'positions'. Returns the value after rotation.
            *
            * @params {number} value, An unsigned 32 bit integer number.
            * @params {number} positions, Number of positions to rotate.
            *
            * @returns {number}, The resulting number after rotation.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static rotateRight32(value: number, positions: number): number;
            /**
            * @description Rotates the bits in the 64 bit integer given in argument 'value' as many positions
            *  rightwise as given in argument 'positions'. Returns the value after rotation.
            *
            * @params {number} value, An unsigned 32 bit integer number.
            * @params {number} positions, Number of positions to rotate.
            *
            * @returns {number}, The resulting number after rotation.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static rotateRight64(value: TS.TypeCode.UInt64, positions: number): TS.TypeCode.UInt64;
            /**
            * @description Shifts the bits in the unsigned 32 bit integer given in argument 'value' as many positions
            *  leftwise as given in argument 'positions'. Returns the value after shifting.
            *
            * @params {number} value, An unsigned 32 bit integer number.
            * @params {number} positions, Number of positions to shift.
            *
            * @returns {number}, the resulting number after shifting.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static shiftLeft32(value: number, positions: number): number;
            /**
            * @description Shifts the bits in the unsigned 32 bit integer given in argument 'value' as many positions
            *  rightwise as given in argument 'positions'. Returns the value after shifting.
            *
            * @params {number} value, An unsigned 32 bit integer number.
            * @params {number} positions, Number of positions to shift.
            *
            * @returns {number}, The resulting number after shifting.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static shiftRight32(value: number, positions: number): number;
            /**
            * @description Shifts the bits in the unsigned 64 bit integer given in argument 'value' as many positions
            *  rightwise as given in argument'positions'. Returns the value after shifting.
            *
            * @params {number} value, An unsigned 64 bit integer number.
            * @params {number} positions, Number of positions to shift.
            *
            * @returns {number}, The resulting number after shifting.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static shiftRight64(value: TS.TypeCode.UInt64, positions: number): TS.TypeCode.UInt64;
            /**
            * @description Performs: (ror 2) ^ (ror 13) ^ (ror 22)
            *
            * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.2 SHA-224 and SHA-256 Functions }
            *
            * @param {number} x
            *
            * @returns {number}
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static sigma0_32(x: number): number;
            /**
            * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.3 SHA-384, SHA-512, SHA-512 / 224 and SHA-512 / 256 Functions }
            *
            * @param {TS.TypeCode.UInt64} x
            *
            * @returns {TS.TypeCode.UInt64}
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static sigma0_64(x: TS.TypeCode.UInt64): TS.TypeCode.UInt64;
            /**
            * @description Performs: (ror 6) ^ (ror 11) ^ (ror 25)
            *
            * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | 4.1.2 SHA-224 and SHA-256 Functions }
            *
            * @param {number} x
            *
            * @returns {number}
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected static sigma1_32(x: number): number;
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.AbstractStreamCipher
        *
        * @description This is the abstract stream cipher base class. The stream cipher operates asynchronous.
        *  You can use one of the write functions to feed the cipher stream. Call the close function when you have finished.
        *  The callback function 'onData' gets called each time a complete encrypted / decrypted chunk of data is available
        *  as long as the stream haven't closed. The 'onClose' callback function is called when the stream has finally
        *  closed. Due to the asynchronous nature of the stream, the call to the 'onClose' callback function on the consumer
        *  side, may appear significant later than the call to the close function from the feedings side of the stream.
        *
        *  The stream uses the 'blockCipher' object which must be an instance of one of the AES operation modes and
        *  schould be set in the constructor. You must also set the 'bufferSizeInBit' which must match with the
        *  requirements of the chosen 'blockCipher'.
        *
        *  The functions 'cipher' and 'internalClose' are abstract and must be implemented in subclasses.
        *
        *  Set the streamState to 'StreamStateEnum.CREATED' when you have finished the construction in a subclass.
        *
        *  The stream can only be used once. Once the 'onClose' or the 'onError' callback has been called, the stream is
        *  locked for further write operations.
        */
        abstract class AbstractStreamCipher {
            /**
            * @private
            */
            private timer;
            /**
            * @description One of the AES operation mode instances.
            *
            * @protected
            */
            protected blockCipher: TS.Security.AES;
            /**
            * @description The cipher operation (encrypt or decrypt) used for the current stream.
            *
            * @protected
            */
            protected cipherOperation: TS.Security.CipherOperationEnum;
            /**
            * @description The buffer size in bit use for the current stream. That is either the block size of the underlying
            *  block cipher or the segment size.
            *
            * @protected
            */
            protected bufferSizeInBit: number;
            /**
            * @description The state of the current stream.
            *
            * @protected
            */
            protected streamState: StreamStateEnum;
            /**
            * @description The input buffer which holds the feeded data as bit string until processing.
            *
            * @protected
            */
            protected inputBuffer: string;
            /**
            * @description The callback handler which is called on each successful processed chunk of data.
            *
            * @protected
            */
            protected onNextData: (bitString: string) => void;
            /**
            * @description The callback handler which is called when the stream has finally closed.
            *
            * @protected
            */
            protected onClosed: () => void;
            /**
            * @description The callback handler which is called when an error occured. After that the stream is locked and can
            *  not longer be used for any operation.
            *
            * @protected
            */
            protected onError: (exception: TS.Exception) => void;
            /**
            * @constructor
            *
            * @description Creates a new AbstractStreamCipher instance with the given cipherOperatin and callback functions
            *  which are common to all stream ciphers classes.
            *
            * @param {TS.Security.CipherOperationEnum} cipherOperation, The cipher operation used in this stream.
            * @param {(bitString: string) => void} onNextData, The callback which is called for each successful processed chunk of data.
            * @param {() => void} onClosed, The callback which is called when the stream has finally closed.
            * @param {(exception: TS.Exception) => void} onError, The callback which is called in case of an error.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidOperationException}
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.ArgumentException}
            * @throws {TS.InvalidTypeException}
            */
            constructor(cipherOperation: TS.Security.CipherOperationEnum, onNextData: (bitString: string) => void, onClosed: () => void, onError: (exception: TS.Exception) => void);
            /**
            * @description Writes the byte array given in argument 'byteArray' to the current stream.
            *
            * @param {Array<number>} byteArray
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.InvalidOperationException}
            */
            writeByteArray(byteArray: Array<number>): void;
            /**
            * @description Writes the byte value given in argument 'byteValue' to the current stream.
            *
            * @param {Array<number>} byteValue
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.InvalidOperationException}
            */
            writeByte(byteValue: number): void;
            /**
            * @description Writes the bit string given in argument 'bitString' to the current stream.
            *
            * @param {string} bitString
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.InvalidOperationException}
            */
            writeBitString(bitString: string): void;
            /**
            * @description Closes the current stream for writing. Since the stream operates asynchronous, the last output
            *  from that stream may appear significant later. The stream is finally closed when the 'onClosed' callback
            *  function is called which was designated during construction.
            */
            close(): void;
            /**
            * @descriptions Stops the internal timer.
            *
            * @private
            */
            private stopTimer();
            /**
            * @descriptions Starts the internal timer.
            *
            * @private
            */
            private startTimer();
            /**
            * @description This function uses the 'blockCipher' which was set in the constructor to encrypt / decrypt
            *  the buffer given in argument 'bitString' and returns the result as bit string. This function must be
            *  iplemented in all derived classes and is used for all cipher operations on the stream.
            *
            * @abstract
            * @protected
            *
            * @param {string} bitString, A bit string which has the length of the 'bufferSizeInBit' which should be set in
            *  the constructor.
            *
            * @returns {string}, The encrypted / decrypted data as bit string.
            */
            protected abstract cipher(bitString: string): string;
            /**
            * @descriptions Initialize the class.
            *
            * @private
            *
            * @throws {TS.InvalidOperationException}
            */
            private initialize();
            /**
            * @descriptions Processes the data from the input buffer. That means, looking if there is enough data to fill a
            *  segment. Execute the cipher operation on that segment and signal the consumer that there is a new chunk
            *  of data available by calling the 'onNextData' callback.
            *
            * @private
            */
            private process();
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.AES
        *
        * @description This class is an implements of the ADVANCED ENCRYPTION STANDARD (AES) as described in the FIPS
        *  publication fips-197, 'Announcing the ADVANCED ENCRYPTION STANDARD (AES)'. The cipher mode described in that
        *  publication is also identical to the ELECTRONIC CODE BOOK (ECB) operation mode described in the NIST
        *  publication 800-38a, 'Recommendation for Block Cipher Modes of Operation'.
        *
        * @see {@link http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf | NIST}
        * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
        */
        class AES extends TS.Security.Cryptography {
            /**
            * @description The working key byte array holds the working key which was created from the initial key by the key
            *  expansion function.
            *
            * @see {TS.Security.AES.expandKey}
            *
            * @protected
            */
            protected workingKeyByteArray: Array<number>;
            /**
            * @description Number of rounds executed per cipher operation. The value of this variable depends on the key
            *  lenght used in the constructor.
            *
            * @protected
            */
            protected rounds: number;
            /**
            * @constructor
            *
            * @description Creates a new AES instance with the key given in argument 'keyByteArray'. The 'keyByteArray' must
            *  have a total length of 128, 192 or 256 bits. That means the 'keyByteArray' array must have a length of either
            *  16, 24 or 32. Using a key which doesn't comply with that rule will raise an exception.
            *
            * @param {Array<number>} keyByteArray, An array of [16 | 24 | 32] byte holding the key.
            *
            * @throws {TS.ArgumentNullOrUndefinedException#}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentOutOfRangeException}
            */
            constructor(keyByteArray: Array<number>);
            /**
            * @description Encrypts the data provided in argument 'data' and returns the enrypted data as byte array. The
            *  data must be aligned to 16 byte. That means the total length of the data byte array must be n * 16, where n is
            *  any positive integer number greater zero.
            *
            * @param {Array<number>} data, The plain data array.
            *
            * @returns {Array<number>}, The enrcypted data array.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentException}
            */
            encrypt(data: Array<number>): Array<number>;
            /**
            * @description Decrypts a block of 16 byte cipher data and returns the decrypted block as byte array.
            *
            * @param {Array<number>} dataByteArray, The array must be aligned to 16 byte. That means the length must be
            *  n * 16, where n is any positive integer number greater zero.
            *
            * @returns {Array<number>}, The decrypted data as byte array.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentException}
            */
            decrypt(dataByteArray: Array<number>): Array<number>;
            /**
            * @description Encrypts or decrypts the data given in argument 'dataByteArray' and returns the processed data as
            *  byte array.
            *
            * @protected
            *
            * @param {Array<number>} dataByteArray, array of 16 byte values.
            * @param {CipherOperationEnum} cipherOperation
            *
            * @return {Array<number>}, The resulting encrypted or decrypted data as byte array.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentException}
            */
            protected encryptDecryptInternal(dataByteArray: Array<number>, cipherOperation: CipherOperationEnum): Array<number>;
            /**
            * @description The function substitues each byte in the byteArray by its substitute and returns the new created
            *  byte array.
            *
            * @private
            * @static
            *
            * @returns {Array<number>}
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            private static substituteBytes(byteArray);
            /**
            * @description Expands the initial key and returns the resulting working key as byte array.
            *
            * @private
            * @static
            *
            * @see {TS.Security.AES.workingKeyByteArray}
            * @see {@link http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf} Chapter 5.2 Key Expansion
            *
            * @param {Array<number>} keyByteArray, An array of bytes which holds the initial key.
            * @param {number} rounds
            *
            * @returns {Array<number>}, The resulting working key as byte array.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentOutOfRangeException}
            */
            private static expandKey(keyByteArray);
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.AES_CBC_Stream
        *
        * @description This is an implementation of the abstract base class 'TS.Security.AbstractStreamCipher' for the
        *  AES_CBC operation mode.
        *
        * @extends {TS.Security.AbstractStreamCipher}
        */
        class AES_CBC_Stream extends TS.Security.AbstractStreamCipher {
            /**
            * @constructor
            *
            * @param {Array<number>} keyByteArray
            * @param {Array<number>} initialisationVector
            * @param {TS.Security.CipherOperationEnum} cipherOperation
            * @param {(bitString: string) => void} onNextData
            * @param {() => void} onClosed
            * @param {(exception: TS.Exception) => void} onError
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentOutOfRangeException}
            */
            constructor(keyByteArray: Array<number>, initialisationVector: Array<number>, cipherOperation: TS.Security.CipherOperationEnum, onNextData: (bitString: string) => void, onClosed: () => void, onError: (exception: TS.Exception) => void);
            /**
            * @description This function uses the current 'blockCipher' to encrypt / decrypt the 'bitString'. Returns the
            *  encrypted / decryped data as bit string.
            *
            * @override
            * @protected
            *
            * @param {string} bitString, A bit string which has the length of the 'bufferSizeInBit'.
            *
            * @returns {string}, The encrypted / decrypted data as bit string.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
            * @throws {TS.InvalidTypeException}
            */
            protected cipher(bitString: string): string;
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.AES_CFB
        *
        * @description This is an implementation of the CIPHER FEEDBACK (CFB) operation mode as described in the NIST
        *  publication 800-38a, 'Recommendation for Block Cipher Modes of Operation'.
        *
        * @extends {TS.Scecurity.AES}
        *
        * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
        */
        class AES_CFB extends TS.Security.AES {
            /**
             * @private
             */
            private inputState;
            private IV;
            /**
             * @private
             */
            private segmentSizeInBit;
            /**
            * @constructor
            *
            * @description Creates a new AES_CFB instance with the key given in argument 'keyByteArray', the initialisation
            *  vector given in argument 'initialisationVector' and the segment size in bit given in argument
            *  'segmentSizeInBit'. The 'keyByteArray' must have a total length of 128, 192 or 256 bits. That means the
            *  'keyByteArray' array must have a length of either 16, 24 or 32. Using a key which doesn't comply with that
            *  rule will raise an exception. The initialisation vector must be an array of unsigned byte values with a total
            *  of 16 elements. The 'segmentSizeInBit' must be a value in the range of [1..128]. The segment size denotes the
            *  data size the cipher object will operate on. The AES_CFB mode is the only AES operation mode which give you
            *  totally freedom in choosing the data size you intend to use. At least in the allowed range between 1 and 128.
            *  So if you have to encrypt / decrypt single bits, this operation mode will be your best choice But you have to
            *  pay for that freedom with a bad runtime behavior. It goes from worst behavior by a segment size of 1 bit, to
            *  best behavior by a segment size of 128 bit, which is the normal block length of the AES algorithm.
            *
            * @param {Array<number>} keyByteArray, An array of [16 | 24 | 32] byte holding the key.
            * @param {Array<number>} initialisationVector, An array of 16 byte holding the initalisation vector.
            * @param {number} segmentSizeInBit, Must be a numbe between [1..128].
            *
            * @throws {TS.ArgumentOutOfRangeException}
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            constructor(keyByteArray: Array<number>, initialisationVector: Array<number>, segmentSizeInBit: number);
            /**
            * @description Encrypts the data given in argument 'plainDataByteArray' and returns the encrypted data as byte
            *  array. This function will not work if the segment size doesn't align with byte length (8 bit).
            *
            * @override
            *
            * @param {Array<number>} plainDataByteArray
            *
            * @returns {Array<number>} The encrypted data as byte array.
            *
            * @throws {TS.InvalidOperationException}
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            encrypt(plainDataByteArray: Array<number>): Array<number>;
            /**
            * @description Decrypts the data given in argument 'plainDataByteArray' and returns the decrypted data as byte
            *  array. This function will not work if the segment size doesn't align with byte length (8 bit).
            *
            * @override
            *
            * @param {Array<number>} cipherDataByteArray
            *
            * @returns {Array<number>} The decrypted data as byte array.
            *
            * @throws {TS.InvalidOperationException}
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            decrypt(cipherDataByteArray: Array<number>): Array<number>;
            /**
            * @description Encrypts the data given in argument 'bitString' and returns the encrypted data as bit string. This
            *  function will not work if the 'bitString' doesn't align with the 'segmentSizeInBit'.
            *
            * @param {string} bitString, The plain data as bit string.
            *
            * @returns {string}, The encrypted data as bit string.
            *
            * @throws {TS.InvalidOperationException}
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
            * @throws {TS.InvalidTypeException}
            */
            encryptBitString(bitString: string): string;
            /**
            * @description Decrypts the data given in argument 'bitString' and returns the decrypted data as bit string. This
            *  function will not work if the 'bitString' doesn't align with the 'segmentSizeInBit'.
            *
            * @param {string} bitString, The encrypted data as bit string.
            *
            * @returns {string}, The decrypted data as bit string.
            *
            * @throws {TS.InvalidOperationException}
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
            * @throws {TS.InvalidTypeException}
            */
            decryptBitString(bitString: string): string;
            /**
            * @description Encrypts or decrypts the data given in argument 'dataByteArray' and returns the processed data as
            *  byte array.
            *
            * @override
            *
            * @param {Array<number>} dataByteArray
            * @param {CipherOperationEnum} cipherOperation
            *
            * @returns {Array<number>}, The resulting encrypted or decrypted data as byte array.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            protected encryptDecryptInternal(dataByteArray: Array<number>, cipherOperation: CipherOperationEnum): Array<number>;
            /**
            * @descriptions Encrypts or decrypts the data given in argument 'bitString' by using the operation mode given in
            *  argument 'cipherOperation'.
            *
            * @private
            *
            * @param {string} bitString
            * @param {CipherOperationEnum} cipherOperation
            *
            * @returns {string}, The ecnrypted or decrypted result string
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
            * @throws {TS.InvalidTypeException}
            */
            private encryptDecryptBitString(bitString, cipherOperation);
            /**
            * @descriptions Encrypts or decrypts the data segment given in argument 'bitString' by using the operation mode
            *  given in argument 'cipherOperation', the state given in argument 'inputState' and the segment size given in
            *  argument 'segmentSizeInBit'.
            *
            * @private
            *
            * @param {string} bitString
            * @param {CipherOperationEnum} cipherOperation
            * @param {TS.Security.State} inputState
            * @param {number} segmentSizeInBit
            *
            * @returns {string}, The ecnrypted or decrypted result string
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
            * @throws {TS.InvalidTypeException}
            */
            private encryptDecryptSegment(bitString, cipherOperation, inputState, segmentSizeInBit);
            /**
            * @description Creates a new state form the state given in argument 'state' and the cipher segment given in
            *  argument 'cipherSegment'.
            *
            * @private
            *
            * @param {TS.Security.State} state
            * @param {string} cipherSegment
            *
            * @returns {TS.Security.State}
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
            * @throws {TS.InvalidTypeException}
            */
            private createNextInputState(state, cipherSegment);
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.AES_CFB_Stream
        *
        * @description This is an implementation of the abstract base class 'TS.Security.AbstractStreamCipher' for the
        *  AES_CFB operation mode.
        *
        * @extends {TS.Security.AbstractStreamCipher}
        */
        class AES_CFB_Stream extends TS.Security.AbstractStreamCipher {
            /**
            * @constructor
            *
            * @param {Array<number>} keyByteArray
            * @param {Array<number>} initialisationVector
            * @param {number} segmentSizeInBit
            * @param {TS.Security.CipherOperationEnum} cipherOperation
            * @param {(bitString: string) => void} onNextData
            * @param {() => void} onClosed
            * @param {(exception: TS.Exception) => void} onError
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentOutOfRangeException}
            */
            constructor(keyByteArray: Array<number>, initialisationVector: Array<number>, segmentSizeInBit: number, cipherOperation: TS.Security.CipherOperationEnum, onNextData: (bitString: string) => void, onClosed: () => void, onError: (exception: TS.Exception) => void);
            /**
            * @description This function uses the current 'blockCipher' to encrypt / decrypt the 'bitString'. Returns the
            *  encrypted / decryped data as byte array.
            *
            * @override
            * @protected
            *
            * @param {string} bitString, A bit string which has the length of the 'bufferSizeInBit'.
            *
            * @returns {string}, The encrypted / decrypted data as bit string.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
            * @throws {TS.InvalidTypeException}
            */
            protected cipher(bitString: string): string;
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.AES_CTR
        *
        * @description This is an implementation of the COUNTER (CTR) operation mode as described in the NIST
        *  publication 800-38a,'Recommendation for Block Cipher Modes of Operation'.
        *
        * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
        */
        class AES_CTR extends AES {
            /**
            * @private
            */
            private internalCTR;
            /**
            * @description The nonce which is actually used in this AES_CTR object. You need to store this nonce along with
            *  your encrypted data. Otherwies you won't be able to decrypt the data anymore.
            *
            * @get {Array<number>} nonce, The nonce as array of 16 byte values.
            */
            nonce: Array<number>;
            /**
            * @constructor
            *
            * @description Creates a new AES_CTR instance with the key given in argument 'keyByteArray' and the counter value
            *  given in argument 'counterValue' The 'keyByteArray' must have a total length of 128, 192 or 256 bits. That
            *  means the 'keyByteArray' array must have a length of either 16, 24 or 32. Using a key which doesn't comply
            *  with that rule will raise an exception. The 'counterValue' must be a value in the range of [0..0xFFFF].
            *
            * @param {Array<number>} keyByteArray, An array of [16 | 24 | 32] byte holding the key.
            * @param {number} counterValue, A value in the range [0..0xFFFFFFFF].
            *
            * @trhows {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.InvalidOperationException}
            * @throws {TS.ArgumentException}
            * @throws {TS.ArgumentOutOfRangeException}
            */
            constructor(keyByteArray: Array<number>, counterValue: number);
            /**
            * @constructor
            *
            * @description Creates a new AES_CTR instance with the key given in argument 'keyByteArray' and the nonce given in
            *  argument 'nonce' The 'keyByteArray' must have a total length of 128, 192 or 256 bits. That means the
            *  'keyByteArray' array must have a length of either 16, 24 or 32. Using a key which doesn't comply with that
            *   rule will raise an exception. The nonce must be a byte array with 16 elements.
            *
            * @param {Array<number>} keyByteArray, An array of [16 | 24 | 32] byte holding the key.
            * @param {Array<number>} nonce, An array of 16 byte value elements.
            *
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.InvalidOperationException}
            * @throws {TS.ArgumentException}
            * @throws {TS.ArgumentOutOfRangeException}
            */
            constructor(keyByteArray: Array<number>, nonce: Array<number>);
            /**
            * @constructor
            *
            * @description Creates a new AES_CTR instance with the key given in argument 'keyByteArray'. The 'keyByteArray'
            *  must have a total length of 128, 192 or 256 bits. That means the 'keyByteArray' array must have a length of
            *  either 16, 24 or 32. Using a key which doesn't comply with that rule will raise an exception. You can use this
            *  constructor when you plan to encrypt some data with the created 'AES_CTR' object. The constructor creates a
            *  random nonce which will be used during the encryption process. You can allways access the actually used nonce
            *  by reading out the 'nonce' property of the 'AES_CTR' object. You must store that nonce together with the
            *  enrypted data. You will need that nonce for the decryption process.
            *
            * @param {Array<number>} keyByteArray, An array of [16 | 24 | 32] byte holding the key.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidOperationException}
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentOutOfRangeException}
            */
            constructor(keyByteArray: Array<number>);
            /**
            * @description Encrypts the data given in argument 'plainDataByteArray' and returns the encrypted data as byte
            *  array.
            *
            * @override
            *
            * @param {Array<number>} plainDataByteArray
            *
            * @returns {Array<number>}, The encrypted data as byte array.
            *
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.InvalidTypeException}
            */
            encrypt(plainDataByteArray: Array<number>): Array<number>;
            /**
            * @description Decrypts the data given in argument 'plainDataByteArray' and returns the decrypted data as byte
            *  array.
            *
            * @override
            *
            * @param { Array<number>} cipherDataByteArray
            *
            * @returns {Array<number>}, The decrypted data as byte array.
            *
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.InvalidTypeException}
            */
            decrypt(cipherDataByteArray: Array<number>): Array<number>;
            /**
            * @description Encrypts or decrypts the data given in argument 'dataByteArray' and returns the processed data as
            *  byte array.
            *
            * @override
            *
            * @param {Array<number>} dataByteArray
            *
            * @return {Array<number>}, The resulting encrypted or decrypted data as byte array.
            */
            protected encryptDecryptInternal(dataByteArray: Array<number>): Array<number>;
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.AES_CTR_Stream
        *
        * @description This is an implementation of the abstract base class 'TS.Security.AbstractStreamCipher' for the
        *  AES_CTR operation mode.
        *
        * @see {TS.Security.AbstractStreamCipher}
        */
        class AES_CTR_Stream extends AbstractStreamCipher {
            /**
            * @constructor
            *
            * @description Create a new AES_CTR_Stream instance with the key given in argument 'keyByteArray' and the nonce
            *  given in argument 'nonce'. The 'keyByteArray' must have a total length of 128, 192 or 256 bits. That means the
            *  'keyByteArray' array must have a length of either 16, 24 or 32. Using a key which doesn't comply with that
            *  rule will raise an exception.
            *
            * @param {Array<number>} keyByteArray, An array of [16 | 24 | 32] byte holding the key.
            * @param {Array<number>} nonce, An array of 16 byte holding the nonce for the cipher object.
            * @param {TS.Security.CipherOperationEnum} cipherOperation, The cipher operation executed in this stream.
            * @param {(bitString: string) => void} onNextData, The callback which is called for each successful ciphered chunk of data.
            * @param {() => void} onClosed, The callback which is called when the stream has finally closed.
            * @param {(exception: TS.Exception) => void} onError, The callback which is called in case of an error.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentOutOfRangeException}
            */
            constructor(keyByteArray: Array<number>, nonce: Array<number>, cipherOperation: TS.Security.CipherOperationEnum, onNextData: (bitString: string) => void, onClosed: () => void, onError: (exception: TS.Exception) => void);
            /**
            * @constructor
            *
            * @description Create a new AES_CTR_Stream instance with the key given in argument 'keyByteArray' and the counter
            *  value given in argument 'counterValue'. The 'keyByteArray' must have a total length of 128, 192 or 256 bits.
            *  That means the 'keyByteArray' array must have a length of either 16, 24 or 32. Using a key which doesn't
            *  comply with that rule will raise an exception.
            *
            * @param {Array<number>} keyByteArray, An array of [16 | 24 | 32] byte holding the key.
            * @param {number} counterValue, The initial conter value of the cipher object in the range [0..0xFFFF].
            * @param {TS.Security.CipherOperationEnum} cipherOperation, The cipher operation executed in this stream.
            * @param {(bitString: string) => void} onNextData, The callback which is called for each successful ciphered
            *  chunk of data.
            * @param {() => void} onClosed, The callback which is called when the stream has finally closed.
            * @param {(exception: TS.Exception) => void} onError, The callback which is called in case of an error.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentOutOfRangeException}
            */
            constructor(keyByteArray: Array<number>, counterValue: number, cipherOperation: TS.Security.CipherOperationEnum, onNextData: (bitString: string) => void, onClosed: () => void, onError: (exception: TS.Exception) => void);
            /**
            * @description This function uses the current 'blockCipher' to encrypt / decrypt the 'bitString'. Returns the
            *  encrypted / decryped data as bit string.
            *
            * @override
            * @protected
            *
            * @param {string} bitString, A bit string which has the length of the 'bufferSizeInBit'.
            *
            * @returns {string}, The encrypted / decrypted data as bit string.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
            * @throws {TS.InvalidTypeException}
            */
            protected cipher(bitString: string): string;
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.AES_OFB
        *
        * @description This is an implementation of the OUTPUT FEEDBACK (OFB) operation mode as described in the NIST
        *  publication 800-38a, 'Recommendation for Block Cipher Modes of Operation'.
        *
        * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
        */
        class AES_OFB extends TS.Security.AES {
            /**
            * @private
            */
            private IV;
            /**
            * @constructor
            *
            * @description Creates a new AES_OFB instance with the key given in argument 'keyByteArray'. The 'keyByteArray'
            *  must have a total length of 128, 192 or 256 bits. That means the 'keyByteArray' array must have a length of
            *  either 16, 24 or 32. Using a key which doesn't comply with that rule will raise an exception.
            *  The value of argument 'initialisationVector' must be an array of 16 byte.
            *
            * @param {Array<number>}, keyByteArray
            * @param { Array<number>} initialisationVector
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidOperationException}
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentOutOfRangeException}
            */
            constructor(keyByteArray: Array<number>, initialisationVector: Array<number>);
            /**
            * @description Encrypts the data given in argument 'plainDataByteArray' and returns the encrypted data as byte
            *  array.
            *
            * @override
            *
            * @param {Array<number>} plainDataByteArray
            *
            * @returns {Array<number>}, The encrypted data as byte array.
            *
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.InvalidTypeException}
            */
            encrypt(plainDataByteArray: Array<number>): Array<number>;
            /**
            * @description Decrypts the data given in argument 'plainDataByteArray' and returns the decrypted data as byte
            *  array.
            *
            * @override
            *
            * @param { Array<number>} cipherDataByteArray
            *
            * @returns {Array<number>}, The decrypted data as byte array.
            *
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.InvalidTypeException}
            */
            decrypt(cypherDataByteArray: Array<number>): Array<number>;
            /**
            * @description Encrypts or decrypts the data given in argument 'dataByteArray' and returns the processed data as
            *  byte array.
            *
            * @override
            *
            * @param {Array<number>} dataByteArray
            *
            * @return {Array<number>}, The resulting encrypted or decrypted data as byte array.
            */
            protected encryptDecryptInternal(dataByteArray: Array<number>): Array<number>;
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.AES_OFB_Stream
        *
        * @description This is an implementation of the abstract base class 'TS.Security.AbstractStreamCipher' for the
        *  AES_OFB operation mode.
        *
        * @extends {TS.Security.AbstractStreamCipher}
        */
        class AES_OFB_Stream extends TS.Security.AbstractStreamCipher {
            /**
            * @constructor
            *
            * @description Create a new AES_OFB_Stream instance with the key given in argument 'keyByteArray' and the
            *  initialisation vector given in argument 'initialisationVector'. The 'keyByteArray' must have a total length of
            *  128, 192 or 256 bits. That means the 'keyByteArray' array must have a length of either 16, 24 or 32. Using a
            *  key which doesn't comply with that rule will raise an exception.
            *
            * @param {Array<number>} keyByteArray, An array of [16 | 24 | 32] byte holding the key.
            * @param {Array<number>} initialisationVector, An array of 16 byte holding the initalisation vector.
            * @param {TS.Security.CipherOperationEnum} cipherOperation, The cipher operation executed in this stream.
            * @param {(bitString: string) => void} onNextData, The callback which is called for each successful ciphered chunk of data.
            * @param {() => void} onClosed, The callback which is called when the stream has finally closed.
            * @param {(exception: TS.Exception) => void} onError, The callback which is called in case of an error.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidOperationException}
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.ArgumentException}
            * @throws {TS.ArgumentOutOfRangeException}
            * @throws {TS.InvalidTypeException}
            */
            constructor(keyByteArray: Array<number>, initialisationVector: Array<number>, cipherOperation: TS.Security.CipherOperationEnum, onNextData: (bitString: string) => void, onClosed: () => void, onError: (exception: TS.Exception) => void);
            /**
            * @description This function uses the current 'blockCipher' to encrypt / decrypt the 'bitString'. Returns the
            *  encrypted / decryped data as bit string.
            *
            * @override
            * @protected
            *
            * @param {string} bitString, A bit string which has the length of the 'bufferSizeInBit'.
            *
            * @returns {string}, The encrypted / decrypted data as bit string.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
            * @throws {TS.InvalidTypeException}
            */
            protected cipher(bitString: string): string;
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.AES_Stream
        *
        * @description This is an implementation of the abstract base class 'TS.Security.AbstractStreamCipher' for the
        *  AES / AES_ECB operation mode.
        *
        * @see {TS.Security.AbstractStreamCipher}
        */
        class AES_Stream extends AbstractStreamCipher {
            /**
            * @constructor
            *
            * @description Create a new AES_Stream instance with the key given in argument 'keyByteArray'. The 'keyByteArray'
            *  must have a total length of 128, 192 or 256 bits. That means the 'keyByteArray' array must have a length of
            *  either 16, 24 or 32. Using a key which doesn't comply with that rule will raise an exception.
            *
            * @param {Array<number>} keyByteArray, An array of [16 | 24 | 32] byte holding the key.
            * @param {TS.Security.CipherOperationEnum} cipherOperation, The cipher operation executed in this stream.
            * @param {(bitString: string) => void} onNextData, The callback which is called for each successful ciphered chunk of data.
            * @param {() => void} onClosed, The callback which is called when the stream has finally closed.
            * @param {(exception: TS.Exception) => void} onError, The callback which is called in case of an error.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidOperationException}
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.ArgumentException}
            * @throws {TS.ArgumentOutOfRangeException}
            * @throws {TS.InvalidTypeException}
            */
            constructor(keyByteArray: Array<number>, cipherOperation: TS.Security.CipherOperationEnum, onNextData: (bitString: string) => void, onClosed: () => void, onError: (exception: TS.Exception) => void);
            /**
            * @description This function uses the current 'blockCipher' to encrypt / decrypt the 'bitString'. Returns the
            *  encrypted / decryped data as bit string.
            *
            * @override
            * @protected
            *
            * @param {string} bitString, A bit string which has the length of the 'bufferSizeInBit'.
            *
            * @returns {string}, The encrypted / decrypted data as bit string.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
            * @throws {TS.InvalidTypeException}
            */
            protected cipher(bitString: string): string;
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.Counter
        *
        * @description A counter which returns a maximum of 0xFFFFFFFF <=> 4294967295 distinguish values. The counter can
        *  be used as simple counter which produces integer numbers by consecutive readings of the 'nextCounter' property
        *  or as a state generator by consecutive readings of the 'nextState' property.
        *
        * @extends {TS.Security.Cryptography}
        */
        class Counter extends TS.Security.Cryptography {
            private internalCurrentCounterValue;
            private internalInitialCounterValue;
            private internalCounterStarted;
            private internalNonceArray;
            /**
            * @get {Array<number>} nonce, The nonce wich was used or created during construction.
            */
            nonce: Array<number>;
            /**
            * @get { TS.Security.State} nextState, The next counter state.
            *
            * @throws {TS.IndexOutOfRangeException}
            */
            nextState: TS.Security.State;
            /**
            * @get { TS.Security.State} nextCounter, The next counter.
            *
            * @throws {TS.IndexOutOfRangeException}
            */
            nextCounter: number;
            /**
            * @constructor
            *
            * @description Creates a new counter using the provided 'nonce' value to create the initial value. Setting the
            *  'initialCounter' to 0.
            *
            * @param {Array<number>} nonce, An array of 16 unsigned byte values.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidOperationException}
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.ArgumentOutOfRangeException}
            * @throws {TS.InvalidTypeException}
            */
            constructor(nonce: Array<number>);
            /**
            * @constructor
            *
            * @description Creates a new counter using the provided 'initialCounter' to initialize the counter.
            *
            * @param {number} initialCounter, An unsigned integer in the range of [0..0xFFFFFFFF]
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidOperationException}
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.ArgumentOutOfRangeException}
            * @throws {TS.InvalidTypeException}
            */
            constructor(initialCounter: number);
            /**
            * @constructor
            *
            * @description Creates a new counter using a default nonce to initialize the counter.
            *
            * @param {Array<number>} nonce,
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidOperationException}
            */
            constructor();
            /**
            * @returns {number}, The next counter value.
            *
            * @throws {TS.IndexOutOfRangeException}
            */
            private getNextCounter();
            /**
            * @returns {TS.Security.State} , The next counter state.
            *
            * @throws {TS.IndexOutOfRangeException}
            */
            private getNextState();
            /**
             * @private
             */
            private createNonceArray();
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.RandomNumberGenerator
        *
        * @description This class is an implements of the Random Number Generator as described in the NIST publication:
        *  'NIST Recommended Random Number Generator Based On ANSI X9.31 Appendix A.2.4'.
        *
        * @see {@link http://csrc.nist.gov/groups/STM/cavp/documents/rng/931rngext.pdf | NIST}
        */
        class RandomNumberGenerator extends TS.Security.Cryptography {
            private aes;
            private state;
            /**
            * @description Returns the next array of 16 random bytes.
            */
            next: Array<number>;
            /**
            * @constructor
            *
            * @description Create a new RandomNumberGenerator instance with the key given in argument 'keyByteArray'. The
            *  'keyByteArray' must have a total length of 128, 192 or 256 bits. That means the 'keyByteArray' array must have
            *   a length of either 16, 24 or 32. Using a key which doesn't comply with that rule will raise an exception. The
            *   initialisationVector must be an array of 16 byte values which should show a high level of entropy.
            *
            * @param {Array<number>} keyByteArray
            * @param {Array<number>} initialisationVector, An array of 16 byte holding the initalisation vector.
            *
            * @throws {TS.ArgumentException}
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.ArgumentOutOfRangeException}
            */
            constructor(keyByteArray: Array<number>, initialisationVector: Array<number>);
            /**
            * @description Creates and returns the next array of 16 random bytes.
            *
            * @returns {Array<number>} , An array of 16 random bytes.
            */
            private createNext();
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.SHA1
        *
        * @classdesc This class implements the SHA1 hash algorithm as described in the nist publication
        *  'FIPS PUB 180-4, Secure Hash Standard (SHS)'.
        *
        * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | NIST }
        */
        class SHA1 extends Cryptography {
            /**
            * @private
            */
            private hash0;
            /**
            * @private
            */
            private hash1;
            /**
            * @private
            */
            private hash2;
            /**
            * @private
            */
            private hash3;
            /**
            * @private
            */
            private hash4;
            /**
            * @private
            */
            private roundConstant0;
            /**
            * @private
            */
            private roundConstant1;
            /**
            * @private
            */
            private roundConstant2;
            /**
            * @private
            */
            private roundConstant3;
            /**
            * @constructor
            */
            constructor();
            /**
            * @descriptions Initializes the hash values and the round constants.
            *
            * @private
            */
            private initialize();
            /**
            * @description Encrypts the plain text given in argument 'message' and returns the digest / SHA1 hash as a
            *  hexadecimal string.
            *
            * @param {string | Array<number>} message, Either a simple text string or an array of unsigned byte values.
            *
            * @returns {string}, The resulting digest / SHA1 as HEX string.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            encrypt(message: string | Array<number>): string;
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.SHA224
        *
        * @classdesc This class implements the SAH224 hash algorithm as described in the nist publication
        *  'FIPS PUB 180-4, Secure Hash Standard (SHS)'.
        *
        *  @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | NIST }
        */
        class SHA224 extends TS.Security.Cryptography {
            /**
            * @private
            */
            private hash0;
            /**
            * @private
            */
            private hash1;
            /**
            * @private
            */
            private hash2;
            /**
            * @private
            */
            private hash3;
            /**
            * @private
            */
            private hash4;
            /**
            * @private
            */
            private hash5;
            /**
            * @private
            */
            private hash6;
            /**
            * @private
            */
            private hash7;
            /**
            * @private
            */
            private roundConstantArray;
            constructor();
            /**
            * @descriptions Initializes the hash values and the round constant array.
            *
            * @private
            */
            private initialize();
            /**
            * @description Encrypts the plain text given in argument 'message' and returns the digest / SHA224 hash as a
            *  hexadecimal string.
            *
            * @param {string | Array<number>} message, Either a simple text string or an array of unsigned byte values.
            * @returns {string}, The resulting digest / SHA224 as HEX string.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            encrypt(message: string | Array<number>): string;
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.SHA256
        *
        * @classdesc This class implements the SHA256 hash algorithm as described in the nist publication
        *  'FIPS PUB 180-4, Secure Hash Standard (SHS)'.
        *
        *  @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | NIST }
        */
        class SHA256 extends Cryptography {
            /**
            * @private
            */
            private hash0;
            /**
            * @private
            */
            private hash1;
            /**
            * @private
            */
            private hash2;
            /**
            * @private
            */
            private hash3;
            /**
            * @private
            */
            private hash4;
            /**
            * @private
            */
            private hash5;
            /**
            * @private
            */
            private hash6;
            /**
            * @private
            */
            private hash7;
            /**
            * @private
            */
            private roundConstantArray;
            /**
            * @constructor
            */
            constructor();
            private initialize();
            /**
            * @description Encrypts the plain text given in argument 'message' and returns the digest / SHA256 hash as a hexadecimal string.
            *
            * @param {string | Array<number>} message, Either a simple text string or an array of unsigned byte values.
            * @returns {string}, The resulting digest / SHA256 as HEX string.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            encrypt(message: string | Array<number>): string;
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.State
        * @extends {TS.Security.Cryptography}
        */
        class State extends TS.Security.Cryptography {
            private state;
            Hex: Array<Array<string>>;
            /**
            * @constructor
            * @description Creates a new State instance from the byte array given in argument 'byteArray16'.
            *
            * @param {Array<number>} byteArray16, An array of 16 byte values.
            *
            * @throws {TS.ArgumentNullUndefOrEmptyException}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentOutOfRangeException}
            */
            constructor(byteArray16: Array<number>);
            /**
            * @description Executes the forward cipher operation on the current state.
            *
            * @param {Array<number>} workingKeyByteArray
            * @param {number} rounds
            */
            encrypt(workingKeyByteArray: Array<number>, rounds: number): void;
            /**
            * @description Executes the backward cipher operation on the current state.
            *
            * @param {Array<number>} workingKeyByteArray
            * @param {number} rounds
            */
            decrypt(workingKeyByteArray: Array<number>, rounds: number): void;
            /**
            * @description Returns all bytes of the current state as a byte array with 16 elements.
            *
            * @returns {Array<number>}, An array of 16 byte
            */
            toArray(): Array<number>;
            /**
            * @description Executes the XOR operation on all bytes of the current state with the corresponding bytes of the
            *  'otherState'.
            *
            * @params {TS.Security.State} otherState
            */
            xor(otherState: State): void;
            /**
            * @description Overwrites the state array with the values given in argument byteArray16.
            *
            * @private
            *
            * @param {Array<number>} byteArray16, An array of 16 byte
            */
            private fromArray(byteArray16);
            /**
            * @description Returns the row with the specified index from the state array.
            *
            * @private
            *
            * @param {number} rowIndex
            *
            * @returns {Array<number>}, The requested row in an array of 4 byte values.
            *
            * @throws {TS.ArgumentException}
            * @throws {TS.ArgumentOutOfRangeException}
            */
            private getRow(rowIndex);
            /**
            * @description Sets the row with the specified index in the state array.
            *
            * @private
            *
            * @param {number} rowIndex
            * @param {Array<number>} byteArray4 (Array of four byte)
            *
            * @throws {TS.ArgumentOutOfRangeException}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentException}
            */
            private setRow(rowIndex, byteArray4);
            /**
            * @description Returns the column with the specified index from the state array.
            *
            * @private
            *
            * @param {number} columnIndex
            *
            * @returns {Array<number>}, the requested column in an array of 4 byte values.
            *
            * @throws {TS.ArgumentOutOfRangeException}
            */
            private getColumn(columnIndex);
            /**
            * @description Sets the column with the specified index in the state array.
            *
            * @private
            *
            * @param {number} columnIndex
            * @param {Array<number>} byteArray4 (Array of four byte)
            *
            * @throws {TS.ArgumentOutOfRangeException}
            * @throws {TS.InvalidTypeException}
            */
            private setColumn(columnIndex, byteArray4);
            /**
            * @private
            *
            * @param {Array<number>} workingKeyByteArray
            * @param {number} workingKeyByteArrayOffset
            */
            private addRoundKey(workingKeyByteArray, workingKeyByteArrayOffset);
            /**
            * @private
            */
            private shiftRows();
            /**
            * @private
            */
            private inverseShiftRows();
            /**
            * @private
            */
            private mixColumns();
            /**
            * @private
            */
            private inverseMixColumns();
            /**
            * @private
            */
            private substituteBytes();
            /**
            * @private
            */
            private inverseSubstituteBytes();
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.AES_CBC
        *
        * @description This is an implementation of the CIPHER BLOCK CHAINING (CBC) operation mode as described in the NIST
        *  publication 800-38a, 'Recommendation for Block Cipher Modes of Operation'.
        *
        * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
        */
        class AES_CBC extends AES {
            /**
            * @private
            */
            private IV;
            /**
            * @constructor
            *
            * @description Creates a new AES_CBC instance with the key given in argument 'keyByteArray' and the initialisation
            *  vector given in argument 'initialisationVector'. The 'keyByteArray' must have a total length of 128, 192 or
            *  256 bits. That means the 'keyByteArray' array must have a length of either 16, 24 or 32. Using a key which
            *  doesn't comply with that rule will raise an exception. The initialisation vector must be an array of unsigned
            *  byte values with a total of 16 elements.
            *
            * @param {Array<number>} keyByteArray, an array of [16 | 24 | 32] byte holding the key.
            * @param {Array<number>} initialisationVector, array of 16 unsigned byte values.
            *
            * @throws {TS.InvalidOperationException}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentOutOfRangeException}
            */
            constructor(keyByteArray: Array<number>, initialisationVector: Array<number>);
            /**
            * @override
            *
            * @param {Array<number>} plainDataByteArray
            *
            * @returns {Array<number>}, The encrypted data as byte array.
            *
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentException}
            */
            encrypt(plainDataByteArray: Array<number>): Array<number>;
            /**
            * @override
            *
            * @param {Array<number>} cypherDataByteArray
            *
            * @returns {Array<number>}, The decrypted data as byte array.
            *
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentException}
            */
            decrypt(cypherDataByteArray: Array<number>): Array<number>;
        }
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @description This is an implementation of the 'HMAC' (The Keyed-Hash Message Authentication Code) using the SHA1
        *  hash algorithm. See the FIPS publication 198a and 198-1.
        *
        * @see {@link http://csrc.nist.gov/publications/fips/fips198/fips-198a.pdf | FIPS}
        *
        * @param {string | Array<number>} authenticationKey, Either a simple text string or an array of unsigned byte
        *  values.
        * @param {string | Array<number>} message, Either a simple text string or an array of unsigned byte values.
        *
        * @returns {string}, A HEX string as a result of the keyed hash operation.
        *
        * @throws {TS.ArgumentNullOrUndefinedException}
        * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
        * @throws {TS.InvalidTypeException}
        */
        function HMAC_SHA1(authenticationKey: string | Array<number>, message: string | Array<number>): string;
        /**
        * @description This is an implementation of the 'HMAC' (The Keyed-Hash Message Authentication Code) using the MD5
        *  hash algorithm. See the IETF publication rfc2104.
        *
        * @see {@link https://tools.ietf.org/pdf/rfc2104.pdf | IETF}
        *
        * @param {string | Array<number>} authenticationKey, Either a simple text string or an array of unsigned byte
        *  values.
        * @param {string | Array<number>} message, Either a simple text string or an array of unsigned byte values.
        *
        * @returns {string}, A HEX string as a result of the keyed hash operation.
        *
        * @throws {TS.ArgumentNullOrUndefinedException}
        * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
        * @throws {TS.InvalidTypeException}
        */
        function HMAC_MD5(authenticationKey: string | Array<number>, message: string | Array<number>): string;
    }
}
declare namespace TS {
    namespace Security {
        /**
        * @class TS.Security.MD5
        *
        * @classdesc This class implements the MD5 hash algorithm as described in the IETF publication
        *  'The MD5 Message-Digest Algorithm'.
        *
        * @see {@link https://www.ietf.org/rfc/rfc1321.txt | IETF }
        */
        class MD5 extends Cryptography {
            /**
            *
            * @param {string | Array<number>} message, Either a simple text string or an array of unsigned byte values.
            *
            * @returns {string}, The resulting digest / MD5 as HEX string.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            static encrypt(message: string | Array<number>): string;
        }
    }
}
declare namespace TS {
    namespace Security {
        function PBKDF2_HMAC_SHA1(password: Array<number>, salt: Array<number>, iterations: number, requiredDerivedKeyLengthInByte: number): Array<number>;
    }
}
