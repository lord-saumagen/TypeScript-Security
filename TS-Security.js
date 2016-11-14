/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        /**
        * @description An enumeration which declares the two possible cipher operations. (ENCRYPT, DECRYPT).
        */
        (function (CipherOperationEnum) {
            CipherOperationEnum[CipherOperationEnum["DECRYPT"] = 0] = "DECRYPT";
            CipherOperationEnum[CipherOperationEnum["ENCRYPT"] = 1] = "ENCRYPT";
        })(Security.CipherOperationEnum || (Security.CipherOperationEnum = {}));
        var CipherOperationEnum = Security.CipherOperationEnum;
        /**
        * @description An enumeration which declares the possible stream states.
        */
        (function (StreamStateEnum) {
            StreamStateEnum[StreamStateEnum["CREATED"] = 0] = "CREATED";
            StreamStateEnum[StreamStateEnum["INITIALIZED"] = 1] = "INITIALIZED";
            StreamStateEnum[StreamStateEnum["REQUEST_FOR_CLOSE"] = 2] = "REQUEST_FOR_CLOSE";
            StreamStateEnum[StreamStateEnum["CLOSED"] = 3] = "CLOSED";
        })(Security.StreamStateEnum || (Security.StreamStateEnum = {}));
        var StreamStateEnum = Security.StreamStateEnum;
        Security.MD5_KEY_SIZE = 64;
        Security.MD5_HASH_SIZE = 16;
        Security.SHA1_KEY_SIZE = 64;
        Security.SHA1_HASH_SIZE = 20;
        Security.SHA224_KEY_SIZE = 64;
        Security.SHA224_HASH_SIZE = 28;
        Security.SHA256_KEY_SIZE = 64;
        Security.SHA256_HASH_SIZE = 32;
        Security.SHA384_KEY_SIZE = 128;
        Security.SHA384_HASH_SIZE = 48;
        Security.SHA512_KEY_SIZE = 128;
        Security.SHA512_HASH_SIZE = 64;
        Security.HMAC_SHA256_KEY_SIZE = 64;
        Security.HMAC_SHA256_HASH_SIZE = 32;
        Security.HMAC_SHA384_KEY_SIZE = 128;
        Security.HMAC_SHA384_HASH_SIZE = 48;
        Security.HMAC_SHA512_KEY_SIZE = 128;
        Security.HMAC_SHA512_HASH_SIZE = 64;
        //TODO: Crate the test functions.
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
        function sliceData(data, sliceLengthInByte = 4) {
            let workingData;
            let resultArray = new Array();
            TS.Utils.checkUByteArrayParameter("data", data, "TS.Security.sliceData");
            TS.Utils.checkUIntNumberParameter("sliceLengthInByte", sliceLengthInByte, "TS.Security.sliceData");
            if (sliceLengthInByte <= 0 || sliceLengthInByte > 255) {
                throw new TS.ArgumentOutOfRangeException("sliceLengthInByte", sliceLengthInByte, "Argument 'sliceLengthInByte' must be a value in range [1..255]. The error occured in function 'TS.Security.sliceData'.");
            } //END if
            if ((data.length % sliceLengthInByte) != 0) {
                throw new TS.InvalidOperationException("Slicing the data into blocks of length " + sliceLengthInByte.toString() + " failed because the data length is not a multitude of the required slice length. The error occured in function 'TS.Security.sliceData'.");
            } //END if
            workingData = data.slice();
            while (workingData.length > 0) {
                resultArray.push(workingData.slice(0, sliceLengthInByte));
                workingData = workingData.slice(sliceLengthInByte);
            } //END while
            return resultArray;
        }
        Security.sliceData = sliceData;
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
        function pad_SHA(data) {
            /**
            * @description The result array is an array of four byte words which is a simple unsigned integer in JavaScript.
            * @see fourByteWord
            */
            let resultArray;
            let messageArray;
            let messageLength;
            let UInt64MessageBitLength;
            /**
            * @description A four byte word in JavaScript is simply a number which holds four unsigned byte values in one
            *  unsigned integer value. The byte values are stored in order of appearance. That means the most significant
            *  byte is the first and the least significant byte is the last.
            *  [byte0][byte1][byte2][byte3] <=> UnsignedInteger
            */
            let fourByteWord;
            if (TS.Utils.Assert.isNullOrUndefined(data)) {
                throw new TS.ArgumentNullOrUndefinedException("data", "Argument data must be null or undefined in function 'TS.Security.padMD5_SHA'.");
            } //END if
            if (!TS.Utils.Assert.isEmptyArray(data) && !TS.Utils.Assert.isString(data) && !TS.Utils.Assert.isUnsignedByteArray(data)) {
                throw new TS.InvalidTypeException("data", data, "Argument data must be a valid string or an array of unsigned byte values in function 'TS.Security.padMD5_SHA'.");
            } //END if
            if (TS.Utils.Assert.isString(data)) {
                if (data.length > 0) {
                    messageArray = TS.Encoding.UTF.UTF16StringToUTF8Array(data);
                }
                else {
                    messageArray = new Array();
                }
            }
            else {
                messageArray = data.slice();
            }
            messageLength = messageArray.length;
            resultArray = new Array();
            //
            // Slice the message in 4 character substrings and
            // and store the characters as bytes in a 32bit
            // integer. 
            //
            for (let index = 0; index < messageLength - 3; index += 4) {
                fourByteWord = messageArray[index] * 0x1000000 + messageArray[index + 1] * 0x10000 + messageArray[index + 2] * 0x100 + messageArray[index + 3];
                resultArray.push(fourByteWord);
            } //END for
            //
            // Add the remaining bytes, a stop bit and fill up with zeros up to a total length of 4 byte.
            // Add the four byte word to the result array afterwards.
            //
            switch (messageLength % 4) {
                case 0:
                    {
                        fourByteWord = TS.Security.UByteArrayToFourByteWord([0x80, 0x0, 0x0, 0x0]);
                        break;
                    }
                case 1:
                    {
                        fourByteWord = TS.Security.UByteArrayToFourByteWord([messageArray[messageLength - 1], 0x80, 0x0, 0x0]);
                        break;
                    }
                case 2:
                    {
                        fourByteWord = TS.Security.UByteArrayToFourByteWord([messageArray[messageLength - 2], messageArray[messageLength - 1], 0x80, 0x0]);
                        break;
                    }
                case 3:
                    {
                        fourByteWord = TS.Security.UByteArrayToFourByteWord([messageArray[messageLength - 3], messageArray[messageLength - 2], messageArray[messageLength - 1], 0x80]);
                        break;
                    }
            } //END switch
            resultArray.push(fourByteWord);
            //
            // Fill the result array with empty entries ( 0 values) until the  array has reached a length of: n * 512 + 448 
            //  in  bit. Each entry in the array has a length of 32 bit. 16 * 32 = 512, 14 * 32 = 448
            //
            while ((resultArray.length % 16) != 14) {
                resultArray.push(0);
            } //END while
            //
            // Calculate the message length in bit and store the result in a 64 bit unsigned integer. 64 bit = 8 byte.
            //
            UInt64MessageBitLength = TS.TypeCode.UInt64.UIntToUInt64(messageLength * 8);
            //
            // Add the message length in bit to the result array. The result array has length of n * 512 + 488 byte so far.
            // Adding the 8 byte of the UInt64 and the result array has a length of (n + 1) * 512.
            //
            resultArray.push(UInt64MessageBitLength.mostSignificantInteger, UInt64MessageBitLength.leastSignificantInteger);
            return resultArray;
        }
        Security.pad_SHA = pad_SHA;
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
        function pad_MD5(data) {
            let resultArray = TS.Security.pad_SHA(data);
            let temp1;
            let temp2;
            temp1 = TS.Utils.UInt32SwapSignificantByteOrder(resultArray.pop());
            temp2 = TS.Utils.UInt32SwapSignificantByteOrder(resultArray.pop());
            resultArray.push(temp1);
            resultArray.push(temp2);
            return resultArray;
        }
        Security.pad_MD5 = pad_MD5;
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
        function UByteArrayToFourByteWord(byteArray) {
            let result;
            let factor = 0x1000000;
            TS.Utils.checkUByteArrayParameter("byteArray", byteArray, "TS.Security.UByteArrayToFourByteWord");
            if (byteArray.length > 4) {
                throw new TS.ArgumentOutOfRangeException("byteArray", byteArray, "Argument 'byteArray' must be an array of unsigned bytes with a length < 4 in function 'TS.Security.UByteArrayToFourByteWord'.");
            }
            result = 0;
            for (let index = 0; index < byteArray.length; index++) {
                result += byteArray[index] * (factor >> (index * 8));
            }
            return result;
        }
        Security.UByteArrayToFourByteWord = UByteArrayToFourByteWord;
        //TODO: Crate the test functions. Add descripion
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
        function padData(data, requiredBlockLength = 16) {
            let resultArray = new Array();
            let reminder;
            let index;
            let workingData;
            TS.Utils.checkUByteArrayParameter("data", data, "TS.Security.padData");
            TS.Utils.checkUIntNumberParameter("requiredBlockLength", requiredBlockLength, "TS.Security.padData");
            workingData = data.slice();
            reminder = workingData.length % requiredBlockLength;
            if (requiredBlockLength <= 0 || requiredBlockLength > 255) {
                throw new TS.ArgumentOutOfRangeException("requiredBlockLength", requiredBlockLength, "Argument 'requiredBlockLength' must be a value in range [1..255] in function TS.Security.padData.");
            } //END if
            if (reminder == 0) {
                for (index = requiredBlockLength; index > 0; index--) {
                    workingData.push(requiredBlockLength);
                } //END if
            }
            else {
                for (index = requiredBlockLength - reminder; index > 0; index--) {
                    workingData.push(requiredBlockLength - reminder);
                } //END if
            }
            return workingData;
        }
        Security.padData = padData;
        //TODO: Crate the test functions. Add descripion
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
        function unpadData(data) {
            let resultArray = new Array();
            let padLengthInByte;
            let index;
            let workingData;
            TS.Utils.checkUByteArrayParameter("data", data, "TS.Security.unpadData");
            workingData = data.slice();
            padLengthInByte = data[data.length - 1];
            if (((workingData.length - padLengthInByte) < 0) || (padLengthInByte > 255)) {
                throw new TS.ArgumentException("data", data, "The 'data' given in function 'unpadData' appears to be not a padded byte array. The error occured in function TS.Security.unpadData.");
            } //END if
            resultArray = workingData.slice(0, workingData.length - padLengthInByte);
            return resultArray;
        }
        Security.unpadData = unpadData;
        //TODO: Crate the test functions.
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
        function XORByteArray(firstArray, secondArray) {
            let resultArray;
            TS.Utils.checkUByteArrayParameter("firstArray", firstArray, "TS.Security.XORByteArray");
            TS.Utils.checkUByteArrayParameter("secondArray", secondArray, "TS.Security.XORByteArray");
            if (firstArray.length > secondArray.length) {
                return TS.Security.XORByteArray(secondArray, firstArray);
            }
            resultArray = new Array();
            for (let index = 0; index < firstArray.length; index++) {
                resultArray.push(firstArray[index] ^ secondArray[index]);
            }
            for (let index = firstArray.length; index < secondArray.length; index++) {
                resultArray.push(secondArray[index]);
            }
            return resultArray;
        }
        Security.XORByteArray = XORByteArray;
        /**
        * @description Returns an array of round constants as required for the SHA-224 and SHA-256 hash algorithm.
        *
        * @returns {Array<number>}
        */
        function getSHA224_256RoundConstants() {
            return [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
        }
        Security.getSHA224_256RoundConstants = getSHA224_256RoundConstants;
        /**
        * @descriptions Returns a precalculated array of integer sine values from the values [1..64] multiplied by
        *  0x100000000.
        *
        * @see {@link https://www.ietf.org/rfc/rfc1321.txt | RFC 1321,3.4 Step 4. Process Message in 16‐Word Blocks}
        *
        * @returns {Array<number>}
        */
        function getMD5_SineTable() {
            return [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8,
                0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391];
        }
        Security.getMD5_SineTable = getMD5_SineTable;
        /**
        * @description Returns the substitution table as defined for the MD5 algorithm.
        *
        * @see {@link https://www.ietf.org/rfc/rfc1321.txt | IETF}
        *
        * @returns {Array<number>}
        */
        function getMD5_PerRoundShiftAmountTable() {
            return [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
        }
        Security.getMD5_PerRoundShiftAmountTable = getMD5_PerRoundShiftAmountTable;
        /**
        * @description Returns an array of precalculated modulo operation values over the set {0..255}.
        *
        * @returns {Array<number>}
        */
        function getAES_multByTwoArray() {
            return [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158, 160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190, 192, 194, 196, 198, 200, 202, 204, 206, 208, 210, 212, 214, 216, 218, 220, 222, 224, 226, 228, 230, 232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254, 27, 25, 31, 29, 19, 17, 23, 21, 11, 9, 15, 13, 3, 1, 7, 5, 59, 57, 63, 61, 51, 49, 55, 53, 43, 41, 47, 45, 35, 33, 39, 37, 91, 89, 95, 93, 83, 81, 87, 85, 75, 73, 79, 77, 67, 65, 71, 69, 123, 121, 127, 125, 115, 113, 119, 117, 107, 105, 111, 109, 99, 97, 103, 101, 155, 153, 159, 157, 147, 145, 151, 149, 139, 137, 143, 141, 131, 129, 135, 133, 187, 185, 191, 189, 179, 177, 183, 181, 171, 169, 175, 173, 163, 161, 167, 165, 219, 217, 223, 221, 211, 209, 215, 213, 203, 201, 207, 205, 195, 193, 199, 197, 251, 249, 255, 253, 243, 241, 247, 245, 235, 233, 239, 237, 227, 225, 231, 229];
        }
        Security.getAES_multByTwoArray = getAES_multByTwoArray;
        /**
        * @description Returns an array of precalculated modulo operation values over the set {0..255}.
        *
        * @returns {Array<number>}
        */
        function getAES_multByThreeArray() {
            return [0, 3, 6, 5, 12, 15, 10, 9, 24, 27, 30, 29, 20, 23, 18, 17, 48, 51, 54, 53, 60, 63, 58, 57, 40, 43, 46, 45, 36, 39, 34, 33, 96, 99, 102, 101, 108, 111, 106, 105, 120, 123, 126, 125, 116, 119, 114, 113, 80, 83, 86, 85, 92, 95, 90, 89, 72, 75, 78, 77, 68, 71, 66, 65, 192, 195, 198, 197, 204, 207, 202, 201, 216, 219, 222, 221, 212, 215, 210, 209, 240, 243, 246, 245, 252, 255, 250, 249, 232, 235, 238, 237, 228, 231, 226, 225, 160, 163, 166, 165, 172, 175, 170, 169, 184, 187, 190, 189, 180, 183, 178, 177, 144, 147, 150, 149, 156, 159, 154, 153, 136, 139, 142, 141, 132, 135, 130, 129, 155, 152, 157, 158, 151, 148, 145, 146, 131, 128, 133, 134, 143, 140, 137, 138, 171, 168, 173, 174, 167, 164, 161, 162, 179, 176, 181, 182, 191, 188, 185, 186, 251, 248, 253, 254, 247, 244, 241, 242, 227, 224, 229, 230, 239, 236, 233, 234, 203, 200, 205, 206, 199, 196, 193, 194, 211, 208, 213, 214, 223, 220, 217, 218, 91, 88, 93, 94, 87, 84, 81, 82, 67, 64, 69, 70, 79, 76, 73, 74, 107, 104, 109, 110, 103, 100, 97, 98, 115, 112, 117, 118, 127, 124, 121, 122, 59, 56, 61, 62, 55, 52, 49, 50, 35, 32, 37, 38, 47, 44, 41, 42, 11, 8, 13, 14, 7, 4, 1, 2, 19, 16, 21, 22, 31, 28, 25, 26];
        }
        Security.getAES_multByThreeArray = getAES_multByThreeArray;
        /**
        * @description Returns an array of precalculated modulo operation values over the set {0..255}.
        *
        * @returns {Array<number>}
        */
        function getAES_multByFourteenArray() {
            return [0, 14, 28, 18, 56, 54, 36, 42, 112, 126, 108, 98, 72, 70, 84, 90, 224, 238, 252, 242, 216, 214, 196, 202, 144, 158, 140, 130, 168, 166, 180, 186, 219, 213, 199, 201, 227, 237, 255, 241, 171, 165, 183, 185, 147, 157, 143, 129, 59, 53, 39, 41, 3, 13, 31, 17, 75, 69, 87, 89, 115, 125, 111, 97, 173, 163, 177, 191, 149, 155, 137, 135, 221, 211, 193, 207, 229, 235, 249, 247, 77, 67, 81, 95, 117, 123, 105, 103, 61, 51, 33, 47, 5, 11, 25, 23, 118, 120, 106, 100, 78, 64, 82, 92, 6, 8, 26, 20, 62, 48, 34, 44, 150, 152, 138, 132, 174, 160, 178, 188, 230, 232, 250, 244, 222, 208, 194, 204, 65, 79, 93, 83, 121, 119, 101, 107, 49, 63, 45, 35, 9, 7, 21, 27, 161, 175, 189, 179, 153, 151, 133, 139, 209, 223, 205, 195, 233, 231, 245, 251, 154, 148, 134, 136, 162, 172, 190, 176, 234, 228, 246, 248, 210, 220, 206, 192, 122, 116, 102, 104, 66, 76, 94, 80, 10, 4, 22, 24, 50, 60, 46, 32, 236, 226, 240, 254, 212, 218, 200, 198, 156, 146, 128, 142, 164, 170, 184, 182, 12, 2, 16, 30, 52, 58, 40, 38, 124, 114, 96, 110, 68, 74, 88, 86, 55, 57, 43, 37, 15, 1, 19, 29, 71, 73, 91, 85, 127, 113, 99, 109, 215, 217, 203, 197, 239, 225, 243, 253, 167, 169, 187, 181, 159, 145, 131, 141];
        }
        Security.getAES_multByFourteenArray = getAES_multByFourteenArray;
        /**
        * @description Returns an array of precalculated modulo operation values over the set {0..255}.
        *
        * @returns {Array<number>}
        */
        function getAES_multByThirteenArray() {
            return [0, 13, 26, 23, 52, 57, 46, 35, 104, 101, 114, 127, 92, 81, 70, 75, 208, 221, 202, 199, 228, 233, 254, 243, 184, 181, 162, 175, 140, 129, 150, 155, 187, 182, 161, 172, 143, 130, 149, 152, 211, 222, 201, 196, 231, 234, 253, 240, 107, 102, 113, 124, 95, 82, 69, 72, 3, 14, 25, 20, 55, 58, 45, 32, 109, 96, 119, 122, 89, 84, 67, 78, 5, 8, 31, 18, 49, 60, 43, 38, 189, 176, 167, 170, 137, 132, 147, 158, 213, 216, 207, 194, 225, 236, 251, 246, 214, 219, 204, 193, 226, 239, 248, 245, 190, 179, 164, 169, 138, 135, 144, 157, 6, 11, 28, 17, 50, 63, 40, 37, 110, 99, 116, 121, 90, 87, 64, 77, 218, 215, 192, 205, 238, 227, 244, 249, 178, 191, 168, 165, 134, 139, 156, 145, 10, 7, 16, 29, 62, 51, 36, 41, 98, 111, 120, 117, 86, 91, 76, 65, 97, 108, 123, 118, 85, 88, 79, 66, 9, 4, 19, 30, 61, 48, 39, 42, 177, 188, 171, 166, 133, 136, 159, 146, 217, 212, 195, 206, 237, 224, 247, 250, 183, 186, 173, 160, 131, 142, 153, 148, 223, 210, 197, 200, 235, 230, 241, 252, 103, 106, 125, 112, 83, 94, 73, 68, 15, 2, 21, 24, 59, 54, 33, 44, 12, 1, 22, 27, 56, 53, 34, 47, 100, 105, 126, 115, 80, 93, 74, 71, 220, 209, 198, 203, 232, 229, 242, 255, 180, 185, 174, 163, 128, 141, 154, 151];
        }
        Security.getAES_multByThirteenArray = getAES_multByThirteenArray;
        /**
        * @description Returns an array of precalculated modulo operation values over the set {0..255}.
        *
        * @returns {Array<number>}
        */
        function getAES_multByElevenArray() {
            return [0, 11, 22, 29, 44, 39, 58, 49, 88, 83, 78, 69, 116, 127, 98, 105, 176, 187, 166, 173, 156, 151, 138, 129, 232, 227, 254, 245, 196, 207, 210, 217, 123, 112, 109, 102, 87, 92, 65, 74, 35, 40, 53, 62, 15, 4, 25, 18, 203, 192, 221, 214, 231, 236, 241, 250, 147, 152, 133, 142, 191, 180, 169, 162, 246, 253, 224, 235, 218, 209, 204, 199, 174, 165, 184, 179, 130, 137, 148, 159, 70, 77, 80, 91, 106, 97, 124, 119, 30, 21, 8, 3, 50, 57, 36, 47, 141, 134, 155, 144, 161, 170, 183, 188, 213, 222, 195, 200, 249, 242, 239, 228, 61, 54, 43, 32, 17, 26, 7, 12, 101, 110, 115, 120, 73, 66, 95, 84, 247, 252, 225, 234, 219, 208, 205, 198, 175, 164, 185, 178, 131, 136, 149, 158, 71, 76, 81, 90, 107, 96, 125, 118, 31, 20, 9, 2, 51, 56, 37, 46, 140, 135, 154, 145, 160, 171, 182, 189, 212, 223, 194, 201, 248, 243, 238, 229, 60, 55, 42, 33, 16, 27, 6, 13, 100, 111, 114, 121, 72, 67, 94, 85, 1, 10, 23, 28, 45, 38, 59, 48, 89, 82, 79, 68, 117, 126, 99, 104, 177, 186, 167, 172, 157, 150, 139, 128, 233, 226, 255, 244, 197, 206, 211, 216, 122, 113, 108, 103, 86, 93, 64, 75, 34, 41, 52, 63, 14, 5, 24, 19, 202, 193, 220, 215, 230, 237, 240, 251, 146, 153, 132, 143, 190, 181, 168, 163];
        }
        Security.getAES_multByElevenArray = getAES_multByElevenArray;
        /**
        * @description Returns an array of precalculated modulo operation values over the set {0..255}.
        *
        * @returns {Array<number>}
        */
        function getAES_multByNineArray() {
            return [0, 9, 18, 27, 36, 45, 54, 63, 72, 65, 90, 83, 108, 101, 126, 119, 144, 153, 130, 139, 180, 189, 166, 175, 216, 209, 202, 195, 252, 245, 238, 231, 59, 50, 41, 32, 31, 22, 13, 4, 115, 122, 97, 104, 87, 94, 69, 76, 171, 162, 185, 176, 143, 134, 157, 148, 227, 234, 241, 248, 199, 206, 213, 220, 118, 127, 100, 109, 82, 91, 64, 73, 62, 55, 44, 37, 26, 19, 8, 1, 230, 239, 244, 253, 194, 203, 208, 217, 174, 167, 188, 181, 138, 131, 152, 145, 77, 68, 95, 86, 105, 96, 123, 114, 5, 12, 23, 30, 33, 40, 51, 58, 221, 212, 207, 198, 249, 240, 235, 226, 149, 156, 135, 142, 177, 184, 163, 170, 236, 229, 254, 247, 200, 193, 218, 211, 164, 173, 182, 191, 128, 137, 146, 155, 124, 117, 110, 103, 88, 81, 74, 67, 52, 61, 38, 47, 16, 25, 2, 11, 215, 222, 197, 204, 243, 250, 225, 232, 159, 150, 141, 132, 187, 178, 169, 160, 71, 78, 85, 92, 99, 106, 113, 120, 15, 6, 29, 20, 43, 34, 57, 48, 154, 147, 136, 129, 190, 183, 172, 165, 210, 219, 192, 201, 246, 255, 228, 237, 10, 3, 24, 17, 46, 39, 60, 53, 66, 75, 80, 89, 102, 111, 116, 125, 161, 168, 179, 186, 133, 140, 151, 158, 233, 224, 251, 242, 205, 196, 223, 214, 49, 56, 35, 42, 21, 28, 7, 14, 121, 112, 107, 98, 93, 84, 79, 70];
        }
        Security.getAES_multByNineArray = getAES_multByNineArray;
        /**
        * @description Returns an array of substitution values as defined in the AES algorithm.
        *
        * @returns {Array<number>}
        */
        function getAES_substitutionTable() {
            return [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22];
        }
        Security.getAES_substitutionTable = getAES_substitutionTable;
        /**
        * @description Returns an array of inverse substitution values as defined in the AES algorithm.
        *
        * @returns {Array<number>}
        */
        function getAES_inverseSubstitutionTable() {
            return [82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125];
        }
        Security.getAES_inverseSubstitutionTable = getAES_inverseSubstitutionTable;
        /**
        * @description Returns an array of round constant values as defined in the AES algorithm.
        *
        * @returns {Array<number>}
        */
        function getAES_roundConstants() {
            return [141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141];
        }
        Security.getAES_roundConstants = getAES_roundConstants;
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
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
            constructor() {
            }
            /**
            * @description Corrects a negative result which may occure after a bitoperation on a positive integer.
            *
            * @param {number} value, The value to correct.
            *
            * @returns {number}, The corrected value
            */
            static correctNegative(value) {
                if (value < 0) {
                    value = 0x100000000 + value;
                }
                ;
                return value;
            }
            // F(X,Y,Z) = XY v not(X) Z 
            static MD5FuncOne(roundB, roundC, roundD) {
                return TS.Security.Cryptography.correctNegative((roundB & roundC) | (~roundB & roundD));
            }
            // G(X,Y,Z) = XZ v Y not(Z) 
            static MD5FuncTwo(roundB, roundC, roundD) {
                return TS.Security.Cryptography.correctNegative((roundB & roundD) | (roundC & ~roundD));
            }
            // H(X,Y,Z) = X xor Y xor Z
            static MD5FuncThree(roundB, roundC, roundD) {
                return TS.Security.Cryptography.correctNegative((roundB ^ roundC ^ roundD));
            }
            //I(X, Y, Z) = Y xor (X v not(Z)) 
            static MD5FuncFour(roundB, roundC, roundD) {
                return TS.Security.Cryptography.correctNegative(roundC ^ (roundB | ~roundD));
            }
            //TODO: Create the test functions.
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
            static xorWord(firstWord, secondWord) {
                TS.Utils.checkUByteArrayParameter("data", firstWord, "TS.Security.Cryptography.xorWord");
                TS.Utils.checkUByteArrayParameter("data", secondWord, "TS.Security.Cryptography.xorWord");
                if (firstWord.length != 4) {
                    throw new TS.ArgumentException("firstWord", firstWord, "Argument 'firstWord' has not the required length of 4 elements in function 'TS.Security.Cryptography.xorWord'.");
                } //END if
                if (secondWord.length != 4) {
                    throw new TS.ArgumentException("secondWord", secondWord, "Argument 'secondWord' has not the required length of 4 elements in function 'TS.Security.Cryptography.xorWord'.");
                } //END if
                return [firstWord[0] ^ secondWord[0], firstWord[1] ^ secondWord[1], firstWord[2] ^ secondWord[2], firstWord[3] ^ secondWord[3]];
            }
            //TODO: Create the test functions.
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
            static rotateLeft(data, positions) {
                var resultData;
                var index;
                var sourceIndex;
                TS.Utils.checkUIntNumberParameter("positions", positions, "TS.Security.Cryptography.rotateLeft");
                TS.Utils.checkArrayParameter("data", data, "TS.Security.Cryptography.rotateLeft");
                resultData = new Array();
                for (index = 0; index < data.length; index++) {
                    sourceIndex = (index + positions) % data.length;
                    resultData.push(data[sourceIndex]);
                } //END for
                return resultData;
            }
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
            static ch32(x, y, z) {
                TS.Utils.checkIntNumberParameter("x", x, "TS.Security.Cryptography.ch32");
                TS.Utils.checkIntNumberParameter("y", y, "TS.Security.Cryptography.ch32");
                TS.Utils.checkIntNumberParameter("z", z, "TS.Security.Cryptography.ch32");
                return TS.Security.Cryptography.correctNegative((x & y) ^ (~x & z));
            }
            //TODO: Create the test functions. Add descripion
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
            static ch64(x, y, z) {
                let tempMSInteger;
                let tempLSInteger;
                TS.Utils.checkUInt64NumberParameter("x", x, "TS.Security.Cryptography.ch64");
                TS.Utils.checkUInt64NumberParameter("y", y, "TS.Security.Cryptography.ch64");
                TS.Utils.checkUInt64NumberParameter("z", z, "TS.Security.Cryptography.ch64");
                tempMSInteger = this.ch32(x.mostSignificantInteger, y.mostSignificantInteger, z.mostSignificantInteger);
                tempLSInteger = this.ch32(x.leastSignificantInteger, y.leastSignificantInteger, z.leastSignificantInteger);
                return new TS.TypeCode.UInt64(tempMSInteger, tempLSInteger);
            }
            //TODO: Create the test functions.
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
            static gamma0_32(x) {
                TS.Utils.checkIntNumberParameter("x", x, "TS.Security.Cryptography.gamma0_32");
                return TS.Security.Cryptography.correctNegative(this.rotateRight32(x, 7) ^ this.rotateRight32(x, 18) ^ this.shiftRight32(x, 3));
            }
            //TODO: Create the test functions.
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
            static gamma1_32(x) {
                TS.Utils.checkIntNumberParameter("x", x, "TS.Security.Cryptography.gamma1_32");
                return TS.Security.Cryptography.correctNegative(this.rotateRight32(x, 17) ^ this.rotateRight32(x, 19) ^ this.shiftRight32(x, 10));
            }
            //TODO: Create the test functions.
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
            static maj32(x, y, z) {
                TS.Utils.checkIntNumberParameter("x", x, "TS.Security.Cryptography.maj32");
                TS.Utils.checkIntNumberParameter("y", y, "TS.Security.Cryptography.maj32");
                TS.Utils.checkIntNumberParameter("z", z, "TS.Security.Cryptography.maj32");
                return TS.Security.Cryptography.correctNegative((x & y) ^ (x & z) ^ (y & z));
            }
            //TODO: Create the test functions.  Add descripion
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
            static maj64(x, y, z) {
                let tempMSInteger;
                let tempLSInteger;
                TS.Utils.checkUInt64NumberParameter("x", x, "TS.Security.Cryptography.maj64");
                TS.Utils.checkUInt64NumberParameter("y", y, "TS.Security.Cryptography.maj64");
                TS.Utils.checkUInt64NumberParameter("z", z, "TS.Security.Cryptography.maj64");
                tempMSInteger = this.maj32(x.mostSignificantInteger, y.mostSignificantInteger, z.mostSignificantInteger);
                tempLSInteger = this.maj32(x.leastSignificantInteger, y.leastSignificantInteger, z.leastSignificantInteger);
                return new TS.TypeCode.UInt64(tempMSInteger, tempLSInteger);
            }
            //TODO: Create the test functions.
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
            static parity(x, y, z) {
                TS.Utils.checkIntNumberParameter("x", x, "TS.Security.Cryptography.parity");
                TS.Utils.checkIntNumberParameter("y", y, "TS.Security.Cryptography.parity");
                TS.Utils.checkIntNumberParameter("z", z, "TS.Security.Cryptography.parity");
                return TS.Security.Cryptography.correctNegative((x ^ y ^ z));
            }
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
            static rotateLeft32(value, positions) {
                if (!TS.Utils.Assert.isIntegerNumber(value) || value < 0) {
                    debugger;
                }
                TS.Utils.checkUIntNumberParameter("value", value, "TS.Security.Cryptography.rotateLeft32");
                TS.Utils.checkUIntNumberParameter("positions", positions, "TS.Security.Cryptography.rotateLeft32");
                positions = positions % 32;
                return TS.Security.Cryptography.correctNegative((value << positions) | (value >>> (32 - positions)));
            }
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
            static rotateRight32(value, positions) {
                TS.Utils.checkUIntNumberParameter("value", value, "TS.Security.Cryptography.rotateRight32");
                TS.Utils.checkUIntNumberParameter("positions", positions, "TS.Security.Cryptography.rotateRight32");
                positions = positions % 32;
                return TS.Security.Cryptography.correctNegative((value >>> positions) | (value << (32 - positions)));
            }
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
            static rotateRight64(value, positions) {
                TS.Utils.checkUInt64NumberParameter("value", value, "TS.Security.Cryptography.rotateRight64");
                TS.Utils.checkUIntNumberParameter("positions", positions, "TS.Security.Cryptography.rotateRight32");
                positions = positions % 64;
                let tempMSInteger;
                let tempLSInteger;
                let returnUInt64;
                let swap;
                tempMSInteger = 0;
                tempLSInteger = 0;
                if (0 == positions) {
                    tempMSInteger = value.mostSignificantInteger;
                    tempLSInteger = value.leastSignificantInteger;
                } //END if
                if (0 < positions && positions < 32) {
                    tempMSInteger = (value.mostSignificantInteger >>> positions) | (value.leastSignificantInteger << (32 - positions));
                    tempLSInteger = (value.leastSignificantInteger >>> positions) | (value.mostSignificantInteger << (32 - positions));
                } //END if
                if (positions == 32) {
                    tempMSInteger = value.leastSignificantInteger;
                    tempLSInteger = value.mostSignificantInteger;
                } //END if
                if (32 < positions) {
                    tempMSInteger = (value.leastSignificantInteger >>> (positions - 32)) | (value.mostSignificantInteger << (64 - positions));
                    tempLSInteger = (value.mostSignificantInteger >>> (positions - 32)) | (value.leastSignificantInteger << (64 - positions));
                } //END else
                tempMSInteger = TS.Security.Cryptography.correctNegative(tempMSInteger);
                tempLSInteger = TS.Security.Cryptography.correctNegative(tempLSInteger);
                return new TS.TypeCode.UInt64(tempMSInteger, tempLSInteger);
            }
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
            static shiftLeft32(value, positions) {
                TS.Utils.checkUIntNumberParameter("value", value, "TS.Security.Cryptography.shiftRight32");
                TS.Utils.checkUIntNumberParameter("positions", positions, "TS.Security.Cryptography.rotateRight32");
                positions = positions % 32;
                value = value << positions;
                return TS.Security.Cryptography.correctNegative(value);
            }
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
            static shiftRight32(value, positions) {
                TS.Utils.checkUIntNumberParameter("value", value, "TS.Security.Cryptography.shiftRight32");
                TS.Utils.checkUIntNumberParameter("positions", positions, "TS.Security.Cryptography.rotateRight32");
                positions = positions % 32;
                value = value >>> positions;
                return TS.Security.Cryptography.correctNegative(value);
            }
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
            static shiftRight64(value, positions) {
                TS.Utils.checkUInt64NumberParameter("value", value, "TS.Security.Cryptography.shiftRight64");
                TS.Utils.checkUIntNumberParameter("positions", positions, "TS.Security.Cryptography.shiftRight64");
                positions = positions % 64;
                let tempMSInteger;
                let tempLSInteger;
                let returnUInt64;
                let swap;
                tempMSInteger = 0;
                tempLSInteger = 0;
                if (0 == positions) {
                    tempMSInteger = value.mostSignificantInteger;
                    tempLSInteger = value.leastSignificantInteger;
                } //END if
                if (0 < positions && positions < 32) {
                    tempMSInteger = value.mostSignificantInteger >>> positions;
                    tempLSInteger = (value.leastSignificantInteger >>> positions) | (value.mostSignificantInteger << (32 - positions));
                } //END if
                if (positions == 32) {
                    tempMSInteger = 0;
                    tempLSInteger = value.mostSignificantInteger;
                } //END if
                if (32 < positions) {
                    tempMSInteger = 0;
                    tempLSInteger = value.mostSignificantInteger >>> (positions - 32);
                } //END if
                tempLSInteger = TS.Security.Cryptography.correctNegative(tempLSInteger);
                tempMSInteger = TS.Security.Cryptography.correctNegative(tempMSInteger);
                return new TS.TypeCode.UInt64(tempMSInteger, tempLSInteger);
            }
            //TODO: Create the test functions.
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
            static sigma0_32(x) {
                TS.Utils.checkIntNumberParameter("x", x, "TS.Security.Cryptography.sigma0_32");
                return TS.Security.Cryptography.correctNegative(this.rotateRight32(x, 2) ^ this.rotateRight32(x, 13) ^ this.rotateRight32(x, 22));
            }
            //TODO: Create the test functions.  Add descripion
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
            static sigma0_64(x) {
                let tempMSInteger;
                let tempLSInteger;
                let rot28;
                let rot34;
                let rot39;
                TS.Utils.checkUInt64NumberParameter("x", x, "TS.Security.Cryptography.sigma0_64");
                rot28 = this.rotateRight64(x, 28);
                rot34 = this.rotateRight64(x, 34);
                rot39 = this.rotateRight64(x, 39);
                tempMSInteger = rot28.mostSignificantInteger ^ rot34.mostSignificantInteger ^ rot39.mostSignificantInteger;
                tempLSInteger = rot28.leastSignificantInteger ^ rot34.leastSignificantInteger ^ rot39.leastSignificantInteger;
                tempLSInteger = TS.Security.Cryptography.correctNegative(tempLSInteger);
                tempMSInteger = TS.Security.Cryptography.correctNegative(tempMSInteger);
                return new TS.TypeCode.UInt64(tempMSInteger, tempLSInteger);
            }
            //TODO: Create the test functions.
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
            static sigma1_32(x) {
                TS.Utils.checkIntNumberParameter("x", x, "TS.Security.Cryptography.sigma1_32");
                return TS.Security.Cryptography.correctNegative(this.rotateRight32(x, 6) ^ this.rotateRight32(x, 11) ^ this.rotateRight32(x, 25));
            }
        }
        Security.Cryptography = Cryptography; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
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
        class AbstractStreamCipher {
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
            constructor(cipherOperation, onNextData, onClosed, onError) {
                TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AbstractStreamCipher.constructor");
                TS.Utils.checkFunctionParameter("onNextData", onNextData, "TS.Security.AbstractStreamCipher.constructor");
                TS.Utils.checkFunctionParameter("onClosed", onClosed, "TS.Security.AbstractStreamCipher.constructor");
                TS.Utils.checkFunctionParameter("onError", onError, "TS.Security.AbstractStreamCipher.constructor");
                if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum)) {
                    throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "Argument 'cipherOperation' must be a valid element of the 'TS.Security.CipherOperationEnum' enumeration in function 'TS.Security.AbstractStreamCipher.constructor'.");
                } //END if
                this.cipherOperation = cipherOperation;
                this.onNextData = onNextData;
                this.onClosed = onClosed;
                this.onError = onError;
                //
                //The block cipher must be
                //set in subclasses
                //
                this.blockCipher = null;
                //
                //The buffer size must be set
                //in subclasses
                //
                this.bufferSizeInBit = null;
                this.inputBuffer = "";
                this.timer = null;
                //
                //The stream state must be set
                //to 'StreamStateEnum.CREATED'
                //at the end of the construction
                //in subclasses.
                //
                this.streamState = null;
            }
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
            writeByteArray(byteArray) {
                TS.Utils.checkUByteArrayParameter("byteArray", byteArray, "TS.Security.AbstractStreamCipher.writeByteArray");
                this.writeBitString(TS.Utils.byteArrayToBitString(byteArray));
            }
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
            writeByte(byteValue) {
                TS.Utils.checkUByteArrayParameter("byteValue", byteValue, "TS.Security.AbstractStreamCipher.writeByte");
                this.writeBitString(TS.Utils.byteToBitString(byteValue));
            }
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
            writeBitString(bitString) {
                TS.Utils.checkBitStringParameter("bitString", bitString, "TS.Security.AbstractStreamCipher.writeBitString");
                if ((this.streamState == Security.StreamStateEnum.CLOSED) || (this.streamState == Security.StreamStateEnum.REQUEST_FOR_CLOSE)) {
                    throw new TS.InvalidOperationException("Invalid call to 'write' on a closed stream.");
                } //END if
                if (this.streamState < Security.StreamStateEnum.INITIALIZED) {
                    this.initialize();
                } //END if
                this.inputBuffer += bitString;
            }
            /**
            * @description Closes the current stream for writing. Since the stream operates asynchronous, the last output
            *  from that stream may appear significant later. The stream is finally closed when the 'onClosed' callback
            *  function is called which was designated during construction.
            */
            close() {
                this.streamState = Security.StreamStateEnum.REQUEST_FOR_CLOSE;
            }
            /**
            * @descriptions Stops the internal timer.
            *
            * @private
            */
            stopTimer() {
                try {
                    clearInterval(this.timer);
                } //END try
                catch (e) { }
                ;
            }
            /**
            * @descriptions Starts the internal timer.
            *
            * @private
            */
            startTimer() {
                this.timer = setInterval(this.process.bind(this), 15);
            }
            /**
            * @descriptions Initialize the class.
            *
            * @private
            *
            * @throws {TS.InvalidOperationException}
            */
            initialize() {
                //Don't initialize until the construction of the 
                //current class has finished.
                if (this.streamState != Security.StreamStateEnum.CREATED) {
                    return;
                } //END if
                if ((this.blockCipher == null) || (this.bufferSizeInBit == null)) {
                    throw new TS.InvalidOperationException("Initialization of the abstract class 'TS.Security.AbstractStreamCipher' is not supported.");
                } //END if
                this.inputBuffer = "";
                this.streamState = Security.StreamStateEnum.INITIALIZED;
                this.startTimer();
            }
            /**
            * @descriptions Processes the data from the input buffer. That means, looking if there is enough data to fill a
            *  segment. Execute the cipher operation on that segment and signal the consumer that there is a new chunk
            *  of data available by calling the 'onNextData' callback.
            *
            * @private
            */
            process() {
                let segment;
                let processedData;
                //
                // Stream is already closed, return.
                //
                if (this.streamState == Security.StreamStateEnum.CLOSED) {
                    this.stopTimer();
                    return;
                } //END if
                //
                // No complete buffer available, return and wait for more data.
                //
                if ((this.streamState != Security.StreamStateEnum.REQUEST_FOR_CLOSE) && (this.inputBuffer.length < this.bufferSizeInBit)) {
                    return;
                } //END if
                //
                // Normal operation on state 'INITIALIZED' or 'REQUEST_FOR_CLOSE' as
                // long as there is data which fills a complete buffer.
                //
                if ((this.streamState == Security.StreamStateEnum.INITIALIZED) || (this.streamState == Security.StreamStateEnum.REQUEST_FOR_CLOSE)) {
                    this.stopTimer();
                    while (this.inputBuffer.length >= this.bufferSizeInBit) {
                        segment = this.inputBuffer.substr(0, this.bufferSizeInBit);
                        this.inputBuffer = this.inputBuffer.substr(this.bufferSizeInBit);
                        try {
                            processedData = this.cipher(segment);
                            this.onNextData(processedData);
                        } //END try
                        catch (Exception) {
                            this.streamState = TS.Security.StreamStateEnum.CLOSED;
                            this.stopTimer();
                            this.inputBuffer = null;
                            this.onError(Exception);
                            return;
                        } //END catch
                    } //END while
                    if (this.streamState == Security.StreamStateEnum.REQUEST_FOR_CLOSE) {
                        //
                        // Set the 'CLOSED' flag and block the stream for writing. 
                        //
                        this.streamState = Security.StreamStateEnum.CLOSED;
                        //
                        // Stop the timer
                        //
                        this.stopTimer();
                        //
                        // Check the buffer for remaining data
                        //
                        if (this.inputBuffer.length != 0) {
                            //
                            //Clear the buffer
                            //
                            this.inputBuffer = "";
                            //
                            // Signal an error if the buffer isn't empty.
                            //
                            this.onError(new TS.InvalidOperationException("The data does not align with the buffer size. The stream cipher terminated incomplete."));
                            return;
                        } //END if
                        else {
                            //
                            //Clear the buffer
                            //
                            this.inputBuffer = "";
                            //
                            //Signal that the stream has closed.
                            //
                            this.onClosed();
                            return;
                        } //END else
                    } //END if
                    this.startTimer();
                } //END if
            }
        }
        Security.AbstractStreamCipher = AbstractStreamCipher; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace  
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        function getRoundConstant(index) {
            return TS.Security.getAES_roundConstants()[index];
        }
        function getSubstitution(index) {
            return TS.Security.getAES_substitutionTable()[index];
        }
        /**
        * @class TS.Security.AES
        *
        * @description This class is an implements of the ADVANCED ENCRYPTION STANDARD (AES) as described in the FIPS
        *  publication fips-197, 'Announcing the ADVANCED ENCRYPTION STANDARD (AES)'. The cipher mode decribed in that
        *  publication is also identical to the ELECTRONIC CODE BOOK (ECB) operation mode described in the NIST
        *  publication 800-38a, 'Recommendation for Block Cipher Modes of Operation'.
        *
        * @see {@link http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf | NIST}
        * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
        */
        class AES extends TS.Security.Cryptography {
            /**
            * @constructor
            *
            * @description Create a new AES instance with the key given in argument 'keyByteArray'. The 'keyByteArray' must
            *  have a total length of 128, 192 or 256 bits. That means the 'keyByteArray' array must have a length of either
            *  16, 24 or 32. Using a key which doesn't comply with that rule will raise an exception.
            *
            * @param {Array<number>} keyByteArray, An array of [16 | 24 | 32] byte holding the key.
            *
            * @throws {TS.ArgumentNullOrUndefinedException#}
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentOutOfRangeException}
            */
            constructor(keyByteArray) {
                TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES.constructor");
                super();
                switch (keyByteArray.length) {
                    case 16:
                        {
                            this.rounds = 10;
                            this.workingKeyByteArray = TS.Security.AES.expandKey(keyByteArray);
                            break;
                        }
                    case 24:
                        {
                            this.rounds = 12;
                            this.workingKeyByteArray = TS.Security.AES.expandKey(keyByteArray);
                            break;
                        }
                    case 32:
                        {
                            this.rounds = 14;
                            this.workingKeyByteArray = TS.Security.AES.expandKey(keyByteArray);
                            break;
                        }
                    default:
                        {
                            this.rounds = 0;
                            this.workingKeyByteArray = new Array();
                            throw new TS.ArgumentOutOfRangeException("keyByteArray", keyByteArray, "The argument 'keyByteArray' must be a byte array with one of the following lengths: [16,24,32]. All other array lengths are considered invalid.");
                        }
                } //END switch
            }
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
            encrypt(data) {
                let resultByteArray;
                let dataByteArray;
                TS.Utils.checkUByteArrayParameter("data", data, "TS.Security.AES.encrypt");
                if ((data.length % 16) != 0) {
                    throw new TS.ArgumentException("data", data, "The 'data' must be an array of n * 16 byte elements (the AES block size). Use the 'padData' function in order to give your data an appropriate length.");
                } //END if
                dataByteArray = data.slice();
                resultByteArray = new Array();
                while (dataByteArray.length > 0) {
                    resultByteArray = resultByteArray.concat(this.encryptDecryptInternal(dataByteArray.slice(0, 16), TS.Security.CipherOperationEnum.ENCRYPT));
                    dataByteArray = dataByteArray.slice(16);
                } //END while
                return resultByteArray;
            }
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
            decrypt(dataByteArray) {
                let resultByteArray;
                let dataArray;
                TS.Utils.checkUByteArrayParameter("dataByteArray", dataByteArray, "TS.Security.AES.decrypt");
                if ((dataByteArray.length % 16) != 0) {
                    throw new TS.ArgumentException("dataByteArray", dataByteArray, "The 'dataByteArray' must be an array of n * 16 elements (the AES block size).");
                } //END if
                dataArray = dataByteArray.slice();
                resultByteArray = new Array();
                while (dataArray.length > 0) {
                    resultByteArray = resultByteArray.concat(this.encryptDecryptInternal(dataArray.slice(0, 16), TS.Security.CipherOperationEnum.DECRYPT));
                    dataArray = dataArray.slice(16);
                } //END while
                return resultByteArray;
            }
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
            encryptDecryptInternal(dataByteArray, cipherOperation) {
                let state;
                let index;
                let resultByteArray;
                TS.Utils.checkUByteArrayParameter("dataByteArray", dataByteArray, "TS.Security.AES.encryptDecryptInternal");
                TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES.encryptDecryptInternal");
                if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum)) {
                    throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "Argument 'cipherOperation' must be a valid element of the 'TS.Security.AES.encryptDecryptInternal' enumeration in function 'TS.Security.AES_CFB_Stream.constructor'.");
                } //END if
                resultByteArray = new Array();
                index = 0;
                state = new Security.State(dataByteArray);
                if (cipherOperation == Security.CipherOperationEnum.ENCRYPT) {
                    state.encrypt(this.workingKeyByteArray, this.rounds);
                } //END if
                else {
                    state.decrypt(this.workingKeyByteArray, this.rounds);
                } //END else
                return state.toArray();
            }
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
            static substituteBytes(byteArray) {
                var index;
                var resultByteArray;
                TS.Utils.checkUByteArrayParameter("byteArray", byteArray, "TS.Security.AES.substituteBytes");
                resultByteArray = new Array();
                for (index = 0; index < byteArray.length; index++) {
                    resultByteArray[index] = getSubstitution(byteArray[index]);
                } //END for
                return resultByteArray;
            }
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
            static expandKey(keyByteArray) {
                let tempArray;
                let tempWord;
                let resultArray;
                let index;
                let columnIndex;
                let roundConstantArray;
                let blockSizeInWords = 4;
                let keyLengthInWords;
                let rounds;
                TS.Utils.checkUByteArrayParameter("byteArray", keyByteArray, "TS.Security.AES.expandKey");
                tempArray = new Array();
                resultArray = new Array();
                index = 0;
                switch (keyByteArray.length) {
                    case 16:
                        {
                            rounds = 10;
                            break;
                        }
                    case 24:
                        {
                            rounds = 12;
                            break;
                        }
                    case 32:
                        {
                            rounds = 14;
                            break;
                        }
                    default:
                        {
                            rounds = 0;
                            throw new TS.ArgumentOutOfRangeException("keyByteArray", keyByteArray, "The argument 'keyByteArray' must be a byte array with one of the following lengths: [16,24,32]. All other array lengths are considered invalid.");
                        }
                } //END switch
                keyLengthInWords = keyByteArray.length / 4;
                while (index * 4 < keyByteArray.length) {
                    tempArray[index] = keyByteArray.slice(index * 4, (index + 1) * 4);
                    index++;
                }
                for (index = keyLengthInWords; index < blockSizeInWords * (rounds + 1); index++) {
                    tempWord = tempArray[index - 1];
                    if (index % keyLengthInWords === 0) {
                        roundConstantArray = [getRoundConstant(index / keyLengthInWords), 0, 0, 0];
                        tempWord = this.rotateLeft(tempWord, 1);
                        tempWord = this.substituteBytes(tempWord);
                        tempWord = this.xorWord(tempWord, roundConstantArray);
                    } //END if
                    else if (keyLengthInWords > 6 && index % keyLengthInWords === 4) {
                        tempWord = TS.Security.AES.substituteBytes(tempWord);
                    } //END else
                    tempArray[index] = this.xorWord(tempArray[index - keyLengthInWords], tempWord);
                } //END for
                for (index = 0; index < tempArray.length; index++) {
                    for (columnIndex = 0; columnIndex < 4; columnIndex++) {
                        resultArray.push(tempArray[index][columnIndex]);
                    } //END for
                } //END for
                return resultArray;
            }
        }
        Security.AES = AES; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        /**
        * @class TS.Security.AES_CBCStreamEnabled
        *
        * @description This is an implementation of the CIPHER BLOCK CHAINING (CBC) operation mode as described in the NIST
        *  publication 800-38a, 'Recommendation for Block Cipher Modes of Operation'. This class differs from the
        *  'TS.Security.AES_CBC' in that way, that the class is more streaming friendly.
        *
        * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
        *
        * @extends {TS.Security.AES}
        */
        class AES_CBCStreamEnabled extends TS.Security.AES {
            /**
            * @constructor
            *
            * @param {Array<number>} keyByteArray
            * @param {Array<number>} initialisationVector
            */
            constructor(keyByteArray, initialisationVector) {
                super(keyByteArray);
                this.IV = new Security.State(initialisationVector);
                this.previousState = null;
            }
            /**
            * @override
            *
            * @param {Array<number>} plainDataByteArray, An array of 16 byte values.
            *
            * @returns {Array<number>}, The encrypted data as array of bytes;
            *
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentException}
            */
            encrypt(plainDataByteArray) {
                let state;
                TS.Utils.checkUByteArrayParameter("plainDataByteArray", plainDataByteArray, "TS.Security.AES_CBCStreamEnabled.encrypt");
                if (plainDataByteArray.length != 16) {
                    throw new TS.ArgumentException("plainDataByteArray", plainDataByteArray, "The 'plainDataByteArray' must have a lenght which is a multiple of 16 (the AES block size). Use the 'padData' function in oder to give your data an appropriate length.");
                } //END if
                if (this.previousState == null) {
                    this.previousState = this.IV;
                } //END if
                state = new Security.State(plainDataByteArray);
                state.xor(this.previousState);
                state.encrypt(this.workingKeyByteArray, this.rounds);
                this.previousState = new Security.State(state.toArray());
                return state.toArray();
            }
            /**
            * @override
            *
            * @param {Array<number>} cypherDataByteArray, An array of 16 byte values.
            *
            * @returns {Array<number>}, The decrypted data as array of bytes;
            *
            * @throws {TS.InvalidTypeException}
            * @throws {TS.ArgumentException}
            */
            decrypt(cypherDataByteArray) {
                let state;
                let tempState;
                TS.Utils.checkUByteArrayParameter("cypherDataByteArray", cypherDataByteArray, "TS.Security.AES_CBCStreamEnabled.decrypt");
                if (cypherDataByteArray.length != 16) {
                    throw new TS.ArgumentException("cypherDataByteArray", cypherDataByteArray, "The 'cypherDataByteArray' must have a lenght which is a multiple of 16 (the AES block size). Use the 'padData' function in oder to give your data an appropriate length.");
                } //END if
                if (this.previousState == null) {
                    this.previousState = this.IV;
                } //END if
                state = new Security.State(cypherDataByteArray);
                tempState = new Security.State(cypherDataByteArray);
                state.decrypt(this.workingKeyByteArray, this.rounds);
                state.xor(this.previousState);
                this.previousState = new Security.State(tempState.toArray());
                return state.toArray();
            }
        }
         //END class
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
            constructor(keyByteArray, initialisationVector, cipherOperation, onNextData, onClosed, onError) {
                TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_CBC_Stream.constructor");
                TS.Utils.checkUByteArrayParameter("initialisationVector", initialisationVector, "TS.Security.AES_CBC_Stream.constructor");
                TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES_CBC_Stream.constructor");
                TS.Utils.checkFunctionParameter("onNextData", onNextData, "TS.Security.AES_CBC_Stream.constructor");
                TS.Utils.checkFunctionParameter("onClosed", onClosed, "TS.Security.AES_CBC_Stream.constructor");
                TS.Utils.checkFunctionParameter("onError", onError, "TS.Security.AES_CBC_Stream.constructor");
                if (initialisationVector.length != 16) {
                    throw new TS.ArgumentOutOfRangeException("initialisationVector", initialisationVector, "Argument 'initialisationVector' must be a byte array of the length 16 in function 'TS.Security.AES_CBC_Stream.constructor'.");
                } //END if
                if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum)) {
                    throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "Argument 'cipherOperation' must be a valid element of the 'TS.Security.CipherOperationEnum' enumeration in function 'TS.Security.AES_CBC_Stream.constructor'.");
                } //END if
                super(cipherOperation, onNextData, onClosed, onError);
                //
                //Set the blockCipher object.
                //
                this.blockCipher = new AES_CBCStreamEnabled(keyByteArray, initialisationVector);
                //
                //Set the bufferSize which is 128 bit for AES / AES_ECB.
                //
                this.bufferSizeInBit = 128;
                //
                //Set the streamState to signal the end of the class construction.
                //
                this.streamState = Security.StreamStateEnum.CREATED;
            }
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
            cipher(bitString) {
                let block;
                block = TS.Utils.bitStringToByteArray(bitString);
                if (this.cipherOperation == TS.Security.CipherOperationEnum.DECRYPT) {
                    return TS.Utils.byteArrayToBitString(this.blockCipher.decrypt(block));
                } //END if
                if (this.cipherOperation == TS.Security.CipherOperationEnum.ENCRYPT) {
                    return TS.Utils.byteArrayToBitString(this.blockCipher.encrypt(block));
                } //END if
            }
        }
        Security.AES_CBC_Stream = AES_CBC_Stream; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
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
            constructor(keyByteArray, initialisationVector, segmentSizeInBit) {
                TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_CFB.constructor");
                TS.Utils.checkUByteArrayParameter("initialisationVector", initialisationVector, "TS.Security.AES_CFB.constructor");
                TS.Utils.checkUIntNumberParameter("segmentSizeInBit", segmentSizeInBit, "TS.Security.AES_CFB.constructor");
                if (initialisationVector.length != 16) {
                    throw new TS.ArgumentOutOfRangeException("initialisationVector", initialisationVector, "Argument 'initialisationVector' must be a byte array of the length 16 in function 'TS.Security.AES_CFB.constructor'.");
                } //END if
                if ((segmentSizeInBit < 1) || (segmentSizeInBit > 128)) {
                    throw new TS.ArgumentOutOfRangeException("segmentSizeInBit", segmentSizeInBit, "The argument value must be a value in the range of [1..128]. Error occured in 'TS.Security.AES_CFB.constructor'.");
                } //END if
                super(keyByteArray);
                this.segmentSizeInBit = segmentSizeInBit;
                this.IV = new Security.State(initialisationVector);
            }
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
            encrypt(plainDataByteArray) {
                TS.Utils.checkUByteArrayParameter("plainDataByteArray", plainDataByteArray, "TS.Security.AES_CFB.encrypt");
                if ((this.segmentSizeInBit % 8) != 0) {
                    throw new TS.InvalidOperationException("The 'encrypt' function which uses a byte array as input parameter can only be use if the segment size aligns with 8 bit. That means, segment size must be a value which is n * 8, where n is a positive integer > 0. Use the 'encryptBitString' function if the segment size doesn't fit. Error occured in 'TS.Security.AES_CFB.encrypt'.");
                } //END if
                return this.encryptDecryptInternal(plainDataByteArray, Security.CipherOperationEnum.ENCRYPT);
            }
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
            decrypt(cipherDataByteArray) {
                TS.Utils.checkUByteArrayParameter("cipherDataByteArray", cipherDataByteArray, "TS.Security.AES_CFB.encrypt");
                if ((this.segmentSizeInBit % 8) != 0) {
                    throw new TS.InvalidOperationException("The 'decrypt' function which uses a byte array as input parameter can only be use if the segment size aligns with 8 bit. That means, segment size must be a value which is n * 8, where n is a positive integer > 0. Use the 'decryptBitString' function if the segment size doesn't fit. Error occured in 'TS.Security.AES_CFB.decrypt'.");
                } //END if
                return this.encryptDecryptInternal(cipherDataByteArray, Security.CipherOperationEnum.DECRYPT);
            }
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
            encryptBitString(bitString) {
                TS.Utils.checkBitStringParameter("bitString", bitString, "TS.Security.AES_CFB.encryptBitString");
                if ((bitString.length % this.segmentSizeInBit) != 0) {
                    throw new TS.InvalidOperationException("The input bit string must align with the current segment size. So the bit string must have a length of n * segment size. Where n is a positive integer > 0. Error occured in 'TS.Security.AES_CFB.encryptBitString'.");
                } //END if
                return this.encryptDecryptBitString(bitString, TS.Security.CipherOperationEnum.ENCRYPT);
            }
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
            decryptBitString(bitString) {
                TS.Utils.checkBitStringParameter("bitString", bitString, "TS.Security.AES_CFB.encryptBitString");
                if ((bitString.length % this.segmentSizeInBit) != 0) {
                    throw new TS.InvalidOperationException("The input bit string must align with the current segment size. That means the bit string must have a length of n * segment size. Where n is a positive integer > 0. Error occured in 'TS.Security.AES_CFB.decryptBitString'.");
                } //END if
                return this.encryptDecryptBitString(bitString, TS.Security.CipherOperationEnum.DECRYPT);
            }
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
            encryptDecryptInternal(dataByteArray, cipherOperation) {
                let resultArray;
                let workingByteArray;
                let segmentByteArray;
                let inputState;
                let outputSegment;
                let inputSegment;
                let segmentSizeInByte;
                TS.Utils.checkUByteArrayParameter("dataByteArray", dataByteArray, "TS.Security.AES_CFB.encryptDecryptInternal");
                TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES_CFB.encryptDecryptInternal");
                if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum)) {
                    throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "The value of argument 'cipherOperation' must be a valid value from the 'TS.Security.CipherOperationEnum' in function 'TS.Security.AES_CFB.encryptDecryptInternal'.");
                }
                if ((this.segmentSizeInBit % 8) != 0) {
                    throw new TS.InvalidOperationException("The 'encryptDecryptInternal' function which uses a byte array as input parameter can only be use if the segment size aligns with 8 bit. That means, segment size must be a value which is n * 8, where n is a positive integer > 0. Use the 'encryptDecryptBitString' function if the segment size doesn't fit. Error occured in 'TS.Security.AES_CFB.encryptDecryptInternal'.");
                } //END if
                segmentSizeInByte = this.segmentSizeInBit / 8;
                workingByteArray = dataByteArray.slice();
                inputState = new Security.State(this.IV.toArray());
                resultArray = new Array();
                while (workingByteArray.length > 0) {
                    segmentByteArray = workingByteArray.slice(0, segmentSizeInByte);
                    if (segmentByteArray.length != segmentSizeInByte) {
                        throw new TS.InvalidOperationException("The given data doesn't align with the current segment size. Cipher operation cancelled. Error occured in 'TS.Security.AES_CFB.encryptDecryptInternal'.");
                    } //END if
                    inputSegment = TS.Utils.byteArrayToBitString(segmentByteArray);
                    workingByteArray = workingByteArray.slice(segmentSizeInByte);
                    outputSegment = this.encryptDecryptSegment(inputSegment, cipherOperation, inputState, this.segmentSizeInBit);
                    if (cipherOperation == Security.CipherOperationEnum.ENCRYPT) {
                        inputState = this.createNextInputState(inputState, outputSegment);
                    } //END if
                    else {
                        inputState = this.createNextInputState(inputState, inputSegment);
                    } //END else
                    resultArray = resultArray.concat(TS.Utils.bitStringToByteArray(outputSegment));
                } //END while
                return resultArray;
            }
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
            encryptDecryptBitString(bitString, cipherOperation) {
                let inputState;
                let inputString;
                let outputSegment;
                let resulString;
                let inputSegment;
                let workingBitString;
                TS.Utils.checkBitStringParameter("bitString", bitString, "TS.Security.AES_CFB.encryptDecryptBitString");
                TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES_CFB.encryptDecryptBitString");
                if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum)) {
                    throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "The value of argument 'cipherOperation' must be a valid value from the 'TS.Security.CipherOperationEnum' in function 'TS.Security.AES_CFB.encryptDecryptBitString'.");
                }
                inputState = new Security.State(this.IV.toArray());
                resulString = "";
                workingBitString = bitString.substr(0);
                while (workingBitString.length >= this.segmentSizeInBit) {
                    inputSegment = workingBitString.substr(0, this.segmentSizeInBit);
                    workingBitString = workingBitString.substr(this.segmentSizeInBit);
                    outputSegment = this.encryptDecryptSegment(inputSegment, cipherOperation, inputState, this.segmentSizeInBit);
                    resulString += outputSegment;
                    if (cipherOperation == Security.CipherOperationEnum.ENCRYPT) {
                        inputState = this.createNextInputState(inputState, outputSegment);
                    } //END if
                    else {
                        inputState = this.createNextInputState(inputState, inputSegment);
                    } //END else
                } //END while
                return resulString;
            }
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
            encryptDecryptSegment(bitString, cipherOperation, inputState, segmentSizeInBit) {
                let outputState;
                let resultString;
                let xorString;
                let index;
                TS.Utils.checkBitStringParameter("bitString", bitString, "TS.Security.AES_CFB.encryptDecryptSegment");
                TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES_CFB.encryptDecryptSegment");
                if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum)) {
                    throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "The value of argument 'cipherOperation' must be a valid value from the 'TS.Security.CipherOperationEnum' in function 'TS.Security.AES_CFB.encryptDecryptSegment'.");
                }
                TS.Utils.checkInstanceOfParameter("inputState", inputState, TS.Security.State, "TS.Security.AES_CFB.encryptDecryptSegment");
                TS.Utils.checkUIntNumberParameter("segmentSizeInBit", segmentSizeInBit, "TS.Security.AES_CFB.encryptDecryptSegment");
                outputState = new Security.State(inputState.toArray());
                outputState.encrypt(this.workingKeyByteArray, this.rounds);
                xorString = TS.Utils.byteArrayToBitString(outputState.toArray());
                xorString = xorString.substr(0, segmentSizeInBit);
                resultString = "";
                for (index = 0; index < segmentSizeInBit; index++) {
                    resultString += (parseInt(xorString.charAt(index), 2) ^ parseInt(bitString.charAt(index), 2)).toString(2);
                } //END for
                return resultString;
            }
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
            createNextInputState(state, cipherSegment) {
                let bitString;
                let byteString;
                let resultArray;
                TS.Utils.checkInstanceOfParameter("state", state, TS.Security.State, "TS.Security.AES_CFB.createNextInputState");
                TS.Utils.checkStringParameter(cipherSegment, cipherSegment, "TS.Security.AES_CFB.createNextInputState");
                bitString = "";
                state.toArray().forEach((value, index, array) => { bitString += TS.Utils.byteToBitString(value); });
                bitString = bitString.substr(this.segmentSizeInBit) + cipherSegment;
                resultArray = new Array();
                while (bitString.length >= 8) {
                    byteString = bitString.slice(0, 8);
                    bitString = bitString.slice(8);
                    resultArray.push(parseInt(byteString, 2));
                } //END while
                return new Security.State(resultArray);
            }
        }
        Security.AES_CFB = AES_CFB; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        /**
        * @class TS.Security.AES_CFBStreamEnabled
        *
        * @description This is an implementation of the CIPHER FEEDBACK (CFB) operation mode as described in the NIST
        *  publication 800-38a, 'Recommendation for Block Cipher Modes of Operation'. This class differs from the
        *  'TS.Security.AES_CFB' in that way, that the class is more streaming friendly.
        *
        * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
        *
        * @extends {TS.Security.AES}
        */
        class AES_CFBStreamEnabled extends TS.Security.AES {
            /**
            * @constructor
            *
            * @description Creates a new instance of the 'TS.Security.AES_CFG_Stream' class.
            *
            * @param {Array<number>} keyByteArray
            * @param { Array<number>} initialisationVector
            * @param {number} segmentSizeInBit
            */
            constructor(keyByteArray, initialisationVector, segmentSizeInBit) {
                super(keyByteArray);
                this.segmentSizeInBit = segmentSizeInBit;
                this.IV = new Security.State(initialisationVector);
                this.inputState = null;
            }
            /**
            * @override
            *
            * @throws {TS.NotImplementedException}
            */
            encrypt(plainDataByteArray) {
                throw new TS.NotImplementedException("Function 'encrypt' is not implemente in class 'TS.Security.AES_CFBStreamEnabled'.");
            }
            /**
            * @override
            *
            * @throws {TS.NotImplementedException}
            */
            decrypt(cipherDataByteArray) {
                throw new TS.NotImplementedException("Function 'decrypt' is not implemente in class 'TS.Security.AES_CFBStreamEnabled'.");
            }
            /**
            * @description Encrypts the data given in argument 'bitString' and returns the encrypted data as bit string.
            *
            * @param {string} bitString
            *
            * @returns {string}, The encrypted data as bit string.
            */
            encryptBitString(bitString) {
                return this.encryptDecryptBitString(bitString, TS.Security.CipherOperationEnum.ENCRYPT);
            }
            /**
            * @description Decrypts the data given in argument 'bitString' and returns the decrypted data as bit string.
            *
            * @param {string} bitString
            *
            * @returns {string}, The decrypted data as bit string.
            */
            decryptBitString(bitString) {
                return this.encryptDecryptBitString(bitString, TS.Security.CipherOperationEnum.DECRYPT);
            }
            /**
            * @override
            *
            * @throws {TS.NotImplementedException}
            */
            encryptDecryptInternal(dataByteArray, cipherOperation) {
                throw new TS.NotImplementedException("Function 'decrypt' is not implemente in class 'TS.Security.AES_CFBStreamEnabled'.");
            }
            /**
            * @private
            *
            * @param {string} bitString
            * @param {TS.Security.CipherOperationEnum} cipherOperation
            *
            * @returns {string}
            */
            encryptDecryptBitString(bitString, cipherOperation) {
                let outputSegment;
                if (this.inputState == null) {
                    this.inputState = new Security.State(this.IV.toArray());
                } //END if
                outputSegment = this.encryptDecryptSegment(bitString, cipherOperation, this.inputState);
                if (cipherOperation == Security.CipherOperationEnum.ENCRYPT) {
                    this.inputState = this.createNextInputState(this.inputState, outputSegment);
                } //END if
                else {
                    this.inputState = this.createNextInputState(this.inputState, bitString);
                } //END else
                return outputSegment;
            }
            /**
            * @private
            *
            * @param {string} binaryString
            * @param {TS.Security.CipherOperationEnum} cipherOperation
            * @param {TS.Security.State} inputState
             *
            * @returns {string}
            */
            encryptDecryptSegment(binaryString, cipherOperation, inputState) {
                let outputState;
                let resultString;
                let xorString;
                let index;
                outputState = new Security.State(inputState.toArray());
                outputState.encrypt(this.workingKeyByteArray, this.rounds);
                xorString = TS.Utils.byteArrayToBitString(outputState.toArray());
                xorString = xorString.substr(0, this.segmentSizeInBit);
                resultString = "";
                for (index = 0; index < this.segmentSizeInBit; index++) {
                    resultString += (parseInt(xorString.charAt(index), 2) ^ parseInt(binaryString.charAt(index), 2)).toString(2);
                } //END for
                return resultString;
            }
            /**
            * @private
            *
            * @param {TS.Security.State} state
            * @param {TS.Security.State} cipherSegment
            *
            * @returns {TS.Security.State}
            */
            createNextInputState(state, cipherSegment) {
                let bitString;
                let byteString;
                let resultArray;
                bitString = "";
                state.toArray().forEach((value, index, array) => { bitString += TS.Utils.byteToBitString(value); });
                bitString = bitString.substr(this.segmentSizeInBit) + cipherSegment;
                resultArray = new Array();
                while (bitString.length >= 8) {
                    byteString = bitString.slice(0, 8);
                    bitString = bitString.slice(8);
                    resultArray.push(parseInt(byteString, 2));
                } //END while
                return new Security.State(resultArray);
            }
        }
         //END class
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
            constructor(keyByteArray, initialisationVector, segmentSizeInBit, cipherOperation, onNextData, onClosed, onError) {
                TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_CFB_Stream.constructor");
                TS.Utils.checkUByteArrayParameter("initialisationVector", initialisationVector, "TS.Security.AES_CFB_Stream.constructor");
                TS.Utils.checkUIntNumberParameter("segmentSizeInBit", segmentSizeInBit, "TS.Security.AES_CFB.constructor");
                TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES_CFB_Stream.constructor");
                TS.Utils.checkFunctionParameter("onNextData", onNextData, "TS.Security.AES_CFB_Stream.constructor");
                TS.Utils.checkFunctionParameter("onClosed", onClosed, "TS.Security.AES_CFB_Stream.constructor");
                TS.Utils.checkFunctionParameter("onError", onError, "TS.Security.AES_CFB_Stream.constructor");
                if (initialisationVector.length != 16) {
                    throw new TS.ArgumentOutOfRangeException("initialisationVector", initialisationVector, "Argument 'initialisationVector' must be a byte array of the length 16 in function 'TS.Security.AES_CFB_Stream.constructor'.");
                } //END if
                if ((segmentSizeInBit < 1) || (segmentSizeInBit > 128)) {
                    throw new TS.ArgumentOutOfRangeException("segmentSizeInBit", segmentSizeInBit, "Argument 'segmentSizeInBit' must be a value in the range [0..128] in function 'TS.Security.AES_CFB_Stream.constructor'.");
                } //END if
                if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum)) {
                    throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "Argument 'cipherOperation' must be a valid element of the 'TS.Security.CipherOperationEnum' enumeration in function 'TS.Security.AES_CFB_Stream.constructor'.");
                } //END if
                super(cipherOperation, onNextData, onClosed, onError);
                //
                //Set ther blockCipher object.
                //
                this.blockCipher = new AES_CFBStreamEnabled(keyByteArray, initialisationVector, segmentSizeInBit);
                //
                //Set the bufferSize which is equal to the 
                //segment size in AES_CFB operation mode.
                //
                this.bufferSizeInBit = segmentSizeInBit;
                //
                //Set the streamState to signal the end of the class construction.
                //
                this.streamState = Security.StreamStateEnum.CREATED;
            }
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
            cipher(bitString) {
                if (this.cipherOperation == TS.Security.CipherOperationEnum.DECRYPT) {
                    return this.blockCipher.decryptBitString(bitString);
                } //END if
                if (this.cipherOperation == TS.Security.CipherOperationEnum.ENCRYPT) {
                    return this.blockCipher.encryptBitString(bitString);
                } //END if
            }
        }
        Security.AES_CFB_Stream = AES_CFB_Stream; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace 
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        /**
        * @class TS.Security.AES_CTR
        *
        * @description This is an implementation of the COUNTER (CTR) operation mode as described in the NIST
        *  publication 800-38a,'Recommendation for Block Cipher Modes of Operation'.
        *
        * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
        */
        class AES_CTR extends Security.AES {
            constructor(keyByteArray) {
                TS.Utils.checkNotEmptyParameter("keyByteArray", keyByteArray, "TS.Security.AES_CTR.constructor");
                TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_CTR.constructor");
                super(keyByteArray);
                if (arguments.length > 1) {
                    if (TS.Utils.Assert.isUnsignedByteArray(arguments[1])) {
                        if (arguments[1].length != 16) {
                            throw new TS.ArgumentOutOfRangeException("nonce", arguments[1], "Argument 'nonce' must be a byte value array with 16 elements in function 'TS.Security.AES_CTR.constructor'.");
                        } //END if
                        this.internalCTR = new TS.Security.Counter(arguments[1]);
                    } //END if
                    else if (TS.Utils.Assert.isUnsignedIntegerNumber(arguments[1])) {
                        if (arguments[1] > 0xFFFFFFFF) {
                            throw new TS.ArgumentOutOfRangeException("counterValue", arguments[1], "Argument 'counterValue' must not exceed the maximum allowed value: '" + 0xFFFFFFFF .toString() + "' in function 'TS.Security.AES_CTR.constructor'.");
                        } //END if
                        this.internalCTR = new TS.Security.Counter(arguments[1]);
                    } //END if
                    else {
                        throw new TS.InvalidTypeException("nonce | counterValue", arguments[1], "The second argument in the constructor of 'TS.Security.AES_CTR' has an invalid type. Error occured in 'TS.Security.AES_CTR.constructor'.");
                    } //END else
                } //END if
                else {
                    this.internalCTR = new TS.Security.Counter();
                } //END else
            }
            /**
            * @description The nonce which is actually used in this AES_CTR object. You need to store this nonce along with
            *  your encrypted data. Otherwies you won't be able to decrypt the data anymore.
            *
            * @get {Array<number>} nonce, The nonce as array of 16 byte values.
            */
            get nonce() {
                return this.internalCTR.nonce;
            }
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
            encrypt(plainDataByteArray) {
                TS.Utils.checkNotEmptyParameter("plainDataByteArray", plainDataByteArray, "TS.Security.AES_CFB.encrypt");
                TS.Utils.checkUByteArrayParameter("plainDataByteArray", plainDataByteArray, "TS.Security.AES_CFB.encrypt");
                return this.encryptDecryptInternal(plainDataByteArray);
            }
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
            decrypt(cipherDataByteArray) {
                TS.Utils.checkNotEmptyParameter("cipherDataByteArray", cipherDataByteArray, "TS.Security.AES_CFB.decrypt");
                TS.Utils.checkUByteArrayParameter("cipherDataByteArray", cipherDataByteArray, "TS.Security.AES_CFB.decrypt");
                return this.encryptDecryptInternal(cipherDataByteArray);
            }
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
            encryptDecryptInternal(dataByteArray) {
                let index;
                let dataSegment;
                let numberOfFillBytes;
                let state;
                let dataState;
                let resultByteArray;
                index = 0;
                resultByteArray = new Array();
                numberOfFillBytes = 0;
                this.internalCTR = new TS.Security.Counter(this.nonce);
                while (index * 16 < dataByteArray.length) {
                    state = this.internalCTR.nextState;
                    state.encrypt(this.workingKeyByteArray, this.rounds);
                    dataSegment = dataByteArray.slice(index * 16, (index + 1) * 16);
                    while (dataSegment.length < 16) {
                        dataSegment.push(0);
                        numberOfFillBytes++;
                    } //END while
                    dataState = new Security.State(dataSegment);
                    dataState.xor(state);
                    resultByteArray = resultByteArray.concat(dataState.toArray());
                    index++;
                } //END while
                while (numberOfFillBytes > 0) {
                    resultByteArray.pop();
                    numberOfFillBytes--;
                } //END while
                return resultByteArray;
            }
        }
        Security.AES_CTR = AES_CTR; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        /**
        * @class TS.Security.AES_CTRStreamEnabled
        *
        * @description This is an implementation of the COUNTER (CTR) operation mode as described in the NIST publication
        *  800-38a, 'Recommendation for Block Cipher Modes of Operation'. This class differs from the
        *  'TS.Security.AES_CTR' in that way, that the class is more streaming friendly.
        *
        * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
        */
        class AES_CTRStreamEnabled extends Security.AES {
            constructor(keyByteArray) {
                super(keyByteArray);
                if (arguments.length > 1) {
                    if (TS.Utils.Assert.isUnsignedByteArray(arguments[1])) {
                        this.CTR = new TS.Security.Counter(arguments[1]);
                    } //END if
                    else if (TS.Utils.Assert.isUnsignedIntegerNumber(arguments[1])) {
                        this.CTR = new TS.Security.Counter(arguments[1]);
                    } //END if
                    else {
                        throw new TS.InvalidTypeException("nonce | counterValue", arguments[1], "The second argument in the constructor of 'TS.Security.AES_CTRStreamEnabled' has an invalid type. Error occured in 'TS.Security.AES_CTRStreamEnabled.constructor'.");
                    } //END else
                } //END if
                else {
                    this.CTR = new TS.Security.Counter();
                } //END else
            }
            /**
            * get {boolean} closed
            */
            get closed() {
                return this.internalClosed;
            }
            /**
            * @description That property give access to the nonce which is actually used in this AES_CTR object. You need to
            *  store this nonce along wiht your encrypted data. Otherwies you won't be able to decrypt the data anymore.
            *
            * @get {Array<number>} nonce, The nonce as array of 16 byte values.
            */
            get nonce() {
                return this.CTR.nonce;
            }
            /**
            * @override
            *
            * @param {Array<number>} plainDataByteArray
            *
            * @returns {Array<number>}
            *
            * @throws {TS.InvalidOperationException}
            */
            encrypt(plainDataByteArray) {
                if (this.closed) {
                    throw new TS.InvalidOperationException("A call to function 'encrypt' is not allowed after the cipher object has closed. Error occured in 'TS.Security.AES_CTRStreamEnabled.enrypt'.");
                } //END if
                if (plainDataByteArray.length < 16) {
                    this.internalClosed = true;
                } //END if
                return this.encryptDecryptInternal(plainDataByteArray);
            }
            /**
            * @override
            *
            * @param {Array<number>} cypherDataByteArray
            *
            * @returns {Array<number>}
            *
            * @throws {TS.InvalidOperationException}
            */
            decrypt(cypherDataByteArray) {
                if (this.closed) {
                    throw new TS.InvalidOperationException("A call to function 'encrypt' is not allowed after the cipher object has closed. Error occured in 'TS.Security.AES_CTRStreamEnabled.decrypt'.");
                } //END if
                if (cypherDataByteArray.length < 16) {
                    this.internalClosed = true;
                } //END if
                return this.encryptDecryptInternal(cypherDataByteArray);
            }
            /**
            * @description Encrypts or decrypts the data given in argument 'dataByteArray' and returns the processed data as
            *  byte array.
            *
            * @override
            *
            * @param {Array<number>} dataByteArray, Array of 16 byte values.
            *
            * @return {Array<number>}, The resulting encrypted or decrypted data as byte array.
            */
            encryptDecryptInternal(dataByteArray) {
                let dataSegment;
                let numberOfFillBytes;
                let state;
                let dataState;
                let resultByteArray;
                resultByteArray = new Array();
                numberOfFillBytes = 0;
                state = this.CTR.nextState;
                state.encrypt(this.workingKeyByteArray, this.rounds);
                dataSegment = dataByteArray.slice();
                while (dataSegment.length < 16) {
                    dataSegment.push(0);
                    numberOfFillBytes++;
                } //END while
                dataState = new Security.State(dataSegment);
                dataState.xor(state);
                resultByteArray = dataState.toArray();
                while (numberOfFillBytes > 0) {
                    resultByteArray.pop();
                    numberOfFillBytes--;
                } //END while
                return resultByteArray;
            }
        }
         //END class
        /**
        * @class TS.Security.AES_CTR_Stream
        *
        * @description This is an implementation of the abstract base class 'TS.Security.AbstractStreamCipher' for the
        *  AES_CTR operation mode.
        *
        * @see {TS.Security.AbstractStreamCipher}
        */
        class AES_CTR_Stream extends Security.AbstractStreamCipher {
            constructor(keyByteArray, nonceOrcounterValue, cipherOperation, onNextData, onClosed, onError) {
                let nonce;
                let counterValue;
                TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_CTR_Stream.constructor");
                TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES_CTR_Stream.constructor");
                TS.Utils.checkFunctionParameter("onNextData", onNextData, "TS.Security.AES_CTR_Stream.constructor");
                TS.Utils.checkFunctionParameter("onClosed", onClosed, "TS.Security.AES_CTR_Stream.constructor");
                TS.Utils.checkFunctionParameter("onError", onError, "TS.Security.AES_CTR_Stream.constructor");
                nonce = null;
                counterValue = null;
                if (TS.Utils.Assert.isUnsignedByteArray(arguments[1])) {
                    if (arguments[1].length != 16) {
                        throw new TS.ArgumentOutOfRangeException("nonce", arguments[1], "Argument 'nonce' must be a byte value array with 16 elements in function 'TS.Security.AES_CTR.constructor'.");
                    } //END if
                    nonce = arguments[1];
                } //END if
                else if (TS.Utils.Assert.isUnsignedIntegerNumber(arguments[1])) {
                    if (arguments[2] > 0xFFFFFFFF) {
                        throw new TS.ArgumentOutOfRangeException("counterValue", arguments[1], "Argument 'counterValue' must not exceed the maximum allowed value: '" + 0xFFFFFFFF .toString() + "' in function 'TS.Security.AES_CTR.constructor'.");
                    } //END if
                    counterValue = arguments[1];
                } //END if
                else {
                    throw new TS.InvalidTypeException("nonce | counterValue", arguments[1], "The second argument in the constructor of 'TS.Security.AES_CTR_Stream' has an invalid type. Error occured in 'TS.Security.AES_CTR_Stream.constructor'.");
                } //END else
                if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum)) {
                    throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "Argument 'cipherOperation' must be a valid element of the 'TS.Security.CipherOperationEnum' enumeration in function 'TS.Security.AES_CTR_Stream.constructor'.");
                } //END if
                super(cipherOperation, onNextData, onClosed, onError);
                //
                //Set ther blockCipher object.
                //
                if (nonce != null) {
                    this.blockCipher = new AES_CTRStreamEnabled(keyByteArray, nonce);
                } //END if
                else if (counterValue != null) {
                    this.blockCipher = new AES_CTRStreamEnabled(keyByteArray, counterValue);
                } //END if
                //
                //Set the bufferSize which is 128 bit for AES_CTR.
                //
                this.bufferSizeInBit = 128;
                //
                //Set the streamState to signal the end of the class construction.
                //
                this.streamState = Security.StreamStateEnum.CREATED;
            }
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
            cipher(bitString) {
                let block;
                block = TS.Utils.bitStringToByteArray(bitString);
                if (this.cipherOperation == TS.Security.CipherOperationEnum.DECRYPT) {
                    return TS.Utils.byteArrayToBitString(this.blockCipher.decrypt(block));
                } //END if
                if (this.cipherOperation == TS.Security.CipherOperationEnum.ENCRYPT) {
                    return TS.Utils.byteArrayToBitString(this.blockCipher.encrypt(block));
                } //END if
            }
        }
        Security.AES_CTR_Stream = AES_CTR_Stream; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace 
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
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
            constructor(keyByteArray, initialisationVector) {
                TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_OFB.constructor");
                TS.Utils.checkUByteArrayParameter("initialisationVector", initialisationVector, "TS.Security.AES_OFB.constructor");
                if (initialisationVector.length != 16) {
                    throw new TS.ArgumentOutOfRangeException("initialisationVector", initialisationVector, "Argument 'initialisationVector' must be a byte array of the length 16 in function 'TS.Security.AES_OFB.constructor'.");
                } //END if
                super(keyByteArray);
                this.IV = new Security.State(initialisationVector);
            }
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
            encrypt(plainDataByteArray) {
                TS.Utils.checkUByteArrayParameter("plainDataByteArray", plainDataByteArray, "TS.Security.AES_OFB.encrypt");
                return this.encryptDecryptInternal(plainDataByteArray);
            }
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
            decrypt(cypherDataByteArray) {
                TS.Utils.checkNotEmptyParameter("plainDataByteArray", cypherDataByteArray, "TS.Security.AES_OFB.decrypt");
                TS.Utils.checkUByteArrayParameter("cypherDataByteArray", cypherDataByteArray, "TS.Security.AES_OFB.decrypt");
                return this.encryptDecryptInternal(cypherDataByteArray);
            }
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
            encryptDecryptInternal(dataByteArray) {
                let index;
                let dataSegment;
                let numberOfFillBytes;
                let state;
                let dataState;
                let resultByteArray;
                index = 0;
                resultByteArray = new Array();
                state = new Security.State(this.IV.toArray());
                numberOfFillBytes = 0;
                while (index * 16 < dataByteArray.length) {
                    state.encrypt(this.workingKeyByteArray, this.rounds);
                    dataSegment = dataByteArray.slice(index * 16, (index + 1) * 16);
                    while (dataSegment.length < 16) {
                        dataSegment.push(0);
                        numberOfFillBytes++;
                    } //END while
                    dataState = new Security.State(dataSegment);
                    dataState.xor(state);
                    resultByteArray = resultByteArray.concat(dataState.toArray());
                    index++;
                } //END while
                while (numberOfFillBytes > 0) {
                    resultByteArray.pop();
                    numberOfFillBytes--;
                } //END while
                return resultByteArray;
            }
        }
        Security.AES_OFB = AES_OFB; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        /**
        * @class TS.Security.AES_OFBStreamEnabled
        *
        * @description This is an implementation of the OUTPUT FEEDBACK (OFB) operation mode as described in the NIST
        *  publication 800-38a, 'Recommendation for Block Cipher Modes of Operation'. This class differs from the
        *  'TS.Security.AES_OFB' in that way, that the class is more streaming friendly.
        *
        * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
        */
        class AES_OFBStreamEnabled extends TS.Security.AES {
            constructor(keyByteArray, initialisationVector) {
                super(keyByteArray);
                this.IV = new Security.State(initialisationVector);
                this.workingState = null;
                this.internalClosed = false;
            }
            /**
            * get {boolean} closed
            */
            get closed() {
                return this.internalClosed;
            }
            /**
             * @override
             * @throws {TS.InvalidOperationException}
             */
            encrypt(plainDataByteArray) {
                if (this.internalClosed) {
                    throw new TS.InvalidOperationException("A call to function 'encrypt' is not allowed after the cipher object has closed. Error occured in 'TS.Security.AES_OFBStreamEnabled.enrypt'.");
                } //END if
                if (plainDataByteArray.length < 16) {
                    this.internalClosed = true;
                } //END if
                return this.encryptDecryptInternal(plainDataByteArray);
            }
            /**
             * @override
             * @throws {TS.InvalidOperationException}
             */
            decrypt(cypherDataByteArray) {
                if (this.internalClosed) {
                    throw new TS.InvalidOperationException("A call to function 'encrypt' is not allowed after the cipher object has closed. Error occured in 'TS.Security.AES_OFBStreamEnabled.decrypt'.");
                } //END if
                if (cypherDataByteArray.length < 16) {
                    this.internalClosed = true;
                } //END if
                return this.encryptDecryptInternal(cypherDataByteArray);
            }
            /**
            * @description Encrypts or decrypts the data given in argument 'dataByteArray' and returns the processed data as
            *  byte array.
            *
            * @override
            * @protected
            *
            * @param {Array<number>} dataByteArray
            *
            * @return {Array<number>}, The resulting encrypted or decrypted data as byte array.
            */
            encryptDecryptInternal(dataByteArray) {
                let index;
                let dataSegment;
                let numberOfFillBytes;
                let dataState;
                let resultByteArray;
                index = 0;
                resultByteArray = new Array();
                numberOfFillBytes = 0;
                if (this.workingState == null) {
                    this.workingState = new Security.State(this.IV.toArray());
                } //END if
                dataSegment = dataByteArray.slice();
                this.workingState.encrypt(this.workingKeyByteArray, this.rounds);
                while (dataSegment.length < 16) {
                    dataSegment.push(0);
                    numberOfFillBytes++;
                } //END while
                dataState = new Security.State(dataSegment);
                dataState.xor(this.workingState);
                resultByteArray = dataState.toArray();
                while (numberOfFillBytes > 0) {
                    resultByteArray.pop();
                    numberOfFillBytes--;
                } //END while
                return resultByteArray;
            }
        }
         //END class
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
            constructor(keyByteArray, initialisationVector, cipherOperation, onNextData, onClosed, onError) {
                TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_OFB_Stream.constructor");
                TS.Utils.checkUByteArrayParameter("initialisationVector", initialisationVector, "TS.Security.AES_OFB_Stream.constructor");
                TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES_OFB_Stream.constructor");
                TS.Utils.checkFunctionParameter("onNextData", onNextData, "TS.Security.AES_OFB_Stream.constructor");
                TS.Utils.checkFunctionParameter("onClosed", onClosed, "TS.Security.AES_OFB_Stream.constructor");
                TS.Utils.checkFunctionParameter("onError", onError, "TS.Security.AES_OFB_Stream.constructor");
                if (initialisationVector.length != 16) {
                    throw new TS.ArgumentOutOfRangeException("initialisationVector", initialisationVector, "Argument 'initialisationVector' must be a byte array of the length 16 in function 'TS.Security.AES_OFB_Stream.constructor'.");
                } //END if
                if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum)) {
                    throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "Argument 'cipherOperation' must be a valid element of the 'TS.Security.CipherOperationEnum' enumeration in function 'TS.Security.AES_OFB_Stream.constructor'.");
                } //END if
                super(cipherOperation, onNextData, onClosed, onError);
                //
                //Set ther blockCipher object.
                //
                this.blockCipher = new AES_OFBStreamEnabled(keyByteArray, initialisationVector);
                //
                //Set the bufferSize which is 128 bit for AES_OFB.
                //
                this.bufferSizeInBit = 128;
                //
                //Set the streamState to signal the end of the class construction.
                //
                this.streamState = Security.StreamStateEnum.CREATED;
            }
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
            cipher(bitString) {
                var block;
                block = TS.Utils.bitStringToByteArray(bitString);
                if (this.cipherOperation == TS.Security.CipherOperationEnum.DECRYPT) {
                    return TS.Utils.byteArrayToBitString(this.blockCipher.decrypt(block));
                } //END if
                if (this.cipherOperation == TS.Security.CipherOperationEnum.ENCRYPT) {
                    return TS.Utils.byteArrayToBitString(this.blockCipher.encrypt(block));
                } //END if
            }
        }
        Security.AES_OFB_Stream = AES_OFB_Stream; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        /**
        * @class TS.Security.AES_Stream
        *
        * @description This is an implementation of the abstract base class 'TS.Security.AbstractStreamCipher' for the
        *  AES / AES_ECB operation mode.
        *
        * @see {TS.Security.AbstractStreamCipher}
        */
        class AES_Stream extends Security.AbstractStreamCipher {
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
            constructor(keyByteArray, cipherOperation, onNextData, onClosed, onError) {
                TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_Stream.constructor");
                TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES_Stream.constructor");
                TS.Utils.checkFunctionParameter("onNextData", onNextData, "TS.Security.AES_Stream.constructor");
                TS.Utils.checkFunctionParameter("onClosed", onClosed, "TS.Security.AES_Stream.constructor");
                TS.Utils.checkFunctionParameter("onError", onError, "TS.Security.AES_Stream.constructor");
                if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum)) {
                    throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "Argument 'cipherOperation' must be a valid element of the 'TS.Security.CipherOperationEnum' enumeration in function 'TS.Security.AES_Stream.constructor'.");
                } //END if
                super(cipherOperation, onNextData, onClosed, onError);
                //
                //Set the blockCipher object.
                //
                this.blockCipher = new TS.Security.AES(keyByteArray);
                //
                //Set the bufferSize which is 128 bit for AES / AES_ECB.
                //
                this.bufferSizeInBit = 128;
                //
                //Set the streamState to signal the end of the class construction.
                //
                this.streamState = Security.StreamStateEnum.CREATED;
            }
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
            cipher(bitString) {
                var block;
                block = TS.Utils.bitStringToByteArray(bitString);
                if (this.cipherOperation == TS.Security.CipherOperationEnum.DECRYPT) {
                    return TS.Utils.byteArrayToBitString(this.blockCipher.decrypt(block));
                } //END if
                if (this.cipherOperation == TS.Security.CipherOperationEnum.ENCRYPT) {
                    return TS.Utils.byteArrayToBitString(this.blockCipher.encrypt(block));
                } //END if
            }
        }
        Security.AES_Stream = AES_Stream; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace 
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
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
            constructor() {
                let index;
                let counterByteArray;
                super();
                //
                // The default constructor was called.
                //
                if (arguments.length == 0) {
                    this.internalNonceArray = this.createNonceArray();
                    this.internalCurrentCounterValue = this.internalInitialCounterValue = TS.Utils.byteArrayToUInt(this.internalNonceArray.slice(12));
                } //END if
                if (arguments.length > 0) {
                    TS.Utils.checkNotEmptyParameter(arguments[0], "nonce | initialCounter", "TS.Security.Counter.constructor");
                    //
                    // The constructor which provides a nonce array was called.
                    //
                    if (TS.Utils.Assert.isUnsignedByteArray(arguments[0])) {
                        if (arguments[0].length != 16) {
                            throw new TS.ArgumentOutOfRangeException("nonce", arguments[0], "Argument 'nonce' must be a byte array with 16 elements in function 'TS.Security.Counter.constructor'.");
                        } //END if
                        this.internalNonceArray = arguments[0].slice();
                        this.internalCurrentCounterValue = this.internalInitialCounterValue = TS.Utils.byteArrayToUInt(arguments[0].slice(12));
                    } //END else if
                    else if (TS.Utils.Assert.isUnsignedIntegerNumber(arguments[0])) {
                        if (arguments[0] > 0xFFFFFFFF) {
                            throw new TS.ArgumentOutOfRangeException("initialCounter", arguments[0], "Argument 'initialCounter' must not exceed the maximum value of 0xFFFFFFFF in function TS.Security.Counter.constructor.");
                        } //END if
                        this.internalNonceArray = new Array();
                        for (index = 0; index < 12; index++) {
                            this.internalNonceArray.push(0);
                        } //END for
                        this.internalNonceArray.concat(TS.Utils.UInt32To4ByteArray(arguments[0]));
                        this.internalCurrentCounterValue = this.internalInitialCounterValue = arguments[0];
                    } //END else if
                    else {
                        throw new TS.InvalidTypeException("nonce | initialCounter", arguments[0], "The argument in the constructor of 'TS.Security.Counter' has an invalid type. Error occured in function TS.Security.Counter.constructor.");
                    } //END else
                } //END if
                this.internalCounterStarted = false;
            }
            /**
            * @get {Array<number>} nonce, The nonce wich was used or created during construction.
            */
            get nonce() {
                return this.internalNonceArray;
            }
            /**
            * @get { TS.Security.State} nextState, The next counter state.
            *
            * @throws {TS.IndexOutOfRangeException}
            */
            get nextState() {
                return this.getNextState();
            }
            /**
            * @get { TS.Security.State} nextCounter, The next counter.
            *
            * @throws {TS.IndexOutOfRangeException}
            */
            get nextCounter() {
                return this.getNextCounter();
            }
            /**
            * @returns {number}, The next counter value.
            *
            * @throws {TS.IndexOutOfRangeException}
            */
            getNextCounter() {
                if (!this.internalCounterStarted) {
                    this.internalCounterStarted = true;
                    return this.internalInitialCounterValue;
                } //END if
                this.internalCurrentCounterValue++;
                if (this.internalCounterStarted && (this.internalCurrentCounterValue == this.internalInitialCounterValue)) {
                    throw new TS.IndexOutOfRangeException("The current counter exceeded the counter range which is 0xFFFFFFFF different values in function 'TS.Security.Counter.getNext'");
                } //END if
                if (this.internalCurrentCounterValue > 0xFFFFFFFF) {
                    this.internalCurrentCounterValue = 0;
                } //END if
                return this.internalCurrentCounterValue;
            }
            /**
            * @returns {TS.Security.State} , The next counter state.
            *
            * @throws {TS.IndexOutOfRangeException}
            */
            getNextState() {
                let counterByteArray;
                counterByteArray = TS.Utils.UInt32To4ByteArray(this.getNextCounter());
                return new TS.Security.State(this.internalNonceArray.slice(0, 12).concat(counterByteArray));
            }
            /**
             * @private
             */
            createNonceArray() {
                let rng;
                let IV;
                let _resultArray;
                let key;
                IV = [185, 78, 34, 160, 69, 3, 238, 110, 4, 92, 124, 48, 114, 45, 62, 129];
                key = [65, 106, 63, 55, 45, 52, 52, 109, 194, 167, 101, 37, 120, 85, 98, 44]; //"Aj?7-44m§e%xUb,"
                rng = new TS.Security.RandomNumberGenerator(key, IV);
                return rng.next;
            }
        }
        Security.Counter = Counter; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        /**
        * @class TS.Security.RandomNumberGenerator
        *
        * @description This class is an implements of the Random Number Generator as described in the NIST publication:
        *  'NIST Recommended Random Number Generator Based On ANSI X9.31 Appendix A.2.4'.
        *
        * @see {@link http://csrc.nist.gov/groups/STM/cavp/documents/rng/931rngext.pdf | NIST}
        */
        class RandomNumberGenerator extends TS.Security.Cryptography {
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
            constructor(keyByteArray, initialisationVector) {
                TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.RandomNumberGenerator.constructor");
                TS.Utils.checkUByteArrayParameter("initialisationVector", initialisationVector, "TS.Security.RandomNumberGenerator.constructor");
                if (initialisationVector.length != 16) {
                    throw new TS.ArgumentOutOfRangeException("initialisationVector", initialisationVector, "Argument 'initialisationVector' must be a byte array of the length 16 in function 'TS.Security.RandomNumberGenerator.constructor'.");
                } //END if
                super();
                this.aes = new TS.Security.AES(keyByteArray);
                this.state = new TS.Security.State(initialisationVector);
            }
            /**
            * @description Returns the next array of 16 random bytes.
            */
            get next() {
                return this.createNext();
            }
            /**
            * @description Creates and returns the next array of 16 random bytes.
            *
            * @returns {Array<number>} , An array of 16 random bytes.
            */
            createNext() {
                let intermediateState;
                let resultState;
                let dateTimeByteArry;
                dateTimeByteArry = TS.Security.padData(TS.Utils.UIntToByteArray(new Date().valueOf()));
                intermediateState = new Security.State(this.aes.encrypt(dateTimeByteArry));
                intermediateState.xor(this.state);
                resultState = new Security.State(this.aes.encrypt(intermediateState.toArray()));
                intermediateState.xor(resultState);
                this.state = new Security.State(this.aes.encrypt(intermediateState.toArray()));
                return resultState.toArray();
            }
        }
        Security.RandomNumberGenerator = RandomNumberGenerator; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        /**
        * @class TS.Security.SHA1
        *
        * @classdesc This class implements the SHA1 hash algorithm as described in the nist publication
        *  'FIPS PUB 180-4, Secure Hash Standard (SHS)'.
        *
        * @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | NIST }
        */
        class SHA1 extends Security.Cryptography {
            //TODO: Create the test functions. Add descripion
            /**
            * @constructor
            */
            constructor() {
                super();
            }
            /**
            * @descriptions Initializes the hash values and the round constants.
            *
            * @private
            */
            initialize() {
                //
                // Initialize the hash values
                //
                this.hash0 = 0x67452301;
                this.hash1 = 0xEFCDAB89;
                this.hash2 = 0x98BADCFE;
                this.hash3 = 0x10325476;
                this.hash4 = 0xC3D2E1F0;
                //
                // Initialize the round constants
                //
                this.roundConstant0 = 0x5a827999;
                this.roundConstant1 = 0x6ed9eba1;
                this.roundConstant2 = 0x8f1bbcdc;
                this.roundConstant3 = 0xca62c1d6;
            }
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
            encrypt(message) {
                let wordArray;
                let index;
                let blockIndex;
                let temp;
                let resultString;
                //
                // Define the working variables
                //
                let _a;
                let _b;
                let _c;
                let _d;
                let _e;
                //
                // Define the array of message schedule variables.
                //
                let _w;
                if (TS.Utils.Assert.isNullOrUndefined(message)) {
                    throw new TS.ArgumentNullOrUndefinedException("message", "Argument message must be null or undefined in function 'TS.Security.SHA1.encrypt'.");
                } //END if
                if (!TS.Utils.Assert.isString(message) && !TS.Utils.Assert.isUnsignedByteArray(message)) {
                    throw new TS.InvalidTypeException("message", message, "Argument message must be a valid string or an array of unsigned byte values in function 'TS.Security.SHA1.encrypt'.");
                } //END if
                //
                // Pad the message
                //
                wordArray = TS.Security.pad_SHA(message);
                //
                // Initialize constants and hash values.
                //
                this.initialize();
                //
                // Initialize the array of message schedule variables.
                //
                _w = new Array(80);
                for (blockIndex = 0; blockIndex < wordArray.length; blockIndex += 16) {
                    //
                    // Prepare the message schedul
                    //
                    for (index = 0; index < 16; index++) {
                        _w[index] = wordArray[blockIndex + index];
                    } //END of
                    for (index = 16; index <= 79; index++) {
                        _w[index] = SHA1.rotateLeft32(SHA1.correctNegative(_w[index - 3] ^ _w[index - 8] ^ _w[index - 14] ^ _w[index - 16]), 1);
                    } //END for
                    //
                    // Initialize the working variables
                    //
                    _a = this.hash0;
                    _b = this.hash1;
                    _c = this.hash2;
                    _d = this.hash3;
                    _e = this.hash4;
                    //ch
                    for (index = 0; index <= 19; index++) {
                        temp = (SHA1.rotateLeft32(SHA1.correctNegative(_a), 5) + SHA1.ch32(_b, _c, _d) + _e + this.roundConstant0 + _w[index]) % 0x100000000;
                        restOperation();
                    } //END for
                    //parity
                    for (index = 20; index <= 39; index++) {
                        temp = (SHA1.rotateLeft32(SHA1.correctNegative(_a), 5) + SHA1.parity(_b, _c, _d) + _e + this.roundConstant1 + _w[index]) % 0x100000000;
                        restOperation();
                    }
                    //maj
                    for (index = 40; index <= 59; index++) {
                        temp = (SHA1.rotateLeft32(SHA1.correctNegative(_a), 5) + SHA1.maj32(_b, _c, _d) + _e + this.roundConstant2 + _w[index]) % 0x100000000;
                        restOperation();
                    }
                    //parity
                    for (index = 60; index <= 79; index++) {
                        temp = (SHA1.rotateLeft32(SHA1.correctNegative(_a), 5) + SHA1.parity(_b, _c, _d) + _e + this.roundConstant3 + _w[index]) % 0x100000000;
                        restOperation();
                    }
                    function restOperation() {
                        _e = _d;
                        _d = _c;
                        _c = SHA1.rotateLeft32(SHA1.correctNegative(_b), 30) % 0x100000000;
                        _b = _a;
                        _a = temp;
                    }
                    this.hash0 = (this.hash0 + _a) % 0x100000000;
                    this.hash1 = (this.hash1 + _b) % 0x100000000;
                    this.hash2 = (this.hash2 + _c) % 0x100000000;
                    this.hash3 = (this.hash3 + _d) % 0x100000000;
                    this.hash4 = (this.hash4 + _e) % 0x100000000;
                } //END for
                resultString = TS.Utils.UInt32ToHexString(this.hash0) +
                    TS.Utils.UInt32ToHexString(this.hash1) +
                    TS.Utils.UInt32ToHexString(this.hash2) +
                    TS.Utils.UInt32ToHexString(this.hash3) +
                    TS.Utils.UInt32ToHexString(this.hash4);
                return resultString;
            }
        }
        Security.SHA1 = SHA1; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace 
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        /**
        * @class TS.Security.SHA224
        *
        * @classdesc This class implements the SAH224 hash algorithm as described in the nist publication
        *  'FIPS PUB 180-4, Secure Hash Standard (SHS)'.
        *
        *  @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | NIST }
        */
        class SHA224 extends TS.Security.Cryptography {
            constructor() {
                super();
            }
            /**
            * @descriptions Initializes the hash values and the round constant array.
            *
            * @private
            */
            initialize() {
                //
                // Initialize the hash values
                //
                this.hash0 = 0xc1059ed8;
                this.hash1 = 0x367cd507;
                this.hash2 = 0x3070dd17;
                this.hash3 = 0xf70e5939;
                this.hash4 = 0xffc00b31;
                this.hash5 = 0x68581511;
                this.hash6 = 0x64f98fa7;
                this.hash7 = 0xbefa4fa4;
                //
                // Initialize the round constants
                //
                this.roundConstantArray = TS.Security.getSHA224_256RoundConstants();
            }
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
            encrypt(message) {
                let wordArray;
                let index;
                let blockIndex;
                let temp1;
                let temp2;
                let resultString;
                //
                // Define the working variables
                //
                let _a;
                let _b;
                let _c;
                let _d;
                let _e;
                let _f;
                let _g;
                let _h;
                //
                // Define the array of message schedule variables.
                //
                let _w;
                if (TS.Utils.Assert.isNullOrUndefined(message)) {
                    throw new TS.ArgumentNullOrUndefinedException("message", "Argument message must be null or undefined in function 'TS.Security.SHA224.encrypt'.");
                } //END if
                if (!TS.Utils.Assert.isString(message) && !TS.Utils.Assert.isUnsignedByteArray(message)) {
                    throw new TS.InvalidTypeException("message", message, "Argument message must be a valid string or an array of unsigned byte values in function 'TS.Security.SHA224.encrypt'.");
                } //END if
                //
                // Pad the message
                //
                wordArray = TS.Security.pad_SHA(message);
                //
                // Initialize constants and hash values.
                //
                this.initialize();
                //
                // Initialize the array of message schedule variables.
                //
                _w = new Array(63);
                for (blockIndex = 0; blockIndex < wordArray.length; blockIndex += 16) {
                    //
                    // Prepare the message schedul
                    //
                    for (index = 0; index < 16; index++) {
                        _w[index] = wordArray[blockIndex + index];
                    } //END of
                    for (index = 16; index <= 64; index++) {
                        temp1 = (TS.Security.Cryptography.gamma1_32(_w[index - 2]) + _w[index - 7]) % 0x100000000;
                        temp2 = (TS.Security.Cryptography.gamma0_32(_w[index - 15]) + _w[index - 16]) % 0x100000000;
                        _w[index] = (temp1 + temp2) % 0x100000000;
                    } //END for
                    //
                    // Initialize the working variables
                    //
                    _a = this.hash0;
                    _b = this.hash1;
                    _c = this.hash2;
                    _d = this.hash3;
                    _e = this.hash4;
                    _f = this.hash5;
                    _g = this.hash6;
                    _h = this.hash7;
                    for (index = 0; index < 64; index++) {
                        if (index == 17) {
                            var X = 10;
                        } //END if
                        temp1 = (_h + TS.Security.Cryptography.sigma1_32(_e) + TS.Security.Cryptography.ch32(_e, _f, _g) + this.roundConstantArray[index] + _w[index]) % 0x100000000;
                        temp2 = (TS.Security.Cryptography.sigma0_32(_a) + TS.Security.Cryptography.maj32(_a, _b, _c)) % 0x100000000;
                        restOperation();
                    } //END for
                    function restOperation() {
                        _h = _g;
                        _g = _f;
                        _f = _e;
                        _e = (_d + temp1) % 0x100000000;
                        _d = _c;
                        _c = _b;
                        _b = _a;
                        _a = (temp1 + temp2) % 0x100000000;
                    }
                    this.hash0 = (this.hash0 + _a) % 0x100000000;
                    this.hash1 = (this.hash1 + _b) % 0x100000000;
                    this.hash2 = (this.hash2 + _c) % 0x100000000;
                    this.hash3 = (this.hash3 + _d) % 0x100000000;
                    this.hash4 = (this.hash4 + _e) % 0x100000000;
                    this.hash5 = (this.hash5 + _f) % 0x100000000;
                    this.hash6 = (this.hash6 + _g) % 0x100000000;
                    this.hash7 = (this.hash7 + _h) % 0x100000000;
                } //END for
                resultString = TS.Utils.UInt32ToHexString(this.hash0) +
                    TS.Utils.UInt32ToHexString(this.hash1) +
                    TS.Utils.UInt32ToHexString(this.hash2) +
                    TS.Utils.UInt32ToHexString(this.hash3) +
                    TS.Utils.UInt32ToHexString(this.hash4) +
                    TS.Utils.UInt32ToHexString(this.hash5) +
                    TS.Utils.UInt32ToHexString(this.hash6);
                return resultString;
            }
        }
        Security.SHA224 = SHA224; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace 
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        /**
        * @class TS.Security.SHA256
        *
        * @classdesc This class implements the SHA256 hash algorithm as described in the nist publication
        *  'FIPS PUB 180-4, Secure Hash Standard (SHS)'.
        *
        *  @see {@link http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf | NIST }
        */
        class SHA256 extends Security.Cryptography {
            /**
            * @constructor
            */
            constructor() {
                super();
            }
            initialize() {
                //
                // Initialize the hash values
                //
                this.hash0 = 0x6a09e667;
                this.hash1 = 0xbb67ae85;
                this.hash2 = 0x3c6ef372;
                this.hash3 = 0xa54ff53a;
                this.hash4 = 0x510e527f;
                this.hash5 = 0x9b05688c;
                this.hash6 = 0x1f83d9ab;
                this.hash7 = 0x5be0cd19;
                //
                // Initialize the round constants
                //
                this.roundConstantArray = TS.Security.getSHA224_256RoundConstants();
            }
            /**
            * @description Encrypts the plain text given in argument 'message' and returns the digest / SHA256 hash as a hexadecimal string.
            *
            * @param {string | Array<number>} message, Either a simple text string or an array of unsigned byte values.
            * @returns {string}, The resulting digest / SHA256 as HEX string.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            encrypt(message) {
                let wordArray;
                let index;
                let blockIndex;
                let temp1;
                let temp2;
                let resultString;
                //
                // Define the working variables
                //
                let _a;
                let _b;
                let _c;
                let _d;
                let _e;
                let _f;
                let _g;
                let _h;
                //
                // Define the array of message schedule variables.
                //
                let _w;
                if (TS.Utils.Assert.isNullOrUndefined(message)) {
                    throw new TS.ArgumentNullOrUndefinedException("message", "Argument message must be null or undefined in function 'TS.Security.SHA256.encrypt'.");
                } //END if
                if (!TS.Utils.Assert.isString(message) && !TS.Utils.Assert.isUnsignedByteArray(message)) {
                    throw new TS.InvalidTypeException("message", message, "Argument message must be a valid string or an array of unsigned byte values in function 'TS.Security.SHA256.encrypt'.");
                } //END if
                //
                // Pad the message
                //
                wordArray = TS.Security.pad_SHA(message);
                //
                // Initialize constants and hash values.
                //
                this.initialize();
                //
                // Initialize the array of message schedule variables.
                //
                _w = new Array(63);
                for (blockIndex = 0; blockIndex < wordArray.length; blockIndex += 16) {
                    //
                    // Prepare the message schedul
                    //
                    for (index = 0; index < 16; index++) {
                        _w[index] = wordArray[blockIndex + index];
                    } //END of
                    for (index = 16; index <= 64; index++) {
                        temp1 = (TS.Security.Cryptography.gamma1_32(_w[index - 2]) + _w[index - 7]) % 0x100000000;
                        temp2 = (TS.Security.Cryptography.gamma0_32(_w[index - 15]) + _w[index - 16]) % 0x100000000;
                        _w[index] = (temp1 + temp2) % 0x100000000;
                    } //END for
                    //
                    // Initialize the working variables
                    //
                    _a = this.hash0;
                    _b = this.hash1;
                    _c = this.hash2;
                    _d = this.hash3;
                    _e = this.hash4;
                    _f = this.hash5;
                    _g = this.hash6;
                    _h = this.hash7;
                    for (index = 0; index < 64; index++) {
                        if (index == 17) {
                            var X = 10;
                        } //END if
                        temp1 = (_h + TS.Security.Cryptography.sigma1_32(_e) + TS.Security.Cryptography.ch32(_e, _f, _g) + this.roundConstantArray[index] + _w[index]) % 0x100000000;
                        temp2 = (TS.Security.Cryptography.sigma0_32(_a) + TS.Security.Cryptography.maj32(_a, _b, _c)) % 0x100000000;
                        restOperation();
                    } //END for
                    function restOperation() {
                        _h = _g;
                        _g = _f;
                        _f = _e;
                        _e = (_d + temp1) % 0x100000000;
                        _d = _c;
                        _c = _b;
                        _b = _a;
                        _a = (temp1 + temp2) % 0x100000000;
                    }
                    this.hash0 = (this.hash0 + _a) % 0x100000000;
                    this.hash1 = (this.hash1 + _b) % 0x100000000;
                    this.hash2 = (this.hash2 + _c) % 0x100000000;
                    this.hash3 = (this.hash3 + _d) % 0x100000000;
                    this.hash4 = (this.hash4 + _e) % 0x100000000;
                    this.hash5 = (this.hash5 + _f) % 0x100000000;
                    this.hash6 = (this.hash6 + _g) % 0x100000000;
                    this.hash7 = (this.hash7 + _h) % 0x100000000;
                } //END for
                resultString = TS.Utils.UInt32ToHexString(this.hash0) +
                    TS.Utils.UInt32ToHexString(this.hash1) +
                    TS.Utils.UInt32ToHexString(this.hash2) +
                    TS.Utils.UInt32ToHexString(this.hash3) +
                    TS.Utils.UInt32ToHexString(this.hash4) +
                    TS.Utils.UInt32ToHexString(this.hash5) +
                    TS.Utils.UInt32ToHexString(this.hash6) +
                    TS.Utils.UInt32ToHexString(this.hash7);
                return resultString;
            }
        }
        Security.SHA256 = SHA256; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        function multiplyByTwo(x) {
            return TS.Security.getAES_multByTwoArray()[x];
        }
        function multiplyByThree(x) {
            return TS.Security.getAES_multByThreeArray()[x];
        }
        function multiplyByFourteen(x) {
            return TS.Security.getAES_multByFourteenArray()[x];
        }
        function multiplyByThirteen(x) {
            return TS.Security.getAES_multByThirteenArray()[x];
        }
        function multiplyByEleven(x) {
            return TS.Security.getAES_multByElevenArray()[x];
        }
        function multiplyByNine(x) {
            return TS.Security.getAES_multByNineArray()[x];
        }
        function getRoundConstant(index) {
            return TS.Security.getAES_roundConstants()[index];
        }
        function getSubstitution(index) {
            return TS.Security.getAES_substitutionTable()[index];
        }
        function getInversSubstitution(index) {
            return TS.Security.getAES_inverseSubstitutionTable()[index];
        }
        //TODO: Add descripion
        /**
        * @class TS.Security.State
        * @extends {TS.Security.Cryptography}
        */
        class State extends TS.Security.Cryptography {
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
            constructor(byteArray16) {
                TS.Utils.checkUByteArrayParameter("byteArray16", byteArray16, "TS.Security.State.constructor");
                if (byteArray16.length != 16) {
                    throw new TS.ArgumentOutOfRangeException("byteArray16", byteArray16, "Argument 'byteArray16' is not a valid array of 16 unsigned bytes in function: 'Security.State.constructor'.");
                } //END if
                super();
                this.fromArray(byteArray16);
            }
            get Hex() {
                let resultArray;
                let index;
                resultArray = new Array();
                resultArray[0] = new Array();
                resultArray[1] = new Array();
                resultArray[2] = new Array();
                resultArray[3] = new Array();
                for (index = 0; index < 4; index++) {
                    resultArray[0].push(TS.Utils.UByteToHexString(this.state[0][index]));
                    resultArray[1].push(TS.Utils.UByteToHexString(this.state[1][index]));
                    resultArray[2].push(TS.Utils.UByteToHexString(this.state[2][index]));
                    resultArray[3].push(TS.Utils.UByteToHexString(this.state[3][index]));
                } //END for
                return resultArray;
            }
            /**
            * @description Executes the forward cipher operation on the current state.
            *
            * @param {Array<number>} workingKeyByteArray
            * @param {number} rounds
            */
            encrypt(workingKeyByteArray, rounds) {
                let round;
                this.addRoundKey(workingKeyByteArray, 0);
                for (round = 1; round < rounds; round++) {
                    this.substituteBytes();
                    this.shiftRows();
                    this.mixColumns();
                    this.addRoundKey(workingKeyByteArray, round * 16);
                } //END for
                this.substituteBytes();
                this.shiftRows();
                this.addRoundKey(workingKeyByteArray, rounds * 16);
            }
            /**
            * @description Executes the backward cipher operation on the current state.
            *
            * @param {Array<number>} workingKeyByteArray
            * @param {number} rounds
            */
            decrypt(workingKeyByteArray, rounds) {
                let round;
                this.addRoundKey(workingKeyByteArray, rounds * 16);
                for (round = rounds - 1; round > 0; round--) {
                    this.inverseShiftRows();
                    this.inverseSubstituteBytes();
                    this.addRoundKey(workingKeyByteArray, round * 16);
                    this.inverseMixColumns();
                } //END for
                this.inverseShiftRows();
                this.inverseSubstituteBytes();
                this.addRoundKey(workingKeyByteArray, 0);
            }
            /**
            * @description Returns all bytes of the current state as a byte array with 16 elements.
            *
            * @returns {Array<number>}, An array of 16 byte
            */
            toArray() {
                let resultArray;
                let column0;
                let column1;
                let column2;
                let column3;
                resultArray = new Array();
                column0 = this.getColumn(0);
                column1 = this.getColumn(1);
                column2 = this.getColumn(2);
                column3 = this.getColumn(3);
                resultArray.push(column0[0], column0[1], column0[2], column0[3]);
                resultArray.push(column1[0], column1[1], column1[2], column1[3]);
                resultArray.push(column2[0], column2[1], column2[2], column2[3]);
                resultArray.push(column3[0], column3[1], column3[2], column3[3]);
                return resultArray;
            }
            /**
            * @description Executes the XOR operation on all bytes of the current state with the corresponding bytes of the
            *  'otherState'.
            *
            * @params {TS.Security.State} otherState
            */
            xor(otherState) {
                let firstStateArray;
                let secondStateArray;
                let resultArray;
                if (TS.Utils.Assert.isNullOrUndefined(otherState)) {
                    return;
                } //END if
                firstStateArray = this.toArray();
                secondStateArray = otherState.toArray();
                resultArray = new Array();
                firstStateArray.forEach((value, index, arr) => resultArray.push(value ^ secondStateArray[index]));
                this.fromArray(resultArray);
            }
            /**
            * @description Overwrites the state array with the values given in argument byteArray16.
            *
            * @private
            *
            * @param {Array<number>} byteArray16, An array of 16 byte
            */
            fromArray(byteArray16) {
                let index;
                this.state = new Array();
                this.state[0] = [];
                this.state[1] = [];
                this.state[2] = [];
                this.state[3] = [];
                for (index = 0; index < 4; index++) {
                    this.state[0][index] = byteArray16[index * 4 + 0];
                    this.state[1][index] = byteArray16[index * 4 + 1];
                    this.state[2][index] = byteArray16[index * 4 + 2];
                    this.state[3][index] = byteArray16[index * 4 + 3];
                } //END for
            }
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
            getRow(rowIndex) {
                if ((rowIndex < 0) || (rowIndex > 3)) {
                    throw new TS.ArgumentOutOfRangeException("rowIndex", rowIndex, "Argument 'rowIndex' must be an integer value between 0 .. 3 in function 'TS.Security.State.getRow'.");
                } //END if
                return this.state[rowIndex].slice();
            }
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
            setRow(rowIndex, byteArray4) {
                if ((rowIndex < 0) || (rowIndex > 3)) {
                    throw new TS.ArgumentOutOfRangeException("rowIndex", rowIndex, "Argument 'rowIndex' must be an integer value between 0 .. 3 in function 'TS.Security.State.setRow'.");
                } //END if
                TS.Utils.checkUByteArrayParameter("byteArray4", byteArray4, "TS.Security.State.setRow");
                if (byteArray4.length != 4) {
                    throw new TS.ArgumentException("byteArray4", byteArray4, "Argument 'byteArray4' has not the required length of 4 elements in function 'TS.Security.State.setRow'.");
                }
                this.state[rowIndex] = byteArray4.slice();
            }
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
            getColumn(columnIndex) {
                let resultArray;
                if ((columnIndex < 0) || (columnIndex > 3)) {
                    throw new TS.ArgumentOutOfRangeException("columnIndex", columnIndex, "Argument rowIndex must be an integer value between 0 .. 3 in function 'TS.Security.State.getColumn'.");
                } //END if
                resultArray = new Array();
                resultArray.push(this.state[0][columnIndex]);
                resultArray.push(this.state[1][columnIndex]);
                resultArray.push(this.state[2][columnIndex]);
                resultArray.push(this.state[3][columnIndex]);
                return resultArray;
            }
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
            setColumn(columnIndex, byteArray4) {
                if ((columnIndex < 0) || (columnIndex > 3)) {
                    throw new TS.ArgumentOutOfRangeException("columnIndex", columnIndex, "Argument rowIndex must be an integer value between 0 .. 3 in function 'TS.Security.State.setColumn'.");
                } //END if
                TS.Utils.checkUByteArrayParameter("byteArray4", byteArray4, "TS.Security.State.setColumn");
                this.state[0][columnIndex] = byteArray4[0];
                this.state[1][columnIndex] = byteArray4[1];
                this.state[2][columnIndex] = byteArray4[2];
                this.state[3][columnIndex] = byteArray4[3];
            }
            //TODO: Add descripion
            /**
            * @private
            *
            * @param {Array<number>} workingKeyByteArray
            * @param {number} workingKeyByteArrayOffset
            */
            addRoundKey(workingKeyByteArray, workingKeyByteArrayOffset) {
                let resultArray;
                let offset;
                let index;
                let tempWord;
                let tempColumn;
                let tempKeyScheduleColumn;
                let keyScheduleState;
                resultArray = new Array();
                keyScheduleState = new State(workingKeyByteArray.slice(workingKeyByteArrayOffset, workingKeyByteArrayOffset + 16));
                for (index = 0; index < 4; index++) {
                    tempColumn = this.getColumn(index);
                    tempKeyScheduleColumn = keyScheduleState.getColumn(index);
                    tempWord = TS.Security.State.xorWord(tempColumn, tempKeyScheduleColumn);
                    resultArray.push(tempWord[0], tempWord[1], tempWord[2], tempWord[3]);
                } //END for
                this.fromArray(resultArray);
            }
            //TODO: Add descripion
            /**
            * @private
            */
            shiftRows() {
                let rowTmp;
                let row1;
                let row2;
                let row3;
                row1 = this.getRow(1);
                row2 = this.getRow(2);
                row3 = this.getRow(3);
                rowTmp = new Array();
                rowTmp.push(row1[1], row1[2], row1[3], row1[0]);
                this.setRow(1, rowTmp);
                rowTmp = new Array();
                rowTmp.push(row2[2], row2[3], row2[0], row2[1]);
                this.setRow(2, rowTmp);
                rowTmp = new Array();
                rowTmp.push(row3[3], row3[0], row3[1], row3[2]);
                this.setRow(3, rowTmp);
            }
            //TODO: Add descripion
            /**
            * @private
            */
            inverseShiftRows() {
                let rowTmp;
                let row1;
                let row2;
                let row3;
                row1 = this.getRow(1);
                row2 = this.getRow(2);
                row3 = this.getRow(3);
                rowTmp = new Array();
                rowTmp.push(row1[3], row1[0], row1[1], row1[2]);
                this.setRow(1, rowTmp);
                rowTmp = new Array();
                rowTmp.push(row2[2], row2[3], row2[0], row2[1]);
                this.setRow(2, rowTmp);
                rowTmp = new Array();
                rowTmp.push(row3[1], row3[2], row3[3], row3[0]);
                this.setRow(3, rowTmp);
            }
            //TODO: Add descripion
            /**
            * @private
            */
            mixColumns() {
                let index;
                let resultArray;
                let row0;
                let row1;
                let row2;
                let row3;
                resultArray = new Array();
                row0 = this.getRow(0);
                row1 = this.getRow(1);
                row2 = this.getRow(2);
                row3 = this.getRow(3);
                for (index = 0; index < 4; index++) {
                    resultArray.push(multiplyByTwo(row0[index]) ^ multiplyByThree(row1[index]) ^ row2[index] ^ row3[index]);
                    resultArray.push(row0[index] ^ multiplyByTwo(row1[index]) ^ multiplyByThree(row2[index]) ^ row3[index]);
                    resultArray.push(row0[index] ^ row1[index] ^ multiplyByTwo(row2[index]) ^ multiplyByThree(row3[index]));
                    resultArray.push(multiplyByThree(row0[index]) ^ row1[index] ^ row2[index] ^ multiplyByTwo(row3[index]));
                } //END for
                this.fromArray(resultArray);
            }
            //TODO: Add descripion
            /**
            * @private
            */
            inverseMixColumns() {
                let index;
                let resultArray;
                let row0;
                let row1;
                let row2;
                let row3;
                resultArray = new Array();
                row0 = this.getRow(0);
                row1 = this.getRow(1);
                row2 = this.getRow(2);
                row3 = this.getRow(3);
                for (index = 0; index < 4; index++) {
                    resultArray.push(multiplyByFourteen(row0[index]) ^ multiplyByEleven(row1[index]) ^ multiplyByThirteen(row2[index]) ^ multiplyByNine(row3[index]));
                    resultArray.push(multiplyByNine(row0[index]) ^ multiplyByFourteen(row1[index]) ^ multiplyByEleven(row2[index]) ^ multiplyByThirteen(row3[index]));
                    resultArray.push(multiplyByThirteen(row0[index]) ^ multiplyByNine(row1[index]) ^ multiplyByFourteen(row2[index]) ^ multiplyByEleven(row3[index]));
                    resultArray.push(multiplyByEleven(row0[index]) ^ multiplyByThirteen(row1[index]) ^ multiplyByNine(row2[index]) ^ multiplyByFourteen(row3[index]));
                } //END for
                this.fromArray(resultArray);
            }
            //TODO: Add descripion
            /**
            * @private
            */
            substituteBytes() {
                let index;
                let resultArray;
                let sourceArray;
                resultArray = new Array();
                sourceArray = this.toArray();
                for (index = 0; index < sourceArray.length; index++) {
                    resultArray.push(getSubstitution(sourceArray[index]));
                } //END for
                this.fromArray(resultArray);
            }
            //TODO: Add descripion
            /**
            * @private
            */
            inverseSubstituteBytes() {
                let index;
                let resultArray;
                let sourceArray;
                resultArray = new Array();
                sourceArray = this.toArray();
                for (index = 0; index < sourceArray.length; index++) {
                    resultArray.push(getInversSubstitution(sourceArray[index]));
                } //END for
                this.fromArray(resultArray);
            }
        }
        Security.State = State; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace
/// <reference path="../TypeScript-Base/TS-Base.d.ts" />
/// <reference path="Security/Security.ts" />
/// <reference path="Security/Cryptography.ts" />
/// <reference path="Security/AbstractStreamCipher.ts" />
/// <reference path="Security/AES.ts" />
/// <reference path="Security/AES_CBC_Stream.ts" />
/// <reference path="Security/AES_CFB.ts" />
/// <reference path="Security/AES_CFB_Stream.ts" />
/// <reference path="Security/AES_CTR.ts" />
/// <reference path="Security/AES_CTR_Stream.ts" />
/// <reference path="Security/AES_OFB.ts" />
/// <reference path="Security/AES_OFB_Stream.ts" />
/// <reference path="Security/AES_Stream.ts" />
/// <reference path="Security/Counter.ts" />
/// <reference path="Security/RandomNumberGenertor.ts" />
/// <reference path="Security/SHA1.ts" />
/// <reference path="Security/SHA224.ts" />
/// <reference path="Security/SHA256.ts" />
/// <reference path="Security/State.ts" />
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        /**
        * @class TS.Security.AES_CBC
        *
        * @description This is an implementation of the CIPHER BLOCK CHAINING (CBC) operation mode as described in the NIST
        *  publication 800-38a, 'Recommendation for Block Cipher Modes of Operation'.
        *
        * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
        */
        class AES_CBC extends Security.AES {
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
            constructor(keyByteArray, initialisationVector) {
                TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_CBC.constructor");
                TS.Utils.checkUByteArrayParameter("initialisationVector", initialisationVector, "TS.Security.AES_CBC.constructor");
                if (initialisationVector.length != 16) {
                    throw new TS.ArgumentOutOfRangeException("initialisationVector", initialisationVector, "Argument 'initialisationVector' must be a byte array of the length 16 in function 'TS.Security.AES_CBC.constructor'.");
                } //END if
                super(keyByteArray);
                this.IV = new Security.State(initialisationVector);
            }
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
            encrypt(plainDataByteArray) {
                let index;
                let state;
                let previousState;
                let resultByteArray;
                TS.Utils.checkUByteArrayParameter("plainDataByteArray", plainDataByteArray, "TS.Security.AES_CBC.encrypt");
                if ((plainDataByteArray.length % 16) != 0) {
                    throw new TS.ArgumentException("plainDataByteArray", plainDataByteArray, "The 'plainDataByteArray' must have a lenght which is a multiple of 16 (the AES block size). Use the 'padData' function in oder to give your data an appropriate length.");
                } //END if
                index = 0;
                previousState = this.IV;
                resultByteArray = new Array();
                while (index * 16 < plainDataByteArray.length) {
                    state = new Security.State(plainDataByteArray.slice(index * 16, (index + 1) * 16));
                    state.xor(previousState);
                    state.encrypt(this.workingKeyByteArray, this.rounds);
                    resultByteArray = resultByteArray.concat(state.toArray());
                    previousState = new Security.State(state.toArray());
                    index++;
                } //END while
                return resultByteArray;
            }
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
            decrypt(cypherDataByteArray) {
                let index;
                let state;
                let previousState;
                let resultByteArray;
                TS.Utils.checkUByteArrayParameter("cypherDataByteArray", cypherDataByteArray, "TS.Security.AES_CBC.decrypt");
                if ((cypherDataByteArray.length % 16) != 0) {
                    throw new TS.ArgumentException("cypherDataByteArray", cypherDataByteArray, "The 'cypherDataByteArray' must have a lenght which is a multiple of 16 (the AES block size). Use the 'padData' function in oder to give your data an appropriate length.");
                } //END if
                index = 0;
                previousState = this.IV;
                resultByteArray = new Array();
                while (index * 16 < cypherDataByteArray.length) {
                    state = new Security.State(cypherDataByteArray.slice(index * 16, (index + 1) * 16));
                    state.decrypt(this.workingKeyByteArray, this.rounds);
                    state.xor(previousState);
                    resultByteArray = resultByteArray.concat(state.toArray());
                    previousState = new Security.State(cypherDataByteArray.slice(index * 16, (index + 1) * 16));
                    index++;
                } //END while
                return resultByteArray;
            }
        }
        Security.AES_CBC = AES_CBC; //END class
    })(Security = TS.Security || (TS.Security = {})); //END module
})(TS || (TS = {})); //END module
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        /**
        * @description This is an implementation of the 'HMAC' (The Keyed-Hash Message Authentication Code) as described in
        *  the FIPS publication 198a and 198-1. It is mentioned in this standard, that the hash digest is often truncated
        *  but should not be shortened to less than 4 bytes. Since this is only a recommendation but not a requirement this
        *  implementation will return the full length digest. You have to truncate the digest yourself if you need a
        *  truncated digest for interoperability with other implementations.
        *
        * @see {@link http://csrc.nist.gov/publications/fips/fips198/fips-198a.pdf | FIPS}
        *
        * @param {string} authenticationKey, Either a simple text string or an array of unsigned byte values.
        * @param {string} message, Either a simple text string or an array of unsigned byte values.
        * @param {IHashDescriptor} hashDescriptor
        *
        * @returns {string}, A HEX string as a result of the keyed hash operation.
        *
        * @throws {TS.ArgumentNullOrUndefinedException}
        * @throws {TS.ArgumentNullUndefOrWhiteSpaceException}
        * @throws {TS.InvalidTypeException}
        */
        function HMAC(authenticationKey, message, hashDescriptor) {
            let workingKeyArray;
            let messageArray;
            TS.Utils.checkParameter("authenticationKey", authenticationKey, "TS.Security.HMAC");
            TS.Utils.checkParameter("message", message, "TS.Security.HMAC");
            TS.Utils.checkParameter("hashDescriptor", hashDescriptor, "TS.Security.HMAC");
            if (!TS.Utils.Assert.isString(authenticationKey) && !TS.Utils.Assert.isUnsignedByteArray(authenticationKey)) {
                throw new TS.InvalidTypeException("authenticationKey", authenticationKey, "Argument authenticationKey must be a valid string or an array of unsigned byte values in function 'TS.Security.HMAC'.");
            } //END if
            if (!TS.Utils.Assert.isString(message) && !TS.Utils.Assert.isUnsignedByteArray(message)) {
                throw new TS.InvalidTypeException("message", message, "Argument message must be a valid string or an array of unsigned byte values in function 'TS.Security.HMAC'.");
            } //END if
            if (TS.Utils.Assert.isString(authenticationKey)) {
                if (message.length > 0) {
                    workingKeyArray = TS.Encoding.UTF.UTF16StringToUTF8Array(authenticationKey);
                }
                else {
                    workingKeyArray = new Array();
                }
            }
            else {
                workingKeyArray = authenticationKey.slice();
            }
            if (TS.Utils.Assert.isString(message)) {
                if (message.length > 0) {
                    messageArray = TS.Encoding.UTF.UTF16StringToUTF8Array(message);
                }
                else {
                    messageArray = new Array();
                }
            }
            else {
                messageArray = message.slice();
            }
            let innerPad = new Array(hashDescriptor.inputBlockSizeInByte).fill(0x36);
            let outerPad = new Array(hashDescriptor.inputBlockSizeInByte).fill(0x5c);
            let innerKeyPad;
            let outerKeyPad;
            if (workingKeyArray.length > hashDescriptor.inputBlockSizeInByte) {
                workingKeyArray = TS.Utils.HexStringToUByteArray(hashDescriptor.hash(workingKeyArray));
            }
            while (workingKeyArray.length < hashDescriptor.inputBlockSizeInByte) {
                workingKeyArray.push(0);
            }
            innerKeyPad = TS.Security.XORByteArray(innerPad, workingKeyArray);
            outerKeyPad = TS.Security.XORByteArray(outerPad, workingKeyArray);
            debugger;
            let tempResult = hashDescriptor.hash(innerKeyPad.concat(messageArray));
            return hashDescriptor.hash(outerKeyPad.concat(TS.Utils.HexStringToUByteArray(tempResult)));
        }
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
        function HMAC_SHA1(authenticationKey, message) {
            let sha1 = new TS.Security.SHA1();
            return HMAC(authenticationKey, message, { inputBlockSizeInByte: TS.Security.SHA1_KEY_SIZE, outputBlockSizeInByte: TS.Security.SHA1_HASH_SIZE, hash: sha1.encrypt.bind(sha1) });
        }
        Security.HMAC_SHA1 = HMAC_SHA1;
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
        function HMAC_MD5(authenticationKey, message) {
            return HMAC(authenticationKey, message, { inputBlockSizeInByte: TS.Security.MD5_KEY_SIZE, outputBlockSizeInByte: TS.Security.MD5_HASH_SIZE, hash: TS.Security.MD5.encrypt });
        }
        Security.HMAC_MD5 = HMAC_MD5;
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        /**
        * @class TS.Security.MD5
        *
        * @classdesc This class implements the MD5 hash algorithm as described in the IETF publication
        *  'The MD5 Message-Digest Algorithm'.
        *
        * @see {@link https://www.ietf.org/rfc/rfc1321.txt | IETF }
        */
        class MD5 extends Security.Cryptography {
            /**
            *
            * @param {string | Array<number>} message, Either a simple text string or an array of unsigned byte values.
            *
            * @returns {string}, The resulting digest / MD5 as HEX string.
            *
            * @throws {TS.ArgumentNullOrUndefinedException}
            * @throws {TS.InvalidTypeException}
            */
            static encrypt(message) {
                let wordArray;
                //
                // Declare word array variables
                //
                let H0;
                let H1;
                let H2;
                let H3;
                //
                // Declare the sine values table
                //
                let sineTable;
                let perRoundShiftAmountTable;
                //
                // RFC 1321
                //
                //  3.1 Step 1. Append Padding Bits
                //  3.2 Step 2. Append Length
                //
                //
                // Pad the message
                //
                wordArray = TS.Security.pad_MD5(message);
                //
                // RFC 1321,3.3 Step 3. Initialize MD Buffer
                //
                //3.3 Step 3. Initialize MD Buffer
                //  A four‐word buffer (A, B, C, D) is used to compute the message digest.Here each of A,  B,  C,  D is a 32‐bit register. 
                //  These registers are     initialized to the following values in hexadecimal, low‐order bytes     first): 
                //
                // word A: 01 23 45 67
                // word B: 89 ab cd ef
                // word C: fe dc ba 98
                // word D: 76 54 32 10
                //
                H0 = TS.Security.UByteArrayToFourByteWord([0x67, 0x45, 0x23, 0x01]);
                H1 = TS.Security.UByteArrayToFourByteWord([0xef, 0xcd, 0xab, 0x89]);
                H2 = TS.Security.UByteArrayToFourByteWord([0x98, 0xba, 0xdc, 0xfe]);
                H3 = TS.Security.UByteArrayToFourByteWord([0x10, 0x32, 0x54, 0x76]);
                //
                // RFC 1321,3.4 Step 4. Process Message in 16‐Word Blocks
                //
                //
                // Precalculated integer sine values of the values [1..64] * 0x100000000
                //
                sineTable = TS.Security.getMD5_SineTable();
                //
                // Predefined per round shift amount table
                //
                perRoundShiftAmountTable = TS.Security.getMD5_PerRoundShiftAmountTable();
                for (let outerIndex = 0; outerIndex < wordArray.length; outerIndex += 16) {
                    //
                    // Define the round variables.
                    //
                    let roundA;
                    let roundB;
                    let roundC;
                    let roundD;
                    let funcResult;
                    let chunkIndex;
                    //
                    // Create one chunk of 16 words for each round.
                    //
                    let chunk;
                    chunk = new Array();
                    for (let innerIndex = 0; innerIndex < 16; innerIndex++) {
                        chunk.push(TS.Utils.UInt32SwapSignificantByteOrder(wordArray[outerIndex + innerIndex]));
                    }
                    //
                    // Initialize the round variable with the last values of the hash variables.
                    //
                    roundA = H0;
                    roundB = H1;
                    roundC = H2;
                    roundD = H3;
                    for (let roundIndex = 0; roundIndex < 64; roundIndex++) {
                        if (roundIndex < 16) {
                            funcResult = TS.Security.Cryptography.MD5FuncOne(roundB, roundC, roundD);
                            chunkIndex = roundIndex;
                        }
                        if ((roundIndex > 15) && (roundIndex < 32)) {
                            funcResult = TS.Security.Cryptography.MD5FuncTwo(roundB, roundC, roundD);
                            chunkIndex = (5 * roundIndex + 1) % 16;
                        }
                        if ((roundIndex > 31) && (roundIndex < 48)) {
                            funcResult = TS.Security.Cryptography.MD5FuncThree(roundB, roundC, roundD);
                            chunkIndex = (3 * roundIndex + 5) % 16;
                        }
                        if ((roundIndex > 47) && (roundIndex < 64)) {
                            funcResult = TS.Security.Cryptography.MD5FuncFour(roundB, roundC, roundD);
                            chunkIndex = (7 * roundIndex) % 16;
                        }
                        let dTemp = roundD;
                        roundD = roundC;
                        roundC = roundB;
                        roundB = (roundB + TS.Security.Cryptography.rotateLeft32((roundA + funcResult + sineTable[roundIndex] + chunk[chunkIndex]) % 0x100000000, perRoundShiftAmountTable[roundIndex])) % 0x100000000;
                        roundA = dTemp;
                    } //END for
                    H0 = (H0 + roundA) % 0x100000000;
                    H1 = (H1 + roundB) % 0x100000000;
                    H2 = (H2 + roundC) % 0x100000000;
                    H3 = (H3 + roundD) % 0x100000000;
                } //END for
                //
                // Create a hex string and return this string as result.
                //
                return TS.Utils.UInt32ToHexString(TS.Utils.UInt32SwapSignificantByteOrder(H0)) + TS.Utils.UInt32ToHexString(TS.Utils.UInt32SwapSignificantByteOrder(H1)) + TS.Utils.UInt32ToHexString(TS.Utils.UInt32SwapSignificantByteOrder(H2)) + TS.Utils.UInt32ToHexString(TS.Utils.UInt32SwapSignificantByteOrder(H3));
            }
        }
        Security.MD5 = MD5; //END class
    })(Security = TS.Security || (TS.Security = {})); //END namespace
})(TS || (TS = {})); //END namespace 
/// <reference path="../_references.ts" />
var TS;
(function (TS) {
    var Security;
    (function (Security) {
        //https://tools.ietf.org/html/rfc6070 (PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2))
        //https://tools.ietf.org/pdf/rfc2898.pdf (PKCS #5: Password-Based Cryptography Specification Version 2.0)
        //http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf (800-132 Recommendation for Password- Based Key Derivation)
        /**
        * @description This is an implementation of the PBKDF2 (Password-Based Key Derivation Function 2) as described in
        *  RFC 2898.
        *
        * @param { Array<number>} password, A password in the form of a byte array.
        * @param { Array<number>} salt, A salt in the form of a byte array.
        * @param {number} iterations, The number of iteration which should take place to generate the derived key.
        * @param {number} requiredDerivedKeyLengthInByte, The required lenght of the derive key in byte.
        * @param {IPseudoRandomFunctionDescriptor} pseudoRandomFunctionDescriptor, A random function descriptor which has
        *  information about the random function output block size and a 'random' function which takes two byte arrays
        *  and returns a byte array of random byte values. That byte array has the length specified in the block size
        *  info.
        *
        * @returns {Array<number>}, The derived key.
        *
        * @throws {TS.ArgumentOutOfRangeException}
        */
        function PBKDF2(password, salt, iterations, requiredDerivedKeyLengthInByte, pseudoRandomFunctionDescriptor) {
            /**
             * @description The resulting derived key after derivation.
             */
            let derivedKey;
            /**
            * @description An array of output blocks comming from the pseudo random function. The total number of bytes in
            *  that array must be greater or equal to the 'requiredDerivedKeyLengthInByte'.
            *
            * @see blocksPerDerivedKey
            */
            let derivedKeyBlocksArray;
            /**
            * @description The number of blocks needed to get enough bytes to satisfy the 'requiredDerivedKeyLengthInByte'.
            *  It is the maximum lenght of the 'derivedKeyBlocksArray'.
            *
            *  blocksPerDerivedKey * pseudoRandomFunctionDescriptor.outputBlockSizeInByte >= requiredDerivedKeyLengthInByte
            *
            * @see derivedKeyBlocksArray
            */
            let blocksPerDerivedKey;
            let index;
            TS.Utils.checkUByteArrayParameter("password", password, "TS.Security.PBKDF2");
            TS.Utils.checkUByteArrayParameter("salt", salt, "TS.Security.PBKDF2");
            TS.Utils.checkUIntNumberParameter("requiredDerivedKeyLengthInByte", requiredDerivedKeyLengthInByte, "TS.Security.PBKDF2");
            TS.Utils.checkParameter("pseudoRandomFunctionDescriptor", pseudoRandomFunctionDescriptor, "TS.Security.PBKDF2");
            //
            // RFC 2898, 5.2 PBKDF2, Step 1
            //
            // 1. If dkLen > (2 ^ 32 - 1) * hLen, output "derived key too long" and stop.
            //
            if (requiredDerivedKeyLengthInByte > 0xFFFFFFFF) {
                throw new TS.ArgumentOutOfRangeException("requiredDerivedKeyLengthInByte", requiredDerivedKeyLengthInByte, "The value of 'requiredDerivedKeyLengthInByte' exceeds the maximum value which is 0xFFFFFFFF in function 'TS.Security.PBKDF2'.");
            }
            //
            // RFC 2898, 5.2 PBKDF2, Step 2
            //
            // 2. Let l be the number of hLen- octet blocks in the derived key, rounding up, and let r be the number of
            //    octets in the last block:
            //
            //      l = CEIL(dkLen / hLen),
            //      r = dkLen - (l - 1) * hLen.
            //
            //
            // l = CEIL(dkLen / hLen),
            //
            blocksPerDerivedKey = Math.ceil(requiredDerivedKeyLengthInByte / pseudoRandomFunctionDescriptor.outputBlockSizeInByte);
            //
            // RFC 2898, 5.2 PBKDF2, Step 3
            //
            // 3. For each block of the derived key apply the function F defined
            //    below to the password P, the salt S, the iteration count c, and
            //    the block index to compute the block:
            // 
            //      T_1 = F(P, S, c, 1),
            //      T_2 = F(P, S, c, 2),
            //              ...
            //      T_l = F(P, S, c, l),
            // 
            //    where the function F is defined as the exclusive- or sum of the
            //    first c iterates of the underlying pseudorandom function PRF
            //    applied to the password P and the concatenation of the salt S
            //    and the block index i:
            // 
            //      F(P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
            // 
            //    where
            // 
            //      U_1 = PRF(P, S || INT(i)),
            //      U_2 = PRF(P, U_1),
            //              ...
            //      U_c = PRF(P, U_{c-1 }).
            // 
            //    Here, INT(i) is a four- octet encoding of the integer i, most
            //    significant octet first.
            //
            derivedKeyBlocksArray = new Array();
            for (index = 0; index < blocksPerDerivedKey; index++) {
                let data = salt.concat(TS.Utils.UInt32To4ByteArray(index + 1));
                derivedKeyBlocksArray[index] = iteratePseudoRandom(password, data, iterations, pseudoRandomFunctionDescriptor);
            }
            //
            // RFC 2898, 5.2 PBKDF2, Step 4
            //
            // 4. Concatenate the blocks and extract the first dkLen octets to
            //    produce a derived key DK:
            // 
            //      DK = T_1 || T_2 ||  ...  || T_l < 0..r - 1 >
            //
            derivedKey = new Array();
            for (index = 0; index < derivedKeyBlocksArray.length; index++) {
                derivedKey.push(...derivedKeyBlocksArray[index]);
            }
            //
            // RFC 2898, 5.2 PBKDF2, Step 5
            //
            // 5. Output the derived key DK.
            //
            return derivedKey.slice(0, requiredDerivedKeyLengthInByte);
        }
        function iteratePseudoRandom(key, data, iterations, pseudoRandomFunctionDescriptor) {
            let tempData;
            let index;
            tempData = new Array();
            for (index = 0; index < iterations; index++) {
                if (index == 0) {
                    tempData[index] = pseudoRandomFunctionDescriptor.random(key, data);
                }
                else {
                    tempData[index] = pseudoRandomFunctionDescriptor.random(key, tempData[index - 1]);
                }
            }
            return tempData.reduce((prev, curr, idx, arr) => {
                return TS.Security.XORByteArray(prev, curr);
            });
        }
        function PBKDF2_HMAC_SHA1(password, salt, iterations, requiredDerivedKeyLengthInByte) {
            function random(key, data) {
                let hash = TS.Security.HMAC_SHA1(key, data);
                return TS.Utils.HexStringToUByteArray(hash);
            }
            let pseudoRandomFunctionDescriptor = {
                outputBlockSizeInByte: 20,
                random: random
            };
            return PBKDF2(password, salt, iterations, requiredDerivedKeyLengthInByte, pseudoRandomFunctionDescriptor);
        }
        Security.PBKDF2_HMAC_SHA1 = PBKDF2_HMAC_SHA1;
    })(Security = TS.Security || (TS.Security = {}));
})(TS || (TS = {}));
