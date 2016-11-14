/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {

    /**
    * @class TS.Security.AES_Stream
    *
    * @description This is an implementation of the abstract base class 'TS.Security.AbstractStreamCipher' for the
    *  AES / AES_ECB operation mode.
    * 
    * @see {TS.Security.AbstractStreamCipher}
    */
    export class AES_Stream extends AbstractStreamCipher
    {

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
      constructor(keyByteArray: Array<number>,
        cipherOperation: TS.Security.CipherOperationEnum,
        onNextData: (bitString: string) => void,
        onClosed: () => void,
        onError: (exception: TS.Exception) => void)
      {
        TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_Stream.constructor");
        TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES_Stream.constructor");
        TS.Utils.checkFunctionParameter("onNextData", onNextData, "TS.Security.AES_Stream.constructor");
        TS.Utils.checkFunctionParameter("onClosed", onClosed, "TS.Security.AES_Stream.constructor");
        TS.Utils.checkFunctionParameter("onError", onError, "TS.Security.AES_Stream.constructor");

        if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum))
        {
          throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "Argument 'cipherOperation' must be a valid element of the 'TS.Security.CipherOperationEnum' enumeration in function 'TS.Security.AES_Stream.constructor'.");
        }//END if

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
        this.streamState = StreamStateEnum.CREATED;
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
      protected cipher(bitString: string) : string
      {
        var block: Array<number>;

        block = TS.Utils.bitStringToByteArray(bitString);

        if (this.cipherOperation == TS.Security.CipherOperationEnum.DECRYPT)
        {
          return TS.Utils.byteArrayToBitString(this.blockCipher.decrypt(block));
        }//END if

        if (this.cipherOperation == TS.Security.CipherOperationEnum.ENCRYPT)
        {
          return TS.Utils.byteArrayToBitString(this.blockCipher.encrypt(block))
        }//END if
      }

    }//END class

  }//END namespace
}//END namespace 