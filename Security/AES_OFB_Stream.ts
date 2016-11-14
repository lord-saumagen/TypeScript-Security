/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {


    /**
    * @class TS.Security.AES_OFBStreamEnabled
    *
    * @description This is an implementation of the OUTPUT FEEDBACK (OFB) operation mode as described in the NIST
    *  publication 800-38a, 'Recommendation for Block Cipher Modes of Operation'. This class differs from the
    *  'TS.Security.AES_OFB' in that way, that the class is more streaming friendly.
    *
    * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
    */
    class AES_OFBStreamEnabled extends TS.Security.AES
    {
      /**
      * @private 
      */
      private IV: State;

      /**
      * @private
      */
      private workingState: State;

      /**
      * @private
      */
      private internalClosed: boolean;

      /**
      * get {boolean} closed
      */
      public get closed(): boolean
      {
        return this.internalClosed;
      }

      constructor(keyByteArray: Array<number>, initialisationVector: Array<number>)
      {
        super(keyByteArray);
        this.IV = new State(initialisationVector);
        this.workingState = null;
        this.internalClosed = false;
      }

      /**
       * @override
       * @throws {TS.InvalidOperationException}
       */
      public encrypt(plainDataByteArray: Array<number>): Array<number>
      {
        if (this.internalClosed)
        {
          throw new TS.InvalidOperationException("A call to function 'encrypt' is not allowed after the cipher object has closed. Error occured in 'TS.Security.AES_OFBStreamEnabled.enrypt'.");
        }//END if

        if (plainDataByteArray.length < 16)
        {
          this.internalClosed = true;
        }//END if

        return this.encryptDecryptInternal(plainDataByteArray);
      }


      /**
       * @override
       * @throws {TS.InvalidOperationException}
       */
      public decrypt(cypherDataByteArray: Array<number>): Array<number>
      {
        if (this.internalClosed)
        {
          throw new TS.InvalidOperationException("A call to function 'encrypt' is not allowed after the cipher object has closed. Error occured in 'TS.Security.AES_OFBStreamEnabled.decrypt'.");
        }//END if

        if (cypherDataByteArray.length < 16)
        {
          this.internalClosed = true;
        }//END if

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
      protected encryptDecryptInternal(dataByteArray: Array<number>): Array<number>
      {
        let index: number;
        let dataSegment: Array<number>;
        let numberOfFillBytes: number;
        let dataState: State;
        let resultByteArray: Array<number>;

        index = 0;
        resultByteArray = new Array<number>();
        numberOfFillBytes = 0;

        if (this.workingState == null)
        {
          this.workingState = new State(this.IV.toArray());
        }//END if

        dataSegment = dataByteArray.slice();

        this.workingState.encrypt(this.workingKeyByteArray, this.rounds);
        while (dataSegment.length < 16)
        {
          dataSegment.push(0);
          numberOfFillBytes++;
        }//END while
        dataState = new State(dataSegment)
        dataState.xor(this.workingState);
        resultByteArray = dataState.toArray();

        while (numberOfFillBytes > 0)
        {
          resultByteArray.pop();
          numberOfFillBytes--;
        }//END while

        return resultByteArray;
      }
    }//END class


    /**
    * @class TS.Security.AES_OFB_Stream
    *
    * @description This is an implementation of the abstract base class 'TS.Security.AbstractStreamCipher' for the
    *  AES_OFB operation mode.
    * 
    * @extends {TS.Security.AbstractStreamCipher}
    */
    export class AES_OFB_Stream extends TS.Security.AbstractStreamCipher
    {

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
      constructor(keyByteArray: Array<number>,
        initialisationVector: Array<number>,
        cipherOperation: TS.Security.CipherOperationEnum,
        onNextData: (bitString: string) => void,
        onClosed: () => void,
        onError: (exception: TS.Exception) => void)
      {
        TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_OFB_Stream.constructor");
        TS.Utils.checkUByteArrayParameter("initialisationVector", initialisationVector, "TS.Security.AES_OFB_Stream.constructor");
        TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES_OFB_Stream.constructor");
        TS.Utils.checkFunctionParameter("onNextData", onNextData, "TS.Security.AES_OFB_Stream.constructor");
        TS.Utils.checkFunctionParameter("onClosed", onClosed, "TS.Security.AES_OFB_Stream.constructor");
        TS.Utils.checkFunctionParameter("onError", onError, "TS.Security.AES_OFB_Stream.constructor");

        if (initialisationVector.length != 16)
        {
          throw new TS.ArgumentOutOfRangeException("initialisationVector", initialisationVector, "Argument 'initialisationVector' must be a byte array of the length 16 in function 'TS.Security.AES_OFB_Stream.constructor'.");
        }//END if

        if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum))
        {
          throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "Argument 'cipherOperation' must be a valid element of the 'TS.Security.CipherOperationEnum' enumeration in function 'TS.Security.AES_OFB_Stream.constructor'.");
        }//END if


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
      protected cipher(bitString: string): string
      {
        var block: Array<number>;

        block = TS.Utils.bitStringToByteArray(bitString);

        if (this.cipherOperation == TS.Security.CipherOperationEnum.DECRYPT)
        {
          return TS.Utils.byteArrayToBitString(this.blockCipher.decrypt(block));
        }//END if

        if (this.cipherOperation == TS.Security.CipherOperationEnum.ENCRYPT)
        {
          return TS.Utils.byteArrayToBitString(this.blockCipher.encrypt(block));
        }//END if

      }

    }//END class

  }//END namespace
}//END namespace
