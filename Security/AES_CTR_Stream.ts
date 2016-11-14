/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {

    /**
    * @class TS.Security.AES_CTRStreamEnabled
    *
    * @description This is an implementation of the COUNTER (CTR) operation mode as described in the NIST publication
    *  800-38a, 'Recommendation for Block Cipher Modes of Operation'. This class differs from the
    *  'TS.Security.AES_CTR' in that way, that the class is more streaming friendly.
    *
    * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
    */
    class AES_CTRStreamEnabled extends AES
    {
      /**
      * @private
      */
      private CTR: TS.Security.Counter;

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

      /**
      * @description That property give access to the nonce which is actually used in this AES_CTR object. You need to
      *  store this nonce along wiht your encrypted data. Otherwies you won't be able to decrypt the data anymore.
      *
      * @get {Array<number>} nonce, The nonce as array of 16 byte values.
      */
      public get nonce(): Array<number>
      {
        return this.CTR.nonce;
      }

      constructor(keyByteArray: Array<number>, counterValue: number);
      constructor(keyByteArray: Array<number>, nonce: Array<number>);
      constructor(keyByteArray: Array<number>)

      constructor(keyByteArray: Array<number>)
      {

        super(keyByteArray);

        if (arguments.length > 1)
        {
          if (TS.Utils.Assert.isUnsignedByteArray(arguments[1]))
          {
            this.CTR = new TS.Security.Counter(arguments[1]);
          }//END if
          else if (TS.Utils.Assert.isUnsignedIntegerNumber(arguments[1]))
          {
            this.CTR = new TS.Security.Counter(arguments[1]);
          }//END if
          else
          {
            throw new TS.InvalidTypeException("nonce | counterValue", arguments[1], "The second argument in the constructor of 'TS.Security.AES_CTRStreamEnabled' has an invalid type. Error occured in 'TS.Security.AES_CTRStreamEnabled.constructor'.");
          }//END else
        }//END if
        else
        {
          this.CTR = new TS.Security.Counter();
        }//END else

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
      public encrypt(plainDataByteArray: Array<number>): Array<number>
      {
        if (this.closed)
        {
          throw new TS.InvalidOperationException("A call to function 'encrypt' is not allowed after the cipher object has closed. Error occured in 'TS.Security.AES_CTRStreamEnabled.enrypt'.");
        }//END if

        if (plainDataByteArray.length < 16)
        {
          this.internalClosed = true;
        }//END if

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
      public decrypt(cypherDataByteArray: Array<number>): Array<number>
      {
        if (this.closed)
        {
          throw new TS.InvalidOperationException("A call to function 'encrypt' is not allowed after the cipher object has closed. Error occured in 'TS.Security.AES_CTRStreamEnabled.decrypt'.");
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
      *
      * @param {Array<number>} dataByteArray, Array of 16 byte values.
      * 
      * @return {Array<number>}, The resulting encrypted or decrypted data as byte array.
      */
      protected encryptDecryptInternal(dataByteArray: Array<number>): Array<number>
      {
        let dataSegment: Array<number>;
        let numberOfFillBytes: number;
        let state: State;
        let dataState: State;
        let resultByteArray: Array<number>;

        resultByteArray = new Array<number>();
        numberOfFillBytes = 0;

        state = this.CTR.nextState;
        state.encrypt(this.workingKeyByteArray, this.rounds);
        dataSegment = dataByteArray.slice();

        while (dataSegment.length < 16)
        {
          dataSegment.push(0);
          numberOfFillBytes++;
        }//END while

        dataState = new State(dataSegment)
        dataState.xor(state);
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
    * @class TS.Security.AES_CTR_Stream
    *
    * @description This is an implementation of the abstract base class 'TS.Security.AbstractStreamCipher' for the
    *  AES_CTR operation mode.
    * 
    * @see {TS.Security.AbstractStreamCipher}
    */
    export class AES_CTR_Stream extends AbstractStreamCipher
    {

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
      constructor(keyByteArray: Array<number>,
        nonce: Array<number>,
        cipherOperation: TS.Security.CipherOperationEnum,
        onNextData: (bitString: string) => void,
        onClosed: () => void,
        onError: (exception: TS.Exception) => void);
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
      constructor(keyByteArray: Array<number>,
        counterValue: number,
        cipherOperation: TS.Security.CipherOperationEnum,
        onNextData: (bitString: string) => void,
        onClosed: () => void,
        onError: (exception: TS.Exception) => void);

      constructor(keyByteArray: Array<number>,
        nonceOrcounterValue: any,
        cipherOperation: TS.Security.CipherOperationEnum,
        onNextData: (bitString: string) => void,
        onClosed: () => void,
        onError: (exception: TS.Exception) => void)
{
        let nonce: Array<number>;
        let counterValue: number;

        TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_CTR_Stream.constructor");
        TS.Utils.checkParameter("cipherOperation", cipherOperation, "TS.Security.AES_CTR_Stream.constructor");
        TS.Utils.checkFunctionParameter("onNextData", onNextData, "TS.Security.AES_CTR_Stream.constructor");
        TS.Utils.checkFunctionParameter("onClosed", onClosed, "TS.Security.AES_CTR_Stream.constructor");
        TS.Utils.checkFunctionParameter("onError", onError, "TS.Security.AES_CTR_Stream.constructor");

        nonce = null;
        counterValue = null;

        if (TS.Utils.Assert.isUnsignedByteArray(arguments[1]))
        {
          if (arguments[1].length != 16)
          {
            throw new TS.ArgumentOutOfRangeException("nonce", arguments[1], "Argument 'nonce' must be a byte value array with 16 elements in function 'TS.Security.AES_CTR.constructor'.");
          }//END if
          nonce = arguments[1];
        }//END if
        else if (TS.Utils.Assert.isUnsignedIntegerNumber(arguments[1]))
        {
          if (arguments[2] > 0xFFFFFFFF)
          {
            throw new TS.ArgumentOutOfRangeException("counterValue", arguments[1], "Argument 'counterValue' must not exceed the maximum allowed value: '" + 0xFFFFFFFF.toString() + "' in function 'TS.Security.AES_CTR.constructor'.");
          }//END if
          counterValue = arguments[1];
        }//END if
        else
        {
          throw new TS.InvalidTypeException("nonce | counterValue", arguments[1], "The second argument in the constructor of 'TS.Security.AES_CTR_Stream' has an invalid type. Error occured in 'TS.Security.AES_CTR_Stream.constructor'.");
        }//END else

        if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum))
        {
          throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "Argument 'cipherOperation' must be a valid element of the 'TS.Security.CipherOperationEnum' enumeration in function 'TS.Security.AES_CTR_Stream.constructor'.");
        }//END if

        super(cipherOperation, onNextData, onClosed, onError);

        //
        //Set ther blockCipher object.
        //
        if (nonce != null)
        {
          this.blockCipher = new AES_CTRStreamEnabled(keyByteArray, nonce);
        }//END if
        else if (counterValue != null)
        {
          this.blockCipher = new AES_CTRStreamEnabled(keyByteArray, counterValue);
        }//END if

        //
        //Set the bufferSize which is 128 bit for AES_CTR.
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
        let block: Array<number>;

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