/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {


    /**
    * @class TS.Security.AES_CTR
    *
    * @description This is an implementation of the COUNTER (CTR) operation mode as described in the NIST
    *  publication 800-38a,'Recommendation for Block Cipher Modes of Operation'.
    *
    * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
    */
    export class AES_CTR extends AES
    {
      /**
      * @private
      */
      private internalCTR: TS.Security.Counter;

      /**
      * @description The nonce which is actually used in this AES_CTR object. You need to store this nonce along with
      *  your encrypted data. Otherwies you won't be able to decrypt the data anymore.
      *
      * @get {Array<number>} nonce, The nonce as array of 16 byte values.
      */
      public get nonce(): Array<number>
      {
        return this.internalCTR.nonce;
      }

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
      constructor(keyByteArray: Array<number>, counterValue : number);
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
      constructor(keyByteArray: Array<number>)
      constructor(keyByteArray: Array<number>)
      {
        TS.Utils.checkNotEmptyParameter("keyByteArray", keyByteArray, "TS.Security.AES_CTR.constructor");
        TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_CTR.constructor");

        super(keyByteArray);

        if (arguments.length > 1)
        {
          if (TS.Utils.Assert.isUnsignedByteArray(arguments[1]))
          {
            if (arguments[1].length != 16)
            {
              throw new TS.ArgumentOutOfRangeException("nonce", arguments[1], "Argument 'nonce' must be a byte value array with 16 elements in function 'TS.Security.AES_CTR.constructor'.");
            }//END if
            this.internalCTR = new TS.Security.Counter(arguments[1]);
          }//END if
          else if (TS.Utils.Assert.isUnsignedIntegerNumber(arguments[1]))
          {
            if (arguments[1] > 0xFFFFFFFF)
            {
              throw new TS.ArgumentOutOfRangeException("counterValue", arguments[1], "Argument 'counterValue' must not exceed the maximum allowed value: '" + 0xFFFFFFFF.toString() + "' in function 'TS.Security.AES_CTR.constructor'.");
            }//END if
            this.internalCTR = new TS.Security.Counter(arguments[1]);
          }//END if
          else
          {
            throw new TS.InvalidTypeException("nonce | counterValue", arguments[1], "The second argument in the constructor of 'TS.Security.AES_CTR' has an invalid type. Error occured in 'TS.Security.AES_CTR.constructor'.");
          }//END else
        }//END if
        else
        {
          this.internalCTR = new TS.Security.Counter();
        }//END else

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
      public encrypt(plainDataByteArray: Array<number>): Array<number>
      {
        TS.Utils.checkNotEmptyParameter("plainDataByteArray", plainDataByteArray,"TS.Security.AES_CFB.encrypt");
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
      public decrypt(cipherDataByteArray: Array<number>): Array<number>
      {
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
      protected encryptDecryptInternal(dataByteArray: Array<number>): Array<number>
      {
        let index: number;
        let dataSegment: Array<number>;
        let numberOfFillBytes: number;
        let state: State;
        let dataState: State;
        let resultByteArray: Array<number>;

        index = 0;
        resultByteArray = new Array<number>();
        numberOfFillBytes = 0;
        this.internalCTR = new TS.Security.Counter(this.nonce);

        while (index * 16 < dataByteArray.length)
        {
          state = this.internalCTR.nextState;
          state.encrypt(this.workingKeyByteArray, this.rounds);
          dataSegment = dataByteArray.slice(index * 16, (index + 1) * 16);
          while (dataSegment.length < 16)
          {
            dataSegment.push(0);
            numberOfFillBytes++;
          }//END while
          dataState = new State(dataSegment)
          dataState.xor(state);
          resultByteArray = resultByteArray.concat(dataState.toArray());
          index++;
        }//END while

        while (numberOfFillBytes > 0)
        {
          resultByteArray.pop();
          numberOfFillBytes--;
        }//END while

        return resultByteArray;
      }

    }//END class

  }//END namespace
}//END namespace
 