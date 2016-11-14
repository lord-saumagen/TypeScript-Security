/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {


    /**
    * @class TS.Security.AES_OFB
    *
    * @description This is an implementation of the OUTPUT FEEDBACK (OFB) operation mode as described in the NIST
    *  publication 800-38a, 'Recommendation for Block Cipher Modes of Operation'.
    *
    * @see {@link http://csrc.nist.gov/publications/nistpubs/800-38a/addendum-to-nist_sp800-38A.pdf | NIST}
    */
    export class AES_OFB extends TS.Security.AES
    {
      /** 
      * @private
      */
      private IV: State;

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
      constructor(keyByteArray: Array<number>,  initialisationVector: Array<number>)
      {
        TS.Utils.checkKeyByteArray("keyByteArray", keyByteArray, "TS.Security.AES_OFB.constructor");
        TS.Utils.checkUByteArrayParameter("initialisationVector", initialisationVector, "TS.Security.AES_OFB.constructor");

        if (initialisationVector.length != 16)
        {
          throw new TS.ArgumentOutOfRangeException("initialisationVector", initialisationVector, "Argument 'initialisationVector' must be a byte array of the length 16 in function 'TS.Security.AES_OFB.constructor'.");
        }//END if

        super(keyByteArray);
        this.IV = new State(initialisationVector);
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
      public decrypt(cypherDataByteArray: Array<number>): Array<number>
      {

        TS.Utils.checkNotEmptyParameter("plainDataByteArray", cypherDataByteArray,"TS.Security.AES_OFB.decrypt");
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
        state = new State(this.IV.toArray());
        numberOfFillBytes = 0;

        while (index * 16 < dataByteArray.length)
        {
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
