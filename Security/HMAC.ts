/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {

    interface IHashDescriptor
    {
      inputBlockSizeInByte: number;
      outputBlockSizeInByte: number;
      hash(message: string | Array<number>) : string;
    }


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
    function HMAC(authenticationKey: string | Array<number>, message: string | Array<number>, hashDescriptor: IHashDescriptor) : string
    {
      let workingKeyArray: Array<number>;
      let messageArray: Array<number>;

      TS.Utils.checkParameter("authenticationKey", authenticationKey, "TS.Security.HMAC");
      TS.Utils.checkParameter("message", message, "TS.Security.HMAC");
      TS.Utils.checkParameter("hashDescriptor", hashDescriptor, "TS.Security.HMAC");


      if (!TS.Utils.Assert.isString(authenticationKey) && !TS.Utils.Assert.isUnsignedByteArray(authenticationKey))
      {
        throw new TS.InvalidTypeException("authenticationKey", authenticationKey, "Argument authenticationKey must be a valid string or an array of unsigned byte values in function 'TS.Security.HMAC'.");
      }//END if

      if (!TS.Utils.Assert.isString(message) && !TS.Utils.Assert.isUnsignedByteArray(message))
      {
        throw new TS.InvalidTypeException("message", message, "Argument message must be a valid string or an array of unsigned byte values in function 'TS.Security.HMAC'.");
      }//END if

      if (TS.Utils.Assert.isString(authenticationKey))
      {
        if ((message as string).length > 0)
        {
          workingKeyArray = TS.Encoding.UTF.UTF16StringToUTF8Array(authenticationKey as string);
        }
        else
        {
          workingKeyArray = new Array<number>();
        }
      }
      else
      {
        workingKeyArray = (authenticationKey as Array<number>).slice();
      }


      if (TS.Utils.Assert.isString(message))
      {
        if ((message as string).length > 0)
        {
          messageArray = TS.Encoding.UTF.UTF16StringToUTF8Array(message as string);
        }
        else
        {
          messageArray = new Array<number>();
        }
      }
      else
      {
        messageArray = (message as Array<number>).slice();
      }

      let innerPad: Array<number> = new Array<number>(hashDescriptor.inputBlockSizeInByte).fill(0x36);
      let outerPad: Array<number> = new Array<number>(hashDescriptor.inputBlockSizeInByte).fill(0x5c);
      let innerKeyPad: Array<number>;
      let outerKeyPad: Array<number>;

      if (workingKeyArray.length > hashDescriptor.inputBlockSizeInByte)
      {
        workingKeyArray = TS.Utils.HexStringToUByteArray(hashDescriptor.hash(workingKeyArray));
      }

      while (workingKeyArray.length < hashDescriptor.inputBlockSizeInByte)
      {
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
    export function HMAC_SHA1(authenticationKey: string | Array<number>, message: string | Array<number>): string
    {
      let sha1 = new TS.Security.SHA1();
      return HMAC(authenticationKey, message, { inputBlockSizeInByte: TS.Security.SHA1_KEY_SIZE, outputBlockSizeInByte: TS.Security.SHA1_HASH_SIZE, hash: sha1.encrypt.bind(sha1) });
    }

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
    export function HMAC_MD5(authenticationKey: string | Array<number>, message: string | Array<number>): string
    {
      return HMAC(authenticationKey, message, { inputBlockSizeInByte: TS.Security.MD5_KEY_SIZE, outputBlockSizeInByte: TS.Security.MD5_HASH_SIZE, hash: TS.Security.MD5.encrypt });
    }

  }//END namespace
}//END namespace