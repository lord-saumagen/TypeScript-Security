/// <reference path="../_references.ts" />
namespace TS
{
  export namespace Security
  {
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
    export abstract class AbstractStreamCipher
    {
      /** 
      * @private 
      */
      private timer: number;

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
      constructor(
        cipherOperation: TS.Security.CipherOperationEnum,
        onNextData: (bitString: string) => void,
        onClosed: () => void,
        onError: (exception: TS.Exception) => void)
      {
        TS.Utils.checkParameter("cipherOperation", cipherOperation,  "TS.Security.AbstractStreamCipher.constructor");
        TS.Utils.checkFunctionParameter("onNextData", onNextData,  "TS.Security.AbstractStreamCipher.constructor");
        TS.Utils.checkFunctionParameter("onClosed", onClosed, "TS.Security.AbstractStreamCipher.constructor");
        TS.Utils.checkFunctionParameter("onError", onError, "TS.Security.AbstractStreamCipher.constructor");

        if (!TS.Utils.Assert.isValueOfEnum(cipherOperation, TS.Security.CipherOperationEnum))
        {
          throw new TS.InvalidTypeException("cipherOperation", cipherOperation, "Argument 'cipherOperation' must be a valid element of the 'TS.Security.CipherOperationEnum' enumeration in function 'TS.Security.AbstractStreamCipher.constructor'.");
        }//END if

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
        this.streamState = null
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
      public writeByteArray(byteArray: Array<number>): void
      {
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
      public writeByte(byteValue: number): void
      {
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
      public writeBitString(bitString: string): void
      {
        TS.Utils.checkBitStringParameter("bitString", bitString, "TS.Security.AbstractStreamCipher.writeBitString");

        if ((this.streamState == StreamStateEnum.CLOSED) || (this.streamState == StreamStateEnum.REQUEST_FOR_CLOSE))
        {
          throw new TS.InvalidOperationException("Invalid call to 'write' on a closed stream.");
        }//END if

        if (this.streamState < StreamStateEnum.INITIALIZED)
        {
          this.initialize();
        }//END if

        this.inputBuffer += bitString;
      }


      /**
      * @description Closes the current stream for writing. Since the stream operates asynchronous, the last output
      *  from that stream may appear significant later. The stream is finally closed when the 'onClosed' callback
      *  function is called which was designated during construction.
      */
      public close(): void
      {
        this.streamState = StreamStateEnum.REQUEST_FOR_CLOSE;
      }


      /**
      * @descriptions Stops the internal timer.
      *
      * @private
      */
      private stopTimer(): void
      {
        try
        {
          clearInterval(this.timer);
        }//END try
        catch (e) { };
      }


      /**
      * @descriptions Starts the internal timer.
      *
      * @private
      */
      private startTimer(): void
      {
        this.timer = setInterval(this.process.bind(this), 15);
      }

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
      protected abstract cipher(bitString: string) : string


      /**
      * @descriptions Initialize the class.
      *
      * @private
      *
      * @throws {TS.InvalidOperationException}
      */
      private initialize(): void
      {
        //Don't initialize until the construction of the 
        //current class has finished.
        if (this.streamState != StreamStateEnum.CREATED)
        {
          return;
        }//END if

        if ((this.blockCipher == null) || (this.bufferSizeInBit == null))
        {
          throw new TS.InvalidOperationException("Initialization of the abstract class 'TS.Security.AbstractStreamCipher' is not supported.");
        }//END if

        this.inputBuffer = "";
        this.streamState = StreamStateEnum.INITIALIZED;
        this.startTimer();
      }


      /**
      * @descriptions Processes the data from the input buffer. That means, looking if there is enough data to fill a
      *  segment. Execute the cipher operation on that segment and signal the consumer that there is a new chunk
      *  of data available by calling the 'onNextData' callback.
      *
      * @private
      */
      private process(): void
      {

        let segment: string;
        let processedData: string;

        //
        // Stream is already closed, return.
        //
        if (this.streamState == StreamStateEnum.CLOSED)
        {
          this.stopTimer();
          return;
        }//END if

        //
        // No complete buffer available, return and wait for more data.
        //
        if ((this.streamState != StreamStateEnum.REQUEST_FOR_CLOSE) && (this.inputBuffer.length < this.bufferSizeInBit))
        {
          return;
        }//END if

        //
        // Normal operation on state 'INITIALIZED' or 'REQUEST_FOR_CLOSE' as
        // long as there is data which fills a complete buffer.
        //
        if ((this.streamState == StreamStateEnum.INITIALIZED) || (this.streamState == StreamStateEnum.REQUEST_FOR_CLOSE))
        {
          this.stopTimer();

          while (this.inputBuffer.length >= this.bufferSizeInBit)
          {
            segment = this.inputBuffer.substr(0, this.bufferSizeInBit);
            this.inputBuffer = this.inputBuffer.substr(this.bufferSizeInBit);
            try
            {
              processedData = this.cipher(segment);
              this.onNextData(processedData);
            }//END try
            catch (Exception)
            {
              this.streamState = TS.Security.StreamStateEnum.CLOSED;
              this.stopTimer();
              this.inputBuffer = null;
              this.onError(Exception);
              return;
            }//END catch
          }//END while

          if (this.streamState == StreamStateEnum.REQUEST_FOR_CLOSE)
          {
            //
            // Set the 'CLOSED' flag and block the stream for writing. 
            //
            this.streamState = StreamStateEnum.CLOSED;

            //
            // Stop the timer
            //
            this.stopTimer();

            //
            // Check the buffer for remaining data
            //
            if (this.inputBuffer.length != 0)
            {
              //
              //Clear the buffer
              //
              this.inputBuffer = "";

              //
              // Signal an error if the buffer isn't empty.
              //
              this.onError(new TS.InvalidOperationException("The data does not align with the buffer size. The stream cipher terminated incomplete."));
              return;
            }//END if
            else
            {
              //
              //Clear the buffer
              //
              this.inputBuffer = "";

              //
              //Signal that the stream has closed.
              //
              this.onClosed();
              return;
            }//END else
          }//END if

          this.startTimer();

        }//END if
      }

    }//END class

  }//END namespace
}//END namespace  