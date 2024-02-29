# Requires Jython
from burp import IBurpExtender, IIntruderPayloadProcessor, ISessionHandlingAction
import zlib

ext_name = "ZLib Payload Compressor"

class BurpExtender(IBurpExtender, IIntruderPayloadProcessor, ISessionHandlingAction):
    # init
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # register extension
        callbacks.setExtensionName(ext_name)
        callbacks.registerIntruderPayloadProcessor(self)
        callbacks.registerSessionHandlingAction(self)
        print(ext_name + " Loaded Successfully")

    def getProcessorName(self):
        return ext_name

    def getActionName(self):
        return ext_name

    # Intruder -> Extension Payload Processor
    # ----
    # Used specifically with intruder as a payload processor
    def processPayload(self, currentPayload, originalPayload, baseValue):
        payloadString = self._helpers.bytesToString(currentPayload)

        # Used for GZIP Compression
        compressor = zlib.compressobj(wbits=zlib.MAX_WBITS | 16)
        compressedPayload = compressor.compress(payloadString.encode()) + compressor.flush()

        # If you want just standard zlib, just use 
        # compressedPayload = zlib.compress(payloadString.encode())

        # Return the compressed payload
        return compressedPayload

    # Settings -> Session Handling -> Invoke Extension
    # ----
    # Used to compress all burp traffic from scanner/intruder/repeater etc.
    def performAction(self, currentRequest, macroItems):
        requestInfo = self._helpers.analyzeRequest(currentRequest)
        headers = list(requestInfo.getHeaders())

        bodyBytes = currentRequest.getRequest()[requestInfo.getBodyOffset():]

        # Used for GZIP Compression
        compressor = zlib.compressobj(wbits=zlib.MAX_WBITS | 16)
        compressedBody = compressor.compress(bodyBytes) + compressor.flush()

        # If you want just standard zlib, just use 
        # compressedbody = zlib.compress(bodyBytes)

        # fix headers
        headers = [header for header in headers if not header.startswith("Content-Encoding:")]
        headers.append("Content-Encoding: gzip")

        # Rebuild the HTTP request with the modified headers and compressed body
        newRequest = self._helpers.buildHttpMessage(headers, compressedBody)

        # Update the request with the new compressed content
        currentRequest.setRequest(newRequest)
