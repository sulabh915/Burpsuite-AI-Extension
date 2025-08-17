# -*- coding: utf-8 -*-

from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import JScrollPane, JTextArea, SwingUtilities
from java.awt import Font
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
from java.net import URL
from threading import Thread
import json

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AI Response Analyzer (Groq)")
        callbacks.registerMessageEditorTabFactory(self)
        print("[+] Loaded AI Response Analyzer using Groq API")

    def createNewInstance(self, controller, editable):
        return ResponseAnalyzerTab(self._callbacks, self._helpers, controller)

class ResponseAnalyzerTab(IMessageEditorTab):

    def __init__(self, callbacks, helpers, controller):
        self._callbacks = callbacks
        self._helpers = helpers
        self._controller = controller
        self._currentMessage = None

        self._outputArea = JTextArea(25, 80)
        self._outputArea.setEditable(False)
        self._outputArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self._scrollPane = JScrollPane(self._outputArea)

    def getTabCaption(self):
        return "AI Assistant"

    def getUiComponent(self):
        return self._scrollPane

    def isEnabled(self, content, isRequest):
        return not isRequest

    def setMessage(self, content, isRequest):
        if isRequest or content is None:
            self._outputArea.setText("")
            return

        self._currentMessage = content
        responseInfo = self._helpers.analyzeResponse(content)
        body = content[responseInfo.getBodyOffset():]
        body_str = ''.join([chr(b & 0xFF) for b in body])

        self._outputArea.setText("Analyzing with Groq...\n")

        def analyze():
            try:
                analysis = self.callGroqAPI(body_str)
                SwingUtilities.invokeLater(lambda: self._outputArea.setText(analysis))
            except Exception as e:
                SwingUtilities.invokeLater(lambda: self._outputArea.setText("[Error] " + str(e)))

        Thread(target=analyze).start()

    def getMessage(self):
        return self._currentMessage

    def isModified(self):
        return False

    def getSelectedData(self):
        return None

    def callGroqAPI(self, input_text):
        api_key = "gsk_2I55-----"  # Replace with your key from https://console.groq.com/keys

        url = URL("https://api.groq.com/openai/v1/chat/completions")
        connection = url.openConnection()
        connection.setRequestMethod("POST")
        connection.setRequestProperty("Content-Type", "application/json")
        connection.setRequestProperty("Authorization", "Bearer " + api_key)
        connection.setDoOutput(True)

        messages = [{
            "role": "user",
            "content": "Analyze this HTTP response for security vulnerabilities, sensitive data exposure, or misconfigurations:\n\n" + input_text
        }]

        payload = {
            "model": "llama3-70b-8192",  # Current supported Groq model (as of 2025)
            "messages": messages
        }

        out = OutputStreamWriter(connection.getOutputStream())
        out.write(json.dumps(payload))
        out.close()

        status = connection.getResponseCode()
        if status != 200:
            err_stream = BufferedReader(InputStreamReader(connection.getErrorStream()))
            err_msg = ""
            line = err_stream.readLine()
            while line:
                err_msg += line
                line = err_stream.readLine()
            raise Exception("Groq API error " + str(status) + ": " + err_msg)

        reader = BufferedReader(InputStreamReader(connection.getInputStream()))
        response = ""
        line = reader.readLine()
        while line:
            response += line
            line = reader.readLine()
        reader.close()

        result = json.loads(response)
        return result["choices"][0]["message"]["content"]

