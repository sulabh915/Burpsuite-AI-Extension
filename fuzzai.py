# -*- coding: utf-8 -*-

from burp import IBurpExtender, IHttpListener, ITab, IParameter
from javax.swing import JPanel, JTable, JScrollPane, JTextArea, SwingUtilities
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout
from java.net import URL
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
import json
import threading
import re
import time


class BurpExtender(IBurpExtender, IHttpListener, ITab):
    #
    # ---------- Burp lifecycle ----------
    #
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AI Fuzzer Assistant v3")

        # Load keys
        self._loadApiKeys()

        # UI
        self._tableModel = DefaultTableModel(["Param", "Payload", "Status", "Length"], 0)
        self._table = JTable(self._tableModel)
        self._logArea = JTextArea(10, 80)
        self._logArea.setEditable(False)

        self._panel = JPanel(BorderLayout())
        self._panel.add(JScrollPane(self._table), BorderLayout.CENTER)
        self._panel.add(JScrollPane(self._logArea), BorderLayout.SOUTH)

        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        self._log("[+] Loaded %d Groq API key(s)" % len(self._groq_keys))
        self._log("[+] AI Fuzzer Assistant v3 ready.")

    def getTabCaption(self):
        return "AI Fuzzer"

    def getUiComponent(self):
        return self._panel

    #
    # ---------- Helpers ----------
    #
    def _log(self, msg):
        def _append():
            self._logArea.append(msg + "\n")
        SwingUtilities.invokeLater(_append)

    def _loadApiKeys(self):
        self._groq_keys = []
        self._key_index = 0
        try:
            with open("groq_keys.txt", "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self._groq_keys.append(line)
            if not self._groq_keys:
                raise Exception("No keys in groq_keys.txt")
        except Exception as e:
            self._groq_keys = ["invalid"]
            print("[ERROR] Failed to load Groq keys:", str(e))

    def _rotate_key(self):
        key = self._groq_keys[self._key_index]
        self._key_index = (self._key_index + 1) % len(self._groq_keys)
        return key

    #
    # ---------- Listener ----------
    #
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        req = messageInfo.getRequest()
        if req is None:
            return

        analyzed = self._helpers.analyzeRequest(messageInfo)
        params = analyzed.getParameters()
        if params is None or len(params) == 0:
            return

        url = analyzed.getUrl()
        self._log("Intercepted: %s" % url.toString())

        # Build a text representation (headers + body) for the AI context
        headers = analyzed.getHeaders()
        body_bytes = req[analyzed.getBodyOffset():]
        body = ''.join([chr(b & 0xFF) for b in body_bytes])
        request_text = '\r\n'.join(headers) + '\r\n\r\n' + body

        # Run fuzzing in a worker thread
        t = threading.Thread(target=self._fuzz_request, args=(messageInfo.getHttpService(), req, request_text))
        t.start()

    #
    # ---------- Core fuzzing flow ----------
    #
    def _fuzz_request(self, httpService, originalRequestBytes, requestText):
        self._logArea.setText("Fuzzing started...\n")

        # 1) Ask AI for suggestions
        try:
            suggestions = self._call_groq(requestText)
        except Exception as e:
            self._log("[Groq Error] %s" % str(e))
            return

        # suggestions is always a list of dicts (fallback ensures that)
        self._log("Got %d suggestion(s). Sending fuzzed requests..." % len(suggestions))

        # 2) For each suggestion, mutate and send
        for item in suggestions:
            if not isinstance(item, dict):
                continue

            param = item.get("parameter", "").strip()
            payload = item.get("payload", "").strip()
            if not param or payload is None:
                continue

            mutated = self._mutate_request(originalRequestBytes, param, payload)
            if mutated is None:
                # try header mutation if param looked like header (e.g., Referer)
                mutated = self._mutate_header(originalRequestBytes, param, payload)

            if mutated is None:
                self._log("[WARN] Could not mutate request for parameter/header: %s" % param)
                self._add_row(param or "N/A", payload or "", "-", "-")
                continue

            # Send mutated
            try:
                resp = self._callbacks.makeHttpRequest(httpService, mutated)
                rawResp = resp.getResponse()
                if rawResp is None:
                    self._add_row(param, payload, "-", "0")
                    continue
                analyzed = self._helpers.analyzeResponse(rawResp)
                status = analyzed.getStatusCode()
                length = len(rawResp)
                self._add_row(param, payload, str(status), str(length))
            except Exception as e:
                self._log("[ERROR] Sending mutated request failed: %s" % str(e))
                self._add_row(param, payload, "-", "0")

    def _add_row(self, p, pl, s, l):
        def _do():
            self._tableModel.addRow([p, pl, s, l])
        SwingUtilities.invokeLater(_do)

    #
    # ---------- Request mutation ----------
    #
    def _mutate_request(self, originalRequestBytes, name, newValue):
        """
        Tries to mutate URL/body/cookie parameters using Burp helpers.
        Returns mutated request bytes or None.
        """
        try:
            analyzed = self._helpers.analyzeRequest(originalRequestBytes)
            params = analyzed.getParameters()
            targetParam = None
            for par in params:
                if par.getName() == name:
                    targetParam = par
                    break
            if targetParam is None:
                # Try a case-insensitive match
                for par in params:
                    if par.getName().lower() == name.lower():
                        targetParam = par
                        break

            if targetParam is None:
                return None

            # Create a new parameter with same type but new value
            newParam = self._helpers.buildParameter(
                targetParam.getName(),
                newValue,
                targetParam.getType()
            )
            mutated = self._helpers.updateParameter(originalRequestBytes, newParam)
            return mutated
        except Exception as e:
            self._log("[ERROR] updateParameter failed for %s: %s" % (name, str(e)))
            return None

    def _mutate_header(self, originalRequestBytes, headerName, newValue):
        """
        If AI suggests a header (e.g., Referer), mutate/add that header.
        """
        try:
            ri = self._helpers.analyzeRequest(originalRequestBytes)
            headers = list(ri.getHeaders())
            body = originalRequestBytes[ri.getBodyOffset():]

            found = False
            for i in range(len(headers)):
                h = headers[i]
                if ":" in h:
                    k, v = h.split(":", 1)
                    if k.strip().lower() == headerName.lower():
                        headers[i] = "%s: %s" % (k.strip(), newValue)
                        found = True
                        break

            if not found:
                headers.append("%s: %s" % (headerName, newValue))

            msg = self._helpers.buildHttpMessage(headers, body)
            return msg
        except Exception as e:
            self._log("[ERROR] header mutate failed for %s: %s" % (headerName, str(e)))
            return None

    #
    # ---------- AI call + parsing ----------
    #
    def _call_groq(self, requestText, retries=3):
        """
        Returns a list of dicts: [{ "parameter": "...", "payload": "..."}, ...]
        Always returns a list (with fallback), never None.
        """
        last_err = None

        for attempt in range(retries):
            api_key = self._rotate_key()
            try:
                url = URL("https://api.groq.com/openai/v1/chat/completions")
                conn = url.openConnection()
                conn.setRequestMethod("POST")
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setRequestProperty("Authorization", "Bearer " + api_key)
                conn.setDoOutput(True)

                # Prompt: force JSON array only
                prompt = (
                    "You are a web security fuzzer. "
                    "Return ONLY a valid JSON array of objects with exactly these keys: "
                    "\"parameter\" and \"payload\". Do not include prose. Example:\n"
                    "[{\"parameter\": \"id\", \"payload\": \"1' OR '1'='1\"}]\n\n"
                    "Now analyze this raw HTTP request and suggest up to 3 fuzzing payloads:\n\n"
                    + requestText
                )

                payload = {"model": "llama3-70b-8192", "messages": [{"role": "user", "content": prompt}]}

                out = OutputStreamWriter(conn.getOutputStream())
                out.write(json.dumps(payload))
                out.close()

                status = conn.getResponseCode()
                if status == 429:
                    self._log("[WARN] 429 rate-limited. Rotating key and retrying...")
                    time.sleep(2)
                    continue
                if status != 200:
                    try:
                        err = BufferedReader(InputStreamReader(conn.getErrorStream()))
                        em = ""
                        line = err.readLine()
                        while line:
                            em += line
                            line = err.readLine()
                    except:
                        em = "unknown"
                    raise Exception("Groq API error %d: %s" % (status, em))

                reader = BufferedReader(InputStreamReader(conn.getInputStream()))
                raw = ""
                line = reader.readLine()
                while line:
                    raw += line
                    line = reader.readLine()
                reader.close()

                data = json.loads(raw)
                content = data["choices"][0]["message"]["content"]
                return self._parse_ai_content(content)

            except Exception as e:
                last_err = e
                self._log("[ERROR] Groq call failed: %s" % str(e))
                time.sleep(1)

        # Fallback: return one generic suggestion so the UI shows something,
        # but make it explicit it's a fallback.
        self._log("[WARN] All keys failed or invalid AI output. Using fallback suggestions.")
        return [{"parameter": "id", "payload": "1' OR '1'='1"}]

    def _parse_ai_content(self, content):
        """
        Try hard to extract a JSON array. Accepts:
        - Raw JSON
        - JSON wrapped in prose
        - JSON in ```json code fences
        Fallback returns a one-element list with the raw text.
        """
        if content is None:
            return [{"parameter": "N/A", "payload": "No AI content"}]

        txt = content.strip()

        # Strip code fences if present
        fence = re.search(r"```(?:json)?(.*?)```", txt, re.DOTALL | re.IGNORECASE)
        if fence:
            txt = fence.group(1).strip()

        # Try to find the first plausible JSON array
        match = re.search(r"\[\s*{.*}\s*]", txt, re.DOTALL)
        if match:
            block = match.group(0)
            try:
                arr = json.loads(block)
                # normalize items to dicts with required keys
                cleaned = []
                for it in arr:
                    if isinstance(it, dict):
                        p = str(it.get("parameter", "")).strip()
                        v = str(it.get("payload", "")).strip()
                        if p and v:
                            cleaned.append({"parameter": p, "payload": v})
                if cleaned:
                    return cleaned
            except Exception as e:
                self._log("[Parse Error] JSON decode failed: %s" % str(e))

        # As a last resort, attempt to extract pairs like {"parameter": "x", "payload": "y"} anywhere
        pairs = re.findall(r'{"\s*parameter"\s*:\s*"([^"]+)"\s*,\s*"\s*payload"\s*:\s*"([^"]+)"}', txt, re.DOTALL)
        if pairs:
            return [{"parameter": p.strip(), "payload": v.strip()} for (p, v) in pairs]

        # Ultimate fallback: show raw text as a single "payload"
        return [{"parameter": "N/A", "payload": txt[:2000]}]

