# simple-websocket-server
Simple HTTPS and WSS server to manage agent connection

How to use this:
1. Clone or download this repository
2. Install the dependencies
```
$ npm install
```
3. Run the software
```
$ node main.js
```

Run only once to generate client certificate
```
$ node genclientcert.js
```
Run an agent to connect to this machine.
```
$ node agent-ws-test.js
```
