# Example Commands

## USB HardReset
Request:

```
{
	command: “kmsUSBHardReset”,
	parameters: {
		portchain: “0”
	}
}
```

Reply:
```
{
    “statusCode”: 0,
    “response”: {
        “errorMessage”: ””
    }
}
```

Note: response object is optional, only send it if error happens.

## GPIO Power Control

Request:

```json
{
    "command": "kmsGPIOPowerControl",
    "parameters": {
        "state": "0"
    }
}
```

Reply:
```json
{
    "statusCode": "0",
    "response": {
        "errorMessage": ""
    }
}
```

Note: response object is optional, only send it if error happens.

## SMBUS Power Control
Request:

```json
{
    "command": "kmsSMBUSPowerControl",
    "parameters": {
        "state": "0"
    }
}
```

Reply:
```
{
    "statusCode": "0",
    "response": {
        "errorMessage": ""
    }
}
```

Note: response object is optional, only send it if error happens.
