# Example Commands

## USB HardReset
Request:

```json
{
    "command": "kmsUSBHardReset",
    "tid": "1234567",
    "parameters": {
        "portchain": "0"
    }
}
```

Reply:

```json
{
    "statusCode": "0",
    "tid": "1234567",
    "response": {
        "errorMessage": ""
    }
}
```

Note: response object is optional, only send it if error happens.

## GPIO Power Control

Request:

```json
{
    "command": "kmsGPIOPowerControl",
    "tid": "1234568",
    "parameters": {
        "state": "0"
    }
}
```

Reply:
```json
{
    "statusCode": "0",
    "tid": "1234568",
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
    "tid": "12345",
    "parameters": {
        "state": "0"
    }
}
```

Reply:

```json
{
    "statusCode": "0",
    "tid": "12345",
    "response": {
        "errorMessage": ""
    }
}
```

Note: response object is optional, only send it if error happens.
