from pydotenvcage import safe_load

target = {}
result = safe_load(
    "PORT=8080\nHOST=localhost\n",
    target=target,
    schema={
        "required": ["PORT"],
        "keys": {
            "PORT": {"type": "integer", "min": 1, "max": 65535},
            "HOST": {"type": "string", "minLength": 1},
        },
    },
)

print("loaded", result.loaded)
print("port", target["PORT"])
