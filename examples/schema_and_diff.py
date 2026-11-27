from pydotenvcage import diff_dotenv, parse_dotenv, validate_schema

development = "PORT=8080\nMODE=development\n"
production = "PORT=443\nMODE=production\n"

parsed = parse_dotenv(production)
validate_schema(parsed.values, {
    "required": ["PORT", "MODE"],
    "keys": {
        "PORT": {"type": "integer", "min": 1, "max": 65535},
        "MODE": {"type": "enum", "values": ["development", "test", "production"]},
    },
})

print(diff_dotenv(development, production).to_dict())
