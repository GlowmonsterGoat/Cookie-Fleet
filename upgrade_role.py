import json

with open("user_roles.json", "r") as f:
    old_data = json.load(f)

new_data = {}

for uid, role in old_data.items():
    new_data[uid] = {
        "role": role,
        "username": "Unknown"  # You can update this later if you want
    }

with open("user_roles.json", "w") as f:
    json.dump(new_data, f, indent=2)

print("✅ user_roles.json upgraded to object format.")
